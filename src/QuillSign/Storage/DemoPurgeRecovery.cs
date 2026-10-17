using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Storage;

public sealed record PurgeRecoveryBatch(int Examined,int Swept,int Busy,int Failed,int Deleted,int Protected,int Changed,int Pending,bool More);

// Persistent non-personal recovery survives removal of the private SQL envelope.
// No DbContext, user identity, SQL polling, handler registration or automatic producer.
public sealed class DemoPurgeRecovery
{
    public const string Prefix="purge-recovery/";
    private const string Version="demo-purge-recovery-v1",CursorName="purge-recovery-cursor-v1";
    private const int MaximumRecordBytes=32768;
    private readonly BlobContainerClient hints;private readonly IEnvelopePurgeStore storage;private readonly TimeProvider time;
    private readonly IDataProtector markers,cursors;
    private sealed record Marker(string Version,Guid EnvelopeId,string PolicySha256,DateTimeOffset DeleteAfter,PurgeStorageCursor? Cursor,DateTimeOffset? LastPassEndedAt);
    private sealed record BatchCursor(string Version,string? Token);
    private sealed record Saved<T>(T Value,ETag ETag);
    public DemoPurgeRecovery(BlobContainerClient hints,IDataProtectionProvider protection,IEnvelopePurgeStore storage,TimeProvider time)
    {
        if(hints.Uri.Query.Length!=0 || hints.Uri.Fragment.Length!=0 || hints.Uri.UserInfo.Length!=0)throw Invalid();
        this.hints=hints;this.storage=storage;this.time=time;
        var scope=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(hints.Uri.AbsoluteUri.TrimEnd('/'))));
        markers=protection.CreateProtector("QuillSign.DemoPurgeRecovery.Marker.v1",scope);
        cursors=protection.CreateProtector("QuillSign.DemoPurgeRecovery.Cursor.v1",scope);
    }
    public async Task RememberAsync(DemoPurgeAuthority authority,CancellationToken ct=default)
    {
        ArgumentNullException.ThrowIfNull(authority);authority.Demand(ct);
        var marker=new Marker(Version,authority.EnvelopeId,authority.PolicySha256,authority.DeleteAfter,null,null);
        var blob=hints.GetBlobClient(Prefix+marker.EnvelopeId.ToString("N"));
        try {await Write(blob,marker,markers,new() {IfNoneMatch=ETag.All},ct);}
        catch(Exception error) when(!ct.IsCancellationRequested && Uncertain(error)) { /* Exact readback alone resolves races/lost responses. */ }
        var saved=await Read<Marker>(blob,markers,null,ct);Validate(saved.Value,marker.EnvelopeId);
        if(!SamePolicy(saved.Value,marker))throw Invalid();authority.Demand(ct);
    }
    // Only the internal SQL-removal replay path uses this read. It grants no storage scope.
    internal async Task VerifyRememberedAsync(Guid id,string digest,DateTimeOffset deadline,CancellationToken ct)
    {
        var saved=await Read<Marker>(hints.GetBlobClient(Prefix+id.ToString("N")),markers,null,ct);Validate(saved.Value,id);
        if(saved.Value.PolicySha256!=digest || saved.Value.DeleteAfter!=deadline)throw Invalid();
    }
    public async Task<PurgeRecoveryBatch> RecoverBatchAsync(int maximumMarkers=8,CancellationToken ct=default)
    {
        if(maximumMarkers is <1 or >32)throw new ArgumentOutOfRangeException(nameof(maximumMarkers));ct.ThrowIfCancellationRequested();
        var cursorBlob=hints.GetBlobClient(CursorName);Saved<BatchCursor>? cursor=null;
        try {cursor=await Read<BatchCursor>(cursorBlob,cursors,null,ct);if(cursor.Value.Version!=Version || cursor.Value.Token is {Length:>16384})throw Invalid();}
        catch(RequestFailedException e) when(e.Status==404 && e.ErrorCode=="BlobNotFound") { }
        var pages=hints.GetBlobsAsync(new GetBlobsOptions {Prefix=Prefix},ct).AsPages(cursor?.Value.Token,maximumMarkers);
        Azure.Page<BlobItem>? page=null;await foreach(var value in pages.WithCancellation(ct)){page=value;break;}
        if(page is null || page.Values.Count>maximumMarkers)throw Invalid();
        int examined=0,swept=0,busy=0,failed=0,deleted=0,held=0,changed=0,pending=0;
        foreach(var item in page.Values)
        {
            ct.ThrowIfCancellationRequested();examined++;
            if(!item.Name.StartsWith(Prefix,StringComparison.Ordinal) || !Guid.TryParseExact(item.Name[Prefix.Length..],"N",out var id) || id==Guid.Empty ||
                item.Name!=Prefix+id.ToString("N")){failed++;continue;}
            try {
                var result=await RecoverOne(id,ct);
                if(result is null){busy++;continue;}
                swept++;deleted+=result.Deleted;held+=result.Protected;changed+=result.Changed;
                if(!result.ReachedEnd || result.Protected>0 || result.Changed>0)pending++;
            }
            catch(Exception error) when(!ct.IsCancellationRequested && Recoverable(error)){failed++;}
        }
        var next=new BatchCursor(Version,string.IsNullOrEmpty(page.ContinuationToken) ? null : page.ContinuationToken);
        // Concurrent batch cursors can only affect scheduling, never marker authority.
        try {await Write(cursorBlob,next,cursors,cursor is null ? new(){IfNoneMatch=ETag.All} : new(){IfMatch=cursor.ETag},ct);}
        catch(RequestFailedException error) when(error.Status==412 || error.Status==409 && error.ErrorCode=="BlobAlreadyExists") { }
        return new(examined,swept,busy,failed,deleted,held,changed,pending,next.Token is not null);
    }
    private async Task<PurgeStorageBatch?> RecoverOne(Guid id,CancellationToken ct)
    {
        var blob=hints.GetBlobClient(Prefix+id.ToString("N"));var saved=await Read<Marker>(blob,markers,null,ct);Validate(saved.Value,id);
        var lease=blob.GetBlobLeaseClient(Guid.NewGuid().ToString());var started=time.GetUtcNow();var acquired=false;
        using var bounded=CancellationTokenSource.CreateLinkedTokenSource(ct);bounded.CancelAfter(TimeSpan.FromSeconds(40));
        try
        {
            try {await lease.AcquireAsync(TimeSpan.FromSeconds(60),new RequestConditions {IfMatch=saved.ETag},bounded.Token);acquired=true;}
            catch(RequestFailedException error) when(error.Status==412 || error.Status==409 && error.ErrorCode=="LeaseAlreadyPresent"){return null;}
            var conditions=new BlobRequestConditions {LeaseId=lease.LeaseId,IfMatch=saved.ETag};
            var current=await Read<Marker>(blob,markers,conditions,bounded.Token);Validate(current.Value,id);
            if(current.ETag!=saved.ETag || current.Value!=saved.Value)throw Invalid();
            var scope=new VerifiedScope(id,saved.Value.PolicySha256,saved.Value.DeleteAfter,time,started.AddSeconds(45));
            var authority=DemoPurgeAuthority.Recovery(scope);
            var result=await storage.SweepAsync(authority,16,saved.Value.Cursor,bounded.Token);scope.Demand(bounded.Token);
            var next=saved.Value with {Cursor=result.Next,LastPassEndedAt=result.ReachedEnd ? time.GetUtcNow() : saved.Value.LastPassEndedAt};Validate(next,id);
            try {await Write(blob,next,markers,conditions,bounded.Token);}
            catch(Exception error) when(!bounded.IsCancellationRequested && Uncertain(error)) {
                var found=await Read<Marker>(blob,markers,new(){LeaseId=lease.LeaseId},bounded.Token);Validate(found.Value,id);
                if(found.Value!=next)throw Invalid();
            }
            scope.Demand(bounded.Token);return result;
        }
        finally
        {
            if(acquired) {
                using var cleanup=new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try {await lease.ReleaseAsync(cancellationToken:cleanup.Token);}
                catch(Exception error) when(Recoverable(error)){ /* Finite lease expires; never break another owner's lease. */ }
            }
        }
    }
    internal sealed record VerifiedScope(Guid EnvelopeId,string PolicySha256,DateTimeOffset DeleteAfter,TimeProvider Time,DateTimeOffset Until)
    {
        internal void Demand(CancellationToken ct)
        {ct.ThrowIfCancellationRequested();if(EnvelopeId==Guid.Empty || !Hash(PolicySha256) || Time.GetUtcNow()<DeleteAfter || Until<=Time.GetUtcNow())throw Invalid();}
    }
    private void Validate(Marker marker,Guid id)
    {
        if(marker.Version!=Version || marker.EnvelopeId!=id || id==Guid.Empty || !Hash(marker.PolicySha256) || marker.DeleteAfter.Offset!=TimeSpan.Zero ||
            marker.DeleteAfter.Ticks%TimeSpan.TicksPerSecond!=0 || marker.DeleteAfter>time.GetUtcNow() ||
            marker.LastPassEndedAt is DateTimeOffset ended && (ended.Offset!=TimeSpan.Zero || ended<marker.DeleteAfter || ended>time.GetUtcNow()) ||
            marker.Cursor is { } c && (c.EnvelopeId!=id || c.PolicySha256!=marker.PolicySha256 || c.Area is <0 or >3 || c.Continuation is {Length:>16384}))throw Invalid();
    }
    private static bool Hash(string? value)=>value is {Length:64} && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool SamePolicy(Marker a,Marker b)=>a.Version==b.Version && a.EnvelopeId==b.EnvelopeId && a.PolicySha256==b.PolicySha256 && a.DeleteAfter==b.DeleteAfter;
    private static async Task<Saved<T>> Read<T>(BlobClient blob,IDataProtector protection,BlobRequestConditions? conditions,CancellationToken ct)
    {
        var properties=(await blob.GetPropertiesAsync(conditions,ct)).Value;
        if(properties.ContentLength is <1 or >MaximumRecordBytes)throw Invalid();
        var download=(await blob.DownloadStreamingAsync(new(){Conditions=new(){IfMatch=properties.ETag,LeaseId=conditions?.LeaseId}},ct)).Value;
        if(download.Details.ContentLength!=properties.ContentLength || download.Details.ETag!=properties.ETag)throw Invalid();
        await using var input=download.Content;using var memory=new MemoryStream();using var bounded=new BoundedDocumentStream(memory,MaximumRecordBytes);
        await input.CopyToAsync(bounded,ct);if(memory.Length!=properties.ContentLength)throw Invalid();
        var json=protection.Unprotect(new UTF8Encoding(false,true).GetString(memory.GetBuffer(),0,checked((int)memory.Length)));
        if(json.Length>MaximumRecordBytes)throw Invalid();var value=JsonSerializer.Deserialize<T>(json)??throw Invalid();
        if(JsonSerializer.Serialize(value)!=json)throw Invalid();return new(value,properties.ETag);
    }
    private static async Task Write<T>(BlobClient blob,T value,IDataProtector protection,BlobRequestConditions conditions,CancellationToken ct)
    {
        var data=protection.Protect(JsonSerializer.Serialize(value));if(Encoding.UTF8.GetByteCount(data)>MaximumRecordBytes)throw Invalid();
        await blob.UploadAsync(BinaryData.FromString(data),new BlobUploadOptions {Conditions=conditions},ct);
    }
    private static bool Uncertain(Exception e)=>e is IOException or HttpRequestException or TimeoutException or OperationCanceledException ||
        e is RequestFailedException request && (request.Status is 409 or 412 || request.Status>=500);
    private static bool Recoverable(Exception e)=>e is RequestFailedException or IOException or InvalidDataException or HttpRequestException or TimeoutException or OperationCanceledException or CryptographicException or JsonException or UnauthorizedAccessException or ArgumentException;
    private static InvalidDataException Invalid()=>new("The saved demo purge recovery record could not be verified.");
}

public static class DemoPurgeRecoveryConfiguration
{
    public static IServiceCollection AddDemoPurgeRecovery(this IServiceCollection services)
    {
        services.TryAddSingleton<IEnvelopePurgeStore>(sp=>new AzureEnvelopePurgeStore(sp.GetRequiredService<BlobServiceClient>()));
        services.TryAddSingleton<DemoPurgeRecovery>(sp=> {
            var options=sp.GetRequiredService<WorkOptions>();if(!options.Enabled)throw new InvalidOperationException("Durable work is disabled.");
            return new(sp.GetRequiredService<BlobServiceClient>().GetBlobContainerClient(options.HintContainer),sp.GetRequiredService<IDataProtectionProvider>(),sp.GetRequiredService<IEnvelopePurgeStore>(),sp.GetRequiredService<TimeProvider>());
        });return services;
    }
}

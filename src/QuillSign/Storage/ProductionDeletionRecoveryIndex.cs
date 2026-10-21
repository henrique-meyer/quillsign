using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Storage;

// Scheduling facts ONLY. Every consumer must authenticate the independently
// retained immutable deletion journal/plan before SQL or destructive provider IO.
internal sealed record ProductionDeletionRecoveryHint(Guid RecordId,Guid DeletionId,string PlanSha256);
internal sealed record ProductionDeletionRecoveryPage(IReadOnlyList<ProductionDeletionRecoveryHint> Hints,string? Continuation);
internal interface IProductionDeletionRecoveryIndex
{
    Task RememberAsync(ProductionDeletionObjectScope scope,ProductionDeletionRecoveryHint hint,CancellationToken ct=default);
    Task<ProductionDeletionRecoveryHint> ReadAsync(Guid recordId,Guid deletionId,CancellationToken ct=default);
    Task<ProductionDeletionRecoveryPage> ListAsync(string? continuation,int maximum,CancellationToken ct=default);
}
internal sealed class AzureProductionDeletionRecoveryIndex:IProductionDeletionRecoveryIndex,IDisposable
{
    private const int MaximumBytes=8192;
    private const string Version="production-deletion-recovery-hint-v1";
    private static readonly JsonSerializerOptions Json=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=4};
    private readonly BlobContainerClient container;private readonly IDataProtector protector;private readonly string prefix;private readonly HttpClient? ownedClient;
    private sealed record Body(string Version,ProductionDeletionRecoveryHint Hint);
    internal AzureProductionDeletionRecoveryIndex(Uri containerUri,TokenCredential credential,IDataProtectionProvider keys,string installationDigest,HttpPipelineTransport? transport=null)
    {
        if(containerUri is null||!containerUri.IsAbsoluteUri||containerUri.Scheme!="https"||containerUri.Query.Length!=0||containerUri.UserInfo.Length!=0||containerUri.Fragment.Length!=0||
            containerUri.Host.Contains("-secondary.",StringComparison.OrdinalIgnoreCase)||!Hash(installationDigest))throw Invalid();
        var name=containerUri.AbsolutePath.Trim('/');if(name.Length is <3 or >63||name[0]=='-'||name[^1]=='-'||name.Contains("--",StringComparison.Ordinal)||name.Any(c=>c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-')))throw Invalid();
        var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);options.Retry.MaxRetries=0;options.Diagnostics.IsLoggingEnabled=false;options.Diagnostics.IsLoggingContentEnabled=false;options.Diagnostics.IsDistributedTracingEnabled=false;
        if(transport is not null)options.Transport=transport;else{ownedClient=new(new SocketsHttpHandler{AllowAutoRedirect=false});options.Transport=new HttpClientTransport(ownedClient);}
        options.AddPolicy(new ProductionDeletionRefuseRedirectOrChallenge(),HttpPipelinePosition.PerRetry);container=new(containerUri,credential,options);
        prefix=$"production-deletion-recovery/{installationDigest}/";
        protector=keys.CreateProtector(Version,installationDigest,containerUri.AbsoluteUri.TrimEnd('/'));
    }
    public async Task RememberAsync(ProductionDeletionObjectScope scope,ProductionDeletionRecoveryHint hint,CancellationToken ct=default)
    {
        Validate(hint);if(hint.RecordId!=scope.RecordId||hint.DeletionId!=scope.DeletionId)throw Invalid();await scope.DemandAsync(ct);await DemandPrivate(ct);await scope.DemandAsync(ct);
        var bytes=protector.Protect(JsonSerializer.SerializeToUtf8Bytes(new Body(Version,hint),Json));if(bytes.Length>MaximumBytes)throw Invalid();
        try{await container.GetBlobClient(Path(hint.RecordId,hint.DeletionId)).UploadAsync(BinaryData.FromBytes(bytes),new BlobUploadOptions{Conditions=new(){IfNoneMatch=ETag.All}},ct);}
        catch(RequestFailedException e)when(e.Status==412||e.Status==409&&e.ErrorCode=="BlobAlreadyExists"){await scope.DemandAsync(ct);}
        await scope.DemandAsync(ct);var found=await ReadAsync(hint.RecordId,hint.DeletionId,ct);await scope.DemandAsync(ct);if(found!=hint)throw Invalid();
    }
    public async Task<ProductionDeletionRecoveryHint> ReadAsync(Guid recordId,Guid deletionId,CancellationToken ct=default)
    {
        if(recordId==Guid.Empty||deletionId==Guid.Empty)throw Invalid();await DemandPrivate(ct);var blob=container.GetBlobClient(Path(recordId,deletionId));
        var p=(await blob.GetPropertiesAsync(cancellationToken:ct)).Value;if(p.ContentLength is <1 or >MaximumBytes||p.BlobType!=BlobType.Block)throw Invalid();
        var d=(await blob.DownloadStreamingAsync(new(){Conditions=new(){IfMatch=p.ETag}},ct)).Value;await using var input=d.Content;
        if(d.Details.ContentLength!=p.ContentLength||d.Details.ETag!=p.ETag)throw Invalid();var bytes=new byte[checked((int)p.ContentLength)];await input.ReadExactlyAsync(bytes,ct);if(await input.ReadAsync(new byte[1],ct)!=0)throw Invalid();
        var plain=protector.Unprotect(bytes);
        try{if(plain.Length>MaximumBytes)throw Invalid();var body=JsonSerializer.Deserialize<Body>(plain,Json)??throw Invalid();if(body.Version!=Version||!plain.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(body,Json)))throw Invalid();Validate(body.Hint);if(body.Hint.RecordId!=recordId||body.Hint.DeletionId!=deletionId)throw Invalid();return body.Hint;}
        finally{CryptographicOperations.ZeroMemory(plain);}
    }
    public async Task<ProductionDeletionRecoveryPage> ListAsync(string? continuation,int maximum,CancellationToken ct=default)
    {
        if(maximum is <1 or >32||continuation is {Length:>16384})throw Invalid();ct.ThrowIfCancellationRequested();
        var properties=(await container.GetPropertiesAsync(cancellationToken:ct)).Value;if(properties.PublicAccess is not null&&properties.PublicAccess!=PublicAccessType.None)throw Invalid();
        await foreach(var page in container.GetBlobsAsync(new GetBlobsOptions{Prefix=prefix},ct).AsPages(continuation,maximum).WithCancellation(ct))
        {
            if(page.Values.Count>maximum||page.ContinuationToken is {Length:>16384})throw Invalid();var hints=new List<ProductionDeletionRecoveryHint>();
            foreach(var item in page.Values)
            {
                if(!item.Name.StartsWith(prefix,StringComparison.Ordinal))throw Invalid();var parts=item.Name[prefix.Length..].Split('/');
                if(parts.Length!=2||!Guid.TryParseExact(parts[0],"N",out var record)||!Guid.TryParseExact(parts[1],"N",out var deletion)||item.Name!=Path(record,deletion))throw Invalid();
                hints.Add(await ReadAsync(record,deletion,ct));
            }
            return new(hints.AsReadOnly(),string.IsNullOrEmpty(page.ContinuationToken)?null:page.ContinuationToken);
        }
        return new([],null);
    }
    private string Path(Guid record,Guid deletion)=>prefix+$"{record:N}/{deletion:N}";
    private async Task DemandPrivate(CancellationToken ct){var p=(await container.GetPropertiesAsync(cancellationToken:ct)).Value;if(p.PublicAccess is not null&&p.PublicAccess!=PublicAccessType.None)throw Invalid();}
    private static bool Hash(string value)=>value is {Length:64}&&value.All(char.IsAsciiHexDigitLower);
    private static void Validate(ProductionDeletionRecoveryHint hint){if(hint is null||hint.RecordId==Guid.Empty||hint.DeletionId==Guid.Empty||!Hash(hint.PlanSha256))throw Invalid();}
    private static InvalidDataException Invalid()=>new("The production deletion recovery scheduling hint could not be verified.");
    public void Dispose()=>ownedClient?.Dispose();
}

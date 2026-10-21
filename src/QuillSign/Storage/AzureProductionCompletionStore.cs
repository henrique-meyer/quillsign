using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using QuillSign.Lifecycle;

namespace QuillSign.Storage;

internal interface IProductionCompletionStorageFence
{
    Task DemandAsync(CancellationToken ct);
    Task ConsumeMutationAsync(string requestSha256, CancellationToken ct);
    Task AcknowledgeMutationAsync(string requestSha256, CancellationToken ct);
}

// All bytes, targets, blocks, ownership and protection are fixed before the
// external once-only effect start. No caller stream is retained across awaits.
internal sealed class ProductionCompletionStoragePlan
{
    internal const int BlockBytes=4*1024*1024;
    private readonly byte[]? bytes;
    internal ProductionRecordWriteDescriptor? Item { get; }
    internal FinalDocument? FinalTarget { get; }
    internal Guid RecordId { get; }
    internal Guid ObjectId { get; }
    internal long Length { get; }
    internal bool MayWrite=>bytes is not null;
    internal string Sha256 { get; }
    internal CompletionEffectDescriptor Effect { get; }
    internal string Area { get; }
    internal string Name { get; }
    internal string Owner { get; }
    internal DateTimeOffset? Until { get; }
    internal DateTimeOffset RecordedAt { get; }
    internal ImmutableArray<string> Blocks { get; }
    internal bool Final=>Area=="final";
    internal FinalDocumentKind FinalKind=>FinalTarget?.Kind??throw Invalid();
    private ProductionCompletionStoragePlan(ProductionRecordOperation scope,HoldWitnessCompletionContext context,CompletionEffect effect,
        ProductionRecordWriteDescriptor? item,FinalDocument? finalTarget,byte[]? source,DateTimeOffset? until,CompletionEffectDescriptor? saved=null)
    {
        ProductionCompletionProtocol.Context(context);
        var final=effect is CompletionEffect.PublicationExecutedFinal or CompletionEffect.PublicationCertificateFinal;
        var objectId=finalTarget?.ObjectId??item?.Blob.ObjectId??Guid.Empty;
        var length=source?.LongLength??saved?.Length??0;var sha=source is not null?Hash(source):saved?.Sha256;
        if(scope.RecordId==Guid.Empty||scope.OperationId!=context.OperationId||scope.ReservationSequence<1||
            !ProductionCompletionProtocol.Sealing(scope.Kind)||objectId==Guid.Empty||
            !context.Targets.Contains(new(effect,objectId))||length is <1 or >64*1024*1024||!ProductionCompletionProtocol.Hash(sha)||
            source is null&&saved is null||source is not null&&saved is not null||saved is not null&&(saved.Effect!=effect||saved.TargetId!=objectId)||
            (final ? item is not null||finalTarget is null||finalTarget.Value.EnvelopeId!=scope.RecordId||
                finalTarget.Value.Kind!=(effect==CompletionEffect.PublicationExecutedFinal?FinalDocumentKind.Executed:FinalDocumentKind.Certificate) :
                finalTarget is not null||item is null||item.Blob.EnvelopeId!=scope.RecordId||length!=item.Length||sha!=item.Sha256)||
            until is {} deadline&&(deadline.Offset!=TimeSpan.Zero||deadline<=context.RecordedAt||deadline.Ticks%TimeSpan.TicksPerSecond!=0))throw Invalid();
        bytes=source?.ToArray();Length=length;Sha256=bytes is not null?Hash(bytes):sha!;
        if(Sha256!=sha||item is not null&&Sha256!=item.Sha256)throw Invalid();Item=item;FinalTarget=finalTarget;RecordId=scope.RecordId;ObjectId=objectId;
        var expected=effect switch {
            CompletionEffect.CandidatePdf=>DocumentBlobKind.CompletionCandidate,
            CompletionEffect.ExecutedPdf=>DocumentBlobKind.CompletionExecutedSeal,
            CompletionEffect.CertificateSource=>DocumentBlobKind.CompletionCertificateSource,
            CompletionEffect.CertificatePdf=>DocumentBlobKind.CompletionCertificateSeal,
            CompletionEffect.ExecutedTsa or CompletionEffect.CertificateTsa=>throw Invalid(),_=>DocumentBlobKind.CompletionInput};
        if(!final&&(item!.Blob.Kind!=expected||until is not null||expected==DocumentBlobKind.CompletionInput&&length>16*1024*1024+65536))throw Invalid();
        Area=final?"final":"normalized";Until=until;RecordedAt=context.RecordedAt;
        Name=final?$"{scope.RecordId:N}/{(effect==CompletionEffect.PublicationExecutedFinal?"executed":"certificate")}/{objectId:N}":
            $"{scope.RecordId:N}/{(expected switch {DocumentBlobKind.CompletionInput=>"completion-inputs",DocumentBlobKind.CompletionCandidate=>"completion-candidates",
                DocumentBlobKind.CompletionExecutedSeal=>"completion-seals/executed",DocumentBlobKind.CompletionCertificateSource=>"completion-seals/certificate-source",
                DocumentBlobKind.CompletionCertificateSeal=>"completion-seals/certificate",_=>throw Invalid()})}/{objectId:N}";
        Owner=ProductionCompletionProtocol.Digest(new {Version="production-completion-object-owner-v1",scope.RecordId,scope.OperationId,
            scope.ReservationSequence,Context=ProductionCompletionProtocol.Digest(context),Effect=effect,Item=item,FinalTarget,Length,Sha256,Area,Name,Until});
        if(saved is not null)
        {
            Blocks=[];Effect=saved;ProductionCompletionProtocol.Effect(Effect,context);return;
        }
        var blocks=ImmutableArray.CreateBuilder<string>();var requests=ImmutableArray.CreateBuilder<string>();var ownedBytes=bytes??throw Invalid();
        for(var offset=0;offset<ownedBytes.Length;offset+=BlockBytes)
        {
            var index=blocks.Count;var id=Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes($"{Owner}:{index:D8}")));blocks.Add(id);
            requests.Add(ProductionCompletionProtocol.Digest(new {Version="completion-stage-request-v1",Area,Name,Owner,BlockId=id,
                Length=Math.Min(BlockBytes,ownedBytes.Length-offset),Sha256=Hash(ownedBytes.AsSpan(offset,Math.Min(BlockBytes,ownedBytes.Length-offset)))}));
        }
        Blocks=blocks.ToImmutable();requests.Add(ProductionCompletionProtocol.Digest(new {Version="completion-commit-request-v1",Area,Name,Owner,
            Item,FinalTarget,Length,Sha256,Blocks,Until,LegalHold=final&&until is null,Condition="IfNoneMatch:*"}));
        Effect=new(effect,objectId,Length,Sha256,requests.Count,requests.ToImmutable());
        ProductionCompletionProtocol.Effect(Effect,context);
    }
    internal static ProductionCompletionStoragePlan Own(ProductionRecordOperation scope,HoldWitnessCompletionContext context,
        CompletionEffect effect,ProductionRecordWriteDescriptor item,byte[] bytes)=>new(scope,context,effect,item,null,bytes,null);
    internal static ProductionCompletionStoragePlan OwnFinal(ProductionRecordOperation scope,HoldWitnessCompletionContext context,
        CompletionEffect effect,FinalDocument target,byte[] bytes,DateTimeOffset? until)=>new(scope,context,effect,null,target,bytes,until);
    internal static ProductionCompletionStoragePlan ReadObject(ProductionRecordOperation scope,HoldWitnessCompletionContext context,
        CompletionEffectDescriptor saved,ProductionRecordWriteDescriptor item)=>new(scope,context,saved.Effect,item,null,null,null,saved);
    internal static ProductionCompletionStoragePlan ReadFinal(ProductionRecordOperation scope,HoldWitnessCompletionContext context,
        CompletionEffectDescriptor saved,FinalDocument target,DateTimeOffset? until)=>new(scope,context,saved.Effect,null,target,null,until,saved);
    internal Stream OpenBlock(int index)
    {var offset=checked(index*BlockBytes);if(bytes is null||index<0||index>=Blocks.Length)throw Invalid();return new MemoryStream(bytes,offset,Math.Min(BlockBytes,bytes.Length-offset),false);}
    internal static string Hash(ReadOnlySpan<byte> data)=>Convert.ToHexStringLower(SHA256.HashData(data));
    internal static InvalidDataException Invalid()=>new("The exact owned completion object could not be verified.");
}

internal sealed record ProductionCompletionStored(ProductionRecordWriteReceipt? Receipt,FinalStoredDocument? Final);
internal interface IProductionCompletionObjectStore
{
    Task<ProductionCompletionStored> WriteAsync(ProductionCompletionStoragePlan plan,IProductionCompletionStorageFence fence,CancellationToken ct=default);
    Task<ProductionCompletionStored> RecoverAsync(ProductionCompletionStoragePlan plan,IProductionCompletionStorageFence fence,
        ProductionCompletionStored? saved=null,CancellationToken ct=default);
    Task<byte[]> ReadInputAsync(ProductionCompletionStoragePlan plan,ProductionCompletionStored saved,IProductionCompletionStorageFence fence,CancellationToken ct=default);
}

// Private/unregistered. A dedicated token-only client has no automatic mutation
// retries, redirect, authentication-challenge resend or container provisioning.
internal sealed class AzureProductionCompletionStore:IProductionCompletionObjectStore,IProductionCompletionInputSource,IDisposable
{
    private readonly BlobServiceClient service;private readonly HttpClient? owned;
    internal AzureProductionCompletionStore(Uri uri,TokenCredential credential,HttpPipelineTransport? transport=null)
    {
        if(uri is null||!uri.IsAbsoluteUri||uri.Scheme!="https"||uri.AbsolutePath!="/"||uri.Query.Length!=0||uri.Fragment.Length!=0||
            uri.UserInfo.Length!=0||uri.Host.Contains("-secondary.",StringComparison.OrdinalIgnoreCase))throw ProductionCompletionStoragePlan.Invalid();
        ArgumentNullException.ThrowIfNull(credential);
        var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);options.Retry.MaxRetries=0;
        options.Diagnostics.IsLoggingEnabled=false;options.Diagnostics.IsLoggingContentEnabled=false;options.Diagnostics.IsDistributedTracingEnabled=false;
        if(transport is not null)options.Transport=transport;
        else{owned=new(new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false});options.Transport=new HttpClientTransport(owned);}
        options.AddPolicy(new NoResubmission(),HttpPipelinePosition.PerRetry);service=new(uri,credential,options);
    }
    public async Task<ProductionCompletionStored> WriteAsync(ProductionCompletionStoragePlan plan,IProductionCompletionStorageFence fence,CancellationToken ct=default)
    {
        ArgumentNullException.ThrowIfNull(plan);ArgumentNullException.ThrowIfNull(fence);
        if(!plan.MayWrite)throw ProductionCompletionStoragePlan.Invalid();
        await Ready(plan,fence,ct);var client=Client(plan);
        if(await Current(client,fence,ct) is not null)throw ProductionCompletionStoragePlan.Invalid();
        for(var index=0;index<plan.Blocks.Length;index++)
        {
            await fence.DemandAsync(ct);await fence.ConsumeMutationAsync(plan.Effect.Requests[index],ct);
            using var block=plan.OpenBlock(index);await client.StageBlockAsync(plan.Blocks[index],block,cancellationToken:ct);
            await fence.DemandAsync(ct);await fence.AcknowledgeMutationAsync(plan.Effect.Requests[index],ct);
        }
        var commit=plan.Effect.Requests[^1];await fence.DemandAsync(ct);await fence.ConsumeMutationAsync(commit,ct);
        try
        {
            var options=new CommitBlockListOptions {Conditions=new(){IfNoneMatch=ETag.All},HttpHeaders=new(){ContentType=plan.Item?.Blob.Kind==DocumentBlobKind.CompletionInput?"application/octet-stream":"application/pdf"},
                Metadata=new Dictionary<string,string>{{"quillsign_completion",plan.Owner}}};
            if(plan.Final)
            {
                if(plan.Until is {} until)options.ImmutabilityPolicy=new(){ExpiresOn=until,PolicyMode=BlobImmutabilityPolicyMode.Locked};
                else options.LegalHold=true;
            }
            await client.CommitBlockListAsync(plan.Blocks,options,ct);
        }
        catch(Exception error) when(Uncertain(error))
        {
            // Readback can acknowledge this LAST request. Nothing resends the
            // commit, stages another block, locks an old version or changes time.
            ct.ThrowIfCancellationRequested();
        }
        await fence.DemandAsync(ct);var stored=await Verify(plan,fence,null,ct);
        await fence.AcknowledgeMutationAsync(commit,ct);await fence.DemandAsync(ct);return stored;
    }
    public async Task<ProductionCompletionStored> RecoverAsync(ProductionCompletionStoragePlan plan,IProductionCompletionStorageFence fence,
        ProductionCompletionStored? saved=null,CancellationToken ct=default)
    {ArgumentNullException.ThrowIfNull(plan);ArgumentNullException.ThrowIfNull(fence);await Ready(plan,fence,ct);return await Verify(plan,fence,saved,ct);}
    public async Task<byte[]> ReadInputAsync(ProductionCompletionStoragePlan plan,ProductionCompletionStored saved,IProductionCompletionStorageFence fence,CancellationToken ct=default)
    {
        if(plan.MayWrite||plan.Item?.Blob.Kind!=DocumentBlobKind.CompletionInput||plan.Length>ProductionCompletionInputCodec.MaximumCipherBytes||saved.Receipt?.Item!=plan.Item||saved.Final is not null)throw ProductionCompletionStoragePlan.Invalid();
        using var bytes=new MemoryStream(checked((int)plan.Length));await Ready(plan,fence,ct);await Verify(plan,fence,saved,ct,bytes);return bytes.ToArray();
    }
    private BlockBlobClient Client(ProductionCompletionStoragePlan plan)=>service.GetBlobContainerClient(plan.Area).GetBlockBlobClient(plan.Name);
    private async Task Ready(ProductionCompletionStoragePlan plan,IProductionCompletionStorageFence fence,CancellationToken ct)
    {
        await fence.DemandAsync(ct);var p=(await service.GetBlobContainerClient(plan.Area).GetPropertiesAsync(cancellationToken:ct)).Value;await fence.DemandAsync(ct);
        if(p.PublicAccess is not null&&p.PublicAccess!=PublicAccessType.None||plan.Final&&p.HasImmutableStorageWithVersioning!=true)throw ProductionCompletionStoragePlan.Invalid();
    }
    private static async Task<BlobProperties?> Current(BlobBaseClient client,IProductionCompletionStorageFence fence,CancellationToken ct)
    {
        await fence.DemandAsync(ct);
        try{var p=(await client.GetPropertiesAsync(cancellationToken:ct)).Value;await fence.DemandAsync(ct);return p;}
        catch(RequestFailedException e) when(e.Status==404&&e.ErrorCode=="BlobNotFound"){await fence.DemandAsync(ct);return null;}
    }
    private async Task<ProductionCompletionStored> Verify(ProductionCompletionStoragePlan plan,IProductionCompletionStorageFence fence,
        ProductionCompletionStored? saved,CancellationToken ct,Stream? capture=null)
    {
        var root=Client(plan);var current=await Current(root,fence,ct)??throw ProductionCompletionStoragePlan.Invalid();
        if(!Opaque(current.VersionId)||!Opaque(current.ETag.ToString("H")))throw ProductionCompletionStoragePlan.Invalid();
        var versionId=current.VersionId;var etag=current.ETag.ToString("H");
        var receipt=plan.Item is {} item?new ProductionRecordWriteReceipt(item,versionId,etag):null;
        Check(current,plan,versionId,etag);
        var version=root.WithVersion(versionId);var condition=new BlobRequestConditions{IfMatch=new ETag(etag)};
        await fence.DemandAsync(ct);var before=(await version.GetPropertiesAsync(condition,ct)).Value;await fence.DemandAsync(ct);Check(before,plan,versionId,etag);
        await fence.DemandAsync(ct);var response=await version.DownloadStreamingAsync(new(){Conditions=condition},ct);await fence.DemandAsync(ct);
        await using(var stream=response.Value.Content)
        {
            if(response.Value.Details.VersionId!=versionId||response.Value.Details.ETag.ToString("H")!=etag||response.Value.Details.ContentLength!=plan.Length)throw ProductionCompletionStoragePlan.Invalid();
            using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);var buffer=new byte[256*1024];long read=0;
            while(read<plan.Length)
            {
                await fence.DemandAsync(ct);var n=await stream.ReadAsync(buffer.AsMemory(0,(int)Math.Min(buffer.Length,plan.Length-read)),ct);await fence.DemandAsync(ct);
                if(n==0)throw ProductionCompletionStoragePlan.Invalid();hash.AppendData(buffer.AsSpan(0,n));capture?.Write(buffer,0,n);read+=n;
            }
            await fence.DemandAsync(ct);var extra=await stream.ReadAsync(buffer.AsMemory(0,1),ct);await fence.DemandAsync(ct);
            if(extra!=0||Convert.ToHexStringLower(hash.GetHashAndReset())!=plan.Sha256)throw ProductionCompletionStoragePlan.Invalid();
        }
        await fence.DemandAsync(ct);var after=(await version.GetPropertiesAsync(condition,ct)).Value;await fence.DemandAsync(ct);Check(after,plan,versionId,etag);
        // A changed current root or protection bit with unchanged ETag is not
        // silently accepted. Exact historical bytes stay pinned throughout.
        var final=await Current(root,fence,ct)??throw ProductionCompletionStoragePlan.Invalid();Check(final,plan,versionId,etag);
        var document=plan.Final?new FinalStoredDocument(plan.FinalTarget!.Value,plan.Length,
            Convert.FromHexString(plan.Sha256),versionId,etag,plan.Until is null?FinalProtection.LegalHold:FinalProtection.LockedTime,plan.Until,current.CreatedOn):null;
        if(saved is not null&&(saved.Receipt!=receipt||!Same(saved.Final,document)))throw ProductionCompletionStoragePlan.Invalid();
        return new(receipt,document);
    }
    private static void Check(BlobProperties p,ProductionCompletionStoragePlan plan,string versionId,string etag)
    {
        if(p.VersionId!=versionId||p.ETag.ToString("H")!=etag||p.ContentLength!=plan.Length||p.BlobType!=BlobType.Block||
            !p.Metadata.TryGetValue("quillsign_completion",out var marker)||marker!=plan.Owner)throw ProductionCompletionStoragePlan.Invalid();
        if(plan.Final)
        {
            var earliest=new DateTimeOffset(plan.RecordedAt.Ticks-plan.RecordedAt.Ticks%TimeSpan.TicksPerSecond,TimeSpan.Zero);
            if(p.CreatedOn==default||p.CreatedOn.Offset!=TimeSpan.Zero||p.CreatedOn<earliest||p.CreatedOn>plan.RecordedAt.AddMinutes(1))throw ProductionCompletionStoragePlan.Invalid();
            if(plan.Until is {} until ? p.HasLegalHold||p.ImmutabilityPolicy is not {PolicyMode:BlobImmutabilityPolicyMode.Locked,ExpiresOn: {} expiry}||expiry!=until :
                !p.HasLegalHold||p.ImmutabilityPolicy?.ExpiresOn is not null)throw ProductionCompletionStoragePlan.Invalid();
        }
    }
    private static bool Same(FinalStoredDocument? a,FinalStoredDocument? b)=>a is null?b is null:b is not null&&
        a.Document==b.Document&&a.Length==b.Length&&a.Sha256.AsSpan().SequenceEqual(b.Sha256)&&a.VersionId==b.VersionId&&a.ETag==b.ETag&&
        a.Protection==b.Protection&&a.ProtectedUntil==b.ProtectedUntil&&a.CreatedAt==b.CreatedAt;
    private static bool Opaque(string? s)=>s is {Length:>0 and <=256}&&s!="*"&&s.All(c=>c is >= '!' and <= '~');
    private static bool Uncertain(Exception e)=>e is IOException or HttpRequestException||e is RequestFailedException p&&(p.Status==0||p.Status>=500||p.Status==412&&p.ErrorCode is "ConditionNotMet" or "BlobAlreadyExists");
    private sealed class NoResubmission:HttpPipelineSynchronousPolicy
    {public override void OnReceivedResponse(HttpMessage message){if(message.Response.Status==401||message.Response.Status is >=300 and <400)throw new UnauthorizedAccessException("Completion requests cannot be resubmitted or redirected.");}}
    public async Task<byte[]> ReadAsync(ProductionCompletionInputReadScope scope,CancellationToken ct=default)
    {
        scope.Demand(ct);var address=scope.Address;
        if(address.Area!="normalized"||address.Length is <1 or >ProductionCompletionInputCodec.MaximumCipherBytes||
            !Opaque(address.VersionId)||!Opaque(address.ETag)||address.Snapshot.Length!=0)throw ProductionCompletionStoragePlan.Invalid();
        var container=service.GetBlobContainerClient("normalized");var config=(await container.GetPropertiesAsync(cancellationToken:ct)).Value;scope.Demand(ct);
        if(config.PublicAccess is not null&&config.PublicAccess!=PublicAccessType.None)throw ProductionCompletionStoragePlan.Invalid();
        var client=container.GetBlockBlobClient(address.Name).WithVersion(address.VersionId);var condition=new BlobRequestConditions{IfMatch=new ETag(address.ETag)};
        void Check(BlobProperties p)
        {if(p.VersionId!=address.VersionId||p.ETag.ToString("H")!=address.ETag||p.ContentLength!=address.Length||p.BlobType!=BlobType.Block)throw ProductionCompletionStoragePlan.Invalid();}
        var before=(await client.GetPropertiesAsync(condition,ct)).Value;scope.Demand(ct);Check(before);
        var response=await client.DownloadStreamingAsync(new(){Conditions=condition},ct);scope.Demand(ct);
        await using var stream=response.Value.Content;
        if(response.Value.Details.VersionId!=address.VersionId||response.Value.Details.ETag.ToString("H")!=address.ETag||response.Value.Details.ContentLength!=address.Length)throw ProductionCompletionStoragePlan.Invalid();
        var bytes=new byte[checked((int)address.Length)];var offset=0;
        while(offset<bytes.Length)
        {scope.Demand(ct);var count=await stream.ReadAsync(bytes.AsMemory(offset,Math.Min(256*1024,bytes.Length-offset)),ct);scope.Demand(ct);if(count==0)throw ProductionCompletionStoragePlan.Invalid();offset+=count;}
        var extra=new byte[1];scope.Demand(ct);var tail=await stream.ReadAsync(extra,ct);scope.Demand(ct);
        if(tail!=0||ProductionCompletionStoragePlan.Hash(bytes)!=scope.Sha256)throw ProductionCompletionStoragePlan.Invalid();
        var after=(await client.GetPropertiesAsync(condition,ct)).Value;scope.Demand(ct);Check(after);return bytes;
    }
    public void Dispose()=>owned?.Dispose();
}

using System.Buffers;
using System.Security.Cryptography;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace QuillSign.Storage;

// Factual exact-selector adapter. No provisioning, undelete, permanent delete,
// retention shortening, legal-hold changes, bulk snapshots or provider retries.
internal sealed class AzureProductionDeletionStore:IProductionDeletionStore,IDisposable
{
    private readonly BlobServiceClient service;
    private readonly HttpClient? ownedClient;
    internal AzureProductionDeletionStore(Uri serviceUri,TokenCredential credential,HttpPipelineTransport? transport=null)
    {
        if(serviceUri is null||!serviceUri.IsAbsoluteUri||serviceUri.Scheme!="https"||serviceUri.AbsolutePath!="/"||serviceUri.Query.Length!=0||serviceUri.Fragment.Length!=0||
            serviceUri.UserInfo.Length!=0||serviceUri.Host.Contains("-secondary.",StringComparison.OrdinalIgnoreCase))throw Invalid();
        var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);options.Retry.MaxRetries=0;
        options.Diagnostics.IsLoggingEnabled=false;options.Diagnostics.IsLoggingContentEnabled=false;options.Diagnostics.IsDistributedTracingEnabled=false;
        if(transport is not null)options.Transport=transport;
        else{ownedClient=new(new SocketsHttpHandler{AllowAutoRedirect=false});options.Transport=new HttpClientTransport(ownedClient);}
        options.AddPolicy(new ProductionDeletionRefuseRedirectOrChallenge(),HttpPipelinePosition.PerRetry);service=new(serviceUri,credential,options);
    }
    public async Task<ProductionDeletionPage> ListAsync(ProductionDeletionObjectScope scope,string area,string prefix,string? continuation,int maximum,CancellationToken ct=default)
    {
        scope.DemandPrefix(area,prefix);if(maximum is <1 or >128||continuation is {Length:>16384})throw Invalid();
        await scope.DemandAsync(ct);var container=service.GetBlobContainerClient(area);
        var config=(await container.GetPropertiesAsync(cancellationToken:ct)).Value;await scope.DemandAsync(ct);
        if(config.PublicAccess is not null&&config.PublicAccess!=PublicAccessType.None)throw Invalid();
        var pages=container.GetBlobsAsync(new GetBlobsOptions{Prefix=prefix,States=BlobStates.Version|BlobStates.Snapshots|BlobStates.Deleted|BlobStates.DeletedWithVersions},ct).AsPages(continuation,maximum);
        await scope.DemandAsync(ct);
        await foreach(var page in pages.WithCancellation(ct))
        {
            await scope.DemandAsync(ct);if(page.Values.Count>maximum||page.ContinuationToken is {Length:>16384})throw Invalid();var items=new List<ProductionDeletionObject>();
            foreach(var b in page.Values)
            {
                if(b.Properties.BlobType!=BlobType.Block||b.Properties.ContentLength is null)throw Invalid();
                var item=new ProductionDeletionObject(area,b.Name,b.VersionId??"",b.Snapshot??"",b.Properties.ETag?.ToString("H")??"",b.Properties.ContentLength.Value,
                    b.IsLatestVersion==true||string.IsNullOrEmpty(b.VersionId)&&string.IsNullOrEmpty(b.Snapshot),b.Deleted==true,b.HasVersionsOnly==true);
                scope.DemandItem(item);if(!item.Name.StartsWith(prefix,StringComparison.Ordinal))throw Invalid();items.Add(item);
            }
            if(items.Select(x=>(x.Name,x.VersionId,x.Snapshot,x.Deleted)).Distinct().Count()!=items.Count)throw Invalid();
            return new(items.AsReadOnly(),string.IsNullOrEmpty(page.ContinuationToken)?null:page.ContinuationToken);
        }
        await scope.DemandAsync(ct);return new([],null);
    }
    public async Task<ProductionDeletionInspection> InspectAsync(ProductionDeletionObjectScope scope,ProductionDeletionObject item,CancellationToken ct=default)
    {
        scope.DemandItem(item);if(item.Deleted||item.HasVersionsOnly)throw Invalid();var client=Client(item);var before=await Properties(scope,client,item,ct);
        await scope.DemandAsync(ct);var download=(await client.DownloadStreamingAsync(new(){Conditions=new(){IfMatch=new ETag(item.ETag)}},ct)).Value;
        await using var input=download.Content;await scope.DemandAsync(ct);
        if(download.Details.ContentLength!=item.Length||download.Details.ETag.ToString("H")!=item.ETag||(download.Details.VersionId??"")!=item.VersionId)throw Invalid();
        var buffer=ArrayPool<byte>.Shared.Rent(256*1024);using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            long count=0;while(count<item.Length){await scope.DemandAsync(ct);var n=await input.ReadAsync(buffer.AsMemory(0,(int)Math.Min(buffer.Length,item.Length-count)),ct);await scope.DemandAsync(ct);if(n==0)throw Invalid();hash.AppendData(buffer.AsSpan(0,n));count+=n;}
            await scope.DemandAsync(ct);if(await input.ReadAsync(buffer.AsMemory(0,1),ct)!=0)throw Invalid();await scope.DemandAsync(ct);
            var after=await Properties(scope,client,item,ct);if(!ProtectionEqual(before,after))throw Invalid();
            return new(item,Convert.ToHexStringLower(hash.GetHashAndReset()),after.HasLegalHold,after.ImmutabilityPolicy?.ExpiresOn,after.ImmutabilityPolicy?.PolicyMode?.ToString());
        }
        finally{ArrayPool<byte>.Shared.Return(buffer,true);}
    }
    public async Task<ProductionDeletionResult> DeleteAsync(ProductionDeletionObjectScope scope,ProductionDeletionInspection expected,ProductionDeletionPhase phase,CancellationToken ct=default)
    {
        Validate(scope,expected,phase);var current=await InspectAsync(scope,expected.Item,ct);if(current!=expected)throw Invalid();DemandUnprotected(scope,current);
        var item=expected.Item;var root=service.GetBlobContainerClient(item.Area).GetBlobClient(item.Name);
        if(phase==ProductionDeletionPhase.RootDemotion)
        {
            var properties=await Properties(scope,root,item,ct);if(properties.VersionId!=item.VersionId||properties.HasLegalHold!=expected.LegalHold||
                properties.ImmutabilityPolicy?.ExpiresOn!=expected.ImmutableUntil||properties.ImmutabilityPolicy?.PolicyMode?.ToString()!=expected.ImmutableMode)throw Invalid();
            DemandUnprotected(scope,new(item,expected.Sha256,properties.HasLegalHold,properties.ImmutabilityPolicy?.ExpiresOn,properties.ImmutabilityPolicy?.PolicyMode?.ToString()));
        }
        else if(item.VersionId.Length>0)
        {
            var rootState=await MaybeProperties(scope,root,ct);if(rootState?.VersionId==item.VersionId)throw Invalid();
        }
        await scope.DemandAsync(ct);scope.BeginMutation(item,phase);
        var target=phase==ProductionDeletionPhase.RootDemotion?root:Client(item);
        await target.DeleteAsync(conditions:new(){IfMatch=new ETag(item.ETag)},cancellationToken:ct);
        await scope.DemandAsync(ct);return await ReadDeleteOutcomeAsync(scope,expected,phase,ct);
    }
    public async Task<ProductionDeletionResult> ReadDeleteOutcomeAsync(ProductionDeletionObjectScope scope,ProductionDeletionInspection expected,ProductionDeletionPhase phase,CancellationToken ct=default)
    {
        Validate(scope,expected,phase);var item=expected.Item;
        if(phase==ProductionDeletionPhase.RootDemotion)
        {
            var root=await MaybeProperties(scope,service.GetBlobContainerClient(item.Area).GetBlobClient(item.Name),ct);
            if(root is not null)throw Invalid();var retained=await InspectAsync(scope,item,ct);if(retained!=expected)throw Invalid();
            return new(item,phase,false,true,retained);
        }
        var found=await MaybeProperties(scope,Client(item),ct);if(found is not null)throw Invalid();
        return new(item,phase,true,false,null);
    }
    private static void Validate(ProductionDeletionObjectScope scope,ProductionDeletionInspection e,ProductionDeletionPhase phase)
    {if(e is null||!Enum.IsDefined(phase)||e.Sha256 is not {Length:64}||!e.Sha256.All(char.IsAsciiHexDigitLower))throw Invalid();scope.DemandItem(e.Item);if(phase==ProductionDeletionPhase.RootDemotion&&(e.Item.VersionId.Length==0||e.Item.Snapshot.Length!=0||!e.Item.IsCurrent))throw Invalid();}
    private static void DemandUnprotected(ProductionDeletionObjectScope scope,ProductionDeletionInspection x)
    {if(x.LegalHold||x.ImmutableUntil>scope.Now)throw new InvalidDataException("Actual storage protection blocks production deletion.");}
    private BlobClient Client(ProductionDeletionObject x)
    {var client=service.GetBlobContainerClient(x.Area).GetBlobClient(x.Name);return x.VersionId.Length>0?client.WithVersion(x.VersionId):x.Snapshot.Length>0?client.WithSnapshot(x.Snapshot):client;}
    private static async Task<BlobProperties> Properties(ProductionDeletionObjectScope scope,BlobClient client,ProductionDeletionObject item,CancellationToken ct)
    {
        await scope.DemandAsync(ct);Response<BlobProperties> response;
        try{response=await client.GetPropertiesAsync(new(){IfMatch=new ETag(item.ETag)},ct);}
        catch(Exception error)when(error is ArgumentException or FormatException){await scope.DemandAsync(ct);throw new InvalidDataException("Actual storage protection is unsupported or malformed.",error);}
        await scope.DemandAsync(ct);var p=response.Value;var headers=response.GetRawResponse().Headers;
        if(!headers.TryGetValue("x-ms-legal-hold",out var held)||held is not ("true" or "false")||p.HasLegalHold!=(held=="true"))throw Invalid();
        var hasMode=headers.TryGetValue("x-ms-immutability-policy-mode",out var mode);var hasUntil=headers.TryGetValue("x-ms-immutability-policy-until-date",out _);
        if(hasMode!=hasUntil||hasMode&&(mode is not ("Locked" or "Unlocked")||p.ImmutabilityPolicy?.ExpiresOn is not {} until||until.Offset!=TimeSpan.Zero||until<DateTimeOffset.UnixEpoch)||
            !hasMode&&(p.ImmutabilityPolicy?.ExpiresOn is not null||p.ImmutabilityPolicy?.PolicyMode is not null))throw Invalid();
        if(p.ETag.ToString("H")!=item.ETag||p.ContentLength!=item.Length||(p.VersionId??"")!=item.VersionId||p.BlobType!=BlobType.Block)throw Invalid();return p;
    }
    private static async Task<BlobProperties?> MaybeProperties(ProductionDeletionObjectScope scope,BlobClient client,CancellationToken ct)
    {await scope.DemandAsync(ct);try{var p=(await client.GetPropertiesAsync(cancellationToken:ct)).Value;await scope.DemandAsync(ct);return p;}catch(RequestFailedException e)when(e.Status==404&&e.ErrorCode=="BlobNotFound"){await scope.DemandAsync(ct);return null;}}
    private static bool ProtectionEqual(BlobProperties a,BlobProperties b)=>a.HasLegalHold==b.HasLegalHold&&a.ImmutabilityPolicy?.ExpiresOn==b.ImmutabilityPolicy?.ExpiresOn&&a.ImmutabilityPolicy?.PolicyMode==b.ImmutabilityPolicy?.PolicyMode;
    private static InvalidDataException Invalid()=>ProductionDeletionObjectScope.Invalid();
    public void Dispose()=>ownedClient?.Dispose();
}

internal sealed class ProductionDeletionRefuseRedirectOrChallenge:HttpPipelineSynchronousPolicy
{
    public override void OnReceivedResponse(HttpMessage message)
    {
        if(message.Response.Status is >=300 and <400)throw new UnauthorizedAccessException("Production deletion cannot redirect.");
        if(message.Response.Status==401)throw new RequestFailedException(401,"Production deletion authentication requires reconciliation.",
            message.Response.Headers.TryGetValue("x-ms-error-code",out var code)?code:null,null);
    }
}

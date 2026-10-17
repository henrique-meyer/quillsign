using System.Buffers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using QuillSign.Completion;

namespace QuillSign.Storage;

// No container/default-policy provisioning. Fixed-deadline capabilities can set
// protection only on their exact owned new version; generic writes inherit it.
public sealed class AzureCompletionFinalStore(BlobServiceClient service,TimeProvider time,IHostEnvironment environment,bool local=false) : ICompletionFinalStore
{
    private const int BufferSize=256*1024;
    private BlobContainerClient Container=>service.GetBlobContainerClient("final");
    private static string Path(FinalDocument target)=>$"{target.EnvelopeId:N}/{target.Kind.ToString().ToLowerInvariant()}/{target.ObjectId:N}";
    private bool Local=>local && environment.IsDevelopment() && (service.Uri.IsLoopback || service.Uri.Host=="azurite");

    public async Task<FinalStoredDocument> WriteAsync(ClaimsPrincipal authority,FinalDocument target,Stream source,long length,byte[] sha256,
        DateTimeOffset? requiredUntil,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(sha256 is not {Length:32})throw new UnauthorizedAccessException("Invalid final document hash scope."); var expected=sha256.ToArray();
        var cap=CompletionFinalCapability.DemandWrite(authority,target,length,expected,requiredUntil);
        ArgumentNullException.ThrowIfNull(source);
        try
        {
            await Ready(cap,ct); var client=Container.GetBlockBlobClient(Path(target));
            BlobProperties? existing=null;
            try {existing=(await client.GetPropertiesAsync(cancellationToken:ct)).Value;}
            catch(RequestFailedException error) when(error.Status==404) { }
            if(existing is not null)return await VerifyCurrent(cap,target,length,expected,requiredUntil,existing,ct);
            try
            {
                var rented=ArrayPool<byte>.Shared.Rent(BufferSize); var blocks=new List<string>(); var attempt=Guid.NewGuid().ToString("N");
                using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256); long consumed=0;
                try
                {
                    while(consumed<length)
                    {
                        var count=(int)Math.Min(BufferSize,length-consumed); var n=await source.ReadAtLeastAsync(rented.AsMemory(0,count),count,false,ct);
                        if(n==0)throw new InvalidDataException("Final source length changed."); consumed+=n; hash.AppendData(rented.AsSpan(0,n));
                        var id=Convert.ToBase64String(Encoding.ASCII.GetBytes($"{attempt}:{blocks.Count:D8}"));
                        using var part=new MemoryStream(rented,0,n,false); await client.StageBlockAsync(id,part,cancellationToken:ct); blocks.Add(id);
                    }
                    if(await source.ReadAsync(rented.AsMemory(0,1),ct)!=0 || !Same(hash.GetHashAndReset(),expected))throw new InvalidDataException("Final source bytes changed.");
                    if(cap.ExactDeadline)cap.ValidateLifetime();
                    var commit=new CommitBlockListOptions {Conditions=new() {IfNoneMatch=ETag.All},HttpHeaders=new() {ContentType="application/pdf"}};
                    if(cap.ExactDeadline && !Local)commit.ImmutabilityPolicy=new() {ExpiresOn=cap.ExactUntil,PolicyMode=BlobImmutabilityPolicyMode.Locked};
                    await client.CommitBlockListAsync(blocks,commit,ct);
                }
                finally {ArrayPool<byte>.Shared.Return(rented,clearArray:true);}
            }
            catch(Exception error) when(error is IOException or RequestFailedException)
            {
                ct.ThrowIfCancellationRequested();
                // Conditional races and lost upload acknowledgements recover only this intent's exact target/bytes.
                var found=(await client.GetPropertiesAsync(cancellationToken:ct)).Value;
                return await VerifyCurrent(cap,target,length,expected,requiredUntil,found,ct);
            }
            return await VerifyCurrent(cap,target,length,expected,requiredUntil,(await client.GetPropertiesAsync(cancellationToken:ct)).Value,ct);
        }
        catch(RequestFailedException) {throw Unavailable();}
    }

    public async Task ReadAsync(ClaimsPrincipal authority,FinalStoredDocument stored,Stream destination,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(stored is null || stored.Sha256 is not {Length:32})throw new UnauthorizedAccessException("Invalid final document reference scope."); var reference=stored with {Sha256=stored.Sha256.ToArray()};
        var cap=CompletionFinalCapability.DemandRead(authority,reference);
        ArgumentNullException.ThrowIfNull(destination);
        try
        {
            if(reference.Length is <16 or >64*1024*1024 || !Opaque(reference.ETag) || !Opaque(reference.VersionId,true) || !Enum.IsDefined(reference.Protection))throw Invalid();
            if(reference.Protection==FinalProtection.DevelopmentWriteOnce ? !Local || !cap.DevelopmentWriteOnce : Local || string.IsNullOrEmpty(reference.VersionId))throw Invalid();
            await Ready(cap,ct,false);
            var client=Client(reference.Document,reference.VersionId);
            var properties=(await client.GetPropertiesAsync(new() {IfMatch=new ETag(reference.ETag)},ct)).Value;
            if(properties.ContentLength!=reference.Length || properties.ETag.ToString()!=reference.ETag || (properties.VersionId??"")!=reference.VersionId)throw Invalid();
            // Before the promised retention boundary, a weakened policy cannot be silently accepted.
            if(cap.ExactDeadline && reference.Protection!=FinalProtection.DevelopmentWriteOnce)
            {
                if(reference.Protection!=FinalProtection.LockedTime || reference.ProtectedUntil!=cap.ExactUntil || properties.HasLegalHold ||
                    properties.ImmutabilityPolicy?.ExpiresOn>cap.ExactUntil)throw Invalid();
                if(time.GetUtcNow()<cap.ExactUntil)_=Protection(properties,cap.ExactUntil,false,true);
            }
            else if(reference.Protection!=FinalProtection.DevelopmentWriteOnce &&
                (reference.ProtectedUntil is null || time.GetUtcNow()<reference.ProtectedUntil))
            {
                var current=Protection(properties,reference.ProtectedUntil,false);
                if(reference.Protection==FinalProtection.LegalHold && current.Protection!=FinalProtection.LegalHold)throw Invalid();
            }
            await Copy(client,reference.Length,reference.Sha256,reference.ETag,reference.VersionId,destination,ct); cap.ValidateLifetime();
        }
        catch(RequestFailedException) {throw Unavailable();}
    }

    private async Task Ready(CompletionFinalCapability cap,CancellationToken ct,bool createLocal=true)
    {
        if(local && !Local)throw Unavailable();
        if(Local)
        {
            if(!cap.DevelopmentWriteOnce)throw new CompletionPublicationUnavailableException("Development write-once publication must be explicitly selected for a demo request.");
            if(createLocal)await Container.CreateIfNotExistsAsync(PublicAccessType.None,cancellationToken:ct);
            var localProperties=(await Container.GetPropertiesAsync(cancellationToken:ct)).Value;
            if(localProperties.PublicAccess is not null && localProperties.PublicAccess!=PublicAccessType.None)throw Invalid(); return;
        }
        var properties=(await Container.GetPropertiesAsync(cancellationToken:ct)).Value;
        if(properties.PublicAccess is not null && properties.PublicAccess!=PublicAccessType.None || properties.HasImmutableStorageWithVersioning!=true)
            throw new CompletionPublicationUnavailableException("Configure private version-level immutable final storage before publication.");
    }
    private async Task<FinalStoredDocument> VerifyCurrent(CompletionFinalCapability cap,FinalDocument target,long length,byte[] hash,DateTimeOffset? until,BlobProperties properties,CancellationToken ct)
    {
        if(cap.ExactDeadline && !Local)properties=await FixedVersion(cap,target,length,hash,properties,ct);
        var version=properties.VersionId??""; var etag=properties.ETag.ToString();
        if(properties.ContentLength!=length || !Opaque(etag) || !Opaque(version,true) || !Local && string.IsNullOrEmpty(version))throw Invalid();
        var protection=Protection(properties,until,Local && cap.DevelopmentWriteOnce,cap.ExactDeadline);
        // Exact version plus ETag and actual SHA-256; no trust in mutable user metadata.
        await Copy(Client(target,version),length,hash,etag,version,Stream.Null,ct); cap.ValidateLifetime();
        return new(target,length,hash.ToArray(),version,etag,protection.Protection,protection.Until,properties.CreatedOn);
    }
    private async Task<BlobProperties> FixedVersion(CompletionFinalCapability cap,FinalDocument target,long length,byte[] hash,BlobProperties properties,CancellationToken ct)
    {
        if(properties.HasLegalHold || string.IsNullOrEmpty(properties.VersionId) || !Opaque(properties.VersionId) || !Opaque(properties.ETag.ToString()) ||
            properties.ContentLength!=length || properties.ImmutabilityPolicy is not {ExpiresOn:DateTimeOffset until,PolicyMode:var mode} || until!=cap.ExactUntil ||
            mode!=BlobImmutabilityPolicyMode.Locked && mode!=BlobImmutabilityPolicyMode.Unlocked)throw FixedUnavailable();
        if(mode==BlobImmutabilityPolicyMode.Locked)return properties;
        // A lost create/lock acknowledgement can leave an exact owned version with
        // the requested unlocked policy. Verify bytes before this irreversible step.
        var version=properties.VersionId;var client=Client(target,version);
        await Copy(client,length,hash,properties.ETag.ToString(),version,Stream.Null,ct);cap.ValidateLifetime();
        try
        {
            await client.SetImmutabilityPolicyAsync(new() {ExpiresOn=until,PolicyMode=BlobImmutabilityPolicyMode.Locked},
                new() {IfUnmodifiedSince=properties.LastModified},ct);
        }
        catch(Exception e) when(e is RequestFailedException or IOException)
        {ct.ThrowIfCancellationRequested(); /* Readback alone resolves an uncertain lock. */}
        var current=(await client.GetPropertiesAsync(cancellationToken:ct)).Value;cap.ValidateLifetime();
        if(current.VersionId!=version)throw Invalid();
        _=Protection(current,until,false,true);return current;
    }
    private static (FinalProtection Protection,DateTimeOffset? Until) Protection(BlobProperties properties,DateTimeOffset? requiredUntil,bool development,bool exact=false)
    {
        if(development)return (FinalProtection.DevelopmentWriteOnce,null);
        if(properties.HasLegalHold) {if(exact)throw FixedUnavailable();return (FinalProtection.LegalHold,null);}
        if(requiredUntil is DateTimeOffset minimum && properties.ImmutabilityPolicy is {ExpiresOn:DateTimeOffset expires,PolicyMode:var mode} &&
            mode==BlobImmutabilityPolicyMode.Locked && expires>=minimum && (!exact || expires==minimum))return (FinalProtection.LockedTime,expires);
        throw new CompletionPublicationUnavailableException("The final object does not have sufficient verified immutable retention protection.");
    }
    private BlobClient Client(FinalDocument target,string version)
    {var client=Container.GetBlobClient(Path(target)); return string.IsNullOrEmpty(version) ? client : client.WithVersion(version);}
    private static async Task Copy(BlobClient client,long expectedLength,byte[] expectedHash,string etag,string version,Stream output,CancellationToken ct)
    {
        var response=await client.DownloadStreamingAsync(new() {Conditions=new() {IfMatch=new ETag(etag)}},ct);
        if(response.Value.Details.ContentLength!=expectedLength || response.Value.Details.ETag.ToString()!=etag || (response.Value.Details.VersionId??"")!=version)throw Invalid();
        await using var input=response.Value.Content; using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer=ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            long copied=0;
            while(copied<expectedLength)
            {
                var n=await input.ReadAsync(buffer.AsMemory(0,(int)Math.Min(buffer.Length,expectedLength-copied)),ct);
                if(n==0)throw Invalid(); hash.AppendData(buffer.AsSpan(0,n)); await output.WriteAsync(buffer.AsMemory(0,n),ct); copied+=n;
            }
            if(await input.ReadAsync(buffer.AsMemory(0,1),ct)!=0 || !Same(hash.GetHashAndReset(),expectedHash))throw Invalid();
        }
        finally {ArrayPool<byte>.Shared.Return(buffer,clearArray:true);}
    }
    private static bool Opaque(string? value,bool empty=false)=>value is not null && (empty || value.Length>0) && value.Length<=256 && value.All(c=>c is >= ' ' and <= '~');
    private static bool Same(byte[]? a,byte[]? b)=>a is {Length:32} && b is {Length:32} && CryptographicOperations.FixedTimeEquals(a,b);
    private static InvalidDataException Invalid()=>new("The exact retained final object could not be verified.");
    private static IOException Unavailable()=>new("Final packet storage is unavailable or not configured for protected publication.");
    private static CompletionPublicationUnavailableException FixedUnavailable()=>new("The final version does not have the exact frozen retention policy.");
}

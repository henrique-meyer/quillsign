using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace QuillSign.Storage;

// Intentionally not registered or scheduled until durable purge coordination exists.
// Never provisions containers, changes protection, reads content or uses permanent-delete APIs.
public sealed class AzureEnvelopePurgeStore(BlobServiceClient service):IEnvelopePurgeStore
{
    private static readonly string[] Areas=["originals","normalized","previews","final"];
    public async Task<PurgeStorageBatch> SweepAsync(DemoPurgeAuthority authority,int maximumObjects,PurgeStorageCursor? cursor=null,CancellationToken ct=default)
    {
        ArgumentNullException.ThrowIfNull(authority);authority.Demand(ct);
        if(maximumObjects is <1 or >128)throw new ArgumentOutOfRangeException(nameof(maximumObjects));
        if(cursor is not null && (cursor.EnvelopeId!=authority.EnvelopeId || cursor.PolicySha256!=authority.PolicySha256 ||
            cursor.Area is <0 or >3 || cursor.Continuation is {Length:>16384}))throw new UnauthorizedAccessException("Invalid purge continuation scope.");
        var prefix=$"{authority.EnvelopeId:N}/";
        int examined=0,deleted=0,missing=0,held=0,changed=0;
        var area=cursor?.Area??0;var continuation=cursor?.Continuation;
        while(area<Areas.Length)
        {
            authority.Demand(ct);var container=service.GetBlobContainerClient(Areas[area]);
            var pages=container.GetBlobsAsync(new GetBlobsOptions {Prefix=prefix,States=BlobStates.Version|BlobStates.Snapshots},ct)
                .AsPages(continuation,maximumObjects-examined);
            Page<BlobItem>? page=null;
            try {await foreach(var value in pages.WithCancellation(ct)) {page=value;break;}}
            catch(RequestFailedException error) when(error.Status==404 && error.ErrorCode=="ContainerNotFound") { }
            authority.Demand(ct);
            if(page is not null)
            {
                if(page.Values.Count>maximumObjects-examined)throw new InvalidDataException("Purge inventory exceeded its requested bound.");
                foreach(var item in page.Values)
                {
                    authority.Demand(ct);examined++;
                    if(!item.Name.StartsWith(prefix,StringComparison.Ordinal) || item.Name.Length<=prefix.Length ||
                        item.Name.Length>1024 || item.VersionId is {Length:>256} || item.Snapshot is {Length:>256} ||
                        !string.IsNullOrEmpty(item.VersionId) && !string.IsNullOrEmpty(item.Snapshot) || item.Properties.ETag is null ||
                        item.Properties.ETag==ETag.All || string.IsNullOrEmpty(item.Properties.ETag.ToString()) ||
                        item.Name[prefix.Length..].Split('/').Any(part=>part.Length==0 || part.Any(c=>c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-'))))
                        throw new InvalidDataException("Purge inventory escaped its exact object scope.");
                    var client=container.GetBlobClient(item.Name);
                    if(!string.IsNullOrEmpty(item.VersionId))client=client.WithVersion(item.VersionId);
                    else if(!string.IsNullOrEmpty(item.Snapshot))client=client.WithSnapshot(item.Snapshot);
                    var conditions=new BlobRequestConditions {IfMatch=item.Properties.ETag};
                    try
                    {
                        var properties=(await client.GetPropertiesAsync(conditions,ct)).Value;authority.Demand(ct);
                        if(properties.HasLegalHold || properties.ImmutabilityPolicy?.ExpiresOn>authority.Now) {held++;continue;}
                        // Snapshot/current-version conflicts remain incomplete; a subsequent pass can retry.
                        var result=await client.DeleteIfExistsAsync(conditions:conditions,cancellationToken:ct);authority.Demand(ct);
                        if(result.Value)deleted++;else missing++;
                    }
                    catch(RequestFailedException error) when(error.Status==404 && error.ErrorCode is "BlobNotFound" or "ContainerNotFound") {missing++;}
                    catch(RequestFailedException error) when(error.Status==412 || error.Status==409 && error.ErrorCode is
                        "BlobImmutableDueToPolicy" or "BlobImmutableDueToLegalHold" or "SnapshotsPresent" or "LeaseIdMissing" or "LeaseIdMismatchWithBlobOperation")
                    {changed++;}
                    authority.Demand(ct);
                }
                continuation=page.ContinuationToken;
                if(!string.IsNullOrEmpty(continuation))return new(examined,deleted,missing,held,changed,false,new(authority.EnvelopeId,authority.PolicySha256,area,continuation));
            }
            area++;continuation=null;
            if(examined==maximumObjects && area<Areas.Length)return new(examined,deleted,missing,held,changed,false,new(authority.EnvelopeId,authority.PolicySha256,area,null));
        }
        authority.Demand(ct);return new(examined,deleted,missing,held,changed,true,null);
    }
}

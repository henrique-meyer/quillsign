using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using QuillSign.Documents;

namespace QuillSign.Sealing;

public interface IProtectedSealStore
{
    Task<byte[]?> ReadAsync(CancellationToken ct);
    Task<bool> TryCreateAsync(byte[] protectedMaterial,CancellationToken ct);
}
// Platform private material never enters the document store/cookie capability namespace or retention purge.
public sealed class BlobProtectedSealStore : IProtectedSealStore
{
    public const int MaximumBytes=3*1024*1024;
    private readonly BlobContainerClient container;
    private readonly BlobClient blob;
    private readonly bool local;
    public BlobProtectedSealStore(BlobServiceClient service,bool local,string name)
    {
        if(!System.Text.RegularExpressions.Regex.IsMatch(name??"","^demo-seal-[a-zA-Z0-9.-]{1,100}$") ||
            local && !service.Uri.IsLoopback && service.Uri.Host!="azurite")throw new SealUnavailableException("Invalid protected seal storage scope.");
        container=service.GetBlobContainerClient("keys"); blob=container.GetBlobClient(name); this.local=local;
    }
    private async Task Prepare(CancellationToken ct) { if(local)await container.CreateIfNotExistsAsync(PublicAccessType.None,cancellationToken:ct); }
    public async Task<byte[]?> ReadAsync(CancellationToken ct)
    {
        await Prepare(ct);
        try {
            var properties=(await blob.GetPropertiesAsync(cancellationToken:ct)).Value;
            if(properties.ContentLength is <1 or >MaximumBytes)throw new SealUnavailableException("Protected signing material exceeds its limits.");
            using var downloaded=(await blob.DownloadStreamingAsync(new BlobDownloadOptions { Conditions=new BlobRequestConditions { IfMatch=properties.ETag } },ct)).Value.Content;
            using var memory=new MemoryStream(); await downloaded.CopyToAsync(new BoundedDocumentStream(memory,MaximumBytes),ct);
            if(memory.Length!=properties.ContentLength)throw new SealUnavailableException("Protected signing material changed during retrieval."); return memory.ToArray();
        }
        catch(RequestFailedException e) when(e.Status==404 && e.ErrorCode=="BlobNotFound") { return null; }
    }
    public async Task<bool> TryCreateAsync(byte[] protectedMaterial,CancellationToken ct)
    {
        if(protectedMaterial.Length is <1 or >MaximumBytes)throw new SealUnavailableException("Protected signing material exceeds its limits.");
        await Prepare(ct);
        try {
            using var stream=new MemoryStream(protectedMaterial,false);
            await blob.UploadAsync(stream,new BlobUploadOptions {
                Conditions=new BlobRequestConditions { IfNoneMatch=ETag.All },HttpHeaders=new BlobHttpHeaders {ContentType="application/octet-stream"},
                Metadata=new Dictionary<string,string> { ["purpose"]="quillsign-demo-seal-v1" } },ct); return true;
        }
        catch(RequestFailedException e) when((e.Status is 409 or 412) && (e.ErrorCode is "BlobAlreadyExists" or "ConditionNotMet")) { return false; }
    }
}

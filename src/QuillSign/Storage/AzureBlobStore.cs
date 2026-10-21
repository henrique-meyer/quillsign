using System.Buffers;
using System.Security.Claims;
using System.Text;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;

namespace QuillSign.Storage;

public sealed class AzureBlobStore(BlobServiceClient service, long maximumBytes, bool createLocalContainers = false) : IBlobStore
{
    private const int BufferSize = 256 * 1024;

    private BlobContainerClient Container(DocumentBlobKind kind) => service.GetBlobContainerClient(kind switch
    {
        DocumentBlobKind.Original => "originals",
        DocumentBlobKind.ReviewInput or DocumentBlobKind.Normalized or DocumentBlobKind.Signature or DocumentBlobKind.Initials or DocumentBlobKind.CompletionCandidate or
            DocumentBlobKind.CompletionExecutedSeal or DocumentBlobKind.CompletionCertificateSource or DocumentBlobKind.CompletionCertificateSeal => "normalized",
        DocumentBlobKind.Preview => "previews",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    });

    private static string Path(DocumentBlob blob) => blob.Kind switch {
        DocumentBlobKind.ReviewInput=>$"{blob.EnvelopeId:N}/review-inputs/{blob.ObjectId:N}",
        DocumentBlobKind.CompletionCandidate=>$"{blob.EnvelopeId:N}/completion-candidates/{blob.ObjectId:N}",
        DocumentBlobKind.CompletionExecutedSeal=>$"{blob.EnvelopeId:N}/completion-seals/executed/{blob.ObjectId:N}",
        DocumentBlobKind.CompletionCertificateSource=>$"{blob.EnvelopeId:N}/completion-seals/certificate-source/{blob.ObjectId:N}",
        DocumentBlobKind.CompletionCertificateSeal=>$"{blob.EnvelopeId:N}/completion-seals/certificate/{blob.ObjectId:N}",
        _=>$"{blob.EnvelopeId:N}/{blob.ObjectId:N}"
    };

    public async Task WriteAsync(ClaimsPrincipal sender, DocumentBlob blob, Stream source, long length,
        CancellationToken cancellationToken = default)
    {
        EnvelopeStorageAuthorization.Demand(sender, blob);
        if (length <= 0 || length > maximumBytes)
            throw new ArgumentOutOfRangeException(nameof(length), "Document exceeds the configured storage limit or is empty.");

        var container = Container(blob.Kind);
        if (createLocalContainers)
            await container.CreateIfNotExistsAsync(PublicAccessType.None, cancellationToken: cancellationToken);
        var client = container.GetBlockBlobClient(Path(blob));
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        var blocks = new List<string>();
        var attempt = Guid.NewGuid().ToString("N");
        long consumed = 0;
        try
        {
            // Only commit after EOF and the declared size both agree. Failed/cancelled uploads
            // leave no readable object; Azure expires uncommitted blocks automatically.
            while (consumed < length)
            {
                var count = (int)Math.Min(BufferSize, length - consumed);
                var read = await source.ReadAtLeastAsync(buffer.AsMemory(0, count), count, false, cancellationToken);
                if (read == 0) throw new InvalidDataException("Document was shorter than its declared size.");
                consumed += read;
                var id = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{attempt}:{blocks.Count:D8}"));
                using var part = new MemoryStream(buffer, 0, read, false);
                await client.StageBlockAsync(id, part, cancellationToken: cancellationToken);
                blocks.Add(id);
            }
            if (await source.ReadAsync(buffer.AsMemory(0, 1), cancellationToken) != 0)
                throw new InvalidDataException("Document was longer than its declared size.");
            await client.CommitBlockListAsync(blocks, new CommitBlockListOptions
            {
                Conditions = new BlobRequestConditions { IfNoneMatch = ETag.All },
                HttpHeaders = new BlobHttpHeaders { ContentType = "application/octet-stream" }
            }, cancellationToken);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }

    public async Task<long> CopyToAsync(ClaimsPrincipal sender, DocumentBlob blob, Stream destination,
        CancellationToken cancellationToken = default)
    {
        EnvelopeStorageAuthorization.DemandRead(sender, blob);
        var response = await Container(blob.Kind).GetBlobClient(Path(blob)).DownloadStreamingAsync(cancellationToken: cancellationToken);
        await using var source = response.Value.Content;
        var length = response.Value.Details.ContentLength;
        if (length < 0 || length > maximumBytes)
            throw new InvalidDataException("Stored document exceeds the configured storage limit.");
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        long copied = 0;
        try
        {
            while (copied < length)
            {
                var count = (int)Math.Min(BufferSize, length - copied);
                var read = await source.ReadAsync(buffer.AsMemory(0, count), cancellationToken);
                if (read == 0) throw new InvalidDataException("Stored document was truncated.");
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                copied += read;
            }
            if (await source.ReadAsync(buffer.AsMemory(0, 1), cancellationToken) != 0)
                throw new InvalidDataException("Stored document size changed unexpectedly.");
            return copied;
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }

    public async Task DeleteAsync(ClaimsPrincipal sender, DocumentBlob blob, CancellationToken cancellationToken = default)
    {
        EnvelopeStorageAuthorization.DemandDelete(sender, blob);
        await Container(blob.Kind).GetBlobClient(Path(blob)).DeleteIfExistsAsync(cancellationToken: cancellationToken);
    }
}

using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using QuillSign.Lifecycle;

namespace QuillSign.Storage;

internal sealed record ProductionHoldSqlArchiveObject(Guid RecordId, Guid HoldId, Guid PlaceCommandId, long Revision, string FenceHash,
    string SqlStateSha256, string SqlPayloadSha256, string Path, long Length, string CiphertextSha256, string VersionId, string ETag);

// Internal/unregistered. Creates only isolated SQL archive versions with their own
// legal hold; never alters existing final/source protections or provisions storage.
// The returned provider facts still need durable authenticated lifecycle receipts.
internal sealed class AzureProductionHoldSqlArchiveStore(BlobServiceClient service)
{
    internal async Task<ProductionHoldSqlArchiveObject> PreserveAsync(ProductionHoldSqlArchiveCapability capability, CancellationToken ct = default)
    {
        capability.Demand(ct); var container = service.GetBlobContainerClient("final");
        var configuration = (await container.GetPropertiesAsync(cancellationToken: ct)).Value; capability.Demand(ct);
        if (configuration.PublicAccess is not null && configuration.PublicAccess != PublicAccessType.None || configuration.HasImmutableStorageWithVersioning != true) throw Invalid();
        var client = container.GetBlockBlobClient(capability.Path);
        var existing = await Current(client, ct); capability.Demand(ct);
        if (existing is null)
        {
            // Per-attempt uncommitted blocks are isolated; no readable object is
            // committed until exact EOF/hash and the current capability agree.
            using var source = capability.Open(ct); using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = ArrayPool<byte>.Shared.Rent(256 * 1024); var blocks = new List<string>(); var attempt = Guid.NewGuid().ToString("N");
            try
            {
                long consumed = 0;
                while (consumed < capability.Length)
                {
                    capability.Demand(ct);
                    var count = (int)Math.Min(buffer.Length, capability.Length - consumed);
                    var n = await source.ReadAtLeastAsync(buffer.AsMemory(0, count), count, false, ct); if (n == 0) throw Invalid();
                    consumed += n; hash.AppendData(buffer.AsSpan(0, n));
                    var blockId = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{attempt}:{blocks.Count:D8}"));
                    using var block = new MemoryStream(buffer, 0, n, false); await client.StageBlockAsync(blockId, block, cancellationToken: ct);
                    capability.Demand(ct); blocks.Add(blockId);
                }
                if (await source.ReadAsync(buffer.AsMemory(0, 1), ct) != 0 || Convert.ToHexStringLower(hash.GetHashAndReset()) != capability.CiphertextSha256) throw Invalid();
                capability.Demand(ct);
                try
                {
                    await client.CommitBlockListAsync(blocks, new CommitBlockListOptions { Conditions = new() { IfNoneMatch = ETag.All },
                        LegalHold = true, HttpHeaders = new() { ContentType = "application/octet-stream" } }, ct);
                }
                catch (Exception error) when (error is RequestFailedException or IOException)
                {
                    capability.Demand(ct); // Exact readback alone reconciles an uncertain commit.
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
            capability.Demand(ct);
            existing = await Current(client, ct); capability.Demand(ct);
            if (existing is null) throw Invalid();
        }
        return await Verify(capability, client, existing, ct);
    }

    private static async Task<BlobProperties?> Current(BlobBaseClient client, CancellationToken ct)
    {
        try { return (await client.GetPropertiesAsync(cancellationToken: ct)).Value; }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "BlobNotFound") { return null; }
    }
    private static async Task<ProductionHoldSqlArchiveObject> Verify(ProductionHoldSqlArchiveCapability capability, BlobBaseClient root, BlobProperties current, CancellationToken ct)
    {
        capability.Demand(ct);
        if (!current.HasLegalHold || current.ContentLength != capability.Length || !Opaque(current.VersionId) || !Opaque(current.ETag.ToString("H"))) throw Invalid();
        var version = current.VersionId; var etag = current.ETag.ToString("H"); var client = root.WithVersion(version);
        var properties = (await client.GetPropertiesAsync(new() { IfMatch = new ETag(etag) }, ct)).Value; capability.Demand(ct);
        if (properties.VersionId != version || properties.ETag.ToString("H") != etag || properties.ContentLength != capability.Length || !properties.HasLegalHold) throw Invalid();
        var response = await client.DownloadStreamingAsync(new() { Conditions = new() { IfMatch = new ETag(etag) } }, ct);
        await using var input = response.Value.Content; capability.Demand(ct);
        if (response.Value.Details.VersionId != version || response.Value.Details.ETag.ToString("H") != etag || response.Value.Details.ContentLength != capability.Length) throw Invalid();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = ArrayPool<byte>.Shared.Rent(256 * 1024);
        try
        {
            long copied = 0;
            while (copied < capability.Length)
            {
                capability.Demand(ct); var count = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, capability.Length - copied)), ct);
                if (count == 0) throw Invalid(); hash.AppendData(buffer.AsSpan(0, count)); copied += count;
            }
            if (await input.ReadAsync(buffer.AsMemory(0, 1), ct) != 0 || Convert.ToHexStringLower(hash.GetHashAndReset()) != capability.CiphertextSha256) throw Invalid();
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
        // Legal-hold changes do not necessarily change ETag. Check protection
        // again after reading bytes before returning any provider facts.
        var final = (await client.GetPropertiesAsync(new() { IfMatch = new ETag(etag) }, ct)).Value; capability.Demand(ct);
        if (!final.HasLegalHold || final.VersionId != version || final.ETag.ToString("H") != etag || final.ContentLength != capability.Length) throw Invalid();
        return new(capability.RecordId, capability.HoldId, capability.PlaceCommandId, capability.Revision, capability.FenceHash,
            capability.SqlStateSha256, capability.SqlPayloadSha256, capability.Path, capability.Length, capability.CiphertextSha256, version!, etag);
    }
    private static bool Opaque(string? value) => value is { Length: > 0 and <= 256 } && value != "*" && value.All(c => c is >= ' ' and <= '~');
    private static InvalidDataException Invalid() => new("The exact private SQL archive version and legal-hold protection could not be verified.");
}

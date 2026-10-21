using System.Buffers;
using System.Security.Cryptography;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using QuillSign.Lifecycle;

namespace QuillSign.Storage;

// Read-only, internal and unregistered. No provisioning, policy change, public
// authority, download URL, delete, undelete or permanent-delete operation.
internal sealed class AzureProductionHoldObjectSource(BlobServiceClient service) : IProductionHoldObjectSource
{
    public async Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct)
    {
        scope.Demand(ct);
        if (!ProductionHoldObjectScope.Areas.Contains(area, StringComparer.Ordinal) || maximum is < 1 or > 128 || continuation is { Length: > 16384 }) throw Invalid();
        var container = service.GetBlobContainerClient(area);
        // Even an empty or missing container is inspected; permission/missing
        // failures cannot masquerade as a complete empty inventory.
        var properties = (await container.GetPropertiesAsync(cancellationToken: ct)).Value; scope.Demand(ct);
        if (properties.PublicAccess is not null && properties.PublicAccess != PublicAccessType.None) throw Invalid();
        var pages = container.GetBlobsAsync(new GetBlobsOptions { Prefix = scope.Prefix,
            States = BlobStates.Version | BlobStates.Snapshots | BlobStates.Deleted | BlobStates.DeletedWithVersions }, ct).AsPages(continuation, maximum);
        await foreach (var page in pages.WithCancellation(ct))
        {
            scope.Demand(ct); if (page.Values.Count > maximum) throw Invalid();
            var result = new List<HoldObjectAddress>();
            foreach (var item in page.Values)
            {
                // Do not silently omit soft-deleted evidence or claim that listing
                // its tombstone establishes readable/preserved bytes.
                if (item.Deleted == true || item.HasVersionsOnly == true || item.Properties.BlobType != BlobType.Block || item.Properties.ContentLength is null || item.Properties.ETag is null) throw Invalid();
                // List XML and download headers can represent the same ETag with
                // different quoting. Use the SDK's HTTP-header format on both.
                var value = new HoldObjectAddress(area, item.Name, item.VersionId ?? "", item.Snapshot ?? "", item.Properties.ETag.Value.ToString("H"), item.Properties.ContentLength.Value);
                scope.Demand(value, ct); result.Add(value);
            }
            return new(result, page.ContinuationToken);
        }
        return new([], null);
    }

    public async Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress address, CancellationToken ct)
    {
        scope.Demand(address, ct); var client = service.GetBlobContainerClient(address.Area).GetBlobClient(address.Name);
        if (address.VersionId.Length > 0) client = client.WithVersion(address.VersionId);
        else if (address.Snapshot.Length > 0) client = client.WithSnapshot(address.Snapshot);
        var response = await client.DownloadStreamingAsync(new BlobDownloadOptions { Conditions = new() { IfMatch = new ETag(address.ETag) } }, ct);
        await using var input = response.Value.Content; scope.Demand(ct);
        if (response.Value.Details.ContentLength != address.Length) throw new InvalidDataException("The private inventory response length changed.");
        if (response.Value.Details.ETag.ToString("H") != address.ETag) throw new InvalidDataException("The private inventory response ETag changed.");
        if ((response.Value.Details.VersionId ?? "") != address.VersionId) throw new InvalidDataException("The private inventory response version changed.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = ArrayPool<byte>.Shared.Rent(256 * 1024);
        try
        {
            long count = 0;
            while (count < address.Length)
            {
                scope.Demand(ct);
                var read = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, address.Length - count)), ct); scope.Demand(ct);
                if (read == 0) throw Invalid(); hash.AppendData(buffer.AsSpan(0, read)); count += read;
            }
            if (await input.ReadAsync(buffer.AsMemory(0, 1), ct) != 0) throw Invalid(); scope.Demand(ct);
            return Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }
    private static InvalidDataException Invalid() => new("The exact private object bytes could not be inventoried.");
}

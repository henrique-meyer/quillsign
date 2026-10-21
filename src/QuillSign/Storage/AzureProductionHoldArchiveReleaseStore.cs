using System.Buffers;
using System.Security.Cryptography;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using QuillSign.Lifecycle;

namespace QuillSign.Storage;

// Unregistered exact private-archive release adapter. Never lists, deletes,
// shortens immutability, provisions storage or touches an ordinary final object.
internal sealed class AzureProductionHoldArchiveReleaseStore(BlobServiceClient service)
{
    internal async Task<ProductionHoldArchiveStoredObject> InspectAsync(ProductionHoldArchiveReleaseCapability scope, CancellationToken ct = default)
    { _ = await Verify(scope, true, ct); return scope.Stored; }

    internal async Task<ProductionHoldArchiveStoredObject> ReleaseAsync(ProductionHoldArchiveReleaseCapability scope, CancellationToken ct = default)
    {
        // Already-clear replay is allowed only under the same live durable
        // release command/fence. It never follows from untrusted provider facts.
        var before = await Verify(scope, null, ct);
        if (before.HasLegalHold)
        {
            await scope.DemandAsync(ct);
            try
            {
                // This SDK has no BlobRequestConditions overload for legal hold.
                // The request is pinned to the authenticated immutable VersionId;
                // all byte reads use If-Match and both protection states reread.
                await Client(scope).SetLegalHoldAsync(false, ct);
            }
            catch (Exception error) when (error is RequestFailedException or IOException)
            { await scope.DemandAsync(ct); /* Only exact readback reconciles a lost acknowledgement. */ }
            await scope.DemandAsync(ct);
        }
        var after = await Verify(scope, false, ct);
        if (before.ImmutabilityPolicy?.PolicyMode != after.ImmutabilityPolicy?.PolicyMode ||
            before.ImmutabilityPolicy?.ExpiresOn != after.ImmutabilityPolicy?.ExpiresOn) throw Invalid();
        return scope.Stored;
    }

    private async Task<BlobProperties> Verify(ProductionHoldArchiveReleaseCapability scope, bool? held, CancellationToken ct)
    {
        await scope.DemandAsync(ct);
        var container = service.GetBlobContainerClient("final");
        var configuration = (await container.GetPropertiesAsync(cancellationToken: ct)).Value;
        await scope.DemandAsync(ct);
        if (configuration.PublicAccess is not null && configuration.PublicAccess != PublicAccessType.None || configuration.HasImmutableStorageWithVersioning != true) throw Invalid();
        var client = Client(scope); var stored = scope.Stored; var condition = new BlobRequestConditions { IfMatch = new ETag(stored.ETag) };
        await scope.DemandAsync(ct); var before = (await client.GetPropertiesAsync(condition, ct)).Value; await scope.DemandAsync(ct);
        Match(before);
        await scope.DemandAsync(ct); var response = await client.DownloadStreamingAsync(new() { Conditions = condition }, ct); await scope.DemandAsync(ct);
        await using var input = response.Value.Content;
        if (response.Value.Details.VersionId != stored.VersionId || response.Value.Details.ETag.ToString("H") != stored.ETag || response.Value.Details.ContentLength != stored.Length) throw Invalid();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = ArrayPool<byte>.Shared.Rent(256 * 1024);
        try
        {
            long copied = 0;
            while (copied < stored.Length)
            {
                await scope.DemandAsync(ct); var count = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, stored.Length - copied)), ct); await scope.DemandAsync(ct);
                if (count == 0) throw Invalid(); copied += count; hash.AppendData(buffer.AsSpan(0, count));
            }
            await scope.DemandAsync(ct); var tail = await input.ReadAsync(buffer.AsMemory(0, 1), ct); await scope.DemandAsync(ct);
            if (tail != 0 || Convert.ToHexStringLower(hash.GetHashAndReset()) != stored.Sha256) throw Invalid();
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
        await scope.DemandAsync(ct); var after = (await client.GetPropertiesAsync(condition, ct)).Value; await scope.DemandAsync(ct);
        Match(after);
        // A legal-hold change need not change ETag, so bytes are not sufficient.
        if (before.HasLegalHold != after.HasLegalHold || before.ImmutabilityPolicy?.PolicyMode != after.ImmutabilityPolicy?.PolicyMode ||
            before.ImmutabilityPolicy?.ExpiresOn != after.ImmutabilityPolicy?.ExpiresOn) throw Invalid();
        return after;

        void Match(BlobProperties p)
        { if (p.VersionId != stored.VersionId || p.ETag.ToString("H") != stored.ETag || p.ContentLength != stored.Length || held is { } value && p.HasLegalHold != value) throw Invalid(); }
    }
    private BlobBaseClient Client(ProductionHoldArchiveReleaseCapability scope) => service.GetBlobContainerClient("final").GetBlobClient(scope.Stored.Path).WithVersion(scope.Stored.VersionId);
    private static InvalidDataException Invalid() => new("The exact retained archive bytes and release protection could not be verified.");
}

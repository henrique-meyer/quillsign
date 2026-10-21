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
        => (await new AzureProductionHoldArchiveReader(service).VerifyAsync(scope, held, ct)).Properties;
    private BlobBaseClient Client(ProductionHoldArchiveReleaseCapability scope) => AzureProductionHoldArchiveReader.Client(service, scope.Stored);
    private static InvalidDataException Invalid() => new("The exact retained archive bytes and release protection could not be verified.");
}

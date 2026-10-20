using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

internal interface IProductionHoldArchivePayload
{
    string Path { get; }
    long Length { get; }
    string Sha256 { get; }
    HoldObjectAddress? Source { get; }
    void Demand(CancellationToken ct);
    Stream Open(CancellationToken ct);
}

internal sealed class ProductionHoldBundleArchiveCapability : IProductionHoldArchivePayload
{
    private readonly byte[]? memory;
    private readonly TimeProvider time;
    private readonly DateTimeOffset issued, expires;
    internal Guid RecordId { get; }
    internal Guid HoldId { get; }
    internal Guid PlaceCommandId { get; }
    internal long Revision { get; }
    internal string FenceHash { get; }
    internal string SqlStateSha256 { get; }
    internal string SqlPayloadSha256 { get; }
    internal string ManifestSha256 { get; }
    public HoldObjectAddress? Source { get; }
    public string Path { get; }
    public long Length { get; }
    public string Sha256 { get; }

    private ProductionHoldBundleArchiveCapability(ProductionHoldObjectSnapshot snapshot, PendingProductionHold hold, HoldObjectEvidence? item, TimeProvider time)
    {
        RecordId = snapshot.RecordId; HoldId = hold.HoldId; PlaceCommandId = hold.PlacementCommandId; Revision = snapshot.Revision;
        FenceHash = snapshot.FenceHash; SqlStateSha256 = snapshot.SqlStateSha256; SqlPayloadSha256 = snapshot.SqlPayloadSha256; ManifestSha256 = snapshot.ManifestSha256;
        this.time = time; issued = time.GetUtcNow(); expires = issued.AddMinutes(10);
        if (item is null)
        {
            memory = snapshot.ProtectedManifest.ToArray(); Length = memory.LongLength; Sha256 = Convert.ToHexStringLower(SHA256.HashData(memory));
            Path = ProductionHoldArchivePaths.Manifest(RecordId, HoldId, PlaceCommandId, Sha256);
        }
        else
        {
            Source = item.Address; Length = item.Address.Length; Sha256 = item.Sha256;
            Path = ProductionHoldArchivePaths.Object(RecordId, HoldId, PlaceCommandId, item.Address, Sha256);
        }
    }
    // A null selection means only the exact protected manifest. Every raw source
    // selection must match a complete descriptor authenticated in that manifest.
    internal static async Task<ProductionHoldBundleArchiveCapability> AuthorizeLockedAsync(QuillSignDbContext db, IDataProtectionProvider keys,
        TimeProvider time, Guid holdId, ProductionHoldObjectSnapshot snapshot, HoldObjectAddress? selection = null, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested(); var objects = ProductionHoldObjectInventory.OpenVerified(snapshot, keys, time);
        // Reuse current private hold/SQL verification, never participant authority.
        var sql = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(db, keys, time, holdId, snapshot.Sql, ct);
        var item = selection is null ? null : objects.SingleOrDefault(x => x.Address == selection) ?? throw new DocumentConflictException();
        var pending = new PendingProductionHold(holdId, sql.PlaceCommandId, null, ProductionHoldPendingState.PreservationPending);
        var result = new ProductionHoldBundleArchiveCapability(snapshot, pending, item, time); result.Demand(ct); return result;
    }
    public void Demand(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); var now = time.GetUtcNow();
        if (now < issued || now >= expires) throw new UnauthorizedAccessException("The private bundle archive scope expired.");
    }
    public Stream Open(CancellationToken ct)
    {
        Demand(ct); return memory is null ? throw new UnauthorizedAccessException("This archive payload requires its exact scoped source version.") : new MemoryStream(memory, false);
    }
}

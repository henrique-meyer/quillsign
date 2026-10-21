using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

// Private worker authority for one exact encrypted SQL payload. It does not grant
// participant access, hold release, source-file reads or complete preservation.
internal sealed class ProductionHoldSqlArchiveCapability : IProductionHoldArchivePayload
{
    private readonly byte[] payload;
    private readonly TimeProvider time;
    private readonly DateTimeOffset issued, expires;
    internal Guid RecordId { get; }
    internal Guid HoldId { get; }
    internal Guid PlaceCommandId { get; }
    internal long Revision { get; }
    internal string FenceHash { get; }
    internal string SqlStateSha256 { get; }
    internal string SqlPayloadSha256 { get; }
    internal string CiphertextSha256 { get; }
    internal long Length => payload.LongLength;
    // Outside recordGuidN/, so archives never recursively enter a source census.
    internal string Path => ProductionHoldArchivePaths.Sql(RecordId, HoldId, PlaceCommandId, CiphertextSha256);

    private ProductionHoldSqlArchiveCapability(ProductionHoldSqlSnapshot sql, PendingProductionHold hold, TimeProvider time)
    {
        RecordId = sql.RecordId; HoldId = hold.HoldId; PlaceCommandId = hold.PlacementCommandId; Revision = sql.Revision;
        FenceHash = sql.FenceHash; SqlStateSha256 = sql.StateSha256; SqlPayloadSha256 = sql.PayloadSha256;
        payload = sql.ProtectedPayload.ToArray(); CiphertextSha256 = Convert.ToHexStringLower(SHA256.HashData(payload));
        this.time = time; issued = time.GetUtcNow(); expires = issued.AddMinutes(10);
    }
    internal static async Task<ProductionHoldSqlArchiveCapability> AuthorizeLockedAsync(QuillSignDbContext db, IDataProtectionProvider keys,
        TimeProvider time, Guid holdId, ProductionHoldSqlSnapshot sql, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        using var verified = ProductionHoldSqlInventory.OpenVerified(sql, keys);
        await new ProductionHoldControls(db, keys, time).DemandExtendsLockedAsync(sql.RecordId, sql.Control!, ct);
        var now = time.GetUtcNow();
        if (now.Offset != TimeSpan.Zero || sql.CapturedAt.Offset != TimeSpan.Zero || sql.CapturedAt > now || now > DateTimeOffset.MaxValue.AddMinutes(-10))
            throw new InvalidDataException("The private SQL archive clock could not be verified.");
        var requests = await new ProductionHoldRequests(db, keys, time).ReadLockedAsync(sql.RecordId, ct);
        if (requests.Revision != sql.Revision || requests.FenceHash != sql.FenceHash) throw new DocumentConflictException();
        var hold = requests.Holds.SingleOrDefault(x => x.HoldId == holdId);
        if (hold is null || hold.State != ProductionHoldPendingState.PreservationPending) throw new DocumentConflictException();
        var current = await new ProductionHoldSqlInventory(db, keys, time).CaptureLockedAsync(sql.RecordId, sql.Revision, sql.FenceHash, ct: ct);
        if (current.StateSha256 != sql.StateSha256) throw new DocumentConflictException();
        // Recovery can reauthorize the same historical ciphertext only after this
        // fresh current-state check. No participant session or retention is renewed.
        var capability = new ProductionHoldSqlArchiveCapability(sql, hold, time); capability.Demand(ct); return capability;
    }
    internal void Demand(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); var now = time.GetUtcNow();
        if (now < issued || now >= expires) throw new UnauthorizedAccessException("The private SQL archive scope expired.");
    }
    internal Stream Open(CancellationToken ct) { Demand(ct); return new MemoryStream(payload, false); }
    string IProductionHoldArchivePayload.Path => Path;
    long IProductionHoldArchivePayload.Length => Length;
    string IProductionHoldArchivePayload.Sha256 => CiphertextSha256;
    HoldObjectAddress? IProductionHoldArchivePayload.Source => null;
    void IProductionHoldArchivePayload.Demand(CancellationToken ct) => Demand(ct);
    Stream IProductionHoldArchivePayload.Open(CancellationToken ct) => Open(ct);
}

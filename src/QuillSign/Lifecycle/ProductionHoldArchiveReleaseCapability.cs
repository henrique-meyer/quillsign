using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// The connected lifecycle supplies the durable external release fence. A saved
// SQL receipt, a ten-minute clock or an absence listing cannot implement it.
// Release admission must also settle all old in-flight archive writers.
internal interface IProductionHoldReleaseFence
{
    Task DemandReleaseAsync(Guid recordId, Guid holdId, Guid releaseCommandId, long requestRevision,
        string requestFenceHash, CancellationToken ct = default);
}

// One exact, newly-created private archive version belonging to one separately
// authorized release. This never authorizes source/final-file protection changes.
internal sealed class ProductionHoldArchiveReleaseCapability
{
    private readonly IProductionHoldReleaseFence fence;
    private readonly TimeProvider time;
    private readonly DateTimeOffset issued, expires;
    internal Guid RecordId { get; }
    internal Guid HoldId { get; }
    internal Guid PlaceCommandId { get; }
    internal Guid ReleaseCommandId { get; }
    internal Guid PlanId { get; }
    internal string PlanSha256 { get; }
    internal long RequestRevision { get; }
    internal string RequestFenceHash { get; }
    internal ProductionHoldArchiveStoredObject Stored { get; }

    private ProductionHoldArchiveReleaseCapability(ProductionHoldProtectedPlan plan, ProductionHoldFrozenPlan body,
        ProductionHoldItemReceipt receipt, ProductionHoldRequestSnapshot current, Guid releaseCommandId,
        IProductionHoldReleaseFence fence, TimeProvider time)
    {
        RecordId = plan.RecordId; HoldId = plan.HoldId; PlaceCommandId = body.PlaceCommandId;
        ReleaseCommandId = releaseCommandId; PlanId = plan.PlanId; PlanSha256 = plan.Sha256;
        RequestRevision = current.Revision; RequestFenceHash = current.FenceHash!; Stored = receipt.Stored;
        this.fence = fence; this.time = time; issued = time.GetUtcNow(); expires = issued.AddMinutes(10);
    }

    internal static async Task<ProductionHoldArchiveReleaseCapability> AuthorizeLockedAsync(QuillSignDbContext db,
        IDataProtectionProvider keys, TimeProvider time, IProductionHoldReleaseFence fence, Guid holdId,
        Guid releaseCommandId, Guid planId, string path, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(fence); ct.ThrowIfCancellationRequested();
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges())
            throw new InvalidOperationException("Archive release requires a clean caller-owned private transaction.");
        if (holdId == Guid.Empty || releaseCommandId == Guid.Empty || planId == Guid.Empty || path is null || path.Length > 1024)
            throw Invalid();
        // Plan IDs are globally unique, but authority always comes from the
        // authenticated per-record control journal, never from a supplied DTO.
        var row = await db.ProductionHoldControls.AsNoTracking().SingleOrDefaultAsync(
            x => x.EventId == planId && x.PlanId == planId && x.HoldId == holdId && x.Kind == 0, ct) ?? throw Conflict();
        var controls = new ProductionHoldControls(db, keys, time);
        var control = await controls.ReadLockedAsync(row.EnvelopeId, ct);
        if (!control.Plans.TryGetValue(planId, out var plan) || plan.HoldId != holdId) throw Conflict();
        var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
        await controls.DemandExtendsLockedAsync(plan.RecordId, body.Snapshot.Sql.Control!, ct);
        var requests = await new ProductionHoldRequests(db, keys, time).ReadLockedAsync(plan.RecordId, ct);
        var hold = requests.Holds.SingleOrDefault(x => x.HoldId == holdId);
        if (hold is null || hold.PlacementCommandId != body.PlaceCommandId || hold.State != ProductionHoldPendingState.ReleasePending ||
            hold.ReleaseCommandId != releaseCommandId || requests.FenceHash is null) throw Conflict();
        // No missing receipt becomes an absence proof. Partially preserved or
        // uncertain in-flight archives remain ReleasePending for reconciliation.
        var receipts = control.Items.Where(x => x.PlanId == planId).ToArray();
        foreach (var oldPlan in control.Plans.Values.Where(x => x.HoldId == holdId))
        {
            var oldBody = ProductionHoldBundlePlan.OpenVerified(oldPlan, keys, time);
            var oldItems = control.Items.Where(x => x.PlanId == oldPlan.PlanId).ToArray();
            if (oldItems.Length != oldBody.Items.Length || oldBody.Items.Any(x => oldItems.Count(r => r.PlanSha256 == oldPlan.Sha256 &&
                r.Stored.Path == x.Path && r.Stored.Length == x.Length && r.Stored.Sha256 == x.Sha256) != 1)) throw Conflict();
        }
        if (receipts.Length != body.Items.Length || receipts.Any(x => x.PlanSha256 != plan.Sha256) ||
            body.Items.Any(x => receipts.Count(r => r.Stored.Path == x.Path && r.Stored.Length == x.Length && r.Stored.Sha256 == x.Sha256) != 1)) throw Conflict();
        var receipt = receipts.SingleOrDefault(x => x.Stored.Path == path) ?? throw Conflict();
        var current = await new ProductionHoldSqlInventory(db, keys, time).CaptureLockedAsync(plan.RecordId, requests.Revision, requests.FenceHash, ct: ct);
        using var oldSql = ProductionHoldSqlInventory.OpenVerified(body.Snapshot.Sql, keys);
        using var currentSql = ProductionHoldSqlInventory.OpenVerified(current, keys);
        DemandRequestExtension(oldSql.RootElement, currentSql.RootElement);
        var now = time.GetUtcNow();
        if (now.Offset != TimeSpan.Zero || now < body.Snapshot.Sql.CapturedAt || now > DateTimeOffset.MaxValue.AddMinutes(-10)) throw Invalid();
        var capability = new ProductionHoldArchiveReleaseCapability(plan, body, receipt, requests, releaseCommandId, fence, time);
        await capability.DemandAsync(ct); return capability;
    }

    // Both inputs must first be authenticated with OpenVerified. ALL original
    // business evidence remains byte-bound; only exact request-prefix extension
    // and separately authenticated control publication may differ.
    internal static void DemandRequestExtension(JsonElement original, JsonElement current)
    {
        if (original.GetProperty("RecordId").GetGuid() != current.GetProperty("RecordId").GetGuid() ||
            original.GetProperty("Version").GetString() != current.GetProperty("Version").GetString() ||
            original.GetProperty("PolicySha256").GetString() != current.GetProperty("PolicySha256").GetString() ||
            original.GetProperty("Revision").GetInt64() >= current.GetProperty("Revision").GetInt64()) throw Conflict();
        var oldTables = original.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!);
        var newTables = current.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!);
        if (!oldTables.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(newTables.Keys)) throw Conflict();
        foreach (var (name, table) in oldTables)
        {
            var next = newTables[name];
            if (name != "ProductionHoldRequests") { if (table.GetRawText() != next.GetRawText()) throw Conflict(); continue; }
            if (table.GetProperty("Columns").GetRawText() != next.GetProperty("Columns").GetRawText()) throw Conflict();
            var oldRequests = table.GetProperty("Rows").EnumerateArray().OrderBy(x => x.GetProperty("Revision").GetInt64()).ToArray();
            var newRequests = next.GetProperty("Rows").EnumerateArray().OrderBy(x => x.GetProperty("Revision").GetInt64()).ToArray();
            if (oldRequests.LongLength != original.GetProperty("Revision").GetInt64() || newRequests.LongLength != current.GetProperty("Revision").GetInt64() ||
                oldRequests.Length >= newRequests.Length) throw Conflict();
            for (var i = 0; i < oldRequests.Length; i++) if (oldRequests[i].GetRawText() != newRequests[i].GetRawText()) throw Conflict();
            if (Convert.ToHexStringLower(oldRequests[^1].GetProperty("Hash").GetBytesFromBase64()) != original.GetProperty("FenceHash").GetString() ||
                Convert.ToHexStringLower(newRequests[^1].GetProperty("Hash").GetBytesFromBase64()) != current.GetProperty("FenceHash").GetString()) throw Conflict();
        }
        if (!oldTables.ContainsKey("ProductionHoldRequests")) throw Conflict();
    }

    internal async Task DemandAsync(CancellationToken ct = default)
    {
        Check(); await fence.DemandReleaseAsync(RecordId, HoldId, ReleaseCommandId, RequestRevision, RequestFenceHash, ct); Check();
        void Check() { ct.ThrowIfCancellationRequested(); var now = time.GetUtcNow(); if (now < issued || now >= expires) throw new UnauthorizedAccessException("The private archive release scope expired."); }
    }
    private static DocumentConflictException Conflict() => new();
    private static InvalidDataException Invalid() => new("The retained private archive release scope could not be verified.");
}

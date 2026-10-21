using System.Collections.Immutable;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// A private observation, never a bearer capability, a replacement Effective
// receipt, or permission to delete. Original participant clocks are untouched.
internal sealed record ProductionHoldInspectedProtection(Guid HoldId, Guid PlanId, string PlanSha256,
    string PreservationSha256, ImmutableArray<ProductionHoldArchiveStoredObject> Objects);
internal sealed record ProductionHoldProtectionInspection(Guid RecordId, long RequestRevision, string RequestFenceHash,
    long WitnessSequence, string WitnessHead, ProductionHoldControlPrefix Control, DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt, ImmutableArray<ProductionHoldInspectedProtection> Holds);

internal sealed partial class ProductionHoldCoordinator
{
    // Explicit opt-in maintenance only. Ordinary participant/proof/admission
    // readers must never acquire provider archive I/O through ReadVerifiedAsync.
    internal async Task<ProductionHoldProtectionInspection> InspectActiveProtectionAsync(ProductionOperatorAuthority authority,
        ProductionOperatorPolicy operators, Guid recordId, IProductionHoldArchiveInspectionStore reader, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(authority); ArgumentNullException.ThrowIfNull(reader);
        authority.Demand(operators, ProductionOperatorPermission.Status, time);
        if (recordId == Guid.Empty) throw Invalid();
        var issued = time.GetUtcNow();
        if (issued.Offset != TimeSpan.Zero || issued > DateTimeOffset.MaxValue.AddMinutes(-10)) throw Invalid();
        var end = issued.AddMinutes(10); if (authority.ExpiresAt < end) end = authority.ExpiresAt;
        var state = await witness.ReadAsync(recordId, ct); DemandInspectable(state);
        var head = state.HeadHash ?? throw Invalid();
        // This callback intentionally never opens SQL. The caller owns the
        // parent lock throughout all reads; a second context would deadlock.
        async Task Demand(CancellationToken token)
        {
            Check(token);
            var next = await witness.ReadAsync(recordId, token);
            Check(token); DemandInspectable(next);
            if (next.Sequence != state.Sequence || next.HeadHash != head || next.RequestRevision != state.RequestRevision ||
                next.RequestFenceHash != state.RequestFenceHash) throw Invalid();
        }
        DateTimeOffset Check(CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); authority.Demand(operators, ProductionOperatorPermission.Status, time);
            var now = time.GetUtcNow(); if (now.Offset != TimeSpan.Zero || now < issued || now >= end) throw ProductionOperatorAuthority.Denied();
            return now;
        }

        var scopeOpen = false;
        async Task DemandScope(CancellationToken token)
        {
            if (!Volatile.Read(ref scopeOpen)) throw Invalid();
            await Demand(token);
            if (!Volatile.Read(ref scopeOpen)) throw Invalid();
        }
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        try
        {
            Volatile.Write(ref scopeOpen, true);
            if (db.ChangeTracker.HasChanges()) throw Invalid();
            var requests = await Verify(db, recordId, state, ct);
            var controls = new ProductionHoldControls(db, keys, time); var saved = await controls.ReadLockedAsync(recordId, ct);
            // No orphan/extra plan or receipt is hidden by selecting only one hold.
            var witnessed = state.Holds.Values.Where(x => x.PlanSha256 is not null).ToArray();
            if (saved.Plans.Count != witnessed.Length || saved.Plans.Values.Any(x => !witnessed.Any(h => h.Placement.HoldId == x.HoldId &&
                h.PlanId == x.PlanId && h.PlanSha256 == x.Sha256)) || saved.Items.Any(x => !saved.Plans.ContainsKey(x.PlanId))) throw Invalid();
            var current = await new ProductionHoldSqlInventory(db, keys, time).CaptureLockedAsync(recordId, requests.Revision, requests.FenceHash!, ct: ct);
            using var currentSql = ProductionHoldSqlInventory.OpenVerified(current, keys);
            var planned = new List<(HoldWitnessHold Hold, ProductionHoldProtectedPlan Plan, ImmutableArray<ProductionHoldArchiveStoredObject> Items)>();
            var paths = new HashSet<string>(StringComparer.Ordinal); long bytes = 0; var count = 0;
            foreach (var hold in state.Holds.Values.OrderBy(x => x.Placement.HoldId))
            {
                if (hold.PlanId is not { } planId || !saved.Plans.TryGetValue(planId, out var plan) || plan.RecordId != recordId ||
                    plan.HoldId != hold.Placement.HoldId || plan.Sha256 != hold.PlanSha256 || hold.Control is null) throw Invalid();
                var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
                if (body.PlaceCommandId != hold.Placement.CommandId || BundleDigest(plan, body, saved) != hold.PreservationSha256) throw Invalid();
                await controls.DemandExtendsLockedAsync(recordId, body.Snapshot.Sql.Control!, ct);
                await controls.DemandExtendsLockedAsync(recordId, hold.Control, ct);
                // Released histories were authenticated above as part of Verify and
                // the complete control set. Their old business state may legitimately
                // differ after every old hold was released and signing resumed.
                if (hold.Released) continue;
                using var originalSql = ProductionHoldSqlInventory.OpenVerified(body.Snapshot.Sql, keys);
                if (body.Snapshot.Sql.Revision == current.Revision)
                {
                    if (body.Snapshot.Sql.FenceHash != current.FenceHash || body.Snapshot.Sql.StateSha256 != current.StateSha256) throw Invalid();
                }
                else ProductionHoldArchiveReleaseCapability.DemandRequestExtension(originalSql.RootElement, currentSql.RootElement);
                var items = saved.Items.Where(x => x.PlanId == planId).OrderBy(x => x.Stored.Path, StringComparer.Ordinal).Select(x => x.Stored).ToImmutableArray();
                foreach (var item in items)
                {
                    if (!paths.Add(item.Path) || ++count > ProductionHoldControls.MaximumEvents) throw Invalid();
                    bytes = checked(bytes + item.Length);
                }
                planned.Add((hold, plan, items));
            }
            if (count == 0 || bytes < 1) throw Invalid();
            await Demand(ct);
            var observed = ImmutableArray.CreateBuilder<ProductionHoldInspectedProtection>(planned.Count);
            foreach (var (hold, plan, items) in planned)
            {
                foreach (var item in items)
                {
                    var scope = new ProductionHoldActiveArchiveInspectionCapability(item, DemandScope);
                    await scope.DemandAsync(ct); var actual = await reader.InspectAsync(scope, ct); await scope.DemandAsync(ct);
                    if (actual != item) throw Invalid();
                }
                observed.Add(new(hold.Placement.HoldId, plan.PlanId, plan.Sha256, hold.PreservationSha256!, items));
            }
            await Demand(ct); Volatile.Write(ref scopeOpen, false); await tx.RollbackAsync(ct); await tx.DisposeAsync();
            // A command published during read-only completion invalidates the result.
            await Demand(ct); var completed = Check(ct);
            return new(recordId, requests.Revision, requests.FenceHash!, state.Sequence, head, saved.Prefix, issued, completed, observed.MoveToImmutable());
        }
        finally { Volatile.Write(ref scopeOpen, false); }
    }

    private static void DemandInspectable(HoldWitnessState state)
    {
        if (state.Unacknowledged is not null || state.OutstandingOperation is not null || state.RequestRevision < 1 || state.RequestFenceHash is null ||
            !state.Holds.Values.Any(x => !x.Released) || state.Holds.Values.Any(x => !x.Released && (!x.Effective || x.Release is not null))) throw Invalid();
    }

    // Private nested construction prevents a raw provider DTO from becoming an
    // active-read capability. Only the complete authenticated cut above issues it.
    private sealed class ProductionHoldActiveArchiveInspectionCapability(ProductionHoldArchiveStoredObject stored,
        Func<CancellationToken, Task> demand) : IProductionHoldArchiveReadScope
    {
        public ProductionHoldArchiveStoredObject Stored { get; } = stored with { };
        public Task DemandAsync(CancellationToken ct = default) => demand(ct);
    }
}

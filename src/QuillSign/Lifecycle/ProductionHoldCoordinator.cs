using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// Connected private source implementation, deliberately unregistered. Runtime
// admission/worker drains and the remaining evidence schemas must be completed
// before exposing placement. No caller may turn a raw provider DTO into a hold.
internal sealed class ProductionHoldCoordinator(Func<QuillSignDbContext> open, IDataProtectionProvider keys,
    TimeProvider time, ProductionHoldWitnessJournal witness, IProductionHoldObjectSource objects,
    AzureProductionHoldArchiveWriter archive, AzureProductionHoldArchiveReleaseStore releases) : IProductionHoldReleaseFence
{
    internal async Task<HoldWitnessState> SubmitAsync(ProductionOperatorAuthority authority, ProductionOperatorPolicy operators,
        ProductionHoldCommand command, CancellationToken ct = default)
    {
        var before = await witness.ReadAsync(command.RecordId, ct);
        if (before.Unacknowledged is null && before.OutstandingOperation is null) before = await ReadVerifiedAsync(command.RecordId, ct);
        else if (before.Unacknowledged is not null && before.Unacknowledged != command) throw Invalid();
        // Publish before SQL: failed/unknown commits leave a durable closed gate.
        // A replay recovers the existing command rather than reusing its budget
        // or assuming a missing acknowledgement means the commit rolled back.
        var state = await witness.IntentAsync(authority, operators, command, Id(command.CommandId, "intent"), ct);
        // An admitted business operation must settle provider dispatch, its SQL
        // commit AND worker Finish before we acquire the preservation cut. The
        // external intent already blocks later admissions; do not deadlock the
        // drain by holding its SQL parent lock or invent settlement from expiry.
        if (state.OutstandingOperation is not null) return state;
        if (state.Unacknowledged is null) return await ReadVerifiedAsync(command.RecordId, ct);
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        var receipt = await new ProductionHoldRequests(db, keys, time).PrepareLockedAsync(authority, operators, command, ct);
        var sql = await Sql(db, receipt.Current, command.RecordId, ct);
        var content = ContentDigest(sql);
        if (before.OutstandingOperation is null && before.BusinessStateSha256 is not null && before.BusinessStateSha256 != content) throw Invalid();
        authority.Demand(operators, command.Permission, time);
        await tx.CommitAsync(ct);
        return await witness.AcceptSqlAsync(command, receipt, content, Id(command.CommandId, "sql"), ct);
    }

    internal async Task<HoldWitnessState> ReadVerifiedAsync(Guid recordId, CancellationToken ct = default)
    {
        var state = await witness.ReadAsync(recordId, ct);
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        await Verify(db, recordId, state, ct);
        await tx.RollbackAsync(ct);
        var after = await witness.ReadAsync(recordId, ct);
        if (after.HeadHash != state.HeadHash) throw Invalid();
        return after;
    }

    internal async Task<HoldWitnessState> PreserveAsync(Guid recordId, Guid holdId, Guid planId, CancellationToken ct = default)
    {
        var state = await ReadVerifiedAsync(recordId, ct);
        if (!state.Holds.TryGetValue(holdId, out var hold) || hold.Release is not null) throw Invalid();
        if (hold.Effective) return state;
        if (hold.PlanId is not null && hold.PlanId != planId) throw Invalid();
        var work = Id(hold.Placement.CommandId, "preserve-operation");
        state = await witness.ReservePreservationAsync(hold.Placement, planId, work, Id(work, "reserve"), ct);
        ProductionHoldProtectedPlan plan;
        ProductionHoldControlPrefix frozenPrefix;
        await using (var db = open())
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var requests = await Verify(db, recordId, state, ct);
            var controls = new ProductionHoldControls(db, keys, time);
            var saved = await controls.ReadLockedAsync(recordId, ct);
            if (saved.Plans.TryGetValue(planId, out var prior))
            { if (prior.HoldId != holdId) throw Invalid(); plan = prior; }
            else
            {
                var snapshot = await new ProductionHoldObjectInventory(db, keys, time, objects)
                    .CaptureLockedAsync(recordId, requests.Revision, requests.FenceHash!, ct: ct);
                DemandCompleteSchemas(snapshot);
                plan = await ProductionHoldBundlePlan.FreezeLockedAsync(db, keys, time, holdId, planId, snapshot, ct);
                plan = await controls.SavePlanLockedAsync(plan, ct);
            }
            DemandCompleteSchemas(ProductionHoldBundlePlan.OpenVerified(plan, keys, time).Snapshot);
            frozenPrefix = hold.PlanSha256 is not null ? hold.Control! : (await controls.ReadLockedAsync(recordId, ct)).Prefix;
            await tx.CommitAsync(ct);
        }
        await witness.FreezePlanAsync(hold.Placement, planId, plan.Sha256, frozenPrefix, work, Id(work, "plan"), ct);
        var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
        foreach (var item in body.Items)
        {
            await DemandPreservation(recordId, hold.Placement, work, ct);
            await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
            await Verify(db, recordId, await witness.ReadAsync(recordId, ct), ct);
            await new ProductionHoldControls(db, keys, time).PreserveItemLockedAsync(recordId, planId, item.Path,
                Id(planId, item.Path), archive, ct);
            await DemandPreservation(recordId, hold.Placement, work, ct);
            await tx.CommitAsync(ct);
        }
        // Every item has just undergone exact provider bytes/protection readback.
        // Authenticate the complete saved set and control prefix, not just a PDF.
        await using (var db = open())
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await Verify(db, recordId, await witness.ReadAsync(recordId, ct), ct);
            var controls = await new ProductionHoldControls(db, keys, time).ReadLockedAsync(recordId, ct);
            var digest = BundleDigest(plan, body, controls);
            await DemandPreservation(recordId, hold.Placement, work, ct);
            var result = await witness.PreserveAsync(hold.Placement, planId, plan.Sha256, digest, controls.Prefix,
                work, Id(work, "complete"), ct);
            await tx.RollbackAsync(ct); return result;
        }
    }

    internal async Task<HoldWitnessState> ReleaseAsync(Guid recordId, Guid holdId, CancellationToken ct = default)
    {
        var state = await ReadVerifiedAsync(recordId, ct);
        if (!state.Holds.TryGetValue(holdId, out var hold) || hold.Release is not { } release || !hold.Effective) throw Invalid();
        if (hold.Released) return state;
        var work = Id(release.CommandId, "release-operation");
        await witness.ReserveReleaseAsync(release, work, Id(work, "reserve"), ct);
        // Every plan for this hold must be complete; no missing receipt or a
        // temporarily absent blob is accepted as proof of a cancelled write.
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        await Verify(db, recordId, await witness.ReadAsync(recordId, ct), ct);
        var controls = await new ProductionHoldControls(db, keys, time).ReadLockedAsync(recordId, ct);
        var owned = controls.Plans.Values.Where(x => x.HoldId == holdId).OrderBy(x => x.PlanId).ToArray();
        if (owned.Length == 0) throw Invalid();
        var receipts = new List<ProductionHoldArchiveStoredObject>();
        foreach (var plan in owned)
        {
            var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time); _ = BundleDigest(plan, body, controls);
            foreach (var item in body.Items)
            {
                var scope = await ProductionHoldArchiveReleaseCapability.AuthorizeLockedAsync(db, keys, time, this,
                    holdId, release.CommandId, plan.PlanId, item.Path, ct);
                receipts.Add(await releases.ReleaseAsync(scope, ct));
            }
        }
        await DemandReleaseAsync(recordId, holdId, release.CommandId, state.RequestRevision, state.RequestFenceHash!, ct);
        var releaseHash = Digest(new { Version = "production-hold-release-receipt-v1", recordId, holdId,
            release.CommandId, RequestRevision = release.ExpectedRevision + 1, RequestFenceHash = hold.ReleaseFenceHash, controls.Prefix,
            Objects = receipts.OrderBy(x => x.Path, StringComparer.Ordinal).ToArray() });
        var result = await witness.ReleaseAsync(release, releaseHash, controls.Prefix, work, Id(work, "complete"), ct);
        await tx.RollbackAsync(ct); return result;
    }

    public async Task DemandReleaseAsync(Guid recordId, Guid holdId, Guid releaseCommandId, long requestRevision,
        string requestFenceHash, CancellationToken ct = default)
    {
        var state = await witness.ReadAsync(recordId, ct);
        if (state.Unacknowledged is not null || state.RequestRevision != requestRevision || state.RequestFenceHash != requestFenceHash ||
            !state.Holds.TryGetValue(holdId, out var hold) || !hold.Effective || hold.Released || hold.Release?.CommandId != releaseCommandId ||
            state.OutstandingOperation != Id(releaseCommandId, "release-operation")) throw Invalid();
    }

    private async Task DemandPreservation(Guid id, ProductionHoldCommand placement, Guid operation, CancellationToken ct)
    {
        var state = await witness.ReadAsync(id, ct);
        if (state.Unacknowledged is not null || state.OutstandingOperation != operation ||
            !state.Holds.TryGetValue(placement.HoldId, out var hold) || hold.Placement != placement || hold.Release is not null || hold.Effective) throw Invalid();
    }

    private async Task<ProductionHoldRequestSnapshot> Verify(QuillSignDbContext db, Guid id, HoldWitnessState state, CancellationToken ct)
    {
        var requests = await new ProductionHoldRequests(db, keys, time).ReadLockedAsync(id, ct);
        ProductionHoldWitnessJournal.DemandSql(state, requests);
        if (requests.Revision == 0)
        { if (state.Sequence != 0) throw Invalid(); return requests; }
        var sql = await Sql(db, requests, id, ct);
        if (ContentDigest(sql) != state.BusinessStateSha256) throw Invalid();
        var controls = new ProductionHoldControls(db, keys, time);
        var saved = await controls.ReadLockedAsync(id, ct);
        foreach (var hold in state.Holds.Values.Where(x => x.PlanSha256 is not null))
        {
            if (hold.PlanId is not { } planId || hold.PlanSha256 is null || hold.Control is null ||
                !saved.Plans.TryGetValue(planId, out var plan) || plan.HoldId != hold.Placement.HoldId || plan.Sha256 != hold.PlanSha256) throw Invalid();
            await controls.DemandExtendsLockedAsync(id, hold.Control, ct);
            if (!hold.Effective) continue;
            // Check the original complete item set even after later controls were
            // appended for an independent hold. A restored shorter journal fails.
            var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
            if (BundleDigest(plan, body, saved) != hold.PreservationSha256) throw Invalid();
            if (hold.Released)
            {
                var released = saved.Plans.Values.Where(x => x.HoldId == hold.Placement.HoldId).OrderBy(x => x.PlanId)
                    .SelectMany(x => saved.Items.Where(i => i.PlanId == x.PlanId).OrderBy(i => i.Stored.Path, StringComparer.Ordinal))
                    .Select(x => x.Stored).OrderBy(x => x.Path, StringComparer.Ordinal).ToArray();
                var release = hold.Release ?? throw Invalid();
                if (hold.ReleaseSha256 != Digest(new { Version = "production-hold-release-receipt-v1", recordId = id, holdId = hold.Placement.HoldId,
                    release.CommandId, RequestRevision = release.ExpectedRevision + 1, RequestFenceHash = hold.ReleaseFenceHash,
                    Prefix = hold.Control, Objects = released })) throw Invalid();
            }
        }
        return requests;
    }

    private Task<ProductionHoldSqlSnapshot> Sql(QuillSignDbContext db, ProductionHoldRequestSnapshot requests, Guid id, CancellationToken ct)
        => new ProductionHoldSqlInventory(db, keys, time).CaptureLockedAsync(id, requests.Revision, requests.FenceHash!, ct: ct);

    private string ContentDigest(ProductionHoldSqlSnapshot snapshot)
    {
        using var sql = ProductionHoldSqlInventory.OpenVerified(snapshot, keys);
        // The external acknowledgement binds the entire request chain separately
        // through its revision/fence. Keep all other tables byte-for-byte bound
        // across an authorized request append; the original complete SQL
        // snapshot fingerprint still includes EVERY business/request row.
        return Digest(new { Version = "production-hold-external-content-v1", snapshot.RecordId,
            PolicySha256 = sql.RootElement.GetProperty("PolicySha256").GetString(),
            Tables = sql.RootElement.GetProperty("Tables").EnumerateArray()
                .Where(x => x.GetProperty("Table").GetString() != "ProductionHoldRequests").ToArray() });
    }

    private static string BundleDigest(ProductionHoldProtectedPlan plan, ProductionHoldFrozenPlan body, ProductionHoldControlState controls)
    {
        var receipts = controls.Items.Where(x => x.PlanId == plan.PlanId).OrderBy(x => x.Stored.Path, StringComparer.Ordinal).ToArray();
        var items = body.Items.OrderBy(x => x.Path, StringComparer.Ordinal).ToArray();
        if (receipts.Length != items.Length || receipts.Where((x, i) => x.PlanSha256 != plan.Sha256 ||
            x.Stored.Path != items[i].Path || x.Stored.Length != items[i].Length || x.Stored.Sha256 != items[i].Sha256).Any()) throw Invalid();
        return Digest(new { Version = "production-hold-complete-bundle-v1", plan.RecordId, plan.HoldId, plan.PlanId, plan.Sha256,
            body.Snapshot.SqlStateSha256, body.Snapshot.ManifestSha256, Items = receipts });
    }

    private void DemandCompleteSchemas(ProductionHoldObjectSnapshot snapshot)
    {
        // Fail closed while the remaining sent/review/Finish/publication graph is
        // being connected. Existing per-schema codecs have already run in the
        // authenticated inventory reader; unimplemented history stays pending.
        using var sql = ProductionHoldSqlInventory.OpenVerified(snapshot.Sql, keys);
        ProductionHoldAdmissionAuditReferences.Demand(sql.RootElement);
        var tables = sql.RootElement.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        if (tables["Envelopes"].EnumerateArray().Single().GetProperty("Status").GetString() != "Draft") throw Invalid();
        foreach (var audit in tables["AuditEvents"].EnumerateArray())
            if (audit.GetProperty("Event").GetString() is not (ProductionRetentionLedger.EnrollmentEvent or
                "draft_created" or "sender_verification_requested" or "sender_email_verified" or
                "document_uploaded" or "document_replaced" or "preview_confirmed" or "signer_added" or "signer_updated" or "signer_removed" or
                "signers_reordered" or "recipient_added" or "recipient_updated" or "recipient_removed" or "envelope_details_updated" or "fields_saved")) throw Invalid();
    }

    internal static Guid Id(Guid owner, string phase)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"production-hold-coordinator-v1/{owner:N}/{phase}"));
        return new Guid(hash.AsSpan(0, 16));
    }
    private static string Digest<T>(T value) => ProductionHoldWitnessJournal.Digest(JsonSerializer.SerializeToUtf8Bytes(value));
    private static InvalidDataException Invalid() => new("The production hold lifecycle requires reconciliation.");
}

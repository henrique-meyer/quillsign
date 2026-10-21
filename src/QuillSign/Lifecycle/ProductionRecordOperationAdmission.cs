using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

internal sealed record HoldWitnessOperation(Guid OperationId, string Kind, string Reference, long RequestRevision,
    string? RequestFenceHash, string ContentSha256, string SqlStateSha256, long ReservationSequence);

// Immutable saved reservation identity, not participant/operator authority. Every
// use reauthenticates it against the external journal and exact SQL request head.
internal sealed record ProductionRecordOperation(Guid RecordId, Guid OperationId, string Kind, string Reference,
    long RequestRevision, string? RequestFenceHash, string ContentSha256, string SqlStateSha256, long ReservationSequence);

// Private/unregistered admission kernel. Provider work, its SQL transaction and
// durable worker Finish are the caller's responsibility BEFORE CompleteAsync.
// A receipt is their verified exact outcome digest, never an absence listing or
// proof manufactured from an expired lease. Failed/unknown work remains open.
internal sealed partial class ProductionRecordOperationAdmission(Func<QuillSignDbContext> open, IDataProtectionProvider keys,
    TimeProvider time, ProductionHoldWitnessJournal witness)
{
    private sealed record HandlerFinalizationPermit(ProductionRecordOperation Scope, Guid TransactionId, HoldWitnessOutcome HandlerOutcome);
    private readonly ConditionalWeakTable<QuillSignDbContext, HandlerFinalizationPermit> handlerFinalizers = new();
    internal async Task<bool> IsUnenrolledDemoAsync(QuillSignDbContext db, Guid recordId, CancellationToken ct = default)
    {
        var record = await db.Envelopes.AsNoTracking().Where(x => x.Id == recordId).Select(x => new { x.IsDemo }).SingleOrDefaultAsync(ct)
            ?? throw Invalid();
        if (!record.IsDemo) return false;
        // A mutable classification flag cannot downgrade a previously enrolled
        // production record or erase its independently retained external fence.
        if (await db.ProductionRetentionPolicies.AnyAsync(x => x.EnvelopeId == recordId, ct) ||
            (await witness.ReadAsync(recordId, ct)).Sequence != 0) throw Invalid();
        return true;
    }

    internal async Task<HoldWitnessState> InitializeAsync(Guid recordId, CancellationToken ct = default)
    {
        var before = await witness.ReadAsync(recordId, ct);
        if (before.Sequence != 0 && (!before.Initialized || before.Sequence != 1)) throw Invalid();
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        var requests = await Requests(db, recordId, ct);
        if (requests.Revision != 0 || requests.FenceHash is not null || requests.Holds.Count != 0) throw Invalid();
        var sql = await Capture(db, recordId, requests, ct); var content = ContentDigest(sql, keys);
        using (var verified = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys)) DemandFresh(verified.RootElement);
        if (before.Initialized && (before.BusinessStateSha256 != content || before.SqlStateSha256 != sql.StateSha256)) throw Invalid();
        var result = await witness.InitializeAsync(recordId, content, sql.StateSha256, Id(recordId, Guid.Empty, "initialize"), ct);
        if (!result.Initialized || result.BusinessStateSha256 != content || result.SqlStateSha256 != sql.StateSha256 || result.Sequence != 1) throw Invalid();
        await tx.RollbackAsync(ct); return result;
    }

    internal async Task<ProductionRecordOperation> BeginAsync(Guid recordId, Guid operationId, string kind, string reference, CancellationToken ct = default)
    {
        Tuple(recordId, operationId, kind, reference);
        var before = await witness.ReadAsync(recordId, ct);
        if (before.Operations?.ContainsKey(operationId) == true) return await ResumeAsync(recordId, operationId, kind, reference, ct);
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        var scope = await BeginLockedAsync(db, recordId, operationId, kind, reference, ct);
        await tx.RollbackAsync(ct); return scope;
    }

    // Reserve only after the caller's ordinary validation/local rendering and
    // immediately before its first mutation, without acquiring a second connection.
    internal async Task<ProductionRecordOperation> BeginLockedAsync(QuillSignDbContext db, Guid recordId,
        Guid operationId, string kind, string reference, CancellationToken ct = default)
    {
        Tuple(recordId, operationId, kind, reference);
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw Invalid();
        var before = await witness.ReadAsync(recordId, ct);
        if (before.Operations?.ContainsKey(operationId) == true)
        {
            var replay = Scope(recordId, operationId, kind, reference, before);
            await DemandStartingLockedAsync(db, replay, ct); return replay;
        }
        if (!before.Initialized || before.Frozen) throw Invalid();
        var requests = await Requests(db, recordId, ct); ProductionHoldWitnessJournal.DemandSql(before, requests);
        var sql = await Capture(db, recordId, requests, ct); var content = ContentDigest(sql, keys);
        if (content != before.BusinessStateSha256 || before.SqlStateSha256 is not null && sql.StateSha256 != before.SqlStateSha256) throw Invalid();
        await DemandControls(db, recordId, before, ct);
        var state = await witness.ReserveOperationAsync(recordId, operationId, kind, reference, requests, content, sql.StateSha256,
            Id(recordId, operationId, "reserve"), ct);
        var scope = Scope(recordId, operationId, kind, reference, state);
        DemandActive(scope, state); return scope;
    }

    internal async Task<ProductionRecordOperation> ResumeAsync(Guid recordId, Guid operationId, string kind, string reference, CancellationToken ct = default)
    {
        Tuple(recordId, operationId, kind, reference);
        var state = await witness.ReadAsync(recordId, ct); var scope = Scope(recordId, operationId, kind, reference, state);
        // Sealed/settled replay conveys no provider authority. CompleteAsync can
        // reconcile the exact outcome or confirm its historical receipt only.
        if (!state.SettledOperations.ContainsKey(operationId) && state.Outcomes?.ContainsKey(operationId) != true &&
            state.HandlerOutcomes?.ContainsKey(operationId) != true) await DemandAsync(scope, ct);
        return scope;
    }

    // Receipt-only reconciliation after the caller has disposed its read-only
    // Sent transaction. An unknown/unsealed operation cannot replay business IO.
    internal async Task<ProductionRecordOperation?> ReadSendOutcomeAsync(Guid recordId, string reference, CancellationToken ct = default)
    {
        if (recordId == Guid.Empty || !ProductionHoldWitnessJournal.OperationText(reference, 512)) throw Invalid();
        var state = await witness.ReadAsync(recordId, ct);
        if (state.OutstandingOperation is not { } operationId) return null;
        var scope = Scope(recordId, operationId, ProductionRecordSendWriteContract.Kind, reference, state);
        if (state.Outcomes?.ContainsKey(operationId) != true) throw Invalid();
        DemandActive(scope, state, allowOutcome: true); return scope;
    }

    internal async Task DemandAsync(ProductionRecordOperation scope, CancellationToken ct = default)
    {
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DemandLockedAsync(db, scope, ct);
        await tx.RollbackAsync(ct);
    }

    internal async Task<ProductionRecordOperation> ResumeLockedAsync(QuillSignDbContext db, Guid recordId,
        Guid operationId, string kind, string reference, CancellationToken ct = default)
    {
        Tuple(recordId, operationId, kind, reference);
        var scope = Scope(recordId, operationId, kind, reference, await witness.ReadAsync(recordId, ct));
        await DemandLockedAsync(db, scope, ct); return scope;
    }

    // Use the caller's parent transaction. A second connection cannot acquire
    // the same parent update lock, even when it only reads request metadata.
    internal async Task DemandLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw Invalid();
        var dispatchState = await witness.ReadAsync(scope.RecordId, ct);
        DemandActive(scope, dispatchState, allowDispatch: HasDispatchReceiptPermission(db, scope, dispatchState));
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests);
        // Pending hold intent may arrive during the read, but only this same
        // previously admitted operation may drain. Its own business edits need
        // not match the old baseline while it is executing.
        dispatchState = await witness.ReadAsync(scope.RecordId, ct);
        DemandActive(scope, dispatchState, allowDispatch: HasDispatchReceiptPermission(db, scope, dispatchState));
    }

    // Only before the operation's FIRST SQL mutation. Handler/provider changes
    // legitimately differ later and must remain reserved until exact Finish.
    internal async Task DemandStartingLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        await DemandLockedAsync(db, scope, ct);
        var requests = await Requests(db, scope.RecordId, ct);
        var current = await Capture(db, scope.RecordId, requests, ct);
        if (current.StateSha256 != scope.SqlStateSha256 || ContentDigest(current, keys) != scope.ContentSha256) throw Invalid();
        DemandActive(scope, await witness.ReadAsync(scope.RecordId, ct));
    }

    internal async Task<HoldWitnessState> CompleteAsync(ProductionRecordOperation scope, string receiptSha256, CancellationToken ct = default)
    {
        if (!Hash(receiptSha256)) throw Invalid();
        var state = await witness.ReadAsync(scope.RecordId, ct);
        if (Scope(scope.RecordId, scope.OperationId, scope.Kind, scope.Reference, state) != scope) throw Invalid();
        // Historical receipt confirmation is not a current SQL/provider status
        // assertion and cannot advance or replace the authenticated baseline.
        if (state.SettledOperations.TryGetValue(scope.OperationId, out var saved))
        { if (saved != receiptSha256) throw Invalid(); return state; }
        DemandActive(scope, state, allowOutcome: true, allowHandler: true);
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests);
        await DemandControls(db, scope.RecordId, state, ct);
        var current = await Capture(db, scope.RecordId, requests, ct);
        var content = ContentDigest(current, keys);
        var operation = state.Operations![scope.OperationId];
        var outcome = state.Outcomes?.GetValueOrDefault(scope.OperationId);
        if (outcome is null)
        {
            // Without a precommit outcome only the EXACT originally reserved
            // SQL may be acknowledged. Fresh changed SQL is never authority.
            if (state.HandlerOutcomes?.ContainsKey(scope.OperationId) == true || state.UploadWrites?.ContainsKey(scope.OperationId) == true ||
                state.SendWrites?.ContainsKey(scope.OperationId) == true ||
                current.StateSha256 != scope.SqlStateSha256 || content != scope.ContentSha256) throw Invalid();
            state = await witness.PrepareOperationOutcomeAsync(scope.RecordId, operation, content, current.StateSha256,
                Id(scope.RecordId, scope.OperationId, "outcome"), ct);
            outcome = state.Outcomes![scope.OperationId];
        }
        if (outcome!.ContentSha256 != content || outcome.SqlStateSha256 != current.StateSha256) throw Invalid();
        var result = await witness.SettleOperationAsync(scope.RecordId, operation, receiptSha256, content, current.StateSha256,
            Id(scope.RecordId, scope.OperationId, "settle"), ct);
        if (!result.SettledOperations.TryGetValue(scope.OperationId, out var proof) || proof != receiptSha256) throw Invalid();
        await tx.RollbackAsync(ct); return result;
    }

    // Caller must SaveChanges, publish this immutable expected outcome, then
    // commit its same transaction. Publication failure/unknown SQL commit stays
    // quarantined. It can only be reconciled against these exact retained hashes.
    internal async Task PrepareOutcomeLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw Invalid();
        var state = await witness.ReadAsync(scope.RecordId, ct); DemandActive(scope, state, allowOutcome: true, allowHandler: true);
        if (state.HandlerOutcomes?.GetValueOrDefault(scope.OperationId) is { } handler &&
            (!handlerFinalizers.TryGetValue(db, out var permit) || permit.Scope != scope ||
                permit.TransactionId != db.Database.CurrentTransaction.TransactionId || permit.HandlerOutcome != handler)) throw Invalid();
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests);
        await DemandControls(db, scope.RecordId, state, ct);
        var current = await Capture(db, scope.RecordId, requests, ct);
        if (scope.Kind == ProductionRecordUploadWriteContract.Kind)
            ProductionRecordUploadWriteContract.DemandSaved(current, keys, state.UploadWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid());
        if (scope.Kind == ProductionRecordSendWriteContract.Kind)
            await DemandSendOutcomeLocked(db, scope, current, state, ct);
        var result = await witness.PrepareOperationOutcomeAsync(scope.RecordId, state.Operations![scope.OperationId],
            ContentDigest(current, keys), current.StateSha256, Id(scope.RecordId, scope.OperationId, "outcome"), ct);
        DemandActive(scope, result, allowOutcome: true, allowHandler: true);
    }

    // A worker handler's final receipt transaction must checkpoint its exact
    // state BEFORE commit. This is distinct from later WorkStore bookkeeping.
    internal async Task PrepareHandlerOutcomeLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        Worker(scope);
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw Invalid();
        var state = await witness.ReadAsync(scope.RecordId, ct);
        DemandActive(scope, state, allowHandler: true, allowDispatch: DemandDispatchHandlerPermission(db, scope, state));
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests);
        await DemandControls(db, scope.RecordId, state, ct); var current = await Capture(db, scope.RecordId, requests, ct);
        var result = await witness.PrepareHandlerOutcomeAsync(scope.RecordId, state.Operations![scope.OperationId],
            ContentDigest(current, keys), current.StateSha256, Id(scope.RecordId, scope.OperationId, "handler-outcome"), ct);
        DemandActive(scope, result, allowHandler: true, allowDispatch: true);
    }

    internal async Task<ProductionRecordOperation> ResumeHandlerLockedAsync(QuillSignDbContext db, Guid recordId,
        Guid operationId, string kind, string reference, CancellationToken ct = default)
    {
        Tuple(recordId, operationId, kind, reference);
        var scope = Scope(recordId, operationId, kind, reference, await witness.ReadAsync(recordId, ct));
        await DemandHandlerOutcomeLockedAsync(db, scope, ct); return scope;
    }

    // Verifies the committed handler bytes under the SAME caller transaction
    // before WorkStore changes its row. The resulting in-memory permit grants
    // only that exact transaction permission to seal its final bookkeeping.
    internal async Task DemandHandlerOutcomeLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        Worker(scope);
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw Invalid();
        handlerFinalizers.Remove(db);
        var state = await witness.ReadAsync(scope.RecordId, ct); DemandActive(scope, state, allowHandler: true);
        var handler = state.HandlerOutcomes?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests);
        await DemandControls(db, scope.RecordId, state, ct); var current = await Capture(db, scope.RecordId, requests, ct);
        if (handler.ContentSha256 != ContentDigest(current, keys) || handler.SqlStateSha256 != current.StateSha256) throw Invalid();
        var after = await witness.ReadAsync(scope.RecordId, ct); DemandActive(scope, after, allowHandler: true);
        if (after.HandlerOutcomes?.GetValueOrDefault(scope.OperationId) != handler) throw Invalid();
        handlerFinalizers.Add(db, new(scope, db.Database.CurrentTransaction.TransactionId, handler));
    }

    internal static string ContentDigest(ProductionHoldSqlSnapshot snapshot, IDataProtectionProvider keys)
    {
        using var sql = ProductionHoldSqlInventory.OpenAcknowledgementVerified(snapshot, keys);
        // Only the separately authenticated request head is outside this digest.
        // The original full SQL StateSha256 still binds EVERY request/business
        // row. No other evidence or schema column is removed from that binding.
        return ProductionHoldWitnessJournal.Digest(JsonSerializer.SerializeToUtf8Bytes(new { Version = "production-hold-external-content-v1", snapshot.RecordId,
            PolicySha256 = sql.RootElement.GetProperty("PolicySha256").GetString(), Tables = sql.RootElement.GetProperty("Tables").EnumerateArray()
                .Where(x => x.GetProperty("Table").GetString() != "ProductionHoldRequests").ToArray() }));
    }

    private Task<ProductionHoldSqlSnapshot> Capture(QuillSignDbContext db, Guid id, ProductionHoldRequestSnapshot requests, CancellationToken ct)
        => new ProductionHoldSqlInventory(db, keys, time).CaptureAcknowledgementLockedAsync(id, requests.Revision, requests.FenceHash, ct: ct);
    private Task<ProductionHoldRequestSnapshot> Requests(QuillSignDbContext db, Guid id, CancellationToken ct)
        => new ProductionHoldRequests(db, keys, time).ReadLockedAsync(id, ct);
    private async Task DemandControls(QuillSignDbContext db, Guid id, HoldWitnessState state, CancellationToken ct)
    {
        var controls = new ProductionHoldControls(db, keys, time);
        foreach (var prefix in state.Holds.Values.Select(x => x.Control).Where(x => x is not null).Distinct())
            await controls.DemandExtendsLockedAsync(id, prefix!, ct);
    }
    private static ProductionRecordOperation Scope(Guid id, Guid operationId, string kind, string reference, HoldWitnessState state)
    {
        Tuple(id, operationId, kind, reference);
        if (!state.Initialized || state.Operations is null || !state.Operations.TryGetValue(operationId, out var operation) || operation.Kind != kind || operation.Reference != reference) throw Invalid();
        return new(id, operationId, kind, reference, operation.RequestRevision, operation.RequestFenceHash, operation.ContentSha256, operation.SqlStateSha256, operation.ReservationSequence);
    }
    private static void DemandActive(ProductionRecordOperation scope, HoldWitnessState state, bool allowOutcome = false, bool allowHandler = false, bool allowDispatch = false)
    {
        if (Scope(scope.RecordId, scope.OperationId, scope.Kind, scope.Reference, state) != scope || state.OutstandingOperation != scope.OperationId ||
            state.SettledOperations.ContainsKey(scope.OperationId) || !allowOutcome && state.Outcomes?.ContainsKey(scope.OperationId) == true ||
            !allowHandler && state.HandlerOutcomes?.ContainsKey(scope.OperationId) == true ||
            !allowDispatch && state.DispatchStarts?.ContainsKey(scope.OperationId) == true &&
                !(allowHandler && state.HandlerOutcomes?.ContainsKey(scope.OperationId) == true) &&
                !(allowOutcome && state.Outcomes?.ContainsKey(scope.OperationId) == true) ||
            state.RequestRevision != scope.RequestRevision || state.RequestFenceHash != scope.RequestFenceHash ||
            state.Holds.Values.Any(x => !x.Released && state.Unacknowledged?.CommandId != x.Placement.CommandId)) throw Invalid();
    }
    private static void DemandHead(ProductionRecordOperation scope, ProductionHoldRequestSnapshot requests)
    { if (requests.Revision != scope.RequestRevision || requests.FenceHash != scope.RequestFenceHash) throw Invalid(); }
    private static void Tuple(Guid id, Guid operationId, string kind, string reference)
    { if (id == Guid.Empty || operationId == Guid.Empty || !ProductionHoldWitnessJournal.OperationText(kind, 128) || !ProductionHoldWitnessJournal.OperationText(reference, 512)) throw Invalid(); }
    private static void Worker(ProductionRecordOperation scope)
    {
        if (!ProductionHoldWitnessJournal.WorkerOperationText(scope.Kind)) throw Invalid();
    }
    private static void DemandFresh(JsonElement sql)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        var e = tables["Envelopes"].EnumerateArray().Single();
        if (e.GetProperty("IsDemo").GetBoolean() || e.GetProperty("Status").GetString() != nameof(EnvelopeStatus.Draft) ||
            e.GetProperty("SenderVerifiedAt").ValueKind != JsonValueKind.Null || e.GetProperty("PdfBlob").ValueKind != JsonValueKind.Null ||
            e.GetProperty("OriginalBlob").ValueKind != JsonValueKind.Null || e.GetProperty("SentAt").ValueKind != JsonValueKind.Null) throw Invalid();
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "Envelopes", "ProductionRetentionPolicies", "AuditEvents", "WorkItems", "EmailOutbox", "ProductionHoldRequests" };
        if (tables.Any(x => !allowed.Contains(x.Key) && x.Value.GetArrayLength() != 0) || tables["ProductionHoldRequests"].GetArrayLength() != 0 ||
            tables["AuditEvents"].EnumerateArray().Any(x => x.GetProperty("Event").GetString() is not ("production_retention_enrolled" or "draft_created" or "sender_verification_requested"))) throw Invalid();
        foreach (var row in tables["WorkItems"].EnumerateArray())
            if (row.GetProperty("Status").GetString() != nameof(WorkStatus.Queued) || row.GetProperty("Attempts").GetInt32() != 0 ||
                row.GetProperty("LeaseOwner").ValueKind != JsonValueKind.Null || row.GetProperty("LeaseExpiresAt").ValueKind != JsonValueKind.Null ||
                row.GetProperty("LastError").ValueKind != JsonValueKind.Null) throw Invalid();
        foreach (var row in tables["EmailOutbox"].EnumerateArray())
            if (row.GetProperty("Template").GetString() != "sender-verification" || row.GetProperty("Status").GetString() != nameof(EmailStatus.Queued) ||
                row.GetProperty("Attempts").GetInt32() != 0 || row.GetProperty("SubmissionStartedAt").ValueKind != JsonValueKind.Null ||
                row.GetProperty("ProviderMessageId").ValueKind != JsonValueKind.Null || row.GetProperty("Provider").ValueKind != JsonValueKind.Null ||
                row.GetProperty("LeaseOwner").ValueKind != JsonValueKind.Null || row.GetProperty("LeaseExpiresAt").ValueKind != JsonValueKind.Null || row.GetProperty("LastError").ValueKind != JsonValueKind.Null) throw Invalid();
    }
    private static Guid Id(Guid id, Guid operation, string phase) => new(SHA256.HashData(Encoding.ASCII.GetBytes($"production-record-operation-v1:{id:N}:{operation:N}:{phase}")).AsSpan(0, 16));
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    private static InvalidDataException Invalid() => new("The exact production operation admission and acknowledgement could not be verified.");
}

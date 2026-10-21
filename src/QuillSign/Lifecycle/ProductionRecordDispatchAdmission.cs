using System.Data.Common;
using System.Globalization;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

// Opaque identity only. Admission's private context table, not this constructor
// or its RecordId, supplies the nontransferable process-memory authority.
internal sealed class ProductionRecordDispatchPermit
{
    internal Guid RecordId { get; }
    internal ProductionRecordDispatchPermit(Guid recordId) => RecordId = recordId;
}

internal sealed partial class ProductionRecordOperationAdmission
{
    private sealed class DispatchBinding(ProductionRecordDispatchPermit permit, ProductionRecordOperation scope,
        Guid preparingTransaction, DbTransaction preparingSqlTransaction, HoldWitnessOutcome checkpoint, DateTimeOffset deadline)
    {
        internal readonly ProductionRecordDispatchPermit Permit = permit;
        internal readonly ProductionRecordOperation Scope = scope;
        internal readonly Guid PreparingTransaction = preparingTransaction;
        internal readonly DbTransaction PreparingSqlTransaction = preparingSqlTransaction;
        internal DbTransaction? ConsumingSqlTransaction, ReceiptSqlTransaction;
        internal readonly HoldWitnessOutcome Checkpoint = checkpoint;
        internal readonly DateTimeOffset Deadline = deadline;
        internal Guid ConsumingTransaction, ReceiptTransaction;
        internal int Consumed, ReceiptVerified;
    }
    private readonly ConditionalWeakTable<QuillSignDbContext, DispatchBinding> dispatchBindings = new();

    internal async Task<ProductionRecordDispatchPermit> PrepareDispatchLockedAsync(QuillSignDbContext db,
        ProductionRecordOperation scope, CancellationToken ct = default)
    {
        Worker(scope); DemandDispatchTransaction(db);
        var state = await witness.ReadAsync(scope.RecordId, ct); DemandActive(scope, state);
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests);
        await DemandControls(db, scope.RecordId, state, ct); var deadline = await DemandDispatchWorkLocked(db, scope, ct);
        var sql = await Capture(db, scope.RecordId, requests, ct); var content = ContentDigest(sql, keys);
        bool fresh;
        try
        {
            fresh = await witness.BeginDispatchAsync(scope.RecordId, state.Operations![scope.OperationId], content,
                sql.StateSha256, Id(scope.RecordId, scope.OperationId, "dispatch-start"), ct);
        }
        catch (IOException error) { throw new InvalidDataException("Dispatch checkpoint acknowledgement is unknown; provider replay is forbidden.", error); }
        if (!fresh) throw Invalid();
        var after = await witness.ReadAsync(scope.RecordId, ct); DemandActive(scope, after, allowDispatch: true);
        var checkpoint = after.DispatchStarts?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (checkpoint.ContentSha256 != content || checkpoint.SqlStateSha256 != sql.StateSha256 || time.GetUtcNow() >= deadline) throw Invalid();
        var permit = new ProductionRecordDispatchPermit(scope.RecordId);
        dispatchBindings.Remove(db);
        dispatchBindings.Add(db, new(permit, scope, db.Database.CurrentTransaction!.TransactionId, db.Database.CurrentTransaction.GetDbTransaction(), checkpoint, deadline));
        return permit;
    }

    internal async Task ConsumeDispatchLockedAsync(QuillSignDbContext db, ProductionRecordDispatchPermit permit, CancellationToken ct = default)
    {
        var binding = Dispatch(db, permit);
        var transaction = db.Database.CurrentTransaction!.TransactionId;
        if (transaction == binding.PreparingTransaction || ReferenceEquals(db.Database.CurrentTransaction.GetDbTransaction(), binding.PreparingSqlTransaction) ||
            binding.PreparingSqlTransaction.Connection is not null) throw Invalid(); // The actual preparation transaction must have ended.
        if (Interlocked.CompareExchange(ref binding.Consumed, 1, 0) != 0) throw Invalid();
        await DemandDispatchCheckpointLocked(db, binding, ct);
        binding.ConsumingTransaction = transaction;
        binding.ConsumingSqlTransaction = db.Database.CurrentTransaction.GetDbTransaction();
        Volatile.Write(ref binding.Consumed, 2); // Never reset after failure, cancellation or unknown readback.
    }

    internal async Task DemandDispatchReceiptLockedAsync(QuillSignDbContext db, ProductionRecordDispatchPermit permit, CancellationToken ct = default)
    {
        var binding = Dispatch(db, permit); var transaction = db.Database.CurrentTransaction!.TransactionId;
        if (Volatile.Read(ref binding.Consumed) != 2 || transaction == binding.PreparingTransaction || transaction == binding.ConsumingTransaction ||
            ReferenceEquals(db.Database.CurrentTransaction.GetDbTransaction(), binding.PreparingSqlTransaction) ||
            ReferenceEquals(db.Database.CurrentTransaction.GetDbTransaction(), binding.ConsumingSqlTransaction) || binding.ConsumingSqlTransaction?.Connection is not null ||
            Interlocked.CompareExchange(ref binding.ReceiptVerified, 1, 0) != 0) throw Invalid();
        await DemandDispatchCheckpointLocked(db, binding, ct);
        binding.ReceiptTransaction = transaction;
        binding.ReceiptSqlTransaction = db.Database.CurrentTransaction.GetDbTransaction();
        Volatile.Write(ref binding.ReceiptVerified, 2);
    }

    private DispatchBinding Dispatch(QuillSignDbContext db, ProductionRecordDispatchPermit permit)
    {
        DemandDispatchTransaction(db);
        if (!dispatchBindings.TryGetValue(db, out var binding) || !ReferenceEquals(binding.Permit, permit) || permit.RecordId != binding.Scope.RecordId) throw Invalid();
        return binding;
    }
    private static void DemandDispatchTransaction(QuillSignDbContext db)
    { if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw Invalid(); }

    private async Task DemandDispatchCheckpointLocked(QuillSignDbContext db, DispatchBinding binding, CancellationToken ct)
    {
        var scope = binding.Scope; var state = await witness.ReadAsync(scope.RecordId, ct); DemandActive(scope, state, allowDispatch: true);
        if (state.DispatchStarts?.GetValueOrDefault(scope.OperationId) != binding.Checkpoint) throw Invalid();
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests);
        await DemandControls(db, scope.RecordId, state, ct); var deadline = await DemandDispatchWorkLocked(db, scope, ct);
        var current = await Capture(db, scope.RecordId, requests, ct);
        if (current.StateSha256 != binding.Checkpoint.SqlStateSha256 || ContentDigest(current, keys) != binding.Checkpoint.ContentSha256) throw Invalid();
        var after = await witness.ReadAsync(scope.RecordId, ct); DemandActive(scope, after, allowDispatch: true);
        if (after.DispatchStarts?.GetValueOrDefault(scope.OperationId) != binding.Checkpoint || time.GetUtcNow() >= binding.Deadline) throw Invalid();
    }

    // Bind the actual worker/attempt and original lease, not a caller-supplied
    // token or a later current work row. The full snapshot also binds all mail,
    // token hashes, protected payloads, policy clocks and request/control rows.
    private async Task<DateTimeOffset> DemandDispatchWorkLocked(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct)
    {
        if (scope.Kind != "work/" + ((int)WorkKind.Email).ToString(CultureInfo.InvariantCulture)) throw Invalid();
        var parts = scope.Reference.Split("/attempt/", StringSplitOptions.None);
        if (parts.Length != 2 || !Guid.TryParseExact(parts[0], "N", out var id) || id == Guid.Empty ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var attempt) || attempt <= 0 ||
            parts[1] != attempt.ToString(CultureInfo.InvariantCulture)) throw Invalid();
        var work = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct) ?? throw Invalid();
        var mail = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct) ?? throw Invalid();
        var now = time.GetUtcNow();
        if (work.EnvelopeId != scope.RecordId || work.Kind != WorkKind.Email || work.Status != WorkStatus.Leased ||
            work.LeaseOwner != scope.OperationId || work.Attempts != attempt || work.LeaseExpiresAt is null || work.LeaseExpiresAt <= now || work.AvailableAt > now ||
            mail.EnvelopeId != scope.RecordId || mail.Status != EmailStatus.Queued || mail.Attempts != attempt ||
            mail.SubmissionStartedAt is null || mail.SubmissionStartedAt > now || mail.Provider is not null || mail.ProviderMessageId is not null) throw Invalid();
        return work.LeaseExpiresAt.Value;
    }

    private bool HasDispatchReceiptPermission(QuillSignDbContext db, ProductionRecordOperation scope, HoldWitnessState state) =>
        state.DispatchStarts?.GetValueOrDefault(scope.OperationId) is { } checkpoint &&
        db.Database.CurrentTransaction is { } transaction && dispatchBindings.TryGetValue(db, out var binding) &&
        binding.Scope == scope && binding.Checkpoint == checkpoint && time.GetUtcNow() < binding.Deadline && Volatile.Read(ref binding.Consumed) == 2 &&
        Volatile.Read(ref binding.ReceiptVerified) == 2 && binding.ReceiptTransaction == transaction.TransactionId &&
        binding.ReceiptSqlTransaction?.Connection is not null && ReferenceEquals(transaction.GetDbTransaction(), binding.ReceiptSqlTransaction);

    private bool DemandDispatchHandlerPermission(QuillSignDbContext db, ProductionRecordOperation scope, HoldWitnessState state)
    {
        if (state.DispatchStarts?.ContainsKey(scope.OperationId) != true) return false; // Preserve old handler-only records.
        if (!HasDispatchReceiptPermission(db, scope, state)) throw Invalid();
        return true;
    }
}
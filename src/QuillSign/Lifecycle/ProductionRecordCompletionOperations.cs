using System.Collections.Immutable;
using System.Data.Common;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Completion;

namespace QuillSign.Lifecycle;

internal enum CompletionSlot { Candidate, ExecutedSeal, CertificateSeal, PublicationIntent, PublicationResult, HandlerReceipt, WorkFinish }
internal enum CompletionEffect { CandidateInput, CandidatePdf, ExecutedContext, ExecutedRequest, ExecutedTsa, ExecutedResponse, ExecutedPdf, ExecutedResult,
    CertificateContext, CertificateRequest, CertificateTsa, CertificateResponse, CertificateSource, CertificatePdf, CertificateResult,
    PublicationIntentInput, PublicationExecutedFinal, PublicationCertificateFinal, PublicationResultInput }
internal enum CompletionTransitionKind { ClaimPlanned, ClaimExpected, ClaimAcknowledged, SlotOpened, EffectStarted, EffectRecorded, RowsPlanned, SlotExpected, SlotAcknowledged }
internal sealed record CompletionSqlSelector(string Table, string Key, string? BeforeSha256 = null);
internal sealed record CompletionEffectTarget(CompletionEffect Effect, Guid TargetId);
internal sealed record HoldWitnessCompletionClaim(Guid WorkId, int Attempt, DateTimeOffset Until, string PayloadSha256, string WorkBeforeJson, string WorkAfterJson, string RemainderSha256, Guid PhysicalTransaction);
internal sealed record HoldWitnessCompletionContext(CompletionSlot Slot, Guid OperationId, long PredecessorSequence, string PredecessorSqlStateSha256,
    string PredecessorContentSha256, Guid WorkId, int Attempt, DateTimeOffset Until, string PayloadSha256, ImmutableArray<CompletionEffectTarget> Targets, ImmutableArray<CompletionSqlSelector> SqlRows, string RemainderSha256, DateTimeOffset RecordedAt);
internal sealed record CompletionSqlRow(string Table, string Key, string? BeforeJson, string AfterJson);
internal sealed record HoldWitnessCompletionRows(string ContextSha256, ProductionRecordWriteDescriptor? Input, string DeltaSha256);
internal sealed record CompletionEffectDescriptor(CompletionEffect Effect, Guid TargetId, long Length, string Sha256, int MaximumRequests, ImmutableArray<string> Requests);
internal sealed record CompletionEffectReceipt(CompletionEffectDescriptor Effect, string ReceiptSha256, ProductionRecordWriteReceipt? Stored, FinalStoredDocument? Final = null);
internal sealed record HoldWitnessCompletionTransition(CompletionTransitionKind Kind, CompletionSlot? Slot = null,
    HoldWitnessCompletionClaim? Claim = null, HoldWitnessCompletionContext? Context = null, CompletionEffectDescriptor? Effect = null,
    CompletionEffectReceipt? Receipt = null, HoldWitnessCompletionRows? Rows = null, string? ContentSha256 = null,
    string? SqlStateSha256 = null, Guid? PhysicalTransaction = null, string? RemainderSha256 = null);
internal sealed record HoldWitnessCompletionSlot(HoldWitnessCompletionContext Context, long OpenedSequence,
    ImmutableDictionary<CompletionEffect, CompletionEffectDescriptor> Started, ImmutableDictionary<CompletionEffect, CompletionEffectReceipt> Receipts,
    HoldWitnessCompletionRows? Rows = null, string? RemainderSha256 = null, HoldWitnessOutcome? Expected = null, Guid? PreparingTransaction = null, HoldWitnessOutcome? Acknowledged = null);
internal sealed record HoldWitnessCompletionState(HoldWitnessCompletionClaim Claim, long PlannedSequence, HoldWitnessOutcome? ClaimExpected = null,
    HoldWitnessOutcome? ClaimAcknowledged = null, ImmutableDictionary<CompletionSlot, HoldWitnessCompletionSlot>? Slots = null);

// Only the purpose-bound CompletionInput codec's partial can construct these
// verified projections. They contain owned factual plans, never worker authority.
internal sealed partial class VerifiedCompletionSlotContext
{
    private readonly HoldWitnessCompletionContext context;
    private VerifiedCompletionSlotContext(HoldWitnessCompletionContext context) { ProductionCompletionProtocol.Context(context); this.context = context with { Targets = context.Targets.ToImmutableArray() }; }
    internal Guid RecordId { get; private init; }
    internal HoldWitnessCompletionContext Context => context;
}
internal sealed partial class VerifiedCompletionSlotPlan
{
    private readonly CompletionSqlRow[] rows;
    private VerifiedCompletionSlotPlan(HoldWitnessCompletionRows header, IReadOnlyList<CompletionSqlRow> rows)
    {
        if (rows.Count > 1024 || !ProductionCompletionProtocol.Hash(header.ContextSha256) || !ProductionCompletionProtocol.Hash(header.DeltaSha256)) throw ProductionCompletionProtocol.Invalid();
        this.rows = rows.Select(x => x with { }).ToArray();
        if (ProductionCompletionProtocol.Digest(this.rows) != header.DeltaSha256) throw ProductionCompletionProtocol.Invalid(); Header = header;
    }
    internal HoldWitnessCompletionRows Header { get; }
    internal IReadOnlyList<CompletionSqlRow> Rows => rows.Select(x => x with { }).ToArray();
}
internal sealed partial class VerifiedCompletionEffectReceipt
{
    private VerifiedCompletionEffectReceipt(CompletionEffectReceipt receipt) : this(receipt, false) { }
    private readonly CompletionEffectReceipt receipt;
    private VerifiedCompletionEffectReceipt(CompletionEffectReceipt receipt, bool readOnlyComplete) { ProductionCompletionProtocol.Receipt(receipt); this.receipt = Copy(receipt); ReadOnlyComplete = readOnlyComplete; }
    private static CompletionEffectReceipt Copy(CompletionEffectReceipt receipt) => receipt with { Final = receipt.Final is { } f ? f with { Sha256 = f.Sha256.ToArray() } : null };
    internal bool ReadOnlyComplete { get; }
    internal CompletionEffectReceipt Receipt => Copy(receipt);
}

internal static class ProductionCompletionProtocol
{
    internal const string Version = "production-record-completion-slots-v1";
    internal static string Digest<T>(T value) => ProductionHoldWitnessJournal.Digest(JsonSerializer.SerializeToUtf8Bytes(value));
    internal static bool Hash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    internal static InvalidDataException Invalid() => new("The exact production completion checkpoint could not be verified.");
    internal static bool Sealing(string kind) => kind == "work/" + ((int)WorkKind.Sealing).ToString(CultureInfo.InvariantCulture);
    internal static CompletionEffect[] Effects(CompletionSlot slot) => slot switch {
        CompletionSlot.Candidate => [CompletionEffect.CandidateInput, CompletionEffect.CandidatePdf],
        CompletionSlot.ExecutedSeal => [CompletionEffect.ExecutedContext, CompletionEffect.ExecutedRequest, CompletionEffect.ExecutedTsa, CompletionEffect.ExecutedResponse, CompletionEffect.ExecutedPdf, CompletionEffect.ExecutedResult],
        CompletionSlot.CertificateSeal => [CompletionEffect.CertificateContext, CompletionEffect.CertificateSource, CompletionEffect.CertificateRequest, CompletionEffect.CertificateTsa, CompletionEffect.CertificateResponse, CompletionEffect.CertificatePdf, CompletionEffect.CertificateResult],
        CompletionSlot.PublicationIntent => [CompletionEffect.PublicationIntentInput],
        CompletionSlot.PublicationResult => [CompletionEffect.PublicationExecutedFinal, CompletionEffect.PublicationCertificateFinal, CompletionEffect.PublicationResultInput],
        CompletionSlot.HandlerReceipt or CompletionSlot.WorkFinish => [], _ => throw Invalid() };
    internal static bool Tsa(CompletionEffect effect) => effect is CompletionEffect.ExecutedTsa or CompletionEffect.CertificateTsa;
    internal static void Context(HoldWitnessCompletionContext value)
    {
        var effects = Effects(value.Slot);
        if (!Enum.IsDefined(value.Slot) || value.OperationId == Guid.Empty || value.PredecessorSequence < 1 ||
            !Hash(value.PredecessorSqlStateSha256) || !Hash(value.PredecessorContentSha256) || value.WorkId == Guid.Empty || value.Attempt < 1 ||
            value.Until.Offset != TimeSpan.Zero || value.RecordedAt.Offset != TimeSpan.Zero || value.RecordedAt >= value.Until || !Hash(value.PayloadSha256) || value.Targets.IsDefault || value.Targets.Length != effects.Length ||
            !value.Targets.Select(x => x.Effect).SequenceEqual(effects) || value.Targets.Any(x => Tsa(x.Effect) ? x.TargetId != Guid.Empty : x.TargetId == Guid.Empty) ||
            value.SqlRows.IsDefault || value.SqlRows.Length > 1024 || value.SqlRows.Any(x => x.Table is not { Length: > 0 and <= 64 } || x.Key is not { Length: > 0 and <= 32 } || x.BeforeSha256 is not null && !Hash(x.BeforeSha256)) ||
            value.SqlRows.Distinct().Count() != value.SqlRows.Length || !Hash(value.RemainderSha256) ||
            value.Targets.Where(x => x.TargetId != Guid.Empty).Select(x => x.TargetId).Distinct().Count() != value.Targets.Count(x => x.TargetId != Guid.Empty)) throw Invalid();
    }
    internal static void Effect(CompletionEffectDescriptor value, HoldWitnessCompletionContext context)
    {
        if (!Enum.IsDefined(value.Effect) || !context.Targets.Contains(new(value.Effect, value.TargetId)) || value.Length is < 1 or > 64 * 1024 * 1024 ||
            !Hash(value.Sha256) || value.MaximumRequests is < 1 or > 64 || value.Requests.IsDefault || value.Requests.Length != value.MaximumRequests || value.Requests.Distinct().Count() != value.Requests.Length || value.Requests.Any(x => !Hash(x)) || Tsa(value.Effect) && (value.TargetId != Guid.Empty || value.MaximumRequests != 1 || value.Length > 65536)) throw Invalid();
    }
    internal static bool ProviderCreationMatches(DateTimeOffset originalRecordedAt, DateTimeOffset providerCreatedAt, DateTimeOffset now)
        => originalRecordedAt.Offset == TimeSpan.Zero && providerCreatedAt.Offset == TimeSpan.Zero && now.Offset == TimeSpan.Zero &&
            providerCreatedAt >= ProductionRetentionLedger.Seconds(originalRecordedAt) && providerCreatedAt <= now;
    internal static bool FinalEffect(CompletionEffect effect) => effect is CompletionEffect.PublicationExecutedFinal or CompletionEffect.PublicationCertificateFinal;
    internal static void Receipt(CompletionEffectReceipt value)
    {
        if (!Hash(value.ReceiptSha256) || value.Effect is null) throw Invalid();
        if (Tsa(value.Effect.Effect)) { if (value.Stored is not null || value.Final is not null) throw Invalid(); }
        else if (FinalEffect(value.Effect.Effect))
        {
            if (value.Stored is not null || value.Final is not { } f || f.Document.ObjectId != value.Effect.TargetId ||
                f.Document.Kind != (value.Effect.Effect == CompletionEffect.PublicationExecutedFinal ? FinalDocumentKind.Executed : FinalDocumentKind.Certificate) ||
                f.Sha256 is not { Length: 32 } || Convert.ToHexStringLower(f.Sha256) != value.Effect.Sha256 || f.Length != value.Effect.Length ||
                f.VersionId is not { Length: > 0 and <= 512 } || f.ETag is not { Length: > 0 and <= 256 } || f.CreatedAt.Offset != TimeSpan.Zero ||
                f.Protection == FinalProtection.DevelopmentWriteOnce || !Enum.IsDefined(f.Protection) ||
                (f.Protection == FinalProtection.LockedTime ? f.ProtectedUntil is not { Offset: var offset } || offset != TimeSpan.Zero : f.ProtectedUntil is not null)) throw Invalid();
        }
        else if (value.Final is not null || value.Stored is not { } r || r.Item.Blob.ObjectId != value.Effect.TargetId || r.Item.Length != value.Effect.Length || r.Item.Sha256 != value.Effect.Sha256 ||
            r.VersionId is not { Length: > 0 and <= 512 } || r.ETag is not { Length: > 0 and <= 256 }) throw Invalid();
    }
    internal static void Bound(HoldWitnessCompletionTransition value)
    {
        if (!Enum.IsDefined(value.Kind) || value.Claim is { } c && (c.WorkBeforeJson is not { Length: <= 262144 } || c.WorkAfterJson is not { Length: <= 262144 })) throw Invalid();
        if (value.Context is { } context) Context(context);
        foreach (var effect in new[] { value.Effect, value.Receipt?.Effect })
            if (effect is { } e && (e.Requests.IsDefault || e.Requests.Length > 64 || e.Requests.Any(x => !Hash(x)) || !Hash(e.Sha256))) throw Invalid();
        if (value.Receipt is { } receipt) Receipt(receipt);
        if (value.Rows is { } rows && (!Hash(rows.ContextSha256) || !Hash(rows.DeltaSha256) || rows.Input is { } input && !Hash(input.Sha256))) throw Invalid();
    }
    internal static HoldWitnessCompletionState Fold(HoldWitnessCompletionState? saved, HoldWitnessCompletionTransition value, HoldWitnessOperation operation, long sequence, DateTimeOffset at, DateTimeOffset? predecessorAt = null)
    {
        if (!Sealing(operation.Kind) || !Enum.IsDefined(value.Kind)) throw Invalid();
        var canonical = new HoldWitnessCompletionTransition(value.Kind);
        if (value.Kind == CompletionTransitionKind.ClaimPlanned)
        {
            var c = value.Claim ?? throw Invalid();
            if (saved is not null || c.WorkId == Guid.Empty || c.Attempt < 1 || c.Until.Offset != TimeSpan.Zero || c.Until <= at || !Hash(c.PayloadSha256) ||
                c.PhysicalTransaction == Guid.Empty || !Hash(c.RemainderSha256) || c.WorkBeforeJson.Length > 262144 || c.WorkAfterJson.Length > 262144 ||
                operation.Reference != c.WorkId.ToString("N") + "/attempt/" + c.Attempt.ToString(CultureInfo.InvariantCulture)) throw Invalid();
            canonical = canonical with { Claim = c }; saved = new(c, sequence, Slots: ImmutableDictionary<CompletionSlot, HoldWitnessCompletionSlot>.Empty);
        }
        else
        {
            if (saved is null || saved.Claim.Until <= at) throw Invalid();
            if (value.Kind is CompletionTransitionKind.ClaimExpected or CompletionTransitionKind.ClaimAcknowledged)
            {
                if (!Hash(value.ContentSha256) || !Hash(value.SqlStateSha256) || value.PhysicalTransaction is not { } physical || physical == Guid.Empty) throw Invalid();
                canonical = canonical with { ContentSha256 = value.ContentSha256, SqlStateSha256 = value.SqlStateSha256, PhysicalTransaction = physical };
                if (value.Kind == CompletionTransitionKind.ClaimExpected)
                {
                    if (saved.ClaimExpected is not null || physical != saved.Claim.PhysicalTransaction) throw Invalid();
                    saved = saved with { ClaimExpected = new(value.ContentSha256!, value.SqlStateSha256!, sequence) };
                }
                else
                {
                    if (saved.ClaimExpected is not { } expected || saved.ClaimAcknowledged is not null || physical == saved.Claim.PhysicalTransaction ||
                        value.ContentSha256 != expected.ContentSha256 || value.SqlStateSha256 != expected.SqlStateSha256) throw Invalid();
                    saved = saved with { ClaimAcknowledged = new(value.ContentSha256!, value.SqlStateSha256!, sequence) };
                }
            }
            else
            {
                if (saved.ClaimAcknowledged is null || value.Slot is not { } slot || !Enum.IsDefined(slot)) throw Invalid();
                canonical = canonical with { Slot = slot }; var slots = saved.Slots!;
                if (value.Kind == CompletionTransitionKind.SlotOpened)
                {
                    var c = value.Context ?? throw Invalid(); Context(c);
                    var predecessor = slot == CompletionSlot.Candidate ? saved.ClaimAcknowledged : slots.GetValueOrDefault(slot - 1)?.Acknowledged;
                    if (slots.ContainsKey(slot) || predecessor is null || c.RecordedAt > at || predecessorAt is { } earlier && c.RecordedAt < earlier || c.Slot != slot || c.OperationId != operation.OperationId ||
                        c.PredecessorSequence != predecessor.Sequence || c.PredecessorSqlStateSha256 != predecessor.SqlStateSha256 || c.PredecessorContentSha256 != predecessor.ContentSha256 ||
                        c.WorkId != saved.Claim.WorkId || c.Attempt != saved.Claim.Attempt || c.Until != saved.Claim.Until || c.PayloadSha256 != saved.Claim.PayloadSha256 ||
                        c.Targets.Where(x => x.TargetId != Guid.Empty).Any(x => slots.Values.SelectMany(y => y.Context.Targets).Any(y => y.TargetId == x.TargetId))) throw Invalid();
                    slots = slots.Add(slot, new(c, sequence, ImmutableDictionary<CompletionEffect, CompletionEffectDescriptor>.Empty, ImmutableDictionary<CompletionEffect, CompletionEffectReceipt>.Empty));
                    canonical = canonical with { Context = c };
                }
                else
                {
                    var s = slots.GetValueOrDefault(slot) ?? throw Invalid(); if (s.Acknowledged is not null) throw Invalid();
                    if (value.Kind == CompletionTransitionKind.EffectStarted)
                    {
                        var effect = value.Effect ?? throw Invalid(); Effect(effect, s.Context);
                        if (s.Expected is not null || s.Started.ContainsKey(effect.Effect) || s.Context.Targets.TakeWhile(x => x.Effect != effect.Effect).Any(x => !s.Receipts.ContainsKey(x.Effect))) throw Invalid();
                        s = s with { Started = s.Started.Add(effect.Effect, effect) }; canonical = canonical with { Effect = effect };
                    }
                    else if (value.Kind == CompletionTransitionKind.EffectRecorded)
                    {
                        var receipt = value.Receipt ?? throw Invalid(); Receipt(receipt);
                        if (s.Expected is not null || s.Started.GetValueOrDefault(receipt.Effect.Effect) is not { } started || Digest(started) != Digest(receipt.Effect) || s.Receipts.ContainsKey(receipt.Effect.Effect)) throw Invalid();
                        s = s with { Receipts = s.Receipts.Add(receipt.Effect.Effect, receipt) }; canonical = canonical with { Receipt = receipt };
                    }
                    else if (value.Kind == CompletionTransitionKind.RowsPlanned)
                    {
                        if (s.Rows is not null || s.Expected is not null || s.Context.Targets.Any(x => !s.Receipts.ContainsKey(x.Effect)) || value.Rows is not { } rows ||
                            rows.ContextSha256 != Digest(s.Context) || !Hash(rows.DeltaSha256) || !Hash(value.RemainderSha256)) throw Invalid();
                        s = s with { Rows = rows, RemainderSha256 = value.RemainderSha256 };
                        canonical = canonical with { Rows = rows, RemainderSha256 = value.RemainderSha256 };
                    }
                    else if (value.Kind == CompletionTransitionKind.SlotExpected)
                    {
                        if (s.Expected is not null || s.Context.Targets.Any(x => !s.Receipts.ContainsKey(x.Effect)) || value.Rows is not { } rows || s.Rows is null || Digest(s.Rows) != Digest(rows) || !Hash(rows.ContextSha256) ||
                            rows.ContextSha256 != Digest(s.Context) || !Hash(rows.DeltaSha256) || !Hash(value.ContentSha256) || !Hash(value.SqlStateSha256) || value.PhysicalTransaction is not { } physical || physical == Guid.Empty) throw Invalid();
                        s = s with { Rows = rows, Expected = new(value.ContentSha256!, value.SqlStateSha256!, sequence), PreparingTransaction = physical };
                        canonical = canonical with { Rows = rows, ContentSha256 = value.ContentSha256, SqlStateSha256 = value.SqlStateSha256, PhysicalTransaction = physical };
                    }
                    else if (value.Kind == CompletionTransitionKind.SlotAcknowledged)
                    {
                        if (s.Expected is not { } expected || value.ContentSha256 != expected.ContentSha256 || value.SqlStateSha256 != expected.SqlStateSha256 ||
                            value.PhysicalTransaction is not { } physical || physical == Guid.Empty || physical == s.PreparingTransaction && slot != CompletionSlot.HandlerReceipt) throw Invalid();
                        s = s with { Acknowledged = new(value.ContentSha256!, value.SqlStateSha256!, sequence) };
                        canonical = canonical with { ContentSha256 = value.ContentSha256, SqlStateSha256 = value.SqlStateSha256, PhysicalTransaction = physical };
                    }
                    else throw Invalid();
                    slots = slots.SetItem(slot, s);
                }
                saved = saved with { Slots = slots };
            }
        }
        if (Digest(canonical) != Digest(value)) throw Invalid(); return saved;
    }
}

internal sealed class ProductionCompletionClaimPermit { internal ProductionCompletionClaimPermit() { } }
internal sealed class ProductionCompletionSqlPermit { internal ProductionCompletionSqlPermit() { } }
internal sealed class ProductionCompletionEffectPermit { internal ProductionCompletionEffectPermit() { } }

internal sealed partial class ProductionRecordOperationAdmission
{
    private sealed record CompletionTransaction(Guid Id, WeakReference<DbTransaction> Transaction);
    private static readonly ConditionalWeakTable<DbTransaction, CompletionTransaction> completionTransactions = new();
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, WeakReference<DbTransaction>> completionTransactionIds = new();
    private sealed record ClaimBinding(ProductionCompletionClaimPermit Permit, ProductionRecordOperation Scope, Guid Transaction, HoldWitnessCompletionClaim Claim);
    private sealed record SqlBinding(ProductionCompletionSqlPermit Permit, ProductionRecordOperation Scope, Guid Transaction, VerifiedCompletionSlotPlan Plan, CompletionSlot Slot);
    private sealed class EffectBinding(ProductionCompletionEffectPermit permit, ProductionRecordOperation scope, Guid transaction, CompletionSlot slot, CompletionEffectDescriptor effect)
    {
        internal readonly ProductionCompletionEffectPermit Permit = permit; internal readonly ProductionRecordOperation Scope = scope;
        internal readonly Guid Transaction = transaction; internal readonly CompletionSlot Slot = slot; internal readonly CompletionEffectDescriptor Effect = effect;
        internal int Consumed, Recorded, Requests, Inflight;
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<(Guid Record, Guid Operation), long> completionClockFloors = new();
    private readonly ConditionalWeakTable<QuillSignDbContext, ClaimBinding> completionClaims = new();
    private readonly ConditionalWeakTable<QuillSignDbContext, SqlBinding> completionSql = new();
    private readonly ConditionalWeakTable<QuillSignDbContext, EffectBinding> completionEffects = new();
    private sealed record CompletionMutationBinding(ProductionRecordOperation Scope, CompletionSlot Slot, Guid Transaction);
    private readonly ConditionalWeakTable<QuillSignDbContext, CompletionMutationBinding> completionMutations = new();

    private static Guid CompletionTransactionId(QuillSignDbContext db)
    {
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw Invalid();
        var physical = db.Database.CurrentTransaction.GetDbTransaction();
        return completionTransactions.GetValue(physical, x => { var id = Guid.NewGuid(); var weak = new WeakReference<DbTransaction>(x); completionTransactionIds[id] = weak; return new(id, weak); }).Id;
    }
    private static void DemandCompletionTransactionEnded(Guid id, QuillSignDbContext db)
    {
        if (id == CompletionTransactionId(db)) throw Invalid();
        if (completionTransactionIds.TryGetValue(id, out var weak) && weak.TryGetTarget(out var transaction) && transaction.Connection is not null) throw Invalid();
    }
    private static HoldWitnessCompletionState Completion(ProductionRecordOperation scope, HoldWitnessState state) =>
        state.Completions?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
    private void DemandCompletionActive(ProductionRecordOperation scope, HoldWitnessState state, bool final = false)
    {
        DemandActive(scope, state, allowOutcome: final, allowHandler: final, allowCompletion: true);
        if (!ProductionCompletionProtocol.Sealing(scope.Kind)) throw Invalid();
    }
    private DateTimeOffset ObserveCompletionClock(ProductionRecordOperation scope, HoldWitnessState state, DateTimeOffset durableAt)
    {
        var until = Completion(scope, state).Claim.Until;
        var key = (scope.RecordId, scope.OperationId);
        while (true)
        {
            var now = time.GetUtcNow();
            if (now.Offset != TimeSpan.Zero || now < durableAt || now >= until) throw Invalid();
            var old = completionClockFloors.GetOrAdd(key, durableAt.UtcTicks);
            if (now.UtcTicks < old) throw Invalid();
            if (completionClockFloors.TryUpdate(key, now.UtcTicks, old)) return now;
        }
    }
    private async Task<HoldWitnessState> DemandCompletionHeadLocked(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct, bool final = false)
    {
        _ = CompletionTransactionId(db); var clockRead = await witness.ReadCompletionClockAsync(scope.RecordId, ct); var state = clockRead.State;
        DemandCompletionActive(scope, state, final); ObserveCompletionClock(scope, state, clockRead.At);
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests); await DemandControls(db, scope.RecordId, state, ct);
        var c = Completion(scope, state); var work = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == c.Claim.WorkId, ct);
        if (work.EnvelopeId != scope.RecordId || work.Kind != WorkKind.Sealing ||
            work.PayloadJson is null || ProductionCompletionProtocol.Digest(work.PayloadJson) != c.Claim.PayloadSha256 || work.Attempts != c.Claim.Attempt ||
            (!final || work.Status != WorkStatus.Completed) && (work.Status != WorkStatus.Leased || work.LeaseOwner != scope.OperationId || work.LeaseExpiresAt != c.Claim.Until)) throw Invalid();
        ObserveCompletionClock(scope, state, clockRead.At); return state;
    }
    private static HoldWitnessOutcome CompletionAcknowledged(HoldWitnessCompletionState value) => value.Slots!.Values.OrderBy(x => x.Context.Slot)
        .LastOrDefault(x => x.Acknowledged is not null)?.Acknowledged ?? value.ClaimAcknowledged ?? throw Invalid();
    private async Task<ProductionHoldSqlSnapshot> DemandCompletionExactLocked(QuillSignDbContext db, ProductionRecordOperation scope, HoldWitnessState state, HoldWitnessOutcome expected, CancellationToken ct, bool final = false)
    {
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests); var sql = await Capture(db, scope.RecordId, requests, ct);
        if (sql.StateSha256 != expected.SqlStateSha256 || ContentDigest(sql, keys) != expected.ContentSha256) throw Invalid();
        var afterClock = await witness.ReadCompletionClockAsync(scope.RecordId, ct); var after = afterClock.State;
        DemandCompletionActive(scope, after, final); ObserveCompletionClock(scope, after, afterClock.At);
        if (ProductionCompletionProtocol.Digest(Completion(scope, state)) != ProductionCompletionProtocol.Digest(Completion(scope, after))) throw Invalid();
        return sql;
    }
    internal async Task<ProductionRecordOperation> ResumeCompletionLockedAsync(QuillSignDbContext db, Guid recordId, Guid operationId, string kind, string reference, CancellationToken ct = default)
    {
        var scope = Scope(recordId, operationId, kind, reference, await witness.ReadAsync(recordId, ct));
        await DemandCompletionHeadLocked(db, scope, ct, final: true); return scope; // Factual recovery identity only; every new effect separately demands exact acknowledged SQL.
    }
    internal async Task DemandCompletionProgressLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        var state = await DemandCompletionHeadLocked(db, scope, ct); var c = Completion(scope, state);
        if (c.ClaimAcknowledged is null || c.Slots!.Values.Any(x => x.Expected is not null && x.Acknowledged is null) ||
            c.Slots.Values.Any(x => x.Started.Count != x.Receipts.Count)) throw Invalid();
        await DemandCompletionExactLocked(db, scope, state, CompletionAcknowledged(c), ct);
    }
    internal async Task<HoldWitnessCompletionState> ReadCompletionRecoveryLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        var state = await DemandCompletionHeadLocked(db, scope, ct, final: true); var c = Completion(scope, state);
        var expected = c.Slots!.Values.OrderBy(x => x.Context.Slot).LastOrDefault(x => x.Expected is not null)?.Expected ?? c.ClaimExpected ?? throw Invalid();
        var requests = await Requests(db, scope.RecordId, ct); var sql = await Capture(db, scope.RecordId, requests, ct);
        if (sql.StateSha256 != expected.SqlStateSha256 || ContentDigest(sql, keys) != expected.ContentSha256) throw Invalid();
        var after = await witness.ReadCompletionClockAsync(scope.RecordId, ct); DemandCompletionActive(scope, after.State, final: true);
        ObserveCompletionClock(scope, after.State, after.At);
        if (ProductionCompletionProtocol.Digest(Completion(scope, after.State)) != ProductionCompletionProtocol.Digest(c)) throw Invalid();
        return c; // No permit/provider authorization, including on consumed/unknown effects.
    }

    internal async Task<ProductionCompletionClaimPermit> BeginCompletionClaimLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, WorkItem expectedClaim, CancellationToken ct = default)
    {
        var tx = CompletionTransactionId(db); expectedClaim = CloneCompletionWork(expectedClaim);
        await witness.DemandCompletionHeadroomAsync(scope.RecordId, ct);
        await DemandStartingLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct);
        if (!ProductionCompletionProtocol.Sealing(scope.Kind) || state.Completions?.ContainsKey(scope.OperationId) == true) throw Invalid();
        var requests = await Requests(db, scope.RecordId, ct); var original = await Capture(db, scope.RecordId, requests, ct);
        using var sql = ProductionHoldSqlInventory.OpenAcknowledgementVerified(original, keys);
        var before = FindCompletionRow(sql.RootElement, "WorkItems", expectedClaim.Id.ToString("N"));
        var work = JsonSerializer.Deserialize<WorkItem>(before.GetRawText(), CompletionJson) ?? throw Invalid();
        if (work.Kind != WorkKind.Sealing || work.Status != WorkStatus.Queued || work.EnvelopeId != scope.RecordId || work.LeaseOwner is not null || work.LeaseExpiresAt is not null ||
            expectedClaim.Status != WorkStatus.Leased || expectedClaim.LeaseOwner != scope.OperationId || expectedClaim.LeaseExpiresAt is not { } until || until <= time.GetUtcNow() ||
            expectedClaim.Attempts != work.Attempts + 1 || expectedClaim.LastError != work.LastError || expectedClaim.AvailableAt != work.AvailableAt || work.AvailableAt > time.GetUtcNow()) throw Invalid();
        var b = JsonNode.Parse(CompletionRow(before, false))!.AsObject(); var a = JsonNode.Parse(CompletionRow(JsonSerializer.SerializeToElement(expectedClaim, CompletionJson), false))!.AsObject();
        foreach (var column in new[] { "Status", "LeaseOwner", "LeaseExpiresAt", "Attempts" }) b[column] = a[column]?.DeepClone();
        if (b.ToJsonString() != a.ToJsonString()) throw Invalid();
        var row = new CompletionSqlRow("WorkItems", work.Id.ToString("N"), CompletionRow(before, false), CompletionRow(JsonSerializer.SerializeToElement(expectedClaim, CompletionJson), false));
        var claim = new HoldWitnessCompletionClaim(work.Id, expectedClaim.Attempts, until, ProductionCompletionProtocol.Digest(work.PayloadJson), row.BeforeJson!, row.AfterJson,
            CompletionProjection(sql.RootElement, [row], before: true), tx);
        var fresh = await witness.ChangeCompletionAsync(scope.RecordId, state.Operations![scope.OperationId], new(CompletionTransitionKind.ClaimPlanned, Claim: claim), Id(scope.RecordId, scope.OperationId, "completion-claim-plan"), ct);
        if (!fresh) throw Invalid();
        var permit = new ProductionCompletionClaimPermit(); completionClaims.Remove(db); completionClaims.Add(db, new(permit, scope, tx, claim)); return permit;
    }
    internal async Task PrepareCompletionClaimExpectedLockedAsync(QuillSignDbContext db, ProductionCompletionClaimPermit permit, CancellationToken ct = default)
    {
        if (!completionClaims.TryGetValue(db, out var binding) || !ReferenceEquals(binding.Permit, permit) || CompletionTransactionId(db) != binding.Transaction) throw Invalid();
        var scope = binding.Scope; var state = await witness.ReadAsync(scope.RecordId, ct); DemandCompletionActive(scope, state);
        var requests = await Requests(db, scope.RecordId, ct); DemandHead(scope, requests); var sql = await Capture(db, scope.RecordId, requests, ct);
        using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        var rows = new[] { new CompletionSqlRow("WorkItems", binding.Claim.WorkId.ToString("N"), binding.Claim.WorkBeforeJson, binding.Claim.WorkAfterJson) };
        if (CompletionProjection(plain.RootElement, rows, before: false) != binding.Claim.RemainderSha256) throw Invalid();
        await CompletionChange(scope, state, new(CompletionTransitionKind.ClaimExpected, ContentSha256: ContentDigest(sql, keys), SqlStateSha256: sql.StateSha256,
            PhysicalTransaction: binding.Transaction), "claim-expected", ct);
    }
    internal async Task AcknowledgeCompletionClaimLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        var state = await DemandCompletionHeadLocked(db, scope, ct); var c = Completion(scope, state);
        var expected = c.ClaimExpected ?? throw Invalid(); DemandCompletionTransactionEnded(c.Claim.PhysicalTransaction, db);
        await DemandCompletionExactLocked(db, scope, state, expected, ct);
        if (c.ClaimAcknowledged is not null) return;
        await CompletionChange(scope, state, new(CompletionTransitionKind.ClaimAcknowledged, ContentSha256: expected.ContentSha256,
            SqlStateSha256: expected.SqlStateSha256, PhysicalTransaction: CompletionTransactionId(db)), "claim-ack", ct);
    }
    internal async Task AcknowledgeCompletionClaimAsync(ProductionRecordOperation scope, CancellationToken ct = default)
    { await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct); await AcknowledgeCompletionClaimLockedAsync(db, scope, ct); await tx.RollbackAsync(ct); }

    internal Task<HoldWitnessCompletionContext> CreateCompletionContextLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CompletionSlot slot,
        IReadOnlyList<CompletionEffectTarget> targets, IReadOnlyList<CompletionSqlSelector> selectors, CancellationToken ct = default)
        => CreateCompletionContextLockedAsync(db, scope, slot, targets, selectors, time.GetUtcNow(), ct);
    internal async Task<HoldWitnessCompletionContext> CreateCompletionContextLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CompletionSlot slot,
        IReadOnlyList<CompletionEffectTarget> targets, IReadOnlyList<CompletionSqlSelector> selectors, DateTimeOffset recordedAt, CancellationToken ct = default)
    {
        // This is an unverified factual projection. Only the closed purpose-bound
        // input codec may turn it into a verified slot plan accepted by Open.
        if (recordedAt.Offset != TimeSpan.Zero || recordedAt > time.GetUtcNow() || targets.Count > 8 || selectors.Count > 1024 || slot is CompletionSlot.HandlerReceipt or CompletionSlot.WorkFinish) throw Invalid();
        var ownTargets = targets.Select(x => x with { }).ToImmutableArray(); var ownSelectors = selectors.Select(x => x with { }).ToArray();
        await DemandCompletionProgressLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct); var c = Completion(scope, state);
        var previous = CompletionAcknowledged(c);
        var sql = await Capture(db, scope.RecordId, await Requests(db, scope.RecordId, ct), ct); using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        var fixedSelectors = ownSelectors.Select(x => x.Table == "Envelopes" && slot == CompletionSlot.PublicationResult && x.Key == scope.RecordId.ToString("N") ?
            x with { BeforeSha256 = ProductionCompletionProtocol.Digest(CompletionRow(FindCompletionRow(plain.RootElement, x.Table, x.Key), false)) } : x).ToImmutableArray();
        if (!CompletionSelectorFacts(plain.RootElement, fixedSelectors)) throw Invalid();
        var context = new HoldWitnessCompletionContext(slot, scope.OperationId, previous.Sequence, previous.SqlStateSha256, previous.ContentSha256,
            c.Claim.WorkId, c.Claim.Attempt, c.Claim.Until, c.Claim.PayloadSha256, ownTargets, fixedSelectors, CompletionRemainder(plain.RootElement, fixedSelectors), recordedAt);
        ProductionCompletionProtocol.Context(context); if (JsonSerializer.SerializeToUtf8Bytes(context).Length > 49152) throw Invalid(); return context;
    }
    internal async Task PrepareCompletionSlotLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, VerifiedCompletionSlotContext verified, CancellationToken ct = default)
    {
        var context = verified.Context; await DemandCompletionProgressLockedAsync(db, scope, ct);
        var state = await witness.ReadAsync(scope.RecordId, ct); var c = Completion(scope, state);
        if (verified.RecordId != scope.RecordId || context.OperationId != scope.OperationId || context.Slot is CompletionSlot.HandlerReceipt or CompletionSlot.WorkFinish) throw Invalid();
        var original = await Capture(db, scope.RecordId, await Requests(db, scope.RecordId, ct), ct);
        using (var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(original, keys))
            if (!CompletionSelectorFacts(plain.RootElement, context.SqlRows) || CompletionRemainder(plain.RootElement, context.SqlRows) != context.RemainderSha256) throw Invalid();
        if (c.Slots!.ContainsKey(context.Slot)) { if (ProductionCompletionProtocol.Digest(c.Slots[context.Slot].Context) != ProductionCompletionProtocol.Digest(context)) throw Invalid(); return; }
        await CompletionChange(scope, state, new(CompletionTransitionKind.SlotOpened, context.Slot, Context: context), "open-" + context.Slot, ct);
        completionMutations.Remove(db); completionMutations.Add(db, new(scope, context.Slot, CompletionTransactionId(db)));
    }
    // Wakeup hints only. This grants no storage/TSA, SQL mutation or retry
    // authority and cannot escape the original physical slot transaction.
    internal async Task DemandCompletionMutationLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CompletionSlot slot, CancellationToken ct = default)
    {
        if (!completionMutations.TryGetValue(db, out var binding) || binding.Scope != scope || binding.Slot != slot || binding.Transaction != CompletionTransactionId(db)) throw Invalid();
        var state = await DemandCompletionHeadLocked(db, scope, ct); var s = Completion(scope, state).Slots?.GetValueOrDefault(slot) ?? throw Invalid();
        if (s.Expected is not null || s.Context.Targets.Any(x => !s.Receipts.ContainsKey(x.Effect))) throw Invalid();
        var sql = await Capture(db, scope.RecordId, await Requests(db, scope.RecordId, ct), ct);
        using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        if (CompletionRemainder(plain.RootElement, s.Context.SqlRows) != s.Context.RemainderSha256) throw Invalid();
        var after = await witness.ReadCompletionClockAsync(scope.RecordId, ct); DemandCompletionActive(scope, after.State);
        ObserveCompletionClock(scope, after.State, after.At);
    }
    internal async Task<ProductionCompletionEffectPermit> BeginCompletionEffectLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CompletionSlot slot, CompletionEffectDescriptor effect, CancellationToken ct = default)
    {
        await DemandCompletionProgressLockedAsync(db, scope, ct); await witness.DemandCompletionHeadroomAsync(scope.RecordId, ct);
        var state = await witness.ReadAsync(scope.RecordId, ct);
        var s = Completion(scope, state).Slots!.GetValueOrDefault(slot) ?? throw Invalid(); ProductionCompletionProtocol.Effect(effect, s.Context);
        var fresh = await CompletionChange(scope, state, new(CompletionTransitionKind.EffectStarted, slot, Effect: effect), "start-" + effect.Effect, ct);
        if (!fresh) throw Invalid();
        var permit = new ProductionCompletionEffectPermit(); completionEffects.Remove(db); completionEffects.Add(db, new(permit, scope, CompletionTransactionId(db), slot, effect)); return permit;
    }
    // Each irreversible request (stage/commit/lock/TSA), never a readonly
    // HEAD/version GET, consumes a bounded
    // manifest unit. A failed or unknown request is NEVER refunded.
    internal async Task ConsumeCompletionEffectRequestLockedAsync(QuillSignDbContext db, ProductionCompletionEffectPermit permit, string requestSha256, CancellationToken ct = default)
    {
        var b = CompletionEffectBinding(db, permit);
        if (Interlocked.CompareExchange(ref b.Inflight, 1, 0) != 0) throw Invalid();
        var index = Interlocked.Increment(ref b.Requests) - 1;
        if (Volatile.Read(ref b.Recorded) != 0 || index >= b.Effect.MaximumRequests || b.Effect.Requests[index] != requestSha256) throw Invalid();
        Interlocked.Exchange(ref b.Consumed, 1); await DemandCompletionEffectLockedAsync(db, permit, ct);
    }
    internal async Task AcknowledgeCompletionEffectRequestLockedAsync(QuillSignDbContext db, ProductionCompletionEffectPermit permit, string requestSha256, CancellationToken ct = default)
    {
        var b = CompletionEffectBinding(db, permit); var index = Volatile.Read(ref b.Requests) - 1;
        if (Volatile.Read(ref b.Inflight) != 1 || index < 0 || index >= b.Effect.Requests.Length || b.Effect.Requests[index] != requestSha256) throw Invalid();
        await DemandCompletionEffectLockedAsync(db, permit, ct);
        if (Interlocked.CompareExchange(ref b.Inflight, 0, 1) != 1) throw Invalid();
    }
    private EffectBinding CompletionEffectBinding(QuillSignDbContext db, ProductionCompletionEffectPermit permit)
    {
        if (!completionEffects.TryGetValue(db, out var b) || !ReferenceEquals(b.Permit, permit) || b.Transaction != CompletionTransactionId(db)) throw Invalid(); return b;
    }
    internal async Task DemandCompletionEffectLockedAsync(QuillSignDbContext db, ProductionCompletionEffectPermit permit, CancellationToken ct = default)
    {
        var b = CompletionEffectBinding(db, permit); if (Volatile.Read(ref b.Recorded) != 0) throw Invalid();
        var state = await DemandCompletionHeadLocked(db, b.Scope, ct); var c = Completion(b.Scope, state); var slot = c.Slots!.GetValueOrDefault(b.Slot) ?? throw Invalid();
        if (slot.Expected is not null || slot.Rows is not null || slot.Started.GetValueOrDefault(b.Effect.Effect) is not { } begun || ProductionCompletionProtocol.Digest(begun) != ProductionCompletionProtocol.Digest(b.Effect) || slot.Receipts.ContainsKey(b.Effect.Effect)) throw Invalid();
        await DemandCompletionExactLocked(db, b.Scope, state, CompletionAcknowledged(c), ct);
    }
    internal async Task RecordCompletionEffectLockedAsync(QuillSignDbContext db, ProductionCompletionEffectPermit permit, VerifiedCompletionEffectReceipt verified, CancellationToken ct = default)
    {
        var b = CompletionEffectBinding(db, permit); var receipt = verified.Receipt;
        if (Volatile.Read(ref b.Consumed) != 1 || Volatile.Read(ref b.Inflight) != 0 || b.Requests != b.Effect.MaximumRequests || ProductionCompletionProtocol.Digest(receipt.Effect) != ProductionCompletionProtocol.Digest(b.Effect) || Interlocked.CompareExchange(ref b.Recorded, 1, 0) != 0) throw Invalid();
        // Once-only local marker is consumed before await and never reset.
        var state = await DemandCompletionHeadLocked(db, b.Scope, ct); var c = Completion(b.Scope, state);
        await DemandCompletionExactLocked(db, b.Scope, state, CompletionAcknowledged(c), ct);
        await DemandCompletionReceiptOwnerLocked(db, b.Scope, b.Slot, receipt, c, ct);
        await CompletionChange(b.Scope, state, new(CompletionTransitionKind.EffectRecorded, b.Slot, Receipt: receipt), "receipt-" + receipt.Effect.Effect, ct);
    }
    private async Task DemandCompletionReceiptOwnerLocked(QuillSignDbContext db, ProductionRecordOperation scope, CompletionSlot slot, CompletionEffectReceipt receipt, HoldWitnessCompletionState state, CancellationToken ct)
    {
        if (receipt.Stored is { } stored && stored.Item.Blob.EnvelopeId != scope.RecordId || receipt.Final is { } owned && owned.Document.EnvelopeId != scope.RecordId) throw Invalid();
        if (receipt.Final is not { } final) return;
        if (slot != CompletionSlot.PublicationResult) throw Invalid();
        var intent = await db.CompletionPublicationIntents.AsNoTracking().SingleAsync(x => x.EnvelopeId == scope.RecordId, ct);
        var outputId = final.Document.Kind == FinalDocumentKind.Executed ? intent.ExecutedOutputId : intent.CertificateOutputId;
        var target = final.Document.Kind == FinalDocumentKind.Executed ? intent.ExecutedObjectId : intent.CertificateObjectId;
        var output = await db.CompletionSealOutputs.AsNoTracking().SingleAsync(x => x.Id == outputId && x.EnvelopeId == scope.RecordId, ct);
        var originalAt = state.Slots![slot].Context.RecordedAt; var until = CompletionRetentionBinding.RequiredUntil(intent, originalAt);
        if (target != final.Document.ObjectId || final.Length != output.PdfLength || !final.Sha256.AsSpan().SequenceEqual(output.PdfSha256) ||
            !ProductionCompletionProtocol.ProviderCreationMatches(originalAt, final.CreatedAt, time.GetUtcNow()) ||
            (until is null ? final.Protection != FinalProtection.LegalHold || final.ProtectedUntil is not null : final.Protection != FinalProtection.LockedTime || final.ProtectedUntil != until)) throw Invalid();
    }
    internal async Task ReconcileCompletionEffectLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CompletionSlot slot,
        VerifiedCompletionEffectReceipt verified, CancellationToken ct = default)
    {
        if (!verified.ReadOnlyComplete) throw Invalid(); var receipt = verified.Receipt;
        var state = await DemandCompletionHeadLocked(db, scope, ct); var c = Completion(scope, state); var saved = c.Slots?.GetValueOrDefault(slot) ?? throw Invalid();
        if (saved.Started.GetValueOrDefault(receipt.Effect.Effect) is not { } started || ProductionCompletionProtocol.Digest(started) != ProductionCompletionProtocol.Digest(receipt.Effect)) throw Invalid();
        await DemandCompletionReceiptOwnerLocked(db, scope, slot, receipt, c, ct);
        if (saved.Receipts.TryGetValue(receipt.Effect.Effect, out var old))
        {
            if (ProductionCompletionProtocol.Digest(old) != ProductionCompletionProtocol.Digest(receipt)) throw Invalid();
            await ReadCompletionRecoveryLockedAsync(db, scope, ct); return;
        }
        if (saved.Rows is not null || saved.Expected is not null || state.Outcomes?.ContainsKey(scope.OperationId) == true || state.HandlerOutcomes?.ContainsKey(scope.OperationId) == true) throw Invalid();
        await DemandCompletionExactLocked(db, scope, state, CompletionAcknowledged(c), ct);
        await CompletionChange(scope, state, new(CompletionTransitionKind.EffectRecorded, slot, Receipt: receipt), "receipt-" + receipt.Effect.Effect, ct);
        // This deliberately does NOT recreate any effect/SQL/process binding.
        // Unknown SQL phases and spent mutation permits remain quarantined.
    }
    internal async Task<ProductionCompletionSqlPermit> PrepareCompletionSqlLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, VerifiedCompletionSlotPlan plan, CancellationToken ct = default)
    {
        var state = await DemandCompletionHeadLocked(db, scope, ct); var c = Completion(scope, state);
        var s = c.Slots!.Values.SingleOrDefault(x => ProductionCompletionProtocol.Digest(x.Context) == plan.Header.ContextSha256) ?? throw Invalid();
        if (s.Rows is not null || s.Expected is not null || s.Context.Targets.Any(x => !s.Receipts.ContainsKey(x.Effect)) ||
            !completionMutations.TryGetValue(db, out var mutation) || mutation.Scope != scope || mutation.Slot != s.Context.Slot || mutation.Transaction != CompletionTransactionId(db)) throw Invalid();
        DemandCompletionRows(s.Context.Slot, plan.Rows, scope.RecordId, c.Claim.WorkId);
        if (plan.Header.Input is not { } input || !s.Receipts.Values.Any(x => x.Stored?.Item == input)) throw Invalid();
        var sql = await Capture(db, scope.RecordId, await Requests(db, scope.RecordId, ct), ct); using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        if (!plan.Rows.Select(x => new CompletionSqlSelector(x.Table, x.Key, x.BeforeJson is null ? null : ProductionCompletionProtocol.Digest(x.BeforeJson))).SequenceEqual(s.Context.SqlRows) ||
            CompletionProjection(plain.RootElement, plan.Rows, before: false) != s.Context.RemainderSha256) throw Invalid();
        var remainder = s.Context.RemainderSha256;
        await CompletionChange(scope, state, new(CompletionTransitionKind.RowsPlanned, s.Context.Slot, Rows: plan.Header, RemainderSha256: remainder), "rows-" + s.Context.Slot, ct);
        var permit = new ProductionCompletionSqlPermit(); completionSql.Remove(db); completionSql.Add(db, new(permit, scope, CompletionTransactionId(db), plan, s.Context.Slot)); return permit;
    }
    internal async Task PrepareCompletionExpectedLockedAsync(QuillSignDbContext db, ProductionCompletionSqlPermit permit, CancellationToken ct = default)
    {
        if (!completionSql.TryGetValue(db, out var b) || !ReferenceEquals(b.Permit, permit) || b.Transaction != CompletionTransactionId(db)) throw Invalid();
        var state = await DemandCompletionHeadLocked(db, b.Scope, ct); var s = Completion(b.Scope, state).Slots![b.Slot];
        var sql = await Capture(db, b.Scope.RecordId, await Requests(db, b.Scope.RecordId, ct), ct); using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        if (s.Rows is null || ProductionCompletionProtocol.Digest(s.Rows) != ProductionCompletionProtocol.Digest(b.Plan.Header) ||
            CompletionProjection(plain.RootElement, b.Plan.Rows, before: false) != s.RemainderSha256) throw Invalid();
        await CompletionChange(b.Scope, state, new(CompletionTransitionKind.SlotExpected, b.Slot, Rows: b.Plan.Header, ContentSha256: ContentDigest(sql, keys),
            SqlStateSha256: sql.StateSha256, PhysicalTransaction: b.Transaction), "expected-" + b.Slot, ct);
    }
    internal async Task AcknowledgeCompletionSlotLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CompletionSlot slot, CancellationToken ct = default)
    {
        var state = await DemandCompletionHeadLocked(db, scope, ct, final: slot == CompletionSlot.WorkFinish); var s = Completion(scope, state).Slots!.GetValueOrDefault(slot) ?? throw Invalid();
        var expected = s.Expected ?? throw Invalid(); DemandCompletionTransactionEnded(s.PreparingTransaction ?? throw Invalid(), db);
        await DemandCompletionExactLocked(db, scope, state, expected, ct, final: slot == CompletionSlot.WorkFinish);
        if (s.Acknowledged is not null) return;
        await CompletionChange(scope, state, new(CompletionTransitionKind.SlotAcknowledged, slot, ContentSha256: expected.ContentSha256,
            SqlStateSha256: expected.SqlStateSha256, PhysicalTransaction: CompletionTransactionId(db)), "ack-" + slot, ct);
    }
    internal async Task AcknowledgeCompletionSlotAsync(ProductionRecordOperation scope, CompletionSlot slot, CancellationToken ct = default)
    { await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct); await AcknowledgeCompletionSlotLockedAsync(db, scope, slot, ct); await tx.RollbackAsync(ct); }
    private Task<bool> CompletionChange(ProductionRecordOperation scope, HoldWitnessState state, HoldWitnessCompletionTransition value, string phase, CancellationToken ct) =>
        witness.ChangeCompletionAsync(scope.RecordId, state.Operations![scope.OperationId], value, Id(scope.RecordId, scope.OperationId, "completion-" + phase), ct);

    private static readonly JsonSerializerOptions CompletionJson = new() { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };
    private static WorkItem CloneCompletionWork(WorkItem item) => JsonSerializer.Deserialize<WorkItem>(JsonSerializer.SerializeToUtf8Bytes(item, CompletionJson), CompletionJson) ?? throw Invalid();
    internal static string CompletionRow(JsonElement value, bool audit) => JsonSerializer.Serialize(new SortedDictionary<string, JsonElement>(value.EnumerateObject()
        .Where(x => x.Name != "RowVersion" && (!audit || x.Name != "Id")).ToDictionary(x => x.Name, x => x.Value), StringComparer.Ordinal));
    private static string CompletionKey(string table, JsonElement row) => table == "AuditEvents" ? row.GetProperty("Sequence").GetInt64().ToString(CultureInfo.InvariantCulture) :
        row.GetProperty(table is "ProductionRetentionTerminals" or "DocumentRetentionSnapshots" ? "EnvelopeId" : "Id").GetGuid().ToString("N");
    private static JsonElement FindCompletionRow(JsonElement sql, string table, string key) => sql.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == table)
        .GetProperty("Rows").EnumerateArray().Single(x => CompletionKey(table, x) == key);
    private static bool CompletionSelectorFacts(JsonElement sql, IReadOnlyList<CompletionSqlSelector> selectors)
    {
        foreach (var selector in selectors)
        {
            var table = sql.GetProperty("Tables").EnumerateArray().SingleOrDefault(x => x.GetProperty("Table").GetString() == selector.Table);
            if (table.ValueKind == JsonValueKind.Undefined) return false;
            var found = table.GetProperty("Rows").EnumerateArray().Where(x => CompletionKey(selector.Table, x) == selector.Key).ToArray();
            if (selector.BeforeSha256 is null ? found.Length != 0 : found.Length != 1 || ProductionCompletionProtocol.Digest(CompletionRow(found[0], selector.Table == "AuditEvents")) != selector.BeforeSha256) return false;
        }
        return true;
    }
    internal static string CompletionRemainder(JsonElement sql, IReadOnlyList<CompletionSqlSelector> selectors)
    {
        if (selectors.Count > 1024 || selectors.Distinct().Count() != selectors.Count) throw Invalid();
        var tables = sql.GetProperty("Tables").EnumerateArray().Select(table => {
            var name = table.GetProperty("Table").GetString()!;
            var selected = selectors.Where(x => x.Table == name).ToArray();
            return new { Table = name, Columns = table.GetProperty("Columns"), Rows = table.GetProperty("Rows").EnumerateArray()
                .Where(row => selected.Length == 0 || !selected.Any(x => x.Key == CompletionKey(name, row))).ToArray() };
        }).ToArray();
        if (selectors.Any(x => !tables.Any(y => y.Table == x.Table))) throw Invalid();
        return ProductionCompletionProtocol.Digest(new { RecordId = sql.GetProperty("RecordId"), PolicySha256 = sql.GetProperty("PolicySha256"), Tables = tables });
    }
    private static string CompletionProjection(JsonElement sql, IReadOnlyList<CompletionSqlRow> changes, bool before)
    {
        if (changes.Count > 1024 || changes.Select(x => (x.Table, x.Key)).Distinct().Count() != changes.Count) throw Invalid();
        var seen = new HashSet<(string, string)>();
        var tables = sql.GetProperty("Tables").EnumerateArray().Select(table => {
            var name = table.GetProperty("Table").GetString()!;
            var rows = table.GetProperty("Rows").EnumerateArray().Where(row => {
                var possible = changes.Where(x => x.Table == name).ToArray(); if (possible.Length == 0) return true;
                var key = CompletionKey(name, row); var change = possible.SingleOrDefault(x => x.Key == key); if (change is null) return true;
                if (!seen.Add((name, key)) || before && change.BeforeJson is null || CompletionRow(row, name == "AuditEvents") != (before ? change.BeforeJson : change.AfterJson)) throw Invalid();
                if (row.TryGetProperty("RowVersion", out var revision) && (revision.GetBytesFromBase64().Length != 8)) throw Invalid();
                return false;
            }).ToArray();
            return new { Table = name, Columns = table.GetProperty("Columns"), Rows = rows };
        }).ToArray();
        if (changes.Any(x => (before ? x.BeforeJson is not null : true) != seen.Contains((x.Table, x.Key)))) throw Invalid();
        return ProductionCompletionProtocol.Digest(new { RecordId = sql.GetProperty("RecordId"), PolicySha256 = sql.GetProperty("PolicySha256"), Tables = tables });
    }
    private static void DemandCompletionRows(CompletionSlot slot, IReadOnlyList<CompletionSqlRow> rows, Guid record, Guid work)
    {
        if (rows.Count > 1024 || rows.Any(x => x.Table is null || x.Key is null || x.AfterJson is null) || rows.Select(x => (x.Table, x.Key)).Distinct().Count() != rows.Count) throw Invalid();
        var allowed = slot switch {
            CompletionSlot.Candidate => new[] { "CompletionCandidates", "AuditEvents" },
            CompletionSlot.ExecutedSeal or CompletionSlot.CertificateSeal => ["CompletionSealOutputs", "AuditEvents"],
            CompletionSlot.PublicationIntent => ["CompletionPublicationIntents", "AuditEvents"],
            CompletionSlot.PublicationResult => ["Envelopes", "CompletionPublicationResults", "ProductionRetentionTerminals", "EmailOutbox", "WorkItems", "AuditEvents"],
            CompletionSlot.HandlerReceipt => [], CompletionSlot.WorkFinish => ["WorkItems"], _ => throw Invalid() };
        if (rows.Any(x => !allowed.Contains(x.Table, StringComparer.Ordinal)) || slot == CompletionSlot.HandlerReceipt && rows.Count != 0 || slot == CompletionSlot.WorkFinish && rows.Count != 1) throw Invalid();
        foreach (var row in rows)
        {
            using var after = JsonDocument.Parse(row.AfterJson); var a = after.RootElement;
            if (CompletionRow(a, row.Table == "AuditEvents") != row.AfterJson || a.GetProperty(row.Table is "Envelopes" or "ProductionRetentionTerminals" ? (row.Table == "Envelopes" ? "Id" : "EnvelopeId") : "EnvelopeId").GetGuid() != record) throw Invalid();
            if (row.BeforeJson is not null)
            {
                using var prior = JsonDocument.Parse(row.BeforeJson); var b = prior.RootElement;
                if (CompletionRow(b, false) != row.BeforeJson || row.Table is not ("Envelopes" or "WorkItems")) throw Invalid();
                var mutable = row.Table == "Envelopes" ? new[] { "Status", "CompletedAt", "FinalBlob", "FinalSha256", "CertificateBlob", "CertificateSha256", "SealProvider", "SealCertThumbprint", "PurgeAfter" } : ["Status", "LeaseOwner", "LeaseExpiresAt", "AvailableAt", "LastError"];
                if (row.Table == "WorkItems" && (slot != CompletionSlot.WorkFinish || row.Key != work.ToString("N") || a.GetProperty("Status").GetString() != "Completed" ||
                    a.GetProperty("LeaseOwner").ValueKind != JsonValueKind.Null || a.GetProperty("LeaseExpiresAt").ValueKind != JsonValueKind.Null)) throw Invalid();
                if (b.EnumerateObject().Where(x => !mutable.Contains(x.Name)).Any(x => !a.TryGetProperty(x.Name, out var v) || x.Value.GetRawText() != v.GetRawText()) || b.EnumerateObject().Count() != a.EnumerateObject().Count()) throw Invalid();
            }
            else if (row.Table == "Envelopes" || row.Table == "WorkItems" && slot == CompletionSlot.WorkFinish) throw Invalid();
        }
        if (slot is CompletionSlot.Candidate or CompletionSlot.ExecutedSeal or CompletionSlot.CertificateSeal or CompletionSlot.PublicationIntent &&
            (rows.Count != 2 || rows.Count(x => x.Table == "AuditEvents") != 1)) throw Invalid();
    }
}

internal sealed partial class ProductionRecordOperationAdmission
{
    internal async Task<bool> TryDemandCompletionHandlerOutcomeLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        var state = await witness.ReadAsync(scope.RecordId, ct);
        if (state.HandlerOutcomes?.ContainsKey(scope.OperationId) != true) return false;
        await DemandCompletionHeadLocked(db, scope, ct, final: true);
        await DemandHandlerOutcomeLockedAsync(db, scope, ct); return true;
    }
    internal async Task PrepareCompletionHandlerOutcomeLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        // This phase changes NO SQL. Exact readonly replay may finish its own
        // unknown journal acknowledgement, never repeat a provider/SQL effect.
        if (await TryDemandCompletionHandlerOutcomeLockedAsync(db, scope, ct)) return;
        var state = await DemandCompletionHeadLocked(db, scope, ct); var c = Completion(scope, state);
        var result = c.Slots?.GetValueOrDefault(CompletionSlot.PublicationResult)?.Acknowledged ?? throw Invalid();
        await DemandCompletionExactLocked(db, scope, state, result, ct);
        var sql = await Capture(db, scope.RecordId, await Requests(db, scope.RecordId, ct), ct); using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        var context = new HoldWitnessCompletionContext(CompletionSlot.HandlerReceipt, scope.OperationId, result.Sequence, result.SqlStateSha256, result.ContentSha256,
            c.Claim.WorkId, c.Claim.Attempt, c.Claim.Until, c.Claim.PayloadSha256, [], [], CompletionRemainder(plain.RootElement, []), time.GetUtcNow());
        if (!c.Slots!.ContainsKey(CompletionSlot.HandlerReceipt))
        {
            await CompletionChange(scope, state, new(CompletionTransitionKind.SlotOpened, CompletionSlot.HandlerReceipt, Context: context), "open-HandlerReceipt", ct);
            state = await witness.ReadAsync(scope.RecordId, ct);
        }
        var header = new HoldWitnessCompletionRows(ProductionCompletionProtocol.Digest(context), null, ProductionCompletionProtocol.Digest(Array.Empty<CompletionSqlRow>()));
        var saved = Completion(scope, state).Slots![CompletionSlot.HandlerReceipt];
        if (saved.Rows is null)
        {
            await CompletionChange(scope, state, new(CompletionTransitionKind.RowsPlanned, CompletionSlot.HandlerReceipt, Rows: header,
                RemainderSha256: CompletionProjection(plain.RootElement, [], before: true)), "rows-HandlerReceipt", ct);
            state = await witness.ReadAsync(scope.RecordId, ct);
        }
        saved = Completion(scope, state).Slots![CompletionSlot.HandlerReceipt];
        if (saved.Expected is null)
        {
            await CompletionChange(scope, state, new(CompletionTransitionKind.SlotExpected, CompletionSlot.HandlerReceipt, Rows: header, ContentSha256: result.ContentSha256,
                SqlStateSha256: result.SqlStateSha256, PhysicalTransaction: CompletionTransactionId(db)), "expected-HandlerReceipt", ct);
            state = await witness.ReadAsync(scope.RecordId, ct);
        }
        saved = Completion(scope, state).Slots![CompletionSlot.HandlerReceipt];
        if (saved.Acknowledged is null)
        {
            await CompletionChange(scope, state, new(CompletionTransitionKind.SlotAcknowledged, CompletionSlot.HandlerReceipt, ContentSha256: result.ContentSha256,
                SqlStateSha256: result.SqlStateSha256, PhysicalTransaction: CompletionTransactionId(db)), "ack-HandlerReceipt", ct);
            state = await witness.ReadAsync(scope.RecordId, ct);
        }
        await witness.PrepareHandlerOutcomeAsync(scope.RecordId, state.Operations![scope.OperationId], result.ContentSha256, result.SqlStateSha256,
            Id(scope.RecordId, scope.OperationId, "handler-outcome"), ct);
    }

    internal async Task PrepareCompletionWorkFinishLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, WorkItem expectedCompletedWork, CancellationToken ct = default)
    {
        var tx = CompletionTransactionId(db); expectedCompletedWork = CloneCompletionWork(expectedCompletedWork);
        var state = await DemandCompletionHeadLocked(db, scope, ct, final: true); var c = Completion(scope, state);
        var handler = state.HandlerOutcomes?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (!handlerFinalizers.TryGetValue(db, out var permission) || permission.Scope != scope || permission.TransactionId != db.Database.CurrentTransaction!.TransactionId || permission.HandlerOutcome != handler) throw Invalid();
        var sql = await Capture(db, scope.RecordId, await Requests(db, scope.RecordId, ct), ct);
        if (sql.StateSha256 != handler.SqlStateSha256 || ContentDigest(sql, keys) != handler.ContentSha256) throw Invalid();
        using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys); var before = FindCompletionRow(plain.RootElement, "WorkItems", c.Claim.WorkId.ToString("N"));
        if (expectedCompletedWork.LastError is not null || expectedCompletedWork.AvailableAt.Offset != TimeSpan.Zero || expectedCompletedWork.AvailableAt > time.GetUtcNow() ||
            expectedCompletedWork.AvailableAt < before.GetProperty("AvailableAt").GetDateTimeOffset()) throw Invalid();
        var row = new CompletionSqlRow("WorkItems", c.Claim.WorkId.ToString("N"), CompletionRow(before, false), CompletionRow(JsonSerializer.SerializeToElement(expectedCompletedWork, CompletionJson), false));
        DemandCompletionRows(CompletionSlot.WorkFinish, [row], scope.RecordId, c.Claim.WorkId);
        var previous = c.Slots![CompletionSlot.HandlerReceipt].Acknowledged ?? throw Invalid();
        var context = new HoldWitnessCompletionContext(CompletionSlot.WorkFinish, scope.OperationId, previous.Sequence, previous.SqlStateSha256, previous.ContentSha256,
            c.Claim.WorkId, c.Claim.Attempt, c.Claim.Until, c.Claim.PayloadSha256, [], [new("WorkItems", c.Claim.WorkId.ToString("N"), ProductionCompletionProtocol.Digest(row.BeforeJson!))], CompletionRemainder(plain.RootElement, [new("WorkItems", c.Claim.WorkId.ToString("N"), ProductionCompletionProtocol.Digest(row.BeforeJson!))]), time.GetUtcNow());
        await CompletionChange(scope, state, new(CompletionTransitionKind.SlotOpened, CompletionSlot.WorkFinish, Context: context), "open-WorkFinish", ct);
        state = await witness.ReadAsync(scope.RecordId, ct);
        var plan = CompletionWorkFinishPlan(context, [row]);
        await CompletionChange(scope, state, new(CompletionTransitionKind.RowsPlanned, CompletionSlot.WorkFinish, Rows: plan.Header,
            RemainderSha256: CompletionProjection(plain.RootElement, plan.Rows, before: true)), "rows-WorkFinish", ct);
        var permit = new ProductionCompletionSqlPermit(); completionSql.Remove(db); completionSql.Add(db, new(permit, scope, tx, plan, CompletionSlot.WorkFinish));
    }
    private async Task PrepareCompletionWorkFinishLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct)
    {
        if (!completionSql.TryGetValue(db, out var binding) || binding.Scope != scope || binding.Slot != CompletionSlot.WorkFinish || binding.Transaction != CompletionTransactionId(db)) throw Invalid();
        var state = await witness.ReadAsync(scope.RecordId, ct); DemandCompletionActive(scope, state, final: true);
        var sql = await Capture(db, scope.RecordId, await Requests(db, scope.RecordId, ct), ct); using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        var s = Completion(scope, state).Slots![CompletionSlot.WorkFinish];
        if (CompletionProjection(plain.RootElement, binding.Plan.Rows, before: false) != s.RemainderSha256) throw Invalid();
        await CompletionChange(scope, state, new(CompletionTransitionKind.SlotExpected, CompletionSlot.WorkFinish, Rows: binding.Plan.Header,
            ContentSha256: ContentDigest(sql, keys), SqlStateSha256: sql.StateSha256, PhysicalTransaction: binding.Transaction), "expected-WorkFinish", ct);
        state = await witness.ReadAsync(scope.RecordId, ct);
        await witness.PrepareOperationOutcomeAsync(scope.RecordId, state.Operations![scope.OperationId], ContentDigest(sql, keys), sql.StateSha256,
            Id(scope.RecordId, scope.OperationId, "outcome"), ct);
    }
    // WorkFinish has no external/body/provider plan; its sole typed Work mutation
    // is derived under the verified final-handler transaction, never HTTP input.
    private static VerifiedCompletionSlotPlan CompletionWorkFinishPlan(HoldWitnessCompletionContext context, CompletionSqlRow[] rows)
        => VerifiedCompletionSlotPlan.WorkFinish(context, rows);
}
internal sealed partial class VerifiedCompletionSlotPlan
{
    internal static VerifiedCompletionSlotPlan WorkFinish(HoldWitnessCompletionContext context, CompletionSqlRow[] rows)
    {
        if (context.Slot != CompletionSlot.WorkFinish) throw ProductionCompletionProtocol.Invalid();
        return new(new(ProductionCompletionProtocol.Digest(context), null, ProductionCompletionProtocol.Digest(rows)), rows);
    }
}

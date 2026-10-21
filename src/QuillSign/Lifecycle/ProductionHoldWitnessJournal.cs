using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Globalization;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Lifecycle;

internal enum HoldWitnessKind { OperationReserved, OperationSettled, CommandIntent, SqlAccepted, Preserved, Released, PreservationReserved, ReleaseReserved, PlanFrozen, Initialized, OperationOutcomePrepared, HandlerOutcomePrepared, UploadWritesPrepared, UploadWriteStarted, UploadWriteRecorded, SendWritePrepared, SendWriteStarted, SendWriteRecorded, DispatchStarted, PreviewWritesPrepared, PreviewWriteStarted, PreviewWriteRecorded, ReviewWritesPrepared, ReviewWriteStarted, ReviewWriteRecorded }
internal sealed record HoldWitnessEvent(string Version, Guid RecordId, long Sequence, Guid EventId,
    HoldWitnessKind Kind, DateTimeOffset At, string? PreviousHash, ProductionHoldCommand? Command,
    string? Issuer, string? Subject, Guid? OperationId, long RequestRevision, string? RequestFenceHash,
    Guid? PlanId, string? PlanSha256, string? ReceiptSha256, string? BusinessStateSha256, ProductionHoldControlPrefix? Control,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OperationKind = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OperationReference = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SqlStateSha256 = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OutcomeVersion = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? HandlerOutcomeVersion = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? UploadWriteVersion = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteDescriptor? UploadOriginal = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteDescriptor? UploadNormalized = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteDescriptor? UploadItem = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteReceipt? UploadReceipt = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SendWriteVersion = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteDescriptor? SendSource = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteDescriptor? SendTarget = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTimeOffset? SendDeadline = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteReceipt? SendReceipt = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTimeOffset? SendDraftDeadline = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTimeOffset? SendSigningDeadline = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? DispatchStartVersion = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PreviewWriteVersion = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] HoldWitnessPreviewPlan? PreviewPlan = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteDescriptor? PreviewItem = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteReceipt? PreviewReceipt = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ReviewWriteVersion = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] HoldWitnessReviewPlan? ReviewPlan = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteDescriptor? ReviewItem = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProductionRecordWriteReceipt? ReviewReceipt = null);
internal sealed record HoldWitnessOutcome(string ContentSha256, string SqlStateSha256, long Sequence);
internal sealed record HoldWitnessHold(ProductionHoldCommand Placement, ProductionHoldCommand? Release,
    bool Effective, bool Released, Guid? PlanId, string? PlanSha256, string? PreservationSha256, string? ReleaseSha256,
    ProductionHoldControlPrefix? Control, string? ReleaseFenceHash);
internal sealed record HoldWitnessState(long Sequence, string? HeadHash, long RequestRevision, string? RequestFenceHash,
    ProductionHoldCommand? Unacknowledged, Guid? OutstandingOperation, IReadOnlyDictionary<Guid, HoldWitnessHold> Holds,
    string? BusinessStateSha256, IReadOnlyDictionary<Guid, string> SettledOperations, bool Initialized = false,
    string? SqlStateSha256 = null, IReadOnlyDictionary<Guid, HoldWitnessOperation>? Operations = null,
    IReadOnlyDictionary<Guid, HoldWitnessOutcome>? Outcomes = null,
    IReadOnlyDictionary<Guid, HoldWitnessOutcome>? HandlerOutcomes = null,
    IReadOnlyDictionary<Guid, HoldWitnessUploadWrites>? UploadWrites = null,
    IReadOnlyDictionary<Guid, HoldWitnessSendWrite>? SendWrites = null,
    IReadOnlyDictionary<Guid, HoldWitnessOutcome>? DispatchStarts = null,
    IReadOnlyDictionary<Guid, HoldWitnessPreviewWrites>? PreviewWrites = null,
    IReadOnlyDictionary<Guid, HoldWitnessReviewWrites>? ReviewWrites = null)
{
    internal bool Frozen => Unacknowledged is not null || OutstandingOperation is not null || Holds.Values.Any(x => !x.Released);
}

// An external, encrypted, append-only admission journal. These methods remain
// private to the lifecycle coordinator; none is a participant capability. SQL
// acknowledgements and provider receipts must be reconciled by that coordinator.
// Unknown operations never settle by timeout, cancellation or lease expiry.
internal sealed class ProductionHoldWitnessJournal(IProductionHoldWitnessStore store, IDataProtectionProvider keys,
    TimeProvider time, string installationDigest)
{
    internal const string Version = "production-hold-witness-journal-v1";
    private const string OutcomeVersion = "production-record-operation-outcome-v1";
    private const string HandlerOutcomeVersion = "production-record-handler-outcome-v1";
    private const string DispatchStartVersion = "production-record-dispatch-start-v1";
    private const int MaximumEvents = 16384, MaximumPayload = 65536, MaximumBytes = 16 * 1024 * 1024;
    private sealed record ReadResult(HoldWitnessState State, HoldWitnessEvent[] Events, long Bytes);
    private IDataProtector Protector(Guid id)
    {
        if (!Hash(installationDigest) || id == Guid.Empty) throw Invalid();
        return keys.CreateProtector(Version, installationDigest, id.ToString("N"));
    }

    internal async Task<HoldWitnessState> ReadAsync(Guid recordId, CancellationToken ct = default)
        => (await Read(recordId, ct)).State;

    internal Task<HoldWitnessState> InitializeAsync(Guid recordId, string contentSha256, string sqlStateSha256, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.Initialized, ct,
            x => x with { BusinessStateSha256 = contentSha256, SqlStateSha256 = sqlStateSha256 });

    internal Task<HoldWitnessState> ReserveOperationAsync(Guid recordId, Guid operationId, string kind, string reference,
        ProductionHoldRequestSnapshot sql, string contentSha256, string sqlStateSha256, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.OperationReserved, ct, x => x with {
            OperationId = operationId, OperationKind = kind, OperationReference = reference, RequestRevision = sql.Revision,
            RequestFenceHash = sql.FenceHash, BusinessStateSha256 = contentSha256, SqlStateSha256 = sqlStateSha256, OutcomeVersion = OutcomeVersion });

    internal Task<HoldWitnessState> PrepareOperationOutcomeAsync(Guid recordId, HoldWitnessOperation operation,
        string contentSha256, string sqlStateSha256, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.OperationOutcomePrepared, ct, x => x with {
            OperationId = operation.OperationId, OperationKind = operation.Kind, OperationReference = operation.Reference,
            RequestRevision = operation.RequestRevision, RequestFenceHash = operation.RequestFenceHash,
            BusinessStateSha256 = contentSha256, SqlStateSha256 = sqlStateSha256 });

    internal Task<HoldWitnessState> PrepareHandlerOutcomeAsync(Guid recordId, HoldWitnessOperation operation,
        string contentSha256, string sqlStateSha256, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.HandlerOutcomePrepared, ct, x => x with {
            OperationId = operation.OperationId, OperationKind = operation.Kind, OperationReference = operation.Reference,
            RequestRevision = operation.RequestRevision, RequestFenceHash = operation.RequestFenceHash,
            BusinessStateSha256 = contentSha256, SqlStateSha256 = sqlStateSha256, HandlerOutcomeVersion = HandlerOutcomeVersion });

    // Only a definitely acknowledged fresh create grants a process-bound dispatch
    // permit. Replays and unknown acknowledgements can never grant provider IO.
    internal async Task<bool> BeginDispatchAsync(Guid recordId, HoldWitnessOperation operation,
        string contentSha256, string sqlStateSha256, Guid eventId, CancellationToken ct = default)
    {
        var prior = await Read(recordId, ct);
        var proposed = New(recordId, eventId, HoldWitnessKind.DispatchStarted) with {
            OperationId = operation.OperationId, OperationKind = operation.Kind, OperationReference = operation.Reference,
            RequestRevision = operation.RequestRevision, RequestFenceHash = operation.RequestFenceHash,
            BusinessStateSha256 = contentSha256, SqlStateSha256 = sqlStateSha256, DispatchStartVersion = DispatchStartVersion };
        var replay = prior.Events.SingleOrDefault(x => x.EventId == eventId);
        if (replay is not null)
        {
            if (replay != (proposed with { At = replay.At, Sequence = replay.Sequence, PreviousHash = replay.PreviousHash })) throw Invalid();
            return false;
        }
        await Append(prior, proposed, ct); return true;
    }
    internal async Task<HoldWitnessState> SettleOperationAsync(Guid recordId, HoldWitnessOperation operation, string receiptSha256,
        string contentSha256, string sqlStateSha256, Guid eventId, CancellationToken ct = default)
    {
        var state = await ReadAsync(recordId, ct);
        if (state.Operations?.GetValueOrDefault(operation.OperationId) != operation ||
            state.Outcomes?.GetValueOrDefault(operation.OperationId) is not { } outcome ||
            outcome.ContentSha256 != contentSha256 || outcome.SqlStateSha256 != sqlStateSha256) throw Invalid();
        return await Change(recordId, eventId, HoldWitnessKind.OperationSettled, ct, x => x with {
            OperationId = operation.OperationId, OperationKind = operation.Kind, OperationReference = operation.Reference,
            RequestRevision = operation.RequestRevision, RequestFenceHash = operation.RequestFenceHash,
            ReceiptSha256 = receiptSha256, BusinessStateSha256 = contentSha256, SqlStateSha256 = sqlStateSha256 });
    }

    internal Task<HoldWitnessState> PrepareUploadWritesAsync(Guid recordId, HoldWitnessOperation operation,
        ProductionRecordWriteDescriptor original, ProductionRecordWriteDescriptor normalized, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.UploadWritesPrepared, ct, x => UploadEvent(x, operation) with {
            UploadOriginal = original, UploadNormalized = normalized });

    internal async Task<bool> BeginUploadWriteAsync(Guid recordId, HoldWitnessOperation operation, ProductionRecordWriteDescriptor item,
        Guid eventId, CancellationToken ct = default)
    {
        var prior = await Read(recordId, ct); var proposed = UploadEvent(New(recordId, eventId, HoldWitnessKind.UploadWriteStarted), operation) with { UploadItem = item };
        var replay = prior.Events.SingleOrDefault(x => x.EventId == eventId);
        if (replay is not null)
        {
            if (replay != (proposed with { At = replay.At, Sequence = replay.Sequence, PreviousHash = replay.PreviousHash })) throw Invalid();
            return false; // Durable intent can authorize readback ONLY on replay.
        }
        await Append(prior, proposed, ct); return true; // A lost create acknowledgement never returns true.
    }

    internal Task<HoldWitnessState> RecordUploadWriteAsync(Guid recordId, HoldWitnessOperation operation,
        ProductionRecordWriteReceipt receipt, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.UploadWriteRecorded, ct,
            x => UploadEvent(x, operation) with { UploadReceipt = receipt });

    private static HoldWitnessEvent UploadEvent(HoldWitnessEvent value, HoldWitnessOperation operation) => value with {
        OperationId = operation.OperationId, OperationKind = operation.Kind, OperationReference = operation.Reference,
        RequestRevision = operation.RequestRevision, RequestFenceHash = operation.RequestFenceHash, UploadWriteVersion = ProductionRecordUploadWriteContract.Version };

    internal Task<HoldWitnessState> PrepareSendWriteAsync(Guid recordId, HoldWitnessOperation operation,
        ProductionRecordWriteDescriptor source, ProductionRecordWriteDescriptor target, DateTimeOffset deadline,
        DateTimeOffset draftDeadline, DateTimeOffset? signingDeadline, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.SendWritePrepared, ct,
            x => SendEvent(x, operation) with { SendSource = source, SendTarget = target, SendDeadline = deadline,
                SendDraftDeadline = draftDeadline, SendSigningDeadline = signingDeadline });

    internal async Task<bool> BeginSendWriteAsync(Guid recordId, HoldWitnessOperation operation, ProductionRecordWriteDescriptor target,
        Guid eventId, CancellationToken ct = default)
    {
        var prior = await Read(recordId, ct); var proposed = SendEvent(New(recordId, eventId, HoldWitnessKind.SendWriteStarted), operation) with { SendTarget = target };
        var replay = prior.Events.SingleOrDefault(x => x.EventId == eventId);
        if (replay is not null)
        {
            if (replay != (proposed with { At = replay.At, Sequence = replay.Sequence, PreviousHash = replay.PreviousHash })) throw Invalid();
            return false;
        }
        await Append(prior, proposed, ct); return true;
    }

    internal Task<HoldWitnessState> RecordSendWriteAsync(Guid recordId, HoldWitnessOperation operation,
        ProductionRecordWriteReceipt receipt, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.SendWriteRecorded, ct, x => SendEvent(x, operation) with { SendReceipt = receipt });

    private static HoldWitnessEvent SendEvent(HoldWitnessEvent value, HoldWitnessOperation operation) => value with {
        OperationId = operation.OperationId, OperationKind = operation.Kind, OperationReference = operation.Reference,
        RequestRevision = operation.RequestRevision, RequestFenceHash = operation.RequestFenceHash, SendWriteVersion = ProductionRecordSendWriteContract.Version };

    internal Task<HoldWitnessState> PreparePreviewWritesAsync(Guid recordId, HoldWitnessOperation operation,
        HoldWitnessPreviewPlan plan, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.PreviewWritesPrepared, ct, x => PreviewEvent(x, operation) with { PreviewPlan = plan });
    internal async Task<bool> BeginPreviewWriteAsync(Guid recordId, HoldWitnessOperation operation, ProductionRecordWriteDescriptor item,
        Guid eventId, CancellationToken ct = default)
    {
        var prior = await Read(recordId, ct); var proposed = PreviewEvent(New(recordId, eventId, HoldWitnessKind.PreviewWriteStarted), operation) with { PreviewItem = item };
        var replay = prior.Events.SingleOrDefault(x => x.EventId == eventId);
        if (replay is not null)
        {
            if (replay != (proposed with { At = replay.At, Sequence = replay.Sequence, PreviousHash = replay.PreviousHash })) throw Invalid();
            return false;
        }
        await Append(prior, proposed, ct); return true;
    }
    internal Task<HoldWitnessState> RecordPreviewWriteAsync(Guid recordId, HoldWitnessOperation operation,
        ProductionRecordWriteReceipt receipt, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.PreviewWriteRecorded, ct, x => PreviewEvent(x, operation) with { PreviewReceipt = receipt });
    private static HoldWitnessEvent PreviewEvent(HoldWitnessEvent value, HoldWitnessOperation operation) => value with {
        OperationId = operation.OperationId, OperationKind = operation.Kind, OperationReference = operation.Reference,
        RequestRevision = operation.RequestRevision, RequestFenceHash = operation.RequestFenceHash, PreviewWriteVersion = ProductionRecordPreviewWriteContract.Version };

    internal Task<HoldWitnessState> PrepareReviewWritesAsync(Guid recordId, HoldWitnessOperation operation,
        HoldWitnessReviewPlan plan, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.ReviewWritesPrepared, ct, x => ReviewEvent(x, operation) with { ReviewPlan = plan });
    internal async Task<bool> BeginReviewWriteAsync(Guid recordId, HoldWitnessOperation operation, ProductionRecordWriteDescriptor item,
        Guid eventId, CancellationToken ct = default)
    {
        var prior = await Read(recordId, ct); var proposed = ReviewEvent(New(recordId, eventId, HoldWitnessKind.ReviewWriteStarted), operation) with { ReviewItem = item };
        var replay = prior.Events.SingleOrDefault(x => x.EventId == eventId);
        if (replay is not null)
        {
            if (replay != (proposed with { At = replay.At, Sequence = replay.Sequence, PreviousHash = replay.PreviousHash })) throw Invalid();
            return false;
        }
        await Append(prior, proposed, ct); return true;
    }
    internal Task<HoldWitnessState> RecordReviewWriteAsync(Guid recordId, HoldWitnessOperation operation,
        ProductionRecordWriteReceipt receipt, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.ReviewWriteRecorded, ct, x => ReviewEvent(x, operation) with { ReviewReceipt = receipt });
    private static HoldWitnessEvent ReviewEvent(HoldWitnessEvent value, HoldWitnessOperation operation) => value with {
        OperationId = operation.OperationId, OperationKind = operation.Kind, OperationReference = operation.Reference,
        RequestRevision = operation.RequestRevision, RequestFenceHash = operation.RequestFenceHash, ReviewWriteVersion = ProductionRecordReviewWriteContract.Version };

    internal async Task<HoldWitnessState> IntentAsync(ProductionOperatorAuthority authority, ProductionOperatorPolicy policy,
        ProductionHoldCommand command, Guid eventId, CancellationToken ct = default)
    {
        authority.Demand(policy, command.Permission, time); _ = command.Digest();
        var prior = await Read(command.RecordId, ct);
        var replay = prior.Events.SingleOrDefault(x => x.Kind == HoldWitnessKind.CommandIntent && x.Command!.CommandId == command.CommandId);
        if (replay is not null)
        {
            if (replay.Command != command || replay.Issuer != authority.Issuer || replay.Subject != authority.Subject || replay.EventId != eventId) throw Invalid();
            authority.Demand(policy, command.Permission, time); return prior.State;
        }
        authority.Demand(policy, command.Permission, time);
        return await Append(prior, New(command.RecordId, eventId, HoldWitnessKind.CommandIntent) with
        { Command = command, Issuer = authority.Issuer, Subject = authority.Subject }, ct);
    }

    internal async Task<HoldWitnessState> AcceptSqlAsync(ProductionHoldCommand command, ProductionHoldRequestReceipt receipt,
        string businessStateSha256, Guid eventId, CancellationToken ct = default, string? sqlStateSha256 = null)
    {
        _ = command.Digest();
        if (receipt.CommandId != command.CommandId || receipt.CommandRevision != command.ExpectedRevision + 1 ||
            receipt.Current.Revision != receipt.CommandRevision || !Hash(receipt.Current.FenceHash)) throw Invalid();
        var hold = receipt.Current.Holds.SingleOrDefault(x => x.HoldId == command.HoldId) ?? throw Invalid();
        if (command.Operation == ProductionHoldOperation.Place ? hold.PlacementCommandId != command.CommandId || hold.ReleaseCommandId is not null :
            hold.ReleaseCommandId != command.CommandId || hold.State != ProductionHoldPendingState.ReleasePending) throw Invalid();
        return await Change(command.RecordId, eventId, HoldWitnessKind.SqlAccepted, ct,
            x => x with { Command = command, RequestRevision = receipt.CommandRevision, RequestFenceHash = receipt.Current.FenceHash,
                BusinessStateSha256 = businessStateSha256, SqlStateSha256 = sqlStateSha256 });
    }

    internal Task<HoldWitnessState> ReserveAsync(Guid recordId, Guid operationId, Guid eventId,
        ProductionHoldRequestSnapshot sql, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.OperationReserved, ct,
            x => x with { OperationId = operationId, RequestRevision = sql.Revision, RequestFenceHash = sql.FenceHash });

    internal Task<HoldWitnessState> SettleAsync(Guid recordId, Guid operationId, string reconciledReceiptSha256,
        string businessStateSha256, Guid eventId, CancellationToken ct = default)
        => Change(recordId, eventId, HoldWitnessKind.OperationSettled, ct,
            x => x with { OperationId = operationId, ReceiptSha256 = reconciledReceiptSha256, BusinessStateSha256 = businessStateSha256 });

    internal Task<HoldWitnessState> ReservePreservationAsync(ProductionHoldCommand placement, Guid planId, Guid operationId, Guid eventId,
        CancellationToken ct = default) => Change(placement.RecordId, eventId, HoldWitnessKind.PreservationReserved, ct,
            x => x with { Command = placement, PlanId = planId, OperationId = operationId });

    internal Task<HoldWitnessState> FreezePlanAsync(ProductionHoldCommand placement, Guid planId, string planSha256,
        ProductionHoldControlPrefix control, Guid operationId, Guid eventId, CancellationToken ct = default)
        => Change(placement.RecordId, eventId, HoldWitnessKind.PlanFrozen, ct,
            x => x with { Command = placement, PlanId = planId, PlanSha256 = planSha256, Control = control, OperationId = operationId });

    internal Task<HoldWitnessState> ReserveReleaseAsync(ProductionHoldCommand release, Guid operationId, Guid eventId,
        CancellationToken ct = default) => Change(release.RecordId, eventId, HoldWitnessKind.ReleaseReserved, ct,
            x => x with { Command = release, OperationId = operationId });

    internal Task<HoldWitnessState> PreserveAsync(ProductionHoldCommand placement, Guid planId, string planSha256,
        string completeReceiptSha256, ProductionHoldControlPrefix control, Guid operationId, Guid eventId, CancellationToken ct = default)
        => Change(placement.RecordId, eventId, HoldWitnessKind.Preserved, ct,
            x => x with { Command = placement, PlanId = planId, PlanSha256 = planSha256, ReceiptSha256 = completeReceiptSha256,
                Control = control, OperationId = operationId });

    internal Task<HoldWitnessState> ReleaseAsync(ProductionHoldCommand release, string completeReleaseSha256,
        ProductionHoldControlPrefix control, Guid operationId, Guid eventId, CancellationToken ct = default)
        => Change(release.RecordId, eventId, HoldWitnessKind.Released, ct,
            x => x with { Command = release, ReceiptSha256 = completeReleaseSha256, Control = control, OperationId = operationId });

    internal static void DemandSql(HoldWitnessState state, ProductionHoldRequestSnapshot sql)
    {
        if (state.Unacknowledged is not null || state.RequestRevision != sql.Revision || state.RequestFenceHash != sql.FenceHash ||
            sql.Holds.Count != state.Holds.Count || sql.Holds.Any(x => !state.Holds.TryGetValue(x.HoldId, out var hold) ||
                hold.Placement.CommandId != x.PlacementCommandId || hold.Release?.CommandId != x.ReleaseCommandId ||
                (hold.Release is null ? x.State != ProductionHoldPendingState.PreservationPending : x.State != ProductionHoldPendingState.ReleasePending))) throw Invalid();
    }

    private HoldWitnessEvent New(Guid id, Guid eventId, HoldWitnessKind kind) => new(Version, id, 0, eventId, kind,
        time.GetUtcNow(), null, null, null, null, null, 0, null, null, null, null, null, null);

    private async Task<HoldWitnessState> Change(Guid id, Guid eventId, HoldWitnessKind kind, CancellationToken ct,
        Func<HoldWitnessEvent, HoldWitnessEvent> change)
    {
        var prior = await Read(id, ct); var proposed = change(New(id, eventId, kind));
        var replay = prior.Events.SingleOrDefault(x => x.EventId == eventId);
        if (replay is not null)
        {
            // Replay owns the original clock and encrypted bytes. No new event,
            // clock extension or duplicate provider operation is inferred.
            if (replay != (proposed with { At = replay.At, Sequence = replay.Sequence, PreviousHash = replay.PreviousHash })) throw Invalid();
            return prior.State;
        }
        return await Append(prior, proposed, ct);
    }

    private async Task<HoldWitnessState> Append(ReadResult prior, HoldWitnessEvent proposed, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var value = proposed with { Sequence = prior.State.Sequence + 1, PreviousHash = prior.State.HeadHash };
        // Fold before any provider write. A stale caller cannot append an invalid
        // transition. Competing writers still arbitrate the create-only slot.
        _ = Fold(value.RecordId, prior.Events.Append(value).ToArray());
        var plain = JsonSerializer.SerializeToUtf8Bytes(value); byte[] cipher;
        try { cipher = Protector(value.RecordId).Protect(plain); }
        finally { CryptographicOperations.ZeroMemory(plain); }
        try
        {
            if (cipher.Length > MaximumPayload || checked(prior.Bytes + cipher.Length) > MaximumBytes) throw Invalid();
            await store.CreateAsync(new(value.RecordId, value.Sequence, cipher), ct);
        }
        finally { CryptographicOperations.ZeroMemory(cipher); }
        var read = await Read(value.RecordId, ct);
        if (read.Events.Length < value.Sequence || read.Events[(int)value.Sequence - 1] != value) throw Invalid();
        return read.State;
    }

    private async Task<ReadResult> Read(Guid id, CancellationToken ct)
    {
        _ = Protector(id);
        var rows = await store.ReadAsync(id, ct);
        if (rows.Count > MaximumEvents) throw Invalid();
        long bytes = 0; string? previous = null; var events = new List<HoldWitnessEvent>();
        foreach (var row in rows)
        {
            ct.ThrowIfCancellationRequested();
            if (row.ProtectedPayload is not { Length: > 0 and <= MaximumPayload } ||
                (bytes = checked(bytes + row.ProtectedPayload.Length)) > MaximumBytes || row.Sequence != events.Count + 1 ||
                row.Path != $"production-hold-witnesses/{installationDigest}/{id:N}/{row.Sequence:D10}" ||
                string.IsNullOrWhiteSpace(row.VersionId) || string.IsNullOrWhiteSpace(row.ETag) || !row.LegalHold ||
                row.Length != row.ProtectedPayload.LongLength || row.Sha256 != Digest(row.ProtectedPayload)) throw Invalid();
            byte[] plain;
            try { plain = Protector(id).Unprotect(row.ProtectedPayload); }
            catch (CryptographicException error) { throw new InvalidDataException("External hold history could not be verified.", error); }
            try
            {
                if (plain.Length > MaximumPayload) throw Invalid();
                var value = JsonSerializer.Deserialize<HoldWitnessEvent>(plain) ?? throw Invalid();
                if (!plain.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(value)) ||
                    value.Sequence != row.Sequence || value.PreviousHash != previous) throw Invalid();
                events.Add(value); previous = row.Sha256;
            }
            catch (JsonException error) { throw new InvalidDataException("External hold history could not be verified.", error); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        var state = Fold(id, events.ToArray()) with { HeadHash = previous };
        return new(state, events.ToArray(), bytes);
    }

    private HoldWitnessState Fold(Guid id, HoldWitnessEvent[] events)
    {
        if (id == Guid.Empty || events.Length > MaximumEvents) throw Invalid();
        var holds = new Dictionary<Guid, HoldWitnessHold>(); var eventIds = new HashSet<Guid>();
        var operations = new HashSet<Guid>(); var commands = new HashSet<Guid>();
        var settled = new Dictionary<Guid, string>(); bool maintenance = false;
        var typed = new Dictionary<Guid, HoldWitnessOperation>(); bool initialized = false; string? sqlState = null;
        var outcomes = new Dictionary<Guid, HoldWitnessOutcome>(); var outcomeRequired = new HashSet<Guid>();
        var handlerOutcomes = new Dictionary<Guid, HoldWitnessOutcome>();
        var dispatches = new Dictionary<Guid, HoldWitnessOutcome>();
        var uploads = new Dictionary<Guid, HoldWitnessUploadWrites>();
        var sends = new Dictionary<Guid, HoldWitnessSendWrite>();
        var previews = new Dictionary<Guid, HoldWitnessPreviewWrites>();
        var reviews = new Dictionary<Guid, HoldWitnessReviewWrites>();
        Guid? operation = null; ProductionHoldCommand? pending = null; long revision = 0; string? fence = null; string? business = null;
        DateTimeOffset? lastAt = null;
        foreach (var e in events)
        {
            if (e.Version != Version || e.RecordId != id || e.EventId == Guid.Empty || !eventIds.Add(e.EventId) || !Enum.IsDefined(e.Kind) ||
                e.At.Offset != TimeSpan.Zero || e.At > time.GetUtcNow() || e.At < lastAt || e.Sequence != eventIds.Count) throw Invalid();
            lastAt = e.At;
            // Only the fields defined for the exact event are permitted. This
            // closes future-field/shape ambiguity even for protected plaintext.
            var canonical = New(id, e.EventId, e.Kind) with { At = e.At, Sequence = e.Sequence, PreviousHash = e.PreviousHash };
            switch (e.Kind)
            {
                case HoldWitnessKind.Initialized:
                    if (e.Sequence != 1 || initialized || holds.Count != 0 || operation is not null || pending is not null ||
                        !Hash(e.BusinessStateSha256) || !Hash(e.SqlStateSha256)) throw Invalid();
                    initialized = true; business = e.BusinessStateSha256; sqlState = e.SqlStateSha256;
                    canonical = canonical with { BusinessStateSha256 = business, SqlStateSha256 = sqlState }; break;
                case HoldWitnessKind.OperationReserved:
                    if (e.OperationId is not { } op || op == Guid.Empty || !operations.Add(op) || operation is not null || pending is not null ||
                        holds.Values.Any(x => !x.Released) || e.RequestRevision != revision || e.RequestFenceHash != fence) throw Invalid();
                    operation = op; canonical = canonical with { OperationId = op, RequestRevision = revision, RequestFenceHash = fence };
                    if (e.OperationKind is not null || e.OperationReference is not null || e.SqlStateSha256 is not null || e.BusinessStateSha256 is not null)
                    {
                        if (!initialized || !OperationText(e.OperationKind, 128) || !OperationText(e.OperationReference, 512) ||
                            e.BusinessStateSha256 != business || !Hash(e.SqlStateSha256) ||
                            (sqlState is not null && sqlState != e.SqlStateSha256)) throw Invalid();
                        sqlState = e.SqlStateSha256;
                        typed.Add(op, new(op, e.OperationKind!, e.OperationReference!, revision, fence, business!, sqlState!, e.Sequence));
                        canonical = canonical with { OperationKind = e.OperationKind, OperationReference = e.OperationReference,
                            BusinessStateSha256 = business, SqlStateSha256 = sqlState };
                        if (e.OutcomeVersion is not null)
                        {
                            if (e.OutcomeVersion != OutcomeVersion) throw Invalid();
                            outcomeRequired.Add(op); canonical = canonical with { OutcomeVersion = OutcomeVersion };
                        }
                    }
                    else if (initialized) throw Invalid();
                    break;
                case HoldWitnessKind.OperationOutcomePrepared:
                    if (maintenance || operation is null || e.OperationId != operation ||
                        !typed.TryGetValue(operation.Value, out var preparing) || outcomes.ContainsKey(operation.Value) ||
                        e.OperationKind != preparing.Kind || e.OperationReference != preparing.Reference ||
                        e.RequestRevision != preparing.RequestRevision || e.RequestFenceHash != preparing.RequestFenceHash ||
                        revision != preparing.RequestRevision || fence != preparing.RequestFenceHash ||
                        !Hash(e.BusinessStateSha256) || !Hash(e.SqlStateSha256) ||
                        dispatches.ContainsKey(operation.Value) && !handlerOutcomes.ContainsKey(operation.Value) ||
                        uploads.TryGetValue(operation.Value, out var uploadOutcome) && !ProductionRecordUploadWriteContract.Complete(uploadOutcome) ||
                        sends.TryGetValue(operation.Value, out var sendOutcome) &&
                        (!ProductionRecordSendWriteContract.Complete(sendOutcome) || e.At >= sendOutcome.Deadline) ||
                        preparing.Kind == ProductionRecordPreviewWriteContract.Kind && !previews.ContainsKey(operation.Value) ||
                        previews.TryGetValue(operation.Value, out var previewOutcome) &&
                        (!ProductionRecordPreviewWriteContract.Complete(previewOutcome) || e.At >= ProductionRecordPreviewWriteContract.ReadRow(previewOutcome.Plan.PreviewRowJson).ExpiresAt)) throw Invalid();
                    if (preparing.Kind == ProductionRecordReviewWriteContract.Kind && (!reviews.TryGetValue(operation.Value, out var reviewOutcome) || !ProductionRecordReviewWriteContract.Complete(reviewOutcome) || e.At >= ProductionRecordReviewWriteContract.ReadRow(reviewOutcome.Plan.CandidateRowJson).ExpiresAt)) throw Invalid();
                    outcomes.Add(operation.Value, new(e.BusinessStateSha256!, e.SqlStateSha256!, e.Sequence));
                    canonical = canonical with { OperationId = e.OperationId, OperationKind = e.OperationKind, OperationReference = e.OperationReference,
                        RequestRevision = revision, RequestFenceHash = fence, BusinessStateSha256 = e.BusinessStateSha256, SqlStateSha256 = e.SqlStateSha256 };
                    break;
                case HoldWitnessKind.UploadWritesPrepared:
                case HoldWitnessKind.UploadWriteStarted:
                case HoldWitnessKind.UploadWriteRecorded:
                    if (maintenance || operation is null || e.OperationId != operation || !typed.TryGetValue(operation.Value, out var uploading) ||
                        uploading.Kind != ProductionRecordUploadWriteContract.Kind || e.OperationKind != uploading.Kind || e.OperationReference != uploading.Reference ||
                        e.RequestRevision != uploading.RequestRevision || e.RequestFenceHash != uploading.RequestFenceHash ||
                        revision != uploading.RequestRevision || fence != uploading.RequestFenceHash || outcomes.ContainsKey(operation.Value) ||
                        handlerOutcomes.ContainsKey(operation.Value) || e.UploadWriteVersion != ProductionRecordUploadWriteContract.Version) throw Invalid();
                    canonical = UploadEvent(canonical, uploading);
                    if (e.Kind == HoldWitnessKind.UploadWritesPrepared)
                    {
                        if (uploads.ContainsKey(operation.Value) || !ProductionRecordUploadWriteContract.Pair(id, e.UploadOriginal, e.UploadNormalized)) throw Invalid();
                        uploads.Add(operation.Value, new(e.UploadOriginal!, e.UploadNormalized!, [], System.Collections.Immutable.ImmutableDictionary<QuillSign.Storage.DocumentBlob, ProductionRecordWriteReceipt>.Empty));
                        outcomeRequired.Add(operation.Value); canonical = canonical with { UploadOriginal = e.UploadOriginal, UploadNormalized = e.UploadNormalized };
                    }
                    else
                    {
                        if (!uploads.TryGetValue(operation.Value, out var upload)) throw Invalid();
                        if (e.Kind == HoldWitnessKind.UploadWriteStarted)
                        {
                            if (e.UploadItem is not { } item || !ProductionRecordUploadWriteContract.Member(upload, item) || upload.Begun.Contains(item.Blob)) throw Invalid();
                            uploads[operation.Value] = upload with { Begun = upload.Begun.Add(item.Blob) }; canonical = canonical with { UploadItem = item };
                        }
                        else
                        {
                            if (e.UploadReceipt is not { } receipt || !ProductionRecordUploadWriteContract.Receipt(id, receipt) ||
                                !ProductionRecordUploadWriteContract.Member(upload, receipt.Item) || !upload.Begun.Contains(receipt.Item.Blob) || upload.Receipts.ContainsKey(receipt.Item.Blob)) throw Invalid();
                            uploads[operation.Value] = upload with { Receipts = upload.Receipts.Add(receipt.Item.Blob, receipt) }; canonical = canonical with { UploadReceipt = receipt };
                        }
                    }
                    break;
                case HoldWitnessKind.SendWritePrepared:
                case HoldWitnessKind.SendWriteStarted:
                case HoldWitnessKind.SendWriteRecorded:
                    if (maintenance || operation is null || e.OperationId != operation || !typed.TryGetValue(operation.Value, out var sending) ||
                        sending.Kind != ProductionRecordSendWriteContract.Kind || e.OperationKind != sending.Kind || e.OperationReference != sending.Reference ||
                        e.RequestRevision != sending.RequestRevision || e.RequestFenceHash != sending.RequestFenceHash ||
                        revision != sending.RequestRevision || fence != sending.RequestFenceHash || outcomes.ContainsKey(operation.Value) ||
                        handlerOutcomes.ContainsKey(operation.Value) || e.SendWriteVersion != ProductionRecordSendWriteContract.Version) throw Invalid();
                    canonical = SendEvent(canonical, sending);
                    if (e.Kind == HoldWitnessKind.SendWritePrepared)
                    {
                        if (sends.ContainsKey(operation.Value) || !ProductionRecordSendWriteContract.Pair(id, e.SendSource, e.SendTarget) ||
                            e.SendDeadline is not { } deadline || deadline.Offset != TimeSpan.Zero || deadline <= e.At ||
                            e.SendDraftDeadline is not { } draftDeadline || draftDeadline.Offset != TimeSpan.Zero ||
                            e.SendSigningDeadline is { Offset: var offset } && offset != TimeSpan.Zero ||
                            deadline != ProductionRecordSendWriteContract.Earlier(draftDeadline, e.SendSigningDeadline)) throw Invalid();
                        sends.Add(operation.Value, new(e.SendSource!, e.SendTarget!, deadline, false, null, draftDeadline, e.SendSigningDeadline)); outcomeRequired.Add(operation.Value);
                        canonical = canonical with { SendSource = e.SendSource, SendTarget = e.SendTarget, SendDeadline = deadline,
                            SendDraftDeadline = draftDeadline, SendSigningDeadline = e.SendSigningDeadline };
                    }
                    else
                    {
                        if (!sends.TryGetValue(operation.Value, out var send) || e.At >= send.Deadline) throw Invalid();
                        if (e.Kind == HoldWitnessKind.SendWriteStarted)
                        {
                            if (send.Begun || e.SendTarget != send.Target) throw Invalid();
                            sends[operation.Value] = send with { Begun = true }; canonical = canonical with { SendTarget = e.SendTarget };
                        }
                        else
                        {
                            if (!send.Begun || send.Receipt is not null || e.SendReceipt is not { } receipt ||
                                !ProductionRecordUploadWriteContract.Receipt(id, receipt) || receipt.Item != send.Target) throw Invalid();
                            sends[operation.Value] = send with { Receipt = receipt }; canonical = canonical with { SendReceipt = receipt };
                        }
                    }
                    break;
                case HoldWitnessKind.PreviewWritesPrepared:
                case HoldWitnessKind.PreviewWriteStarted:
                case HoldWitnessKind.PreviewWriteRecorded:
                    if (maintenance || operation is null || e.OperationId != operation || !typed.TryGetValue(operation.Value, out var previewing) ||
                        previewing.Kind != ProductionRecordPreviewWriteContract.Kind || e.OperationKind != previewing.Kind || e.OperationReference != previewing.Reference ||
                        e.RequestRevision != previewing.RequestRevision || e.RequestFenceHash != previewing.RequestFenceHash ||
                        revision != previewing.RequestRevision || fence != previewing.RequestFenceHash || outcomes.ContainsKey(operation.Value) ||
                        handlerOutcomes.ContainsKey(operation.Value) || e.PreviewWriteVersion != ProductionRecordPreviewWriteContract.Version) throw Invalid();
                    canonical = PreviewEvent(canonical, previewing);
                    if (e.Kind == HoldWitnessKind.PreviewWritesPrepared)
                    {
                        if (previews.ContainsKey(operation.Value) || e.PreviewPlan is not { } previewPlan) throw Invalid();
                        ProductionRecordPreviewWriteContract.Validate(previewPlan);
                        var previewRow = ProductionRecordPreviewWriteContract.ReadRow(previewPlan.PreviewRowJson);
                        if (previewRow.EnvelopeId != id || previewing.Reference != previewRow.Id.ToString("N") || previewRow.CreatedAt > e.At || previewRow.ExpiresAt <= e.At) throw Invalid();
                        previews.Add(operation.Value, new(previewPlan, [], System.Collections.Immutable.ImmutableDictionary<QuillSign.Storage.DocumentBlob, ProductionRecordWriteReceipt>.Empty));
                        outcomeRequired.Add(operation.Value); canonical = canonical with { PreviewPlan = previewPlan };
                    }
                    else
                    {
                        if (!previews.TryGetValue(operation.Value, out var preview) || e.At >= ProductionRecordPreviewWriteContract.ReadRow(preview.Plan.PreviewRowJson).ExpiresAt) throw Invalid();
                        if (e.Kind == HoldWitnessKind.PreviewWriteStarted)
                        {
                            if (e.PreviewItem is not { } item || !ProductionRecordPreviewWriteContract.Member(preview.Plan, item) || preview.Begun.Contains(item.Blob)) throw Invalid();
                            previews[operation.Value] = preview with { Begun = preview.Begun.Add(item.Blob) }; canonical = canonical with { PreviewItem = item };
                        }
                        else
                        {
                            if (e.PreviewReceipt is not { } receipt || !ProductionRecordPreviewWriteContract.Receipt(id, receipt) ||
                                !ProductionRecordPreviewWriteContract.Member(preview.Plan, receipt.Item) || !preview.Begun.Contains(receipt.Item.Blob) || preview.Receipts.ContainsKey(receipt.Item.Blob)) throw Invalid();
                            previews[operation.Value] = preview with { Receipts = preview.Receipts.Add(receipt.Item.Blob, receipt) }; canonical = canonical with { PreviewReceipt = receipt };
                        }
                    }
                    break;
                case HoldWitnessKind.ReviewWritesPrepared:
                case HoldWitnessKind.ReviewWriteStarted:
                case HoldWitnessKind.ReviewWriteRecorded:
                    if (maintenance || operation is null || e.OperationId != operation || !typed.TryGetValue(operation.Value, out var reviewing) ||
                        reviewing.Kind != ProductionRecordReviewWriteContract.Kind || e.OperationKind != reviewing.Kind || e.OperationReference != reviewing.Reference ||
                        e.RequestRevision != reviewing.RequestRevision || e.RequestFenceHash != reviewing.RequestFenceHash ||
                        revision != reviewing.RequestRevision || fence != reviewing.RequestFenceHash || outcomes.ContainsKey(operation.Value) ||
                        handlerOutcomes.ContainsKey(operation.Value) || e.ReviewWriteVersion != ProductionRecordReviewWriteContract.Version) throw Invalid();
                    canonical = ReviewEvent(canonical, reviewing);
                    if (e.Kind == HoldWitnessKind.ReviewWritesPrepared)
                    {
                        if (reviews.ContainsKey(operation.Value) || e.ReviewPlan is not { } reviewPlan) throw Invalid();
                        ProductionRecordReviewWriteContract.Validate(reviewPlan);
                        var reviewRow = ProductionRecordReviewWriteContract.ReadRow(reviewPlan.CandidateRowJson);
                        if (reviewPlan.OperationId != operation.Value || reviewRow.EnvelopeId != id || reviewing.Reference != reviewRow.Id.ToString("N") || reviewRow.PreparedAt > e.At || reviewRow.ExpiresAt <= e.At) throw Invalid();
                        reviews.Add(operation.Value, new(reviewPlan, [], System.Collections.Immutable.ImmutableDictionary<QuillSign.Storage.DocumentBlob, ProductionRecordWriteReceipt>.Empty));
                        outcomeRequired.Add(operation.Value); canonical = canonical with { ReviewPlan = reviewPlan };
                    }
                    else
                    {
                        if (!reviews.TryGetValue(operation.Value, out var review) || e.At >= ProductionRecordReviewWriteContract.ReadRow(review.Plan.CandidateRowJson).ExpiresAt) throw Invalid();
                        if (e.Kind == HoldWitnessKind.ReviewWriteStarted)
                        {
                            if (e.ReviewItem is not { } item || !ProductionRecordReviewWriteContract.Member(review.Plan, item) || review.Begun.Contains(item.Blob) || item == review.Plan.Pdf && !review.Receipts.ContainsKey(review.Plan.Input.Blob)) throw Invalid();
                            reviews[operation.Value] = review with { Begun = review.Begun.Add(item.Blob) }; canonical = canonical with { ReviewItem = item };
                        }
                        else
                        {
                            if (e.ReviewReceipt is not { } receipt || !ProductionRecordReviewWriteContract.Receipt(id, receipt) ||
                                !ProductionRecordReviewWriteContract.Member(review.Plan, receipt.Item) || !review.Begun.Contains(receipt.Item.Blob) || review.Receipts.ContainsKey(receipt.Item.Blob)) throw Invalid();
                            reviews[operation.Value] = review with { Receipts = review.Receipts.Add(receipt.Item.Blob, receipt) }; canonical = canonical with { ReviewReceipt = receipt };
                        }
                    }
                    break;
                case HoldWitnessKind.DispatchStarted:
                    if (maintenance || operation is null || e.OperationId != operation ||
                        !typed.TryGetValue(operation.Value, out var dispatching) || dispatches.ContainsKey(operation.Value) ||
                        handlerOutcomes.ContainsKey(operation.Value) || outcomes.ContainsKey(operation.Value) ||
                        e.OperationKind != dispatching.Kind || !WorkerOperationText(e.OperationKind) || e.OperationReference != dispatching.Reference ||
                        e.RequestRevision != dispatching.RequestRevision || e.RequestFenceHash != dispatching.RequestFenceHash ||
                        revision != dispatching.RequestRevision || fence != dispatching.RequestFenceHash ||
                        e.DispatchStartVersion != DispatchStartVersion || !Hash(e.BusinessStateSha256) || !Hash(e.SqlStateSha256)) throw Invalid();
                    dispatches.Add(operation.Value, new(e.BusinessStateSha256!, e.SqlStateSha256!, e.Sequence)); outcomeRequired.Add(operation.Value);
                    canonical = canonical with { OperationId = e.OperationId, OperationKind = e.OperationKind, OperationReference = e.OperationReference,
                        RequestRevision = revision, RequestFenceHash = fence, BusinessStateSha256 = e.BusinessStateSha256, SqlStateSha256 = e.SqlStateSha256,
                        DispatchStartVersion = DispatchStartVersion };
                    break;
                case HoldWitnessKind.HandlerOutcomePrepared:
                    if (maintenance || operation is null || e.OperationId != operation ||
                        !typed.TryGetValue(operation.Value, out var handling) || handlerOutcomes.ContainsKey(operation.Value) || outcomes.ContainsKey(operation.Value) ||
                        e.OperationKind != handling.Kind || !WorkerOperationText(e.OperationKind) || e.OperationReference != handling.Reference ||
                        e.RequestRevision != handling.RequestRevision || e.RequestFenceHash != handling.RequestFenceHash ||
                        revision != handling.RequestRevision || fence != handling.RequestFenceHash ||
                        e.HandlerOutcomeVersion != HandlerOutcomeVersion || !Hash(e.BusinessStateSha256) || !Hash(e.SqlStateSha256)) throw Invalid();
                    handlerOutcomes.Add(operation.Value, new(e.BusinessStateSha256!, e.SqlStateSha256!, e.Sequence)); outcomeRequired.Add(operation.Value);
                    canonical = canonical with { OperationId = e.OperationId, OperationKind = e.OperationKind, OperationReference = e.OperationReference,
                        RequestRevision = revision, RequestFenceHash = fence, BusinessStateSha256 = e.BusinessStateSha256, SqlStateSha256 = e.SqlStateSha256,
                        HandlerOutcomeVersion = HandlerOutcomeVersion };
                    break;
                case HoldWitnessKind.OperationSettled:
                    if (maintenance || e.OperationId != operation || operation is null || !Hash(e.ReceiptSha256) || !Hash(e.BusinessStateSha256)) throw Invalid();
                    if (typed.TryGetValue(operation.Value, out var reserved))
                    {
                        if (e.OperationKind != reserved.Kind || e.OperationReference != reserved.Reference || !Hash(e.SqlStateSha256) ||
                            e.RequestRevision != reserved.RequestRevision || e.RequestFenceHash != reserved.RequestFenceHash || revision != reserved.RequestRevision || fence != reserved.RequestFenceHash) throw Invalid();
                        if (outcomeRequired.Contains(operation.Value) && !outcomes.ContainsKey(operation.Value) ||
                            outcomes.TryGetValue(operation.Value, out var expected) &&
                            (expected.ContentSha256 != e.BusinessStateSha256 || expected.SqlStateSha256 != e.SqlStateSha256)) throw Invalid();
                        sqlState = e.SqlStateSha256;
                        canonical = canonical with { OperationKind = e.OperationKind, OperationReference = e.OperationReference,
                            RequestRevision = e.RequestRevision, RequestFenceHash = e.RequestFenceHash, SqlStateSha256 = sqlState };
                    }
                    settled.Add(operation.Value, e.ReceiptSha256!); operation = null; business = e.BusinessStateSha256;
                    canonical = canonical with { OperationId = e.OperationId, ReceiptSha256 = e.ReceiptSha256, BusinessStateSha256 = business }; break;
                case HoldWitnessKind.CommandIntent:
                    var command = e.Command ?? throw Invalid(); _ = command.Digest();
                    if (maintenance || command.RecordId != id || command.ExpectedRevision != revision || pending is not null || !commands.Add(command.CommandId) ||
                        !ProductionOperatorAuthority.Text(e.Issuer, 2048) || !ProductionOperatorAuthority.Text(e.Subject, 256)) throw Invalid();
                    if (command.Operation == ProductionHoldOperation.Place)
                    { if (!holds.TryAdd(command.HoldId, new(command, null, false, false, null, null, null, null, null, null))) throw Invalid(); }
                    else
                    {
                        if (!holds.TryGetValue(command.HoldId, out var hold) || !hold.Effective || hold.Release is not null || hold.Released) throw Invalid();
                        holds[command.HoldId] = hold with { Release = command };
                    }
                    pending = command; canonical = canonical with { Command = command, Issuer = e.Issuer, Subject = e.Subject }; break;
                case HoldWitnessKind.SqlAccepted:
                    if (operation is { } active && typed.ContainsKey(active) || pending is null || e.Command != pending || e.RequestRevision != revision + 1 || !Hash(e.RequestFenceHash) || !Hash(e.BusinessStateSha256)) throw Invalid();
                    revision = e.RequestRevision; fence = e.RequestFenceHash; pending = null;
                    if (e.Command!.Operation == ProductionHoldOperation.Release)
                        holds[e.Command.HoldId] = holds[e.Command.HoldId] with { ReleaseFenceHash = fence };
                    business = e.BusinessStateSha256;
                    if (e.SqlStateSha256 is not null && !Hash(e.SqlStateSha256)) throw Invalid();
                    // A request append changes the full fingerprint. Old event
                    // shapes have no new full hash, so never label the prior R0
                    // fingerprint as an acknowledgement of the newer SQL head.
                    sqlState = e.SqlStateSha256;
                    canonical = canonical with { Command = e.Command, RequestRevision = revision, RequestFenceHash = fence,
                        BusinessStateSha256 = business, SqlStateSha256 = sqlState }; break;
                case HoldWitnessKind.PreservationReserved:
                case HoldWitnessKind.ReleaseReserved:
                    if (pending is not null || operation is not null || e.Command is null || e.OperationId is not { } work || work == Guid.Empty ||
                        !operations.Add(work) || !holds.TryGetValue(e.Command.HoldId, out var working) || working.Released ||
                        (e.Kind == HoldWitnessKind.PreservationReserved ? working.Placement != e.Command || working.Release is not null || working.Effective || e.PlanId is null || e.PlanId == Guid.Empty :
                            working.Release != e.Command || !working.Effective)) throw Invalid();
                    operation = work; maintenance = true; canonical = canonical with { Command = e.Command, OperationId = work };
                    if (e.Kind == HoldWitnessKind.PreservationReserved)
                    { holds[e.Command.HoldId] = working with { PlanId = e.PlanId }; canonical = canonical with { PlanId = e.PlanId }; }
                    break;
                case HoldWitnessKind.PlanFrozen:
                    if (pending is not null || !maintenance || operation is null || e.OperationId != operation || e.Command is null ||
                        !holds.TryGetValue(e.Command.HoldId, out var freezing) || freezing.Placement != e.Command || freezing.Release is not null || freezing.Effective ||
                        freezing.PlanSha256 is not null || e.PlanId != freezing.PlanId || !Hash(e.PlanSha256) || !Prefix(e.Control)) throw Invalid();
                    holds[e.Command.HoldId] = freezing with { PlanSha256 = e.PlanSha256, Control = e.Control };
                    canonical = canonical with { Command = e.Command, OperationId = e.OperationId, PlanId = e.PlanId, PlanSha256 = e.PlanSha256, Control = e.Control }; break;
                case HoldWitnessKind.Preserved:
                    if (pending is not null || operation is null || !maintenance || e.OperationId != operation || e.Command is null || !holds.TryGetValue(e.Command.HoldId, out var preserving) ||
                        preserving.Placement != e.Command || preserving.Release is not null || preserving.Effective || e.PlanId is null || e.PlanId == Guid.Empty ||
                        e.PlanId != preserving.PlanId || e.PlanSha256 != preserving.PlanSha256 || !Hash(e.PlanSha256) || !Hash(e.ReceiptSha256) || !Prefix(e.Control)) throw Invalid();
                    holds[e.Command.HoldId] = preserving with { Effective = true, PlanId = e.PlanId, PlanSha256 = e.PlanSha256,
                        PreservationSha256 = e.ReceiptSha256, Control = e.Control };
                    operation = null; maintenance = false;
                    canonical = canonical with { Command = e.Command, PlanId = e.PlanId, PlanSha256 = e.PlanSha256, ReceiptSha256 = e.ReceiptSha256,
                        Control = e.Control, OperationId = e.OperationId }; break;
                case HoldWitnessKind.Released:
                    if (pending is not null || operation is null || !maintenance || e.OperationId != operation || e.Command is null || !holds.TryGetValue(e.Command.HoldId, out var releasing) ||
                        releasing.Release != e.Command || !releasing.Effective || releasing.Released || !Hash(e.ReceiptSha256) || !Prefix(e.Control)) throw Invalid();
                    holds[e.Command.HoldId] = releasing with { Released = true, ReleaseSha256 = e.ReceiptSha256, Control = e.Control };
                    operation = null; maintenance = false;
                    canonical = canonical with { Command = e.Command, ReceiptSha256 = e.ReceiptSha256, Control = e.Control, OperationId = e.OperationId }; break;
            }
            if (canonical != e) throw Invalid();
        }
        return new(events.LongLength, null, revision, fence, pending, operation, holds, business, settled, initialized, sqlState, typed, outcomes, handlerOutcomes, uploads, sends, dispatches, previews, reviews);
    }

    private static bool Prefix(ProductionHoldControlPrefix? value) => value is { Sequence: > 0 } && Hash(value.Hash);
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    internal static bool OperationText(string? value, int maximum) => value is { Length: > 0 } && value.Length <= maximum && value.Trim() == value &&
        value.All(x => x is >= '!' and <= '~');
    internal static bool WorkerOperationText(string? kind) => kind is not null && kind.StartsWith("work/", StringComparison.Ordinal) &&
        int.TryParse(kind.AsSpan(5), NumberStyles.None, CultureInfo.InvariantCulture, out var value) && Enum.IsDefined((QuillSign.Data.WorkKind)value) &&
        kind == "work/" + value.ToString(CultureInfo.InvariantCulture);
    internal static string Digest(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(SHA256.HashData(value));
    private static InvalidDataException Invalid() => new("External hold history could not be verified.");
}

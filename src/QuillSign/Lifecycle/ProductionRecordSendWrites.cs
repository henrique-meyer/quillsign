using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal sealed record HoldWitnessSendWrite(ProductionRecordWriteDescriptor Source, ProductionRecordWriteDescriptor Target,
    DateTimeOffset Deadline, bool Begun, ProductionRecordWriteReceipt? Receipt, DateTimeOffset DraftDeadline, DateTimeOffset? SigningDeadline);

// One frozen normalized Send object, distinct from the confirmed source. This
// never broadens the upload's two-object contract or permits orphan deletion.
internal static class ProductionRecordSendWriteContract
{
    internal const string Version = "production-record-send-write-v1", Kind = "sender/send";
    internal static DateTimeOffset Earlier(DateTimeOffset draft, DateTimeOffset? signing) => signing is { } until && until < draft ? until : draft;
    internal static bool Pair(Guid id, ProductionRecordWriteDescriptor? source, ProductionRecordWriteDescriptor? target) =>
        ProductionRecordUploadWriteContract.Item(id, source) && ProductionRecordUploadWriteContract.Item(id, target) &&
        source!.Blob.Kind == DocumentBlobKind.Normalized && target!.Blob.Kind == DocumentBlobKind.Normalized && source.Blob.ObjectId != target.Blob.ObjectId;
    internal static bool Complete(HoldWitnessSendWrite plan) => plan.Begun && plan.Receipt is { } receipt &&
        receipt.Item == plan.Target && ProductionRecordUploadWriteContract.Receipt(plan.Target.Blob.EnvelopeId, receipt);
    internal static void DemandSaved(ProductionHoldSqlSnapshot snapshot, IDataProtectionProvider keys, HoldWitnessSendWrite plan)
    {
        if (!Complete(plan)) throw Invalid();
        using var document = ProductionHoldSqlInventory.OpenAcknowledgementVerified(snapshot, keys);
        var row = document.RootElement.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == "Envelopes")
            .GetProperty("Rows").EnumerateArray().Single();
        if (row.GetProperty("Status").GetString() != nameof(EnvelopeStatus.Sent) ||
            row.GetProperty("PdfBlob").GetString() != plan.Source.Blob.ObjectId.ToString("N") ||
            row.GetProperty("SentPdfBlob").GetString() != plan.Target.Blob.ObjectId.ToString("N") ||
            row.GetProperty("PdfSha256").ValueKind != JsonValueKind.String || row.GetProperty("SentPdfSha256").ValueKind != JsonValueKind.String ||
            Convert.ToHexStringLower(row.GetProperty("PdfSha256").GetBytesFromBase64()) != plan.Source.Sha256 ||
            Convert.ToHexStringLower(row.GetProperty("SentPdfSha256").GetBytesFromBase64()) != plan.Target.Sha256 ||
            row.GetProperty("SentAt").ValueKind != JsonValueKind.String || row.GetProperty("SentAt").GetDateTimeOffset() >= plan.Deadline ||
            (row.GetProperty("ExpiresAt").ValueKind == JsonValueKind.Null ? (DateTimeOffset?)null : row.GetProperty("ExpiresAt").GetDateTimeOffset()) != plan.SigningDeadline) throw Invalid();
    }
    private static InvalidDataException Invalid() => new("The exact frozen Send object and saved SQL outcome could not be verified.");
}

internal sealed partial class ProductionRecordOperationAdmission
{
    internal async Task PrepareSendWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor source, ProductionRecordWriteDescriptor target, CancellationToken ct = default)
    {
        if (scope.Kind != ProductionRecordSendWriteContract.Kind || !ProductionRecordSendWriteContract.Pair(scope.RecordId, source, target)) throw Invalid();
        await DemandStartingLockedAsync(db, scope, ct);
        var state = await witness.ReadAsync(scope.RecordId, ct); await DemandControls(db, scope.RecordId, state, ct);
        var deadlines = await SendDeadlineLocked(db, scope, source, draft: true, ct);
        await witness.PrepareSendWriteAsync(scope.RecordId, state.Operations![scope.OperationId], source, target, deadlines.Effective,
            deadlines.Draft, deadlines.Signing, SendId(scope, "plan"), ct);
        DocumentRetentionAccess.Check(deadlines.Effective, time);
    }

    internal async Task<bool> BeginSendWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor target, CancellationToken ct = default)
    {
        var state = await SendAuthorizationLocked(db, scope, target, started: false, ct);
        var began = await witness.BeginSendWriteAsync(scope.RecordId, state.Operations![scope.OperationId], target, SendId(scope, "begin"), ct);
        await DemandSendWriteLockedAsync(db, scope, target, ct); return began;
    }

    internal async Task DemandSendWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor target, CancellationToken ct = default)
        => _ = await SendAuthorizationLocked(db, scope, target, started: true, ct);

    internal async Task RecordSendWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteReceipt receipt, CancellationToken ct = default)
    {
        if (!ProductionRecordUploadWriteContract.Receipt(scope.RecordId, receipt)) throw Invalid();
        var state = await SendAuthorizationLocked(db, scope, receipt.Item, started: true, ct);
        await witness.RecordSendWriteAsync(scope.RecordId, state.Operations![scope.OperationId], receipt, SendId(scope, "receipt"), ct);
        await DemandSendWriteLockedAsync(db, scope, receipt.Item, ct);
    }

    internal async Task<ProductionRecordWriteReceipt?> ReadSendWriteReceiptLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor target, CancellationToken ct = default)
    {
        var state = await SendAuthorizationLocked(db, scope, target, started: false, ct);
        return state.SendWrites![scope.OperationId].Receipt;
    }

    // SQL has legitimately changed under the same reservation. Hints only wake
    // closed admitted workers; this check never authorizes another blob write.
    internal async Task DemandSendProgressLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct = default)
    {
        if (scope.Kind != ProductionRecordSendWriteContract.Kind) throw Invalid();
        await DemandLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct);
        await DemandControls(db, scope.RecordId, state, ct); var plan = state.SendWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (!ProductionRecordSendWriteContract.Complete(plan)) throw Invalid();
        await DemandSendDeadlineLocked(db, scope, plan, draft: false, ct);
        DemandActive(scope, await witness.ReadAsync(scope.RecordId, ct)); DocumentRetentionAccess.Check(plan.Deadline, time);
    }

    private async Task<HoldWitnessState> SendAuthorizationLocked(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor target, bool started, CancellationToken ct)
    {
        if (scope.Kind != ProductionRecordSendWriteContract.Kind) throw Invalid();
        await DemandStartingLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct);
        await DemandControls(db, scope.RecordId, state, ct); var plan = state.SendWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (plan.Target != target || started && !plan.Begun) throw Invalid();
        await DemandSendDeadlineLocked(db, scope, plan, draft: true, ct);
        DemandActive(scope, await witness.ReadAsync(scope.RecordId, ct)); DocumentRetentionAccess.Check(plan.Deadline, time); return state;
    }

    private async Task DemandSendOutcomeLocked(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionHoldSqlSnapshot current, HoldWitnessState state, CancellationToken ct)
    {
        var plan = state.SendWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        await DemandSendDeadlineLocked(db, scope, plan, draft: false, ct);
        ProductionRecordSendWriteContract.DemandSaved(current, keys, plan);
    }

    private async Task DemandSendDeadlineLocked(QuillSignDbContext db, ProductionRecordOperation scope, HoldWitnessSendWrite plan, bool draft, CancellationToken ct)
    {
        var saved = await SendDeadlineLocked(db, scope, plan.Source, draft, ct);
        if (saved.Effective != plan.Deadline || saved.Draft != plan.DraftDeadline || saved.Signing != plan.SigningDeadline) throw Invalid();
        DocumentRetentionAccess.Check(plan.Deadline, time);
    }

    private async Task<(DateTimeOffset Effective, DateTimeOffset Draft, DateTimeOffset? Signing)> SendDeadlineLocked(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor source, bool draft, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw Invalid();
        var row = await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x => x.Id == scope.RecordId, ct) ?? throw Invalid();
        var saved = await ProductionRecordRetentionAccess.ReadLockedAsync(db, row, time, ct);
        if (saved.Kind != ProductionEnrollmentKind.Enrolled || saved.Enrollment is not { } enrolled ||
            (draft ? row.Status != EnvelopeStatus.Draft : row.Status is not (EnvelopeStatus.Draft or EnvelopeStatus.Sent)) ||
            row.SenderVerifiedAt is null || row.PreviewConfirmedAt is null || row.PreviewConfirmedAt > time.GetUtcNow() ||
            row.PdfBlob != source.Blob.ObjectId.ToString("N") || row.PdfSha256 is not { Length: 32 } hash || Convert.ToHexStringLower(hash) != source.Sha256) throw Invalid();
        var draftDeadline = ProductionRetentionPolicyContract.AddDays(enrolled.OriginalCreatedAt, enrolled.Snapshot.Policy.AbandonedDraftDays);
        var signingDeadline = row.ExpiresAt?.ToUniversalTime();
        var deadline = ProductionRecordSendWriteContract.Earlier(draftDeadline, signingDeadline);
        DocumentRetentionAccess.Check(deadline, time); return (deadline, draftDeadline, signingDeadline);
    }

    private static Guid SendId(ProductionRecordOperation scope, string phase)
        => new(SHA256.HashData(Encoding.ASCII.GetBytes($"production-record-send-v1:{scope.RecordId:N}:{scope.OperationId:N}:{phase}")).AsSpan(0, 16));
}

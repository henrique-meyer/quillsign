using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal sealed record ProductionRecordWriteDescriptor(DocumentBlob Blob, long Length, string Sha256);
internal sealed record ProductionRecordWriteReceipt(ProductionRecordWriteDescriptor Item, string VersionId, string ETag);
internal sealed record HoldWitnessUploadWrites(ProductionRecordWriteDescriptor Original, ProductionRecordWriteDescriptor Normalized,
    ImmutableHashSet<DocumentBlob> Begun, ImmutableDictionary<DocumentBlob, ProductionRecordWriteReceipt> Receipts);

// Exactly two create-only objects for one original sender/upload reservation.
// This grants no generic path, deletion, timeout settlement or new operation.
internal static class ProductionRecordUploadWriteContract
{
    internal const string Version = "production-record-upload-writes-v1", Kind = "sender/upload";
    internal const long MaximumBytes = 32L * 1024 * 1024; // Adapter also enforces the configured upload limit.
    internal static bool Item(Guid recordId, ProductionRecordWriteDescriptor? item) => item is not null && recordId != Guid.Empty &&
        item.Blob.EnvelopeId == recordId && item.Blob.ObjectId != Guid.Empty && item.Blob.Kind is DocumentBlobKind.Original or DocumentBlobKind.Normalized &&
        item.Length is > 0 and <= MaximumBytes && item.Sha256 is { Length: 64 } && item.Sha256.All(char.IsAsciiHexDigitLower);
    internal static bool Pair(Guid recordId, ProductionRecordWriteDescriptor? original, ProductionRecordWriteDescriptor? normalized) =>
        Item(recordId, original) && Item(recordId, normalized) && original!.Blob.Kind == DocumentBlobKind.Original &&
        normalized!.Blob.Kind == DocumentBlobKind.Normalized && original.Blob.ObjectId != normalized.Blob.ObjectId;
    internal static bool Member(HoldWitnessUploadWrites plan, ProductionRecordWriteDescriptor item) => plan.Original == item || plan.Normalized == item;
    internal static bool Receipt(Guid recordId, ProductionRecordWriteReceipt? receipt) => receipt is not null && Item(recordId, receipt.Item) &&
        Opaque(receipt.VersionId) && Opaque(receipt.ETag);
    private static bool Opaque(string? value) => value is { Length: > 0 and <= 256 } && value != "*" && value.All(x => x is >= '!' and <= '~');
    internal static bool Complete(HoldWitnessUploadWrites plan) => plan.Begun.Count == 2 && plan.Receipts.Count == 2 &&
        plan.Begun.Contains(plan.Original.Blob) && plan.Begun.Contains(plan.Normalized.Blob) &&
        plan.Receipts.TryGetValue(plan.Original.Blob, out var original) && original.Item == plan.Original && Receipt(plan.Original.Blob.EnvelopeId, original) &&
        plan.Receipts.TryGetValue(plan.Normalized.Blob, out var normalized) && normalized.Item == plan.Normalized && Receipt(plan.Normalized.Blob.EnvelopeId, normalized);
    internal static void DemandSaved(ProductionHoldSqlSnapshot snapshot, IDataProtectionProvider keys, HoldWitnessUploadWrites plan)
    {
        if (!Complete(plan)) throw Invalid();
        using var document = ProductionHoldSqlInventory.OpenAcknowledgementVerified(snapshot, keys);
        var envelope = document.RootElement.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == "Envelopes")
            .GetProperty("Rows").EnumerateArray().Single();
        try
        {
            if (envelope.GetProperty("OriginalBlob").GetString() != plan.Original.Blob.ObjectId.ToString("N") ||
                envelope.GetProperty("PdfBlob").GetString() != plan.Normalized.Blob.ObjectId.ToString("N") ||
                envelope.GetProperty("OriginalSha256").ValueKind != System.Text.Json.JsonValueKind.String ||
                envelope.GetProperty("PdfSha256").ValueKind != System.Text.Json.JsonValueKind.String ||
                Convert.ToHexStringLower(envelope.GetProperty("OriginalSha256").GetBytesFromBase64()) != plan.Original.Sha256 ||
                Convert.ToHexStringLower(envelope.GetProperty("PdfSha256").GetBytesFromBase64()) != plan.Normalized.Sha256) throw Invalid();
        }
        catch (FormatException error) { throw new InvalidDataException("Upload SQL binding is malformed.", error); }
    }
    private static InvalidDataException Invalid() => new("The exact planned upload objects and saved SQL outcome could not be verified.");
}

internal sealed partial class ProductionRecordOperationAdmission
{
    internal async Task PrepareUploadWritesAsync(ProductionRecordOperation scope, ProductionRecordWriteDescriptor original,
        ProductionRecordWriteDescriptor normalized, CancellationToken ct = default)
    {
        if (scope.Kind != ProductionRecordUploadWriteContract.Kind || !ProductionRecordUploadWriteContract.Pair(scope.RecordId, original, normalized)) throw Invalid();
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DemandStartingLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct);
        await DemandControls(db, scope.RecordId, state, ct);
        var deadline = await UploadDeadlineLocked(db, scope.RecordId, ct);
        await witness.PrepareUploadWritesAsync(scope.RecordId, state.Operations![scope.OperationId], original, normalized,
            UploadId(scope, "plan"), ct); await tx.RollbackAsync(ct);
        DocumentRetentionAccess.Check(deadline, time);
    }

    internal async Task<bool> BeginUploadWriteAsync(ProductionRecordOperation scope, ProductionRecordWriteDescriptor item, CancellationToken ct = default)
    {
        var state = await UploadAuthorization(scope, item, false, ct);
        var began = await witness.BeginUploadWriteAsync(scope.RecordId, state.Operations![scope.OperationId], item, UploadId(scope, "begin", item), ct);
        await DemandUploadWriteAsync(scope, item, ct); return began;
    }

    internal async Task DemandUploadWriteAsync(ProductionRecordOperation scope, ProductionRecordWriteDescriptor item, CancellationToken ct = default)
        => _ = await UploadAuthorization(scope, item, true, ct);

    internal async Task RecordUploadWriteAsync(ProductionRecordOperation scope, ProductionRecordWriteReceipt receipt, CancellationToken ct = default)
    {
        if (!ProductionRecordUploadWriteContract.Receipt(scope.RecordId, receipt)) throw Invalid();
        var state = await UploadAuthorization(scope, receipt.Item, true, ct);
        await witness.RecordUploadWriteAsync(scope.RecordId, state.Operations![scope.OperationId], receipt, UploadId(scope, "receipt", receipt.Item), ct);
        await DemandUploadWriteAsync(scope, receipt.Item, ct);
    }

    internal async Task<ProductionRecordWriteReceipt?> ReadUploadWriteReceiptAsync(ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor item, CancellationToken ct = default)
    {
        var state = await UploadAuthorization(scope, item, false, ct);
        return state.UploadWrites![scope.OperationId].Receipts.GetValueOrDefault(item.Blob);
    }

    private async Task<HoldWitnessState> UploadAuthorization(ProductionRecordOperation scope, ProductionRecordWriteDescriptor item, bool requireStarted, CancellationToken ct)
    {
        if (scope.Kind != ProductionRecordUploadWriteContract.Kind || !ProductionRecordUploadWriteContract.Item(scope.RecordId, item)) throw Invalid();
        await using var db = open(); await using var tx = await db.Database.BeginTransactionAsync(ct);
        // Writes precede the caller's final SQL transaction. Recheck all original
        // business/request bytes, not merely the request head, on EVERY boundary.
        await DemandStartingLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct);
        await DemandControls(db, scope.RecordId, state, ct);
        var plan = state.UploadWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (!ProductionRecordUploadWriteContract.Member(plan, item) || requireStarted && !plan.Begun.Contains(item.Blob)) throw Invalid();
        DemandActive(scope, state);
        var deadline = await UploadDeadlineLocked(db, scope.RecordId, ct);
        await tx.RollbackAsync(ct); DocumentRetentionAccess.Check(deadline, time); return state;
    }

    private async Task<DateTimeOffset> UploadDeadlineLocked(QuillSignDbContext db, Guid recordId, CancellationToken ct)
    {
        // Authenticate the saved original policy under the same parent lock.
        // Provider permits never infer a lifetime from current configuration.
        var row = await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x => x.Id == recordId, ct) ?? throw Invalid();
        var retention = await ProductionRecordRetentionAccess.ReadLockedAsync(db, row, time, ct);
        if (retention.Kind != ProductionEnrollmentKind.Enrolled || retention.Stage != ProductionRecordStage.Draft ||
            row.Status != EnvelopeStatus.Draft || retention.Deadline is not { } deadline) throw Invalid();
        DocumentRetentionAccess.Check(deadline, time); return deadline;
    }

    private static Guid UploadId(ProductionRecordOperation scope, string phase, ProductionRecordWriteDescriptor? item = null)
        => new(SHA256.HashData(Encoding.ASCII.GetBytes($"production-record-upload-v1:{scope.RecordId:N}:{scope.OperationId:N}:{phase}:{item?.Blob.Kind}:{item?.Blob.ObjectId:N}")).AsSpan(0, 16));
}

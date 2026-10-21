using System.Security.Claims;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// Opt-in upload-only composition; neither a public capability nor registration.
// The same operation owns both writes, the SQL commit and exact acknowledgement.
internal sealed class ProductionRecordUploadAdmission(ProductionRecordOperationAdmission operations, IProductionRecordUploadStore store)
{
    private readonly ProductionSenderPreparationAdmission preparation = new(operations);

    internal Task<bool> ExecuteAsync(QuillSignDbContext db, Guid recordId, string senderEmail, string publicId,
        Func<ProductionRecordOperation?, Task<bool>> execute, CancellationToken ct)
        => preparation.ExecuteAsync(db, recordId, senderEmail, publicId, "sender/upload", execute, false, false, ct);

    internal Task PrepareAsync(ProductionRecordOperation scope, ProductionRecordWriteDescriptor original,
        ProductionRecordWriteDescriptor normalized, CancellationToken ct)
        => operations.PrepareUploadWritesAsync(scope, original, normalized, ct);

    internal async Task WriteAsync(ProductionRecordOperation scope, ClaimsPrincipal sender,
        ProductionRecordWriteDescriptor item, Stream source, CancellationToken ct)
    {
        var mayWrite = await operations.BeginUploadWriteAsync(scope, item, ct);
        var saved = await operations.ReadUploadWriteReceiptAsync(scope, item, ct);
        var receipt = await store.WriteAsync(scope, sender, item, source, mayWrite, saved,
            token => operations.DemandUploadWriteAsync(scope, item, token), ct);
        await operations.RecordUploadWriteAsync(scope, receipt, ct);
    }

    internal Task DemandStartingLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct)
        => operations.DemandStartingLockedAsync(db, scope, ct);
    internal Task PrepareOutcomeLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, CancellationToken ct)
        => operations.PrepareOutcomeLockedAsync(db, scope, ct);
}

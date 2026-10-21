using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

// Explicit opt-in for these SQL-only sender mutations. Default construction/DI
// stays unchanged. This neither initializes old records nor grants sender access.
internal sealed class ProductionSenderPreparationAdmission(ProductionRecordOperationAdmission operations)
{
    internal async Task<T> ExecuteAsync<T>(QuillSignDbContext db, Guid recordId, string senderEmail, string publicId,
        string kind, Func<ProductionRecordOperation?, Task<T>> execute, T notFound, T blocked, CancellationToken ct)
    {
        // AuditWriter may save all tracked changes. Never let this reservation
        // authorize another caller's pending work or an outer transaction.
        if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())
            throw new InvalidDataException("A clean caller context is required for sender preparation admission.");
        var record = await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x => x.Id == recordId, ct);
        if (record is null || record.PublicId != publicId || record.SenderVerifiedAt is null || record.Status != EnvelopeStatus.Draft ||
            !string.Equals(record.SenderEmail, senderEmail, StringComparison.OrdinalIgnoreCase)) return notFound;
        ProductionRecordOperation operation;
        bool demo;
        try
        {
            demo = await operations.IsUnenrolledDemoAsync(db, recordId, ct);
        }
        catch (Exception error) when (error is InvalidDataException or UnauthorizedAccessException or DocumentConflictException)
        { return blocked; }
        if (demo) return await execute(null);
        try
        {
            operation = await operations.BeginAsync(recordId, Guid.NewGuid(), kind, publicId, ct);
        }
        catch (Exception error) when (error is InvalidDataException or UnauthorizedAccessException or DocumentConflictException)
        { return blocked; }
        // The service's await-using transaction has committed/rolled back AND
        // disposed before it returns. Known validation/no-op results acknowledge
        // unchanged SQL; an exception/unknown commit never settles implicitly.
        var result = await execute(operation);
        var receipt = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            Version = "production-sender-preparation-sql-v1", operation.RecordId, operation.OperationId, operation.Kind, operation.Reference, Result = result
        })));
        await operations.CompleteAsync(operation, receipt, ct); return result;
    }

    internal Task DemandStartingLockedAsync(QuillSignDbContext db, ProductionRecordOperation operation, CancellationToken ct)
        => operations.DemandStartingLockedAsync(db, operation, ct);

    internal Task PrepareOutcomeLockedAsync(QuillSignDbContext db, ProductionRecordOperation operation, CancellationToken ct)
        => operations.PrepareOutcomeLockedAsync(db, operation, ct);
}

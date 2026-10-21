using System.Security.Cryptography;
using System.Text.Json;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

// A SQL-only application seam over the existing reservation protocol. It does
// not supply participant/operator authority, create sessions or retry effects.
internal sealed class ProductionTerminalMutationAdmission(ProductionRecordOperationAdmission operations)
{
    internal async Task<T> ExecuteAsync<T>(QuillSignDbContext db, Guid recordId, string action, string reference,
        Func<ProductionRecordOperation?,Task<T>> execute, CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())throw new InvalidDataException("A clean record action context is required.");
        if(action is not ("contact" or "resend"))throw new InvalidDataException("Unsupported sender action.");
        if(await operations.IsUnenrolledDemoAsync(db,recordId,ct))return await execute(null);
        var operation=await operations.BeginAsync(recordId,Guid.NewGuid(),"record/"+action,reference,ct);
        // The action owns/disposes its original transaction. A known validation
        // no-op can acknowledge only unchanged SQL; an exception/unknown commit
        // never reaches settlement and never authorizes replay or another send.
        var result=await execute(operation);
        await CompleteAsync(operation,JsonSerializer.Serialize(result),ct);
        return result;
    }

    internal async Task<ProductionRecordOperation?> BeginLockedAsync(QuillSignDbContext db, Guid recordId,
        string action, string reference, CancellationToken ct)
    {
        if (action is not ("void" or "expire" or "contact" or "resend")) throw new InvalidDataException("Unsupported terminal mutation.");
        if (await operations.IsUnenrolledDemoAsync(db, recordId, ct)) return null;
        return await operations.BeginLockedAsync(db, recordId, Guid.NewGuid(), "record/" + action, reference, ct);
    }

    internal Task DemandReadLockedAsync(QuillSignDbContext db, Guid recordId, DateTimeOffset until, CancellationToken ct)
        => operations.DemandUnfrozenReadLockedAsync(db, recordId, until, ct);

    internal Task PrepareOutcomeLockedAsync(QuillSignDbContext db, ProductionRecordOperation operation, CancellationToken ct)
        => operations.PrepareOutcomeLockedAsync(db, operation, ct);

    internal Task DemandStartingLockedAsync(QuillSignDbContext db, ProductionRecordOperation operation, CancellationToken ct)
        =>operations.DemandStartingLockedAsync(db,operation,ct);

    internal Task CompleteAsync(ProductionRecordOperation operation, string result, CancellationToken ct)
        => operations.CompleteAsync(operation, Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            Version = "production-record-sql-action-v1", operation.RecordId, operation.OperationId, operation.Kind, operation.Reference, Result = result
        }))), ct);
}

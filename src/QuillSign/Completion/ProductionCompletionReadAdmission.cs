using System.Security.Cryptography;
using System.Text.Json;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Completion;

// Internal opt-in composition. Global mailbox lookup tokens are not record authority.
internal sealed class ProductionCompletionReadAdmission(ProductionRecordOperationAdmission operations,TimeProvider time)
{
    internal async Task DemandLockedAsync(QuillSignDbContext db,Guid id,DateTimeOffset until,CancellationToken ct)
        =>await operations.DemandUnfrozenReadLockedAsync(db,id,until,ct);
    internal Task DemandAsync(Guid id,DateTimeOffset until,CancellationToken ct)
        =>operations.DemandUnfrozenReadAsync(id,until,ct);
    internal async Task<ProductionRecordOperation?> BeginLockedAsync(QuillSignDbContext db,Guid id,string kind,string reference,CancellationToken ct)
        =>await operations.IsUnenrolledDemoAsync(db,id,ct)?null:await operations.BeginLockedAsync(db,id,Guid.NewGuid(),kind,reference,ct);
    internal Task OutcomeLockedAsync(QuillSignDbContext db,ProductionRecordOperation? operation,CancellationToken ct)
        =>operation is null?Task.CompletedTask:operations.PrepareOutcomeLockedAsync(db,operation,ct);
    internal async Task CompleteAsync(ProductionRecordOperation? operation,CancellationToken ct)
    {
        if(operation is null)return;
        var receipt=Receipt(operation.RecordId,operation.OperationId,operation.Kind,operation.Reference);
        await operations.CompleteAsync(operation,receipt,ct);
    }
    internal static string Receipt(Guid recordId,Guid operationId,string kind,string reference)=>Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{version="completion-access-result-v1",RecordId=recordId,OperationId=operationId,Kind=kind,Reference=reference})));
    internal async Task<CompletionAccessPreparation?> PrepareAsync(QuillSignDbContext db,CompletionAccessState state,Guid id,CancellationToken ct)
    {
        var until=time.GetUtcNow().AddMinutes(2);
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var prepared=await state.PrepareLockedAsync(id,t=>DemandLockedAsync(db,id,until,t),()=>{ct.ThrowIfCancellationRequested();if(until<=time.GetUtcNow())throw CompletionAccessState.Invalid();},ct);
        await tx.RollbackAsync(ct);await tx.DisposeAsync();
        if(prepared is not null)await DemandAsync(id,prepared.Until,ct);
        return prepared;
    }
}

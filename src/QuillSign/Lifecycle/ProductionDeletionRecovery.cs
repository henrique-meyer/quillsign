using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Work;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

internal sealed partial class ProductionDeletionCoordinator
{
    internal async Task<(int Examined,int Pending,string? Continuation)> RecoverBatchAsync(string? continuation,CancellationToken ct=default)
    {
        options.Demand();var page=await recovery.ListAsync(continuation,8,ct);var pending=0;
        foreach(var hint in page.Hints){
            if(hint.RecordId==Guid.Empty||hint.DeletionId!=DeletionId(hint.RecordId)||!ProductionDeletionProtocol.Hash(hint.PlanSha256))throw ProductionDeletionProtocol.Invalid();
            try{await RecoverAsync(hint.RecordId,ct);if((await witness.ReadAsync(hint.RecordId,ct)).Deletion?.WorkFinished!=true)pending++;}
            catch(Exception e)when(!ct.IsCancellationRequested&&(e is InvalidDataException or Azure.RequestFailedException or IOException||SqlResume.IsUnavailable(e))){pending++;}
        }
        return(page.Hints.Count,pending,page.Continuation);
    }

    // A bounded, explicitly invoked continuation. The private index can select
    // candidates but never supplies authority; immutable state is read again.
    internal async Task RecoverAsync(Guid recordId,CancellationToken ct=default)
    {
        options.Demand();var state=await witness.ReadAsync(recordId,ct);var d=state.Deletion??throw ProductionDeletionProtocol.Invalid();
        if(d.Header is null)throw ProductionDeletionProtocol.Invalid();
        foreach(var pending in d.Effects!.Where(x=>x.Value.Result is null).ToArray()){
            var parts=pending.Key.Split('/');await ApplyStoragePhase(recordId,int.Parse(parts[0],System.Globalization.CultureInfo.InvariantCulture),
                (QuillSign.Storage.ProductionDeletionPhase)int.Parse(parts[1],System.Globalization.CultureInfo.InvariantCulture),ct);
        }
        if(d.SqlReserved)await ReconcileSql(recordId,ct);
        state=await witness.ReadAsync(recordId,ct);d=state.Deletion!;
        if(d.SqlCommitted){
            // Only the invocation that successfully creates a fresh epoch may
            // use it for new destructive work. A stored live owner or a lost
            // creation acknowledgement is a fact, never an execution permit.
            var ownsEpoch=false;
            if(d.FinishedWorkJson is not null){await ReconcileCompletedAsync(new(d.Header!.WorkId,d.Lease!.Owner,QuillSign.Data.WorkKind.ProductionPurge,d.Lease.Attempt,d.Lease.Until),recordId,ct);return;}
            if(d.Lease!.Until<=time.GetUtcNow()){
                if(d.SqlExpectedSha256 is not null||d.Effects!.Values.Any(x=>x.Result is null))throw ProductionDeletionProtocol.Invalid();
                var original=d.ClaimWorkJson??d.SqlExpectedWorkJson??throw ProductionDeletionProtocol.Invalid();
                var next=new ProductionDeletionMaintenanceLease(Guid.NewGuid(),checked(d.Lease.Attempt+1),time.GetUtcNow().AddSeconds(workOptions.LeaseSeconds),original,true,true);
                await witness.DemandDeletionHeadroomAsync(recordId,0,0,ct);
                state=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.RecoveryReserved,d.Header!.DeletionId,
                    Body:JsonSerializer.Serialize(next,ProductionDeletionProtocol.Json),SqlStateSha256:d.SqlStateSha256,ContentSha256:d.ContentSha256),"lease/"+next.Attempt,ct);
                ownsEpoch=true;
            }
            if(!ownsEpoch)return;
            // No SQL call is needed to finish active object reconciliation once
            // the exact SQL commit acknowledgement is durably recorded.
            if(!state.Deletion!.Terminal){
                await RunStorage(recordId,ct);state=await witness.ReadAsync(recordId,ct);d=state.Deletion!;
                await SealTerminal(state,ct);
            }
            // SQL may still be offline. Storage reconciliation is already
            // recorded; when available, claim/ack the exact technical row under
            // this SAME epoch before worker Finish. Never infer this from absence.
            try{
                await using var finishDb=open();var technicalClaim=await ClaimAsync(finishDb,d.Header!.WorkId,ct);
                if(technicalClaim.Lease is{} currentLease)await FinishAsync(finishDb,currentLease,new(WorkOutcome.Completed,"production-active-data-cleaned"),ct);
                else if(!technicalClaim.Terminal)throw ProductionDeletionProtocol.Invalid();
            }catch(Exception e)when(!ct.IsCancellationRequested&&SqlResume.IsUnavailable(e)){}
            return;
        }
        await using var db=open();var claim=await ClaimAsync(db,d.Header!.WorkId,ct);
        if(claim.Lease is not{} lease)throw ProductionDeletionProtocol.Invalid();
        var result=await ExecuteAsync(lease,ct);await FinishAsync(db,lease,result,ct);
    }
}

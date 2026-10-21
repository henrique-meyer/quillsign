using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

internal sealed partial class ProductionDeletionCoordinator
{
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        options.Demand();await using var db=open();var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct)
            ??throw ProductionDeletionProtocol.Invalid();var payload=ReadPayload(row.PayloadJson);
        var state=await witness.ReadAsync(payload.RecordId,ct);DemandLease(state,lease);
        await RunStorage(payload.RecordId,ct);
        state=await witness.ReadAsync(payload.RecordId,ct);
        if(!state.Deletion!.SqlCommitted)await RemoveSql(payload.RecordId,lease,ct);
        await RunStorage(payload.RecordId,ct);
        state=await witness.ReadAsync(payload.RecordId,ct);
        await SealTerminal(state,ct);
        return new(WorkOutcome.Completed,"production-active-data-cleaned");
    }

    private Task<HoldWitnessState> SealTerminal(HoldWitnessState state,CancellationToken ct)
    {
        var d=state.Deletion!;var h=d.Header!;
        return d.Terminal?Task.FromResult(state):Event(h.RecordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.Terminal,h.DeletionId,
            Sha256:ProductionDeletionProtocol.Digest(new{Version="production-active-data-cleanup-v1",h.RecordId,h.DeletionId,
                d.PlanSha256,d.StorageReceiptSha256,SqlWork=d.SqlExpectedWorkJson})),"terminal",ct);
    }

    private async Task RunStorage(Guid recordId,CancellationToken ct)
    {
        var state=await witness.ReadAsync(recordId,ct);var deletion=state.Deletion??throw ProductionDeletionProtocol.Invalid();
        if(deletion.Header is null||!deletion.ClaimAccepted)throw ProductionDeletionProtocol.Invalid();
        // The mutable index is a scheduling hint only. Every continuation starts
        // again from this authenticated immutable chain, never from hint absence.
        if(deletion.PlanSha256 is null){
            var scope=ReadScope(state,false);ProductionDeletionPlan inventory;
            try{inventory=await Census(scope,ct);}finally{scope.Close();}
            state=await FreezePlan(state,inventory,ct);deletion=state.Deletion!;
        }
        // An earlier publication may have failed before the hint existed. The
        // immutable first-plan digest gives the create-only hint one stable
        // identity even after bounded later plan extensions. Acknowledgement is
        // required on every continuation before any destructive effect.
        var indexScope=ReadScope(state,true);
        try{await recovery.RememberAsync(indexScope,new(recordId,deletion.Header!.DeletionId,deletion.RecoveryPlanSha256??throw ProductionDeletionProtocol.Invalid()),ct);}finally{indexScope.Close();}
        for(var index=0;index<deletion.Items!.Length;index++){
            var item=deletion.Items[index];
            if(item.Item.IsCurrent&&item.Item.VersionId.Length>0)
                state=await ApplyStoragePhase(recordId,index,ProductionDeletionPhase.RootDemotion,ct);
            state=await ApplyStoragePhase(recordId,index,ProductionDeletionPhase.HistoricalDelete,ct);
        }
        state=await witness.ReadAsync(recordId,ct);deletion=state.Deletion!;
        var verify=ReadScope(state,true);ProductionDeletionObject[] remaining;
        try{remaining=await Addresses(verify,ct);}finally{verify.Close();}
        // Known provider soft-deleted/tombstone facts are retained observations,
        // not active bytes and never a universal physical-erasure claim. Unknown
        // names/selectors, including late writes, cannot silently disappear.
        var unknown=remaining.Where(x=>!KnownInactive(deletion,x)).ToArray();
        if(unknown.Length!=0){
            var additions=unknown.Where(x=>!deletion.Items!.Any(i=>SameSelector(i.Item,x))).ToArray();
            if(additions.Length!=unknown.Length||deletion.SqlExpectedSha256 is not null||deletion.Terminal)throw ProductionDeletionProtocol.Invalid();
            var read=ReadScope(state,true);var evidence=new List<ProductionDeletionInspection>();
            try{foreach(var item in additions)evidence.Add(await storage.InspectAsync(read,item,ct));}finally{read.Close();}
            await FreezePlan(state,new(deletion.Items!.Length,evidence.ToArray()),ct);
            // Preserve a finite batch boundary; later work/recovery resumes the
            // immutable extended set. Do not expand one request without bounds.
            throw ProductionDeletionProtocol.Invalid();
        }
        var digest=ProductionDeletionProtocol.Digest(new{Version="production-deletion-storage-observation-v1",recordId,deletion.Header!.DeletionId,
            deletion.PlanSha256,Outcomes=deletion.Effects!.OrderBy(x=>x.Key,StringComparer.Ordinal).ToArray(),Retained=remaining});
        if(deletion.StorageReceiptSha256 is null)
            await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.StorageVerified,deletion.Header.DeletionId,Sha256:digest),
                "storage/"+deletion.Items!.Length,ct);
    }

    private async Task<HoldWitnessState> ApplyStoragePhase(Guid recordId,int index,ProductionDeletionPhase phase,CancellationToken ct)
    {
        var state=await witness.ReadAsync(recordId,ct);var deletion=state.Deletion!;var h=deletion.Header!;
        var key=ProductionDeletionProtocol.EffectKey(index,phase);var purpose="item/"+key;
        if(deletion.Effects!.TryGetValue(key,out var prior)&&prior.Result is not null)return state;
        var expected=deletion.Items![index];
        if(prior is null){
            DemandLeaseLive(deletion);await witness.DemandDeletionHeadroomAsync(recordId,1,0,ct);
            // Inspect immediately before recording intent. Protection is checked
            // again inside the exact provider adapter before any DELETE.
            var check=ReadScope(state,false);
            try{var actual=await storage.InspectAsync(check,expected.Item,ct);
                if(actual!=expected||actual.LegalHold||actual.ImmutableUntil>time.GetUtcNow())throw ProductionDeletionProtocol.Invalid();}
            finally{check.Close();}
            state=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.ItemIntent,h.DeletionId,
                Index:index,Phase:phase,Sha256:ProductionDeletionProtocol.Digest(expected)),purpose+"/intent",ct);
            var scope=ReadScope(state,false);ProductionDeletionResult result;
            try{result=await storage.DeleteAsync(scope,expected,phase,ct);}finally{scope.Close();}
            return await RecordOutcome(state,index,phase,result,purpose,ct);
        }
        // There is already a possibly sent request. Recreated scopes never
        // replay it; only exact readonly outcome reconciliation can progress.
        var recoveryScope=ReadScope(state,true);ProductionDeletionResult observed;
        try{observed=await storage.ReadDeleteOutcomeAsync(recoveryScope,expected,phase,ct);}finally{recoveryScope.Close();}
        return await RecordOutcome(state,index,phase,observed,purpose,ct);
    }
    private Task<HoldWitnessState> RecordOutcome(HoldWitnessState state,int index,ProductionDeletionPhase phase,ProductionDeletionResult result,string purpose,CancellationToken ct)
    {
        var d=state.Deletion!;
        if(phase==ProductionDeletionPhase.RootDemotion?!result.RootAbsent:!result.Absent)throw ProductionDeletionProtocol.Invalid();
        return Event(d.Header!.RecordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.ItemRecorded,d.Header.DeletionId,
            Body:JsonSerializer.Serialize(result,ProductionDeletionProtocol.Json),Index:index,Phase:phase,Sha256:ProductionDeletionProtocol.Digest(result)),purpose+"/outcome",ct);
    }

    private async Task<HoldWitnessState> FreezePlan(HoldWitnessState state,ProductionDeletionPlan plan,CancellationToken ct)
    {
        var h=state.Deletion!.Header!;var bytes=JsonSerializer.SerializeToUtf8Bytes(plan,ProductionDeletionProtocol.Json);
        if(bytes.Length>ProductionDeletionProtocol.MaximumPlanBytes)throw ProductionDeletionProtocol.Invalid();
        var chunks=(bytes.Length+ProductionDeletionProtocol.ChunkBytes-1)/ProductionDeletionProtocol.ChunkBytes;
        await witness.DemandDeletionHeadroomAsync(h.RecordId,plan.Items.Length,chunks,ct);
        try{
            for(var i=0;i<chunks;i++){
                var body=Convert.ToBase64String(bytes.AsSpan(i*ProductionDeletionProtocol.ChunkBytes,Math.Min(ProductionDeletionProtocol.ChunkBytes,bytes.Length-i*ProductionDeletionProtocol.ChunkBytes)));
                state=await Event(h.RecordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.PlanChunk,h.DeletionId,
                    Body:body,Index:i,Count:chunks,Sha256:ProductionDeletionProtocol.Digest(body)),"plan/"+plan.StartIndex+"/chunk/"+i,ct);
            }
            return await Event(h.RecordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.PlanFrozen,h.DeletionId,
                Sha256:Convert.ToHexStringLower(SHA256.HashData(bytes))),"plan/"+plan.StartIndex+"/frozen",ct);
        }finally{CryptographicOperations.ZeroMemory(bytes);}
    }

    private async Task<ProductionDeletionPlan> Census(ProductionDeletionObjectScope scope,CancellationToken ct)
    {
        var before=await Addresses(scope,ct);var values=new List<ProductionDeletionInspection>();
        foreach(var item in before.Where(x=>!x.Deleted&&!x.HasVersionsOnly))values.Add(await storage.InspectAsync(scope,item,ct));
        var after=await Addresses(scope,ct);if(!before.SequenceEqual(after))throw ProductionDeletionProtocol.Invalid();
        return new(0,values.ToArray(),before.Where(x=>x.Deleted||x.HasVersionsOnly).ToArray());
    }
    private async Task<ProductionDeletionObject[]> Addresses(ProductionDeletionObjectScope scope,CancellationToken ct)
    {
        var values=new List<ProductionDeletionObject>();var identities=new HashSet<string>(StringComparer.Ordinal);long bytes=0;
        foreach(var area in ProductionDeletionObjectScope.Areas){
            var prefixes=area=="final"?scope.ArchivePrefixes.Prepend(scope.RecordId.ToString("N")+"/"):new[]{scope.RecordId.ToString("N")+"/"};
            foreach(var prefix in prefixes){string? token=null;var seen=new HashSet<string>(StringComparer.Ordinal);
                do{var page=await storage.ListAsync(scope,area,prefix,token,128,ct);
                    foreach(var item in page.Objects){scope.DemandItem(item);if(!identities.Add(ProductionDeletionProtocol.Identity(item))||values.Count>=4096)throw ProductionDeletionProtocol.Invalid();
                        bytes=checked(bytes+item.Length);if(bytes>256L*1024*1024)throw ProductionDeletionProtocol.Invalid();values.Add(item);}
                    token=page.Continuation;if(token is not null&&!seen.Add(token))throw ProductionDeletionProtocol.Invalid();
                }while(token is not null);
            }
        }
        return values.OrderBy(ProductionDeletionProtocol.Identity,StringComparer.Ordinal).ToArray();
    }
    private ProductionDeletionObjectScope ReadScope(HoldWitnessState state,bool readOnly)
    {
        var d=state.Deletion??throw ProductionDeletionProtocol.Invalid();var h=d.Header??throw ProductionDeletionProtocol.Invalid();
        if(!readOnly)DemandLeaseLive(d);var until=ObservedNow(h.RecordId).AddMinutes(9);
        if(!readOnly&&d.Lease!.Until<until)until=d.Lease.Until;
        return ProductionDeletionObjectScope.Create(h.RecordId,h.DeletionId,h.ArchivePrefixes,time,until,async ct=>{
            _=ObservedNow(h.RecordId);if(!readOnly)DemandLeaseLive(d);var current=await witness.ReadAsync(h.RecordId,ct);
            if(current.HeadHash!=state.HeadHash||current.Deletion?.Header?.DeletionId!=h.DeletionId)throw ProductionDeletionProtocol.Invalid();_=ObservedNow(h.RecordId);
        });
    }
    private static bool KnownInactive(HoldWitnessDeletionState d,ProductionDeletionObject x)
    {
        if(!(x.Deleted||x.HasVersionsOnly))return false;
        if((d.InactiveItems??[]).Contains(x))return true;
        // Root-demotion's versions-only listing is a separately retained
        // provider fact, tied to the exact name whose known current was demoted.
        if(x.HasVersionsOnly&&x.VersionId.Length==0&&x.Snapshot.Length==0&&d.Effects!.Values.Any(e=>
            e.Phase==ProductionDeletionPhase.RootDemotion&&e.Result?.RootAbsent==true&&e.Inspection.Item.Area==x.Area&&e.Inspection.Item.Name==x.Name))return true;
        return d.Effects!.Values.Any(e=>SameSelector(e.Inspection.Item,x)&&e.Phase==ProductionDeletionPhase.HistoricalDelete&&e.Result?.Absent==true);
    }
    private static bool SameSelector(ProductionDeletionObject a,ProductionDeletionObject b)=>a.Area==b.Area&&a.Name==b.Name&&a.VersionId==b.VersionId&&a.Snapshot==b.Snapshot;
    private void DemandLeaseLive(HoldWitnessDeletionState deletion)
    {if(deletion.Lease is not{} lease||!deletion.ClaimAccepted||lease.Until<=ObservedNow(deletion.Header!.RecordId))throw ProductionDeletionProtocol.Invalid();}
    private void DemandLease(HoldWitnessState state,WorkLease lease)
    {var d=state.Deletion??throw ProductionDeletionProtocol.Invalid();var h=d.Header??throw ProductionDeletionProtocol.Invalid();var l=d.Lease!;
        if(lease.Id!=h.WorkId||lease.Owner!=l.Owner||lease.Attempt!=l.Attempt||lease.Until!=l.Until||lease.Kind!=WorkKind.ProductionPurge)throw ProductionDeletionProtocol.Invalid();DemandLeaseLive(d);}
}

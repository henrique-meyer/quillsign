using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

internal sealed partial class ProductionDeletionCoordinator
{
    private async Task RemoveSql(Guid recordId,WorkLease lease,CancellationToken ct)
    {
        var state=await witness.ReadAsync(recordId,ct);var d=state.Deletion!;var h=d.Header!;
        if(d.SqlCommitted)return;
        if(d.SqlReserved){
            if(await ReconcileSql(recordId,ct))return;
            state=await witness.ReadAsync(recordId,ct);d=state.Deletion!;
            if(d.SqlReserved)throw ProductionDeletionProtocol.Invalid();
        }
        DemandLease(state,lease);await witness.DemandDeletionHeadroomAsync(recordId,0,0,ct);
        await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);
        await DemandSql(db,state,ct);
        state=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.SqlReserved,h.DeletionId,
            Sha256:d.StorageReceiptSha256),"sql/"+lease.Attempt+"/"+(d.SqlRound+1)+"/reserved",ct);
        var scope=await ProductionDeletionSqlScope.AuthenticateLockedAsync(db,keys,time,witness,recordId,ct);
        if(!await ProductionPurgeSql.RemoveLockedAsync(db,scope,ct))throw ProductionDeletionProtocol.Invalid();
        var detached=await ReadDetached(db,h,ct);var body=JsonSerializer.Serialize(detached,Rows);
        state=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.SqlExpected,h.DeletionId,
            Body:body,Sha256:ProductionDeletionProtocol.Digest(body)),"sql/"+lease.Attempt+"/"+state.Deletion!.SqlRound+"/expected",ct);
        DemandLease(state,lease);await tx.CommitAsync(ct);await tx.DisposeAsync();
        if(!await ReconcileSql(recordId,ct))throw ProductionDeletionProtocol.Invalid();
    }

    // This path never calls the procedure or changes participant rows. Exact
    // expected detached Work bytes (including generated RV), not SQL absence,
    // reconcile a lost commit acknowledgement. Exact old FULL SQL proves a
    // known rollback; every other restored/partial state stays quarantined.
    private async Task<bool> ReconcileSql(Guid recordId,CancellationToken ct)
    {
        var state=await witness.ReadAsync(recordId,ct);var d=state.Deletion!;var h=d.Header!;
        if(d.SqlCommitted)return true;if(!d.SqlReserved)return false;
        await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);
        var parent=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={recordId}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(parent is null){
            if(d.SqlExpectedWorkJson is null||d.SqlExpectedSha256 is null)throw ProductionDeletionProtocol.Invalid();
            var work=await ReadDetached(db,h,ct);
            if(JsonSerializer.Serialize(work,Rows)!=d.SqlExpectedWorkJson)throw ProductionDeletionProtocol.Invalid();
            var after=await witness.ReadAsync(recordId,ct);if(after.HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
            await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.SqlCommitted,h.DeletionId,Sha256:d.SqlExpectedSha256),
                "sql/"+d.Lease!.Attempt+"/"+d.SqlRound+"/committed",ct);return true;
        }
        // A rolled-back caller transaction restores the very same acknowledged
        // owned SQL, not a new baseline or guessed no-effect from missing rows.
        await DemandSql(db,state,ct);
        await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.SqlNoEffect,h.DeletionId,
            SqlStateSha256:d.SqlStateSha256,ContentSha256:d.ContentSha256),"sql/"+d.Lease!.Attempt+"/"+d.SqlRound+"/no-effect",ct);
        return false;
    }

    private async Task<WorkItem> ReadDetached(QuillSignDbContext db,ProductionDeletionHeader h,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null||await db.Envelopes.AnyAsync(x=>x.Id==h.RecordId,ct)||
            await db.WorkItems.AnyAsync(x=>x.EnvelopeId==h.RecordId,ct))throw ProductionDeletionProtocol.Invalid();
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={h.WorkId}").AsNoTracking().SingleAsync(ct);
        if(row.EnvelopeId is not null||row.Kind!=WorkKind.ProductionPurge||row.PayloadJson!=ProductionDeletionProtocol.Payload(h.RecordId,h.DeletionId))throw ProductionDeletionProtocol.Invalid();
        return row;
    }

    public async Task<DateTimeOffset?> FinishAsync(QuillSignDbContext db,WorkLease lease,WorkResult result,CancellationToken ct)
    {
        options.Demand();if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges()||result.Outcome!=WorkOutcome.Completed||result.Code!="production-active-data-cleaned")throw ProductionDeletionProtocol.Invalid();
        var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,ct);var p=ReadPayload(row.PayloadJson);
        var state=await witness.ReadAsync(p.RecordId,ct);var d=state.Deletion!;var h=d.Header!;
        if(d.WorkFinished){await ReconcileCompletedAsync(lease,p.RecordId,ct);return null;}
        DemandLease(state,lease);if(d.Lease!.StorageOnly||!d.Terminal)throw ProductionDeletionProtocol.Invalid();
        await using var tx=await db.Database.BeginTransactionAsync(ct);row=await ReadDetached(db,h,ct);
        if(d.FinishedWorkJson is null){
            if(JsonSerializer.Serialize(row,Rows)!=(d.ClaimWorkJson??d.SqlExpectedWorkJson))throw ProductionDeletionProtocol.Invalid();
            var now=time.GetUtcNow();
            var changed=await db.WorkItems.Where(x=>x.Id==lease.Id&&x.Kind==lease.Kind&&x.Status==WorkStatus.Leased&&x.LeaseOwner==lease.Owner&&x.Attempts==lease.Attempt&&x.LeaseExpiresAt==lease.Until&&x.LeaseExpiresAt>now)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,WorkStatus.Completed).SetProperty(x=>x.AvailableAt,now).SetProperty(x=>x.LastError,result.Code)
                    .SetProperty(x=>x.LeaseOwner,(Guid?)null).SetProperty(x=>x.LeaseExpiresAt,(DateTimeOffset?)null),ct);
            if(changed!=1)throw ProductionDeletionProtocol.Invalid();
            var saved=await ReadDetached(db,h,ct);var json=JsonSerializer.Serialize(saved,Rows);
            await Event(p.RecordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.WorkFinishExpected,p.DeletionId,
                Body:json,Sha256:ProductionDeletionProtocol.Digest(json)),"finish/"+lease.Attempt+"/"+(d.FinishRound+1)+"/expected",ct);
            if(lease.Until<=time.GetUtcNow())throw ProductionDeletionProtocol.Invalid();await tx.CommitAsync(ct);
        }
        await tx.DisposeAsync();await ReconcileCompletedAsync(lease,p.RecordId,ct);return null;
    }
    public async Task ReconcileCompletedAsync(WorkLease lease,Guid recordId,CancellationToken ct)
    {
        var state=await witness.ReadAsync(recordId,ct);var d=state.Deletion??throw ProductionDeletionProtocol.Invalid();var h=d.Header??throw ProductionDeletionProtocol.Invalid();
        if(!d.Terminal||d.FinishedWorkJson is null||lease.Id!=h.WorkId||lease.Owner!=d.Lease!.Owner||lease.Attempt!=d.Lease.Attempt||lease.Until!=d.Lease.Until||lease.Kind!=WorkKind.ProductionPurge)throw ProductionDeletionProtocol.Invalid();
        await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);var actual=await ReadDetached(db,h,ct);
        var bytes=JsonSerializer.Serialize(actual,Rows);
        if((await witness.ReadAsync(recordId,ct)).HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
        if(bytes==(d.ClaimWorkJson??d.SqlExpectedWorkJson)&&actual.Status==WorkStatus.Leased){
            await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.WorkFinishNoEffect,h.DeletionId,
                Sha256:ProductionDeletionProtocol.Digest(bytes)),"finish/"+lease.Attempt+"/"+d.FinishRound+"/no-effect",ct);return;
        }
        if(actual.Status!=WorkStatus.Completed||actual.Attempts!=lease.Attempt||actual.LeaseOwner is not null||actual.LeaseExpiresAt is not null||bytes!=d.FinishedWorkJson)throw ProductionDeletionProtocol.Invalid();
        if(!d.WorkFinished)await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.WorkFinished,h.DeletionId,
            Sha256:ProductionDeletionProtocol.Digest(d.FinishedWorkJson)),"finish/"+lease.Attempt+"/"+d.FinishRound+"/ack",ct);
    }

    // Recorded external lifecycle facts remain readable when SQL is absent or
    // unavailable. This is not a fresh provider/SQL absence assertion.
    internal async Task<ProductionDeletionStatus> ReadRecordedStatusAsync(Guid recordId,CancellationToken ct=default)
    {
        var state=await witness.ReadAsync(recordId,ct);return RecordedStatus(recordId,state);
    }
    internal static ProductionDeletionStatus RecordedStatus(Guid recordId,HoldWitnessState state)
    {
        var d=state.Deletion;
        var label=d?.Terminal==true?"Recorded active-data cleanup; restore barrier retained":d?.SqlCommitted==true?
            "SQL removal recorded; storage outcome pending":d?.Reserved==true?"Deletion reserved; access frozen":"No deletion reservation recorded";
        return new(recordId,d?.Header?.DeletionId,label,d?.SqlCommitted==true,d?.Terminal==true,d?.Header?.EligibleAt,state.Sequence,state.HeadHash);
    }

    internal async Task<ProductionDeletionStatus> ReadStatusAsync(Guid recordId,CancellationToken ct=default)
    {
        var state=await witness.ReadAsync(recordId,ct);var d=state.Deletion;
        if(d?.Header is{} header){
            await using var db=open();var restored=await db.Envelopes.AsNoTracking().AnyAsync(x=>x.Id==recordId,ct);
            var label=d.SqlCommitted&&restored?"Restored SQL quarantined":d.Terminal?"Verified active-data cleanup":
                d.SqlCommitted?"SQL removed; storage reconciliation pending":d.Effects?.Values.Any(x=>x.Result is null)==true||d.SqlReserved?"Deletion outcome pending":"Deletion reserved; access frozen";
            if((await witness.ReadAsync(recordId,ct)).HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
            return new(recordId,header.DeletionId,label,d.SqlCommitted&&!restored,d.Terminal&&!restored,header.EligibleAt,state.Sequence,state.HeadHash);
        }
        await using(var db=open()){
            var verified=await holds.ReadVerifiedAsync(recordId,ct);if(verified.HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==recordId,ct);var retained=await ProductionRecordRetentionAccess.ReadLockedAsync(db,e,time,ct);
            var text=state.Frozen?"Hold or business outcome blocks deletion":retained.Deadline is null?"Indefinite or awaiting disposition":retained.Deadline>time.GetUtcNow()?"Original retention has not elapsed":
                retained.Stage==ProductionRecordStage.Completed&&d?.Disposition is null?"Copy/archive disposition attestation required":"Original finite retention elapsed";
            return new(recordId,null,text,false,false,retained.Deadline,state.Sequence,state.HeadHash);
        }
    }
}

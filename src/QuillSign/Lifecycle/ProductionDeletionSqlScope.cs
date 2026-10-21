using System.Data.Common;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// The only bridge into the narrow SQL procedure. Authenticate the actual
// immutable deletion state AND the full current SQL projection under the SAME
// physical parent transaction. Digests or a recovery hint alone cannot mint it.
internal sealed class ProductionDeletionSqlScope
{
    private readonly QuillSignDbContext db;
    private readonly DbTransaction transaction;
    private readonly ProductionHoldWitnessJournal witness;
    private readonly TimeProvider time;
    private readonly string head;
    private long observed;
    private ProductionDeletionSqlScope(QuillSignDbContext db,ProductionHoldWitnessJournal witness,TimeProvider time,
        HoldWitnessState state,ProductionHoldSqlSnapshot sql,byte[] rowVersion)
    {
        this.db=db;transaction=db.Database.CurrentTransaction!.GetDbTransaction();this.witness=witness;this.time=time;head=state.HeadHash!;
        var deletion=state.Deletion!;var header=deletion.Header!;
        var current=deletion.Lease!;
        RecordId=header.RecordId;DeletionId=header.DeletionId;Lease=new(header.WorkId,current.Owner,WorkKind.ProductionPurge,current.Attempt,current.Until);
        parentRowVersion=rowVersion.ToArray();PolicySha256=header.PolicySha256;EligibleAt=header.EligibleAt;
        SqlStateSha256=sql.StateSha256;ContentSha256=deletion.ContentSha256!;RequestRevision=header.RequestRevision;FenceHash=header.FenceHash;
        Control=header.Control;PlanSha256=deletion.PlanSha256!;StorageReceiptSha256=deletion.StorageReceiptSha256!;
        Counts=new System.Collections.ObjectModel.ReadOnlyDictionary<string,long>(sql.Tables.ToDictionary(x=>x.Table,x=>x.Rows)
            .Append(new KeyValuePair<string,long>("ProductionHoldControls",header.Control.Sequence)).ToDictionary(x=>x.Key,x=>x.Value));
        observed=time.GetUtcNow().UtcTicks;
    }
    internal Guid RecordId{get;}
    internal Guid DeletionId{get;}
    internal WorkLease Lease{get;}
    private readonly byte[] parentRowVersion;
    internal byte[] ParentRowVersion=>parentRowVersion.ToArray();
    internal string PolicySha256{get;}
    internal DateTimeOffset EligibleAt{get;}
    internal string SqlStateSha256{get;}
    internal string ContentSha256{get;}
    internal long RequestRevision{get;}
    internal string? FenceHash{get;}
    internal ProductionHoldControlPrefix Control{get;}
    internal IReadOnlyDictionary<string,long> Counts{get;}
    internal string PlanSha256{get;}
    internal string StorageReceiptSha256{get;}

    internal static async Task<ProductionDeletionSqlScope> AuthenticateLockedAsync(QuillSignDbContext db,IDataProtectionProvider keys,
        TimeProvider time,ProductionHoldWitnessJournal witness,Guid recordId,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw ProductionDeletionProtocol.Invalid();
        var state=await witness.ReadAsync(recordId,ct);var deletion=state.Deletion;
        if(deletion?.Header is not{} h||deletion.SqlCommitted||!deletion.SqlReserved||deletion.SqlExpectedSha256 is not null||!deletion.ClaimAccepted||
            deletion.StorageReceiptSha256 is null||deletion.PlanSha256 is null||h.RecordId!=recordId||deletion.Lease!.Until<=time.GetUtcNow())throw ProductionDeletionProtocol.Invalid();
        var requests=await new ProductionHoldRequests(db,keys,time).ReadLockedAsync(recordId,ct);
        ProductionHoldWitnessJournal.DemandSql(state,requests);
        var sql=await new ProductionHoldSqlInventory(db,keys,time).CaptureAcknowledgementLockedAsync(recordId,requests.Revision,requests.FenceHash,ct:ct);
        if(sql.StateSha256!=deletion.SqlStateSha256||ProductionRecordOperationAdmission.ContentDigest(sql,keys)!=deletion.ContentSha256||sql.Control!=h.Control)throw ProductionDeletionProtocol.Invalid();
        var parent=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==recordId,ct);
        if(Convert.ToBase64String(parent.RowVersion)!=h.ParentRowVersion||parent.IsDemo)throw ProductionDeletionProtocol.Invalid();
        var work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==h.WorkId,ct);
        if(work.EnvelopeId!=recordId||work.Kind!=WorkKind.ProductionPurge||work.Status!=WorkStatus.Leased||work.LeaseOwner!=deletion.Lease.Owner||
            work.Attempts!=deletion.Lease.Attempt||work.LeaseExpiresAt!=deletion.Lease.Until||work.PayloadJson!=ProductionDeletionProtocol.Payload(recordId,h.DeletionId))throw ProductionDeletionProtocol.Invalid();
        var scope=new ProductionDeletionSqlScope(db,witness,time,state,sql,parent.RowVersion);await scope.DemandAsync(db,ct);return scope;
    }

    internal async Task DemandAsync(QuillSignDbContext caller,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();var now=time.GetUtcNow();var prior=Interlocked.Read(ref observed);
        if(!ReferenceEquals(caller,db)||db.Database.CurrentTransaction is not{} current||!ReferenceEquals(current.GetDbTransaction(),transaction)||
            transaction.Connection is null||!ReferenceEquals(transaction.Connection,db.Database.GetDbConnection())||
            now.Offset!=TimeSpan.Zero||now.UtcTicks<prior||now>=Lease.Until)throw ProductionDeletionProtocol.Invalid();
        while(now.UtcTicks>prior){var value=Interlocked.CompareExchange(ref observed,now.UtcTicks,prior);if(value==prior)break;prior=value;if(now.UtcTicks<prior)throw ProductionDeletionProtocol.Invalid();}
        var actual=await witness.ReadAsync(RecordId,ct);
        if(actual.HeadHash!=head||actual.Deletion?.Header?.DeletionId!=DeletionId||!actual.Deletion.SqlReserved||actual.Deletion.SqlExpectedSha256 is not null||actual.Deletion.SqlCommitted)throw ProductionDeletionProtocol.Invalid();
        var after=time.GetUtcNow();if(after.Offset!=TimeSpan.Zero||after<now||after>=Lease.Until)throw ProductionDeletionProtocol.Invalid();
        var floor=Interlocked.Read(ref observed);while(after.UtcTicks>floor){var changed=Interlocked.CompareExchange(ref observed,after.UtcTicks,floor);if(changed==floor)break;floor=changed;if(after.UtcTicks<floor)throw ProductionDeletionProtocol.Invalid();}
    }
}

using QuillSign.Data;
using Microsoft.EntityFrameworkCore;

namespace QuillSign.Lifecycle;

internal sealed partial class ProductionRecordOperationAdmission
{
    // A fresh proof-producing read may not cross a hold, outstanding operation
    // or restored SQL cut. This acknowledges nothing and grants no mutation.
    internal async Task DemandUnfrozenReadAsync(Guid recordId,DateTimeOffset originalProofExpiresAt,CancellationToken ct=default)
    {
        if(originalProofExpiresAt<=time.GetUtcNow())throw Invalid();
        await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);
        await DemandUnfrozenReadLockedAsync(db,recordId,originalProofExpiresAt,ct);
        await tx.RollbackAsync(ct);
    }

    // Proof readers already holding the common parent transaction must use the
    // same context. A second connection would block against their own lock.
    // This path still cannot read through an outstanding mutation reservation.
    internal async Task DemandUnfrozenReadLockedAsync(QuillSignDbContext db,Guid recordId,DateTimeOffset originalProofExpiresAt,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges()||originalProofExpiresAt<=time.GetUtcNow())throw Invalid();
        if(await IsUnenrolledDemoAsync(db,recordId,ct)){if(originalProofExpiresAt<=time.GetUtcNow())throw Invalid();return;}
        var state=await witness.ReadAsync(recordId,ct);
        if(!state.Initialized||state.Frozen)throw Invalid();
        var requests=await Requests(db,recordId,ct);ProductionHoldWitnessJournal.DemandSql(state,requests);
        var sql=await Capture(db,recordId,requests,ct);
        if(ContentDigest(sql,keys)!=state.BusinessStateSha256||state.SqlStateSha256 is not null&&sql.StateSha256!=state.SqlStateSha256)throw Invalid();
        await DemandControls(db,recordId,state,ct);
        if((await witness.ReadAsync(recordId,ct)).HeadHash!=state.HeadHash)throw Invalid();
        if(originalProofExpiresAt<=time.GetUtcNow())throw Invalid();
    }
}

namespace QuillSign.Lifecycle;

// Private diagnostic facts only: neither a preservation/protection receipt nor
// permission to replay IO, cancel a reservation, release a hold or delete data.
internal enum ProductionHoldRecoveryState { VerifiedSqlHead, Unresolved }
internal enum ProductionHoldRecoveryReason { None, CommandAcknowledgement, OperationOutcome, Preservation, Release }
internal sealed record ProductionHoldRecoveryObservation(Guid RecordId, ProductionHoldRecoveryState State,
    ProductionHoldRecoveryReason Reason, long WitnessSequence, string WitnessHead, long RequestRevision,
    Guid? CommandId, Guid? OperationId, bool Frozen, bool SqlHeadVerified);

internal sealed partial class ProductionHoldCoordinator
{
    // An unknown result has an explicit bounded, nonmutating stop. In particular
    // absence, elapsed leases and cancellation never become no-effect evidence.
    // Exact resumption remains in Submit/Preserve/Release and the original worker
    // receipt readers; this method cannot manufacture their missing outcomes.
    internal async Task<ProductionHoldRecoveryObservation> ObserveRecoveryAsync(ProductionOperatorAuthority authority,
        ProductionOperatorPolicy operators, Guid recordId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        authority.Demand(operators, ProductionOperatorPermission.Status, time);
        if(recordId==Guid.Empty)throw Invalid();
        var started=time.GetUtcNow();var until=started.AddMinutes(2);
        if(authority.ExpiresAt<until)until=authority.ExpiresAt;
        void Demand()
        {
            ct.ThrowIfCancellationRequested();authority.Demand(operators,ProductionOperatorPermission.Status,time);
            var now=time.GetUtcNow();if(started.Offset!=TimeSpan.Zero||now.Offset!=TimeSpan.Zero||now<started||now>=until)throw Invalid();
        }
        Demand();var state=await witness.ReadAsync(recordId,ct);Demand();
        if(!state.Initialized&&state.Sequence==0||state.HeadHash is null)throw Invalid();
        var verified=false;
        var reason=state.Unacknowledged is not null?ProductionHoldRecoveryReason.CommandAcknowledgement:
            state.OutstandingOperation is not null?ProductionHoldRecoveryReason.OperationOutcome:
            state.Holds.Values.Any(x=>!x.Released&&x.Release is not null)?ProductionHoldRecoveryReason.Release:
            state.Holds.Values.Any(x=>!x.Released&&!x.Effective)?ProductionHoldRecoveryReason.Preservation:
            ProductionHoldRecoveryReason.None;
        if(state.Unacknowledged is null&&state.OutstandingOperation is null)
        {
            // Authenticates current full business SQL, extending controls and all
            // historical lifecycle receipts. It deliberately performs no archive
            // IO and makes no fresh provider-protection claim.
            var current=await ReadVerifiedAsync(recordId,ct);Demand();
            if(current.HeadHash!=state.HeadHash||current.Sequence!=state.Sequence)throw Invalid();
            verified=true;
        }
        var after=await witness.ReadAsync(recordId,ct);Demand();
        if(after.HeadHash!=state.HeadHash||after.Sequence!=state.Sequence)throw Invalid();
        return new(recordId,reason==ProductionHoldRecoveryReason.None?ProductionHoldRecoveryState.VerifiedSqlHead:ProductionHoldRecoveryState.Unresolved,
            reason,state.Sequence,state.HeadHash,state.RequestRevision,state.Unacknowledged?.CommandId,
            state.OutstandingOperation,state.Frozen,verified);
    }
}

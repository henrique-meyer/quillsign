using QuillSign.Data;

namespace QuillSign.Work;

// Coordinator-only contract. Neither a generic retry result, lease expiry nor
// this dispatch wrapper can establish deletion eligibility or settle uncertainty.
internal interface IProductionDeletionWorkAdmission
{
    Task<WorkClaim> ClaimAsync(QuillSignDbContext db,Guid id,CancellationToken ct);
    Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct);
    Task<DateTimeOffset?> FinishAsync(QuillSignDbContext db,WorkLease lease,WorkResult result,CancellationToken ct);
    Task ReconcileCompletedAsync(WorkLease lease,Guid recordId,CancellationToken ct);
}

internal sealed class ProductionDeletionWork(Func<IProductionDeletionWorkAdmission> admission):IWorkHandler
{
    public WorkKind Kind=>WorkKind.ProductionPurge;
    public Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if(lease.Kind!=Kind||lease.Id==Guid.Empty||lease.Owner==Guid.Empty||lease.Attempt<1||lease.Until.Offset!=TimeSpan.Zero)
            throw new InvalidOperationException("Production deletion requires an exact typed work lease.");
        return (admission()??throw new InvalidOperationException("Production deletion work admission is not configured.")).ExecuteAsync(lease,cancellationToken);
    }
}

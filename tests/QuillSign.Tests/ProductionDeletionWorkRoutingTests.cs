using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionDeletionWorkRoutingTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Missing_typed_admission_blocks_claim_before_attempt_status_or_lease_changes()
    {
        await using var db=fixture.Open();var work=new WorkItem{Kind=WorkKind.ProductionPurge,PayloadJson="{}"};db.WorkItems.Add(work);await db.SaveChangesAsync();var before=JsonSerializer.Serialize(work);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>new WorkStore(db,new(),TimeProvider.System).ClaimAsync(work.Id,default));
        Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==work.Id)));
    }
    [Fact]
    public async Task Missing_typed_admission_cannot_apply_ordinary_retry_finish_or_historical_reconciliation()
    {
        await using var db=fixture.Open();var now=TimeProvider.System.GetUtcNow();var work=new WorkItem{Kind=WorkKind.ProductionPurge,PayloadJson="{}",Status=WorkStatus.Leased,Attempts=1,LeaseOwner=Guid.NewGuid(),LeaseExpiresAt=now.AddMinutes(3)};db.WorkItems.Add(work);await db.SaveChangesAsync();var before=JsonSerializer.Serialize(work);
        var lease=new WorkLease(work.Id,work.LeaseOwner.Value,work.Kind,1,work.LeaseExpiresAt.Value);var store=new WorkStore(db,new(),TimeProvider.System);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>store.FinishAsync(lease,new(WorkOutcome.Retry,"synthetic-unknown"),default));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>store.ReconcileCompletedAsync(lease,Guid.NewGuid()));
        Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==work.Id)));
    }
    [Fact]
    public async Task Typed_claim_precedes_ordinary_terminal_due_and_exhausted_attempt_decisions()
    {
        await using var db=fixture.Open();var work=new WorkItem{Kind=WorkKind.ProductionPurge,PayloadJson="{}",Status=WorkStatus.Failed,Attempts=int.MaxValue,AvailableAt=TimeProvider.System.GetUtcNow().AddHours(1)};db.WorkItems.Add(work);await db.SaveChangesAsync();var before=JsonSerializer.Serialize(work);
        var adapter=new Admission{ClaimResult=new(null,TimeProvider.System.GetUtcNow().AddMinutes(1),false)};
        var store=new WorkStore(db,new(){MaximumAttempts=1},TimeProvider.System){DeletionAdmission=adapter};
        Assert.Same(adapter.ClaimResult,await store.ClaimAsync(work.Id,default));Assert.Same(db,adapter.Database);Assert.Equal(work.Id,adapter.Id);Assert.Equal(1,adapter.Claims);
        Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==work.Id)));
    }
    [Theory]
    [InlineData(WorkOutcome.Completed)][InlineData(WorkOutcome.Retry)][InlineData(WorkOutcome.Ambiguous)]
    public async Task Typed_finish_and_explicit_readback_never_fall_back_to_generic_work_mutation(WorkOutcome outcome)
    {
        await using var db=fixture.Open();var until=TimeProvider.System.GetUtcNow().AddMinutes(2);var work=new WorkItem{Kind=WorkKind.ProductionPurge,PayloadJson="{}",Status=WorkStatus.Leased,Attempts=1,LeaseOwner=Guid.NewGuid(),LeaseExpiresAt=until};db.WorkItems.Add(work);await db.SaveChangesAsync();var before=JsonSerializer.Serialize(work);
        var adapter=new Admission();var store=new WorkStore(db,new(),TimeProvider.System){DeletionAdmission=adapter};var lease=new WorkLease(work.Id,work.LeaseOwner.Value,work.Kind,work.Attempts,until);var result=new WorkResult(outcome,"synthetic-coordinator-result");
        Assert.Equal(adapter.FinishResult,await store.FinishAsync(lease,result,default));Assert.Same(result,adapter.Result);Assert.Equal(lease,adapter.Lease);Assert.Same(db,adapter.Database);
        var record=Guid.NewGuid();await store.ReconcileCompletedAsync(lease,record);Assert.Equal(record,adapter.Record);Assert.Equal(1,adapter.Finishes);Assert.Equal(1,adapter.Reconciliations);
        Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==work.Id)));
    }
    [Fact]
    public async Task Handler_lazily_delegates_only_exact_typed_lease_and_never_resolves_for_cancelled_or_foreign_work()
    {
        var adapter=new Admission();var resolves=0;var handler=new ProductionDeletionWork(()=>{resolves++;return adapter;});var lease=new WorkLease(Guid.NewGuid(),Guid.NewGuid(),WorkKind.ProductionPurge,1,TimeProvider.System.GetUtcNow().AddMinutes(1));
        Assert.Same(adapter.ExecuteResult,await handler.ExecuteAsync(lease,default));Assert.Equal(lease,adapter.Lease);Assert.Equal(1,resolves);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>handler.ExecuteAsync(lease with{Kind=WorkKind.Purge},default));Assert.Equal(1,resolves);
        using var cancelled=new CancellationTokenSource();cancelled.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>handler.ExecuteAsync(lease,cancelled.Token));Assert.Equal(1,resolves);
    }
    private sealed class Admission:IProductionDeletionWorkAdmission
    {
        internal WorkClaim ClaimResult=new(null,null,false);internal readonly WorkResult ExecuteResult=new(WorkOutcome.Ambiguous,"synthetic-awaiting-reconciliation");internal readonly DateTimeOffset FinishResult=TimeProvider.System.GetUtcNow().AddMinutes(1);
        internal QuillSignDbContext? Database;internal Guid Id,Record;internal WorkLease? Lease;internal WorkResult? Result;internal int Claims,Finishes,Reconciliations;
        public Task<WorkClaim> ClaimAsync(QuillSignDbContext db,Guid id,CancellationToken ct){ct.ThrowIfCancellationRequested();Assert.Null(db.Database.CurrentTransaction);Database=db;Id=id;Claims++;return Task.FromResult(ClaimResult);}
        public Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct){ct.ThrowIfCancellationRequested();Lease=lease;return Task.FromResult(ExecuteResult);}
        public Task<DateTimeOffset?> FinishAsync(QuillSignDbContext db,WorkLease lease,WorkResult result,CancellationToken ct){ct.ThrowIfCancellationRequested();Assert.Null(db.Database.CurrentTransaction);Database=db;Lease=lease;Result=result;Finishes++;return Task.FromResult<DateTimeOffset?>(FinishResult);}
        public Task ReconcileCompletedAsync(WorkLease lease,Guid record,CancellationToken ct){ct.ThrowIfCancellationRequested();Lease=lease;Record=record;Reconciliations++;return Task.CompletedTask;}
    }
}

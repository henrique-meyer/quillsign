using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionDeletionRecoveryTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Known_committed_queued_preparation_rehints_after_unknown_hint_ack_without_SQL_replay()
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;ready.Signals.LoseNextHint=true;
        await Assert.ThrowsAsync<IOException>(()=>ready.Coordinator.PrepareAsync(run.Id));var state=await run.Journal.ReadAsync(run.Id);Assert.Null(state.OutstandingOperation);
        await using var before=fixture.Open();var original=await before.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==ProductionDeletionCoordinator.WorkId(run.Id,ProductionDeletionCoordinator.DeletionId(run.Id)));
        var id=await ready.Coordinator.PrepareAsync(run.Id);Assert.Equal(original.Id,id);Assert.Equal(1,ready.Signals.Published);
        await using var db=fixture.Open();var current=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id);Assert.Equal(original.RowVersion,current.RowVersion);Assert.Equal(0,current.Attempts);
        Assert.Equal(state.HeadHash,(await run.Journal.ReadAsync(run.Id)).HeadHash);Assert.Equal(0,ready.Files.RootDeletes+ready.Files.VersionDeletes);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Original_prepare_outcome_is_reconciled_without_new_job_or_provider_replay(bool committed)
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;
        var gate=Gate(run,ready.Files,ready.Signals,()=>Open(new CommitFault(committed)));
        await Assert.ThrowsAsync<IOException>(()=>gate.PrepareAsync(run.Id));
        var frozen=await run.Journal.ReadAsync(run.Id);Assert.NotNull(frozen.OutstandingOperation);Assert.True(frozen.Outcomes!.ContainsKey(frozen.OutstandingOperation!.Value));
        if(committed){
            var id=await ready.Coordinator.PrepareAsync(run.Id);await using var db=fixture.Open();
            Assert.Single(await db.WorkItems.Where(x=>x.Id==id).ToArrayAsync());Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
            Assert.Equal(0,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)).Attempts);
        }else{
            await Assert.ThrowsAsync<InvalidDataException>(()=>ready.Coordinator.PrepareAsync(run.Id));
            Assert.Equal(frozen.HeadHash,(await run.Journal.ReadAsync(run.Id)).HeadHash);
        }
        Assert.Equal(0,ready.Files.RootDeletes+ready.Files.VersionDeletes);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Claim_expected_commit_and_known_rollback_keep_original_attempt_then_explicit_new_epoch(bool committed)
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;var id=await ready.Coordinator.PrepareAsync(run.Id);
        await using(var db=Open(new CommitFault(committed)))await Assert.ThrowsAsync<IOException>(()=>ready.Coordinator.ClaimAsync(db,id,default));
        var state=await run.Journal.ReadAsync(run.Id);Assert.NotNull(state.Deletion!.SqlExpectedSha256);var original=state.Deletion.Lease!;
        WorkClaim claim;await using(var db=fixture.Open())claim=await ready.Coordinator.ClaimAsync(db,id,default);
        if(!committed){
            Assert.Null(claim.Lease);Assert.Equal(original.Until,claim.RetryAt);Assert.True((await run.Journal.ReadAsync(run.Id)).Deletion!.ClaimRolledBack);
            run.Time.Now=original.Until.AddSeconds(1);await using var db=fixture.Open();claim=await ready.Coordinator.ClaimAsync(db,id,default);
            Assert.Equal(2,claim.Lease!.Attempt);Assert.NotEqual(original.Owner,claim.Lease.Owner);
        }else{
            Assert.Null(claim.Lease);Assert.Equal(original.Until,claim.RetryAt);Assert.True((await run.Journal.ReadAsync(run.Id)).Deletion!.ClaimAccepted);
            run.Time.Now=original.Until.AddSeconds(1);await using var db=fixture.Open();claim=await ready.Coordinator.ClaimAsync(db,id,default);
            Assert.Equal(2,claim.Lease!.Attempt);Assert.NotEqual(original.Owner,claim.Lease.Owner);
        }
        var result=await ready.Coordinator.ExecuteAsync(claim.Lease!,default);await using(var db=fixture.Open())await ready.Coordinator.FinishAsync(db,claim.Lease!,result,default);
        Assert.True((await run.Journal.ReadAsync(run.Id)).Deletion!.WorkFinished);Assert.Equal(4,ready.Files.RootDeletes);Assert.Equal(8,ready.Files.VersionDeletes);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Exact_SQL_expected_ack_or_known_rollback_never_recaptures_missing_parent_as_authority(bool committed)
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;var id=await ready.Coordinator.PrepareAsync(run.Id);
        WorkLease lease;await using(var db=fixture.Open())lease=(await ready.Coordinator.ClaimAsync(db,id,default)).Lease!;
        var fault=Gate(run,ready.Files,ready.Signals,()=>Open(new CommitFault(committed)));
        await Assert.ThrowsAsync<IOException>(()=>fault.ExecuteAsync(lease,default));
        var expected=await run.Journal.ReadAsync(run.Id);Assert.True(expected.Deletion!.SqlReserved);Assert.NotNull(expected.Deletion.SqlExpectedWorkJson);
        run.Time.Now=lease.Until.AddSeconds(1);
        await ready.Coordinator.RecoverAsync(run.Id);
        var state=await run.Journal.ReadAsync(run.Id);Assert.True(state.Deletion!.Terminal);Assert.True(state.Deletion.WorkFinished);
        Assert.Equal(committed?1:2,state.Deletion.SqlRound);Assert.Equal(4,ready.Files.RootDeletes);Assert.Equal(8,ready.Files.VersionDeletes);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Detached_worker_Finish_uses_exact_expected_ack_or_explicit_known_rollback(bool committed)
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;var id=await ready.Coordinator.PrepareAsync(run.Id);
        WorkLease lease;await using(var db=fixture.Open())lease=(await ready.Coordinator.ClaimAsync(db,id,default)).Lease!;
        var result=await ready.Coordinator.ExecuteAsync(lease,default);
        await using(var db=Open(new CommitFault(committed)))await Assert.ThrowsAsync<IOException>(()=>ready.Coordinator.FinishAsync(db,lease,result,default));
        await ready.Coordinator.ReconcileCompletedAsync(lease,run.Id,default);
        if(!committed){Assert.Null((await run.Journal.ReadAsync(run.Id)).Deletion!.FinishedWorkJson);await using var db=fixture.Open();await ready.Coordinator.FinishAsync(db,lease,result,default);}
        Assert.True((await run.Journal.ReadAsync(run.Id)).Deletion!.WorkFinished);Assert.Equal(4,ready.Files.RootDeletes);Assert.Equal(8,ready.Files.VersionDeletes);
    }
    private QuillSignDbContext Open(DbTransactionInterceptor interceptor)
    {
        using var source=fixture.Open();return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(interceptor).Options);
    }
    private ProductionDeletionCoordinator Gate(ProductionRuntimeAdmissionTests.Run run,IProductionDeletionStore files,ProductionDeletionConnectedTests.Signals signals,Func<QuillSignDbContext> open)
        =>new(open,run.Keys,run.Time,run.Journal,run.Coordinator,run.Admission,files,new EmptyIndex(),new(){Enabled=true,CompletedCommitmentStatement="Synthetic explicit per-record copy/archive commitment."},new(){Enabled=true,LeaseSeconds=600},()=>signals);
    private sealed class CommitFault(bool after):DbTransactionInterceptor
    {
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,TransactionEventData e,InterceptionResult result,CancellationToken ct=default)
        {if(!after)throw new IOException("Synthetic known rollback before commit.");return ValueTask.FromResult(result);}
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default)
        {if(after)throw new IOException("Synthetic unknown committed acknowledgement.");return Task.CompletedTask;}
    }
    private sealed class EmptyIndex:IProductionDeletionRecoveryIndex
    {
        public Task RememberAsync(ProductionDeletionObjectScope s,ProductionDeletionRecoveryHint h,CancellationToken ct=default)=>Task.CompletedTask;
        public Task<ProductionDeletionRecoveryHint> ReadAsync(Guid r,Guid d,CancellationToken ct=default)=>throw new InvalidOperationException();
        public Task<ProductionDeletionRecoveryPage> ListAsync(string? c,int m,CancellationToken ct=default)=>Task.FromResult(new ProductionDeletionRecoveryPage([],null));
    }
}

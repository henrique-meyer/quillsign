using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Lifecycle;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionDeletionClaimOwnershipTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Concurrent_and_duplicate_claims_never_regrant_an_existing_live_execution_lease()
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;
        var work=await ready.Coordinator.PrepareAsync(run.Id);
        async Task<WorkClaim?> Claim(){await using var db=fixture.Open();try{return await ready.Coordinator.ClaimAsync(db,work,default);}catch(InvalidDataException){return null;}}
        var claims=await Task.WhenAll(Claim(),Claim());var grant=Assert.Single(claims,x=>x?.Lease is not null);Assert.NotNull(grant);var lease=grant.Lease!;
        var duplicate=await Claim();Assert.NotNull(duplicate);Assert.Null(duplicate.Lease);Assert.Equal(lease.Until,duplicate.RetryAt);
        var before=await run.Journal.ReadAsync(run.Id);
        ready.Files.LoseNextDelete=true;await Assert.ThrowsAsync<IOException>(()=>ready.Coordinator.ExecuteAsync(lease,default));
        var firstEffects=ready.Files.RootDeletes+ready.Files.VersionDeletes;Assert.Equal(1,firstEffects);
        var after=await run.Journal.ReadAsync(run.Id);Assert.Single(after.Deletion!.Effects!);Assert.Null(after.Deletion.Effects!.Values.Single().Result);
        duplicate=await Claim();Assert.NotNull(duplicate);Assert.Null(duplicate.Lease);Assert.Equal(lease.Until,duplicate.RetryAt);
        Assert.Equal(firstEffects,ready.Files.RootDeletes+ready.Files.VersionDeletes);Assert.Equal(0,ready.Files.OutcomeReads);
        Assert.Equal(after.HeadHash,(await run.Journal.ReadAsync(run.Id)).HeadHash);
        await using var read=fixture.Open();var row=await read.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==work);
        Assert.Equal(lease.Owner,row.LeaseOwner);Assert.Equal(1,row.Attempts);Assert.Equal(before.Deletion!.Lease,after.Deletion.Lease);
    }
    [Fact]
    public async Task Sql_committed_recovery_never_reuses_a_live_storage_epoch_between_invocations()
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;var index=new PausedIndex();
        ProductionDeletionCoordinator Gate(Func<QuillSignDbContext> open)=>new(open,run.Keys,run.Time,run.Journal,run.Coordinator,run.Admission,ready.Files,index,
            new(){Enabled=true,CompletedCommitmentStatement="Synthetic explicit disposition."},new(){Enabled=true,LeaseSeconds=600},()=>ready.Signals);
        var work=await ready.Coordinator.PrepareAsync(run.Id);WorkLease lease;
        await using(var db=fixture.Open())lease=(await ready.Coordinator.ClaimAsync(db,work,default)).Lease!;
        QuillSignDbContext Fault(){using var db=fixture.Open();return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(db.Database.GetConnectionString()).AddInterceptors(new LostSqlAck()).Options);}
        await Assert.ThrowsAsync<IOException>(()=>Gate(Fault).ExecuteAsync(lease,default));
        Assert.Equal(1,index.Calls);var gate=Gate(fixture.Open);
        await gate.RecoverAsync(run.Id);var committed=await run.Journal.ReadAsync(run.Id);
        Assert.True(committed.Deletion!.SqlCommitted);Assert.False(committed.Deletion.Terminal);Assert.Equal(1,index.Calls);
        Assert.Equal(lease.Owner,committed.Deletion.Lease!.Owner);Assert.Equal(1,committed.Deletion.Lease.Attempt);
        run.Time.Now=lease.Until.AddSeconds(1);index.Pause=true;
        var owner=gate.RecoverAsync(run.Id);
        try{
            await index.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));var epoch=await run.Journal.ReadAsync(run.Id);
            Assert.True(epoch.Deletion!.Lease!.StorageOnly);Assert.Equal(2,epoch.Deletion.Lease.Attempt);Assert.Equal(2,index.Calls);
            await gate.RecoverAsync(run.Id);
            Assert.Equal(epoch.HeadHash,(await run.Journal.ReadAsync(run.Id)).HeadHash);Assert.Equal(2,index.Calls);
            Assert.Equal(4,ready.Files.RootDeletes);Assert.Equal(8,ready.Files.VersionDeletes);
        }finally{index.Resume.TrySetResult();}
        await owner;var done=await run.Journal.ReadAsync(run.Id);Assert.True(done.Deletion!.WorkFinished);Assert.False(done.Deletion.Lease!.StorageOnly);
        Assert.Equal(2,done.Deletion.Lease.Attempt);Assert.Equal(2,index.Calls);
    }
    private sealed class LostSqlAck:DbTransactionInterceptor{
        public override Task TransactionCommittedAsync(DbTransaction tx,TransactionEndEventData data,CancellationToken ct=default)=>throw new IOException("Synthetic committed SQL acknowledgement lost.");
    }
    private sealed class PausedIndex:IProductionDeletionRecoveryIndex{
        internal int Calls;internal bool Pause;internal readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously),Resume=new(TaskCreationOptions.RunContinuationsAsynchronously);
        private ProductionDeletionRecoveryHint? value;
        public async Task RememberAsync(ProductionDeletionObjectScope scope,ProductionDeletionRecoveryHint hint,CancellationToken ct){
            await scope.DemandAsync(ct);Calls++;if(value is null)value=hint;Assert.Equal(value,hint);
            if(Pause){Pause=false;Entered.TrySetResult();await Resume.Task.WaitAsync(ct);}await scope.DemandAsync(ct);
        }
        public Task<ProductionDeletionRecoveryHint> ReadAsync(Guid r,Guid d,CancellationToken ct)=>Task.FromResult(value??throw new InvalidDataException());
        public Task<ProductionDeletionRecoveryPage> ListAsync(string? c,int m,CancellationToken ct)=>Task.FromResult(new ProductionDeletionRecoveryPage(value is null?[]:[value],null));
    }

}

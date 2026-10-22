using QuillSign.Lifecycle;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionDeletionRecoveryIndexAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Frozen_plan_requires_exact_index_acknowledgement_before_delete_even_after_failed_publication(bool lostAck)
    {
        var ready=await new ProductionDeletionConnectedTests(fixture).CreateReady();await using var run=ready.Run;
        var index=new FailedIndex(lostAck);var gate=new ProductionDeletionCoordinator(fixture.Open,run.Keys,run.Time,run.Journal,run.Coordinator,run.Admission,ready.Files,index,
            new(){Enabled=true,CompletedCommitmentStatement="Synthetic explicit disposition."},new(){Enabled=true,LeaseSeconds=600},()=>ready.Signals);
        var work=await gate.PrepareAsync(run.Id);WorkLease lease;
        await using(var db=fixture.Open())lease=(await gate.ClaimAsync(db,work,default)).Lease!;
        await Assert.ThrowsAsync<IOException>(()=>gate.ExecuteAsync(lease,default));
        var frozen=await run.Journal.ReadAsync(run.Id);Assert.NotNull(frozen.Deletion!.PlanSha256);Assert.Equal(frozen.Deletion.PlanSha256,frozen.Deletion.RecoveryPlanSha256);
        Assert.Empty(frozen.Deletion.Effects!);Assert.Equal(0,ready.Files.RootDeletes+ready.Files.VersionDeletes);Assert.Equal(1,index.Attempts);
        var result=await gate.ExecuteAsync(lease,default);
        await using(var db=fixture.Open())await gate.FinishAsync(db,lease,result,default);
        var done=await run.Journal.ReadAsync(run.Id);Assert.True(done.Deletion!.Terminal);Assert.True(done.Deletion.WorkFinished);
        Assert.True(index.Attempts>=3);Assert.Equal(frozen.Deletion.RecoveryPlanSha256,index.Saved!.PlanSha256);
        Assert.Equal(4,ready.Files.RootDeletes);Assert.Equal(8,ready.Files.VersionDeletes);Assert.Equal(0,ready.Files.OutcomeReads);
    }
    private sealed class FailedIndex(bool lostAck):IProductionDeletionRecoveryIndex
    {
        internal int Attempts;internal ProductionDeletionRecoveryHint? Saved;
        public async Task RememberAsync(ProductionDeletionObjectScope scope,ProductionDeletionRecoveryHint hint,CancellationToken ct){
            await scope.DemandAsync(ct);Attempts++;
            if(Attempts==1){if(lostAck)Saved=hint;throw new IOException("Synthetic recovery index publication acknowledgement lost.");}
            if(Saved is null)Saved=hint;Assert.Equal(Saved,hint);await scope.DemandAsync(ct);
        }
        public Task<ProductionDeletionRecoveryHint> ReadAsync(Guid record,Guid deletion,CancellationToken ct)=>Task.FromResult(Saved??throw new InvalidDataException());
        public Task<ProductionDeletionRecoveryPage> ListAsync(string? cursor,int maximum,CancellationToken ct)=>Task.FromResult(new ProductionDeletionRecoveryPage(Saved is null?[]:[Saved],null));
    }
}

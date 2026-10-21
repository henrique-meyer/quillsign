using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionCompletionRuntimeBoundaryTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Locked_completion_readers_require_the_callers_transaction_before_SQL_or_provider_resolution()
    {
        await using var db=fixture.Open();var clock=TimeProvider.System;var blobs=new ProductionRecordUploadAdmissionTests.Blobs();
        var collector=new CompletionEvidenceCollector(db,new(db,clock),new(blobs,clock),blobs,clock);
        var candidate=new CompletionCandidates(db,collector,new(),blobs,new(db,clock),clock);
        var seal=new CompletionSealOutputs(db,candidate,collector,new(),null!,null!,blobs,new(db,clock),clock);
        var publication=new CompletionPublication(db,candidate,seal,collector,null!,new(db,clock),clock,new(),null!);
        var id=Guid.NewGuid();
        await Assert.ThrowsAsync<InvalidOperationException>(()=>collector.CollectLockedAsync(id,default));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>candidate.ReadLockedAsync(id,default));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>seal.ReadLockedAsync(id,default));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>publication.ReadLockedAsync(id,default));
        Assert.Equal(System.Data.ConnectionState.Closed,db.Database.GetDbConnection().State);Assert.Empty(blobs.Objects);Assert.Equal(0,blobs.Copies);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Partial_or_foreign_context_composition_refuses_before_SQL_or_any_effect(bool foreign)
    {
        var run=new ProductionRecordOperationAdmissionTests.Run(fixture);var effects=new RejectEffects();var admission=new ProductionCompletionAdmission(run.Gate(),effects);
        await using var db=fixture.Open();await using var other=fixture.Open();var clock=TimeProvider.System;var blobs=new ProductionRecordUploadAdmissionTests.Blobs();
        var collector=new CompletionEvidenceCollector(db,new(db,clock),new(blobs,clock),blobs,clock);
        var candidate=new CompletionCandidates(db,collector,new(),blobs,new(db,clock),clock);
        var seal=new CompletionSealOutputs(db,candidate,collector,new(),null!,null!,blobs,new(db,clock),clock);
        var owner=foreign?other:db;var publication=new CompletionPublication(owner,candidate,seal,collector,null!,new(owner,clock),clock,new(),null!);
        var lease=new WorkLease(Guid.NewGuid(),Guid.NewGuid(),WorkKind.Sealing,1,clock.GetUtcNow().AddMinutes(5));
        if(foreign)await Assert.ThrowsAsync<InvalidDataException>(()=>admission.RunAsync(db,candidate,seal,publication,lease,Guid.NewGuid(),default));
        else await Assert.ThrowsAsync<InvalidOperationException>(()=>admission.RunAsync(db,candidate,seal,publication,lease,Guid.NewGuid(),default));
        Assert.Equal(0,effects.CandidateCalls);Assert.Empty(run.Store.Rows);Assert.Equal(0,blobs.Copies);
        Assert.Equal(System.Data.ConnectionState.Closed,db.Database.GetDbConnection().State);Assert.Equal(System.Data.ConnectionState.Closed,other.Database.GetDbConnection().State);
    }

    [Fact]
    public async Task Genuine_last_checkpoint_is_collectable_in_the_same_physical_parent_without_a_nested_transaction()
    {
        await using var run=await Solo();var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);var lease=await ClaimRender(run,accepted.Acceptance!.Id);
        await using(var work=fixture.Open())Assert.Equal(WorkOutcome.Completed,(await Handler(run,work).ExecuteAsync(lease,default)).Outcome);
        await run.FinishWork(lease);await using var db=fixture.Open();
        var collector=new CompletionEvidenceCollector(db,new(db,run.Record.Time),new(run.Blobs,run.Record.Time),run.Blobs,run.Record.Time);
        var candidate=new CompletionCandidates(db,collector,new(),run.Blobs,new(db,run.Record.Time),run.Record.Time);
        var seal=new CompletionSealOutputs(db,candidate,collector,new(),null!,null!,run.Blobs,new(db,run.Record.Time),run.Record.Time);
        var publication=new CompletionPublication(db,candidate,seal,collector,null!,new(db,run.Record.Time),run.Record.Time,new(),null!);
        var events=await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Id);var head=(await run.Record.Journal.ReadAsync(run.Id)).HeadHash;
        await using var tx=await db.Database.BeginTransactionAsync();var physical=tx.GetDbTransaction();
        var source=await collector.CollectLockedAsync(run.Id,default);Assert.NotNull(source);Assert.Equal(1,source.CopyVersion);
        Assert.Equal(review.PdfSha256,Convert.ToHexStringLower(source.Evidence.Document.CurrentSha256));
        Assert.Null(await candidate.ReadLockedAsync(run.Id,default));Assert.Null(await seal.ReadLockedAsync(run.Id,default));
        Assert.Null(await publication.ReadLockedAsync(run.Id,default));Assert.Same(tx,db.Database.CurrentTransaction);Assert.Same(physical,db.Database.CurrentTransaction!.GetDbTransaction());
        Assert.NotNull(physical.Connection);Assert.Equal(events,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Id));
        Assert.Equal(head,(await run.Record.Journal.ReadAsync(run.Id)).HeadHash);Assert.Equal(0,run.Blobs.Deletes);
        await tx.RollbackAsync();
    }

    [Fact]
    public async Task A_missing_authenticated_candidate_effect_never_falls_back_to_generic_writes_or_finally_cleanup()
    {
        await using var run=await Solo();var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);var render=await ClaimRender(run,accepted.Acceptance!.Id);
        await using(var rendering=fixture.Open())Assert.Equal(WorkOutcome.Completed,(await Handler(run,rendering).ExecuteAsync(render,default)).Outcome);
        await run.FinishWork(render);var effects=new RejectEffects();var completion=new ProductionCompletionAdmission(run.Record.Admission,effects);
        var workAdmission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission){Completion=completion};
        WorkLease lease;await using(var claim=fixture.Open())lease=(await new WorkStore(claim,new(){Enabled=true},run.Record.Time,workAdmission).ClaimAsync(CompletionJobs.WorkId(run.Id),default)).Lease!;
        Assert.NotNull(lease);var objects=run.Blobs.Objects.Count;var deletes=run.Blobs.Deletes;
        await using var db=fixture.Open();var scope=new CompletionCommitScope(db,run.Record.Time);var collector=new CompletionEvidenceCollector(db,new(db,run.Record.Time),new(run.Blobs,run.Record.Time),run.Blobs,run.Record.Time);
        var candidate=new CompletionCandidates(db,collector,new(),run.Blobs,new(db,run.Record.Time),run.Record.Time,scope);
        var seals=new CompletionSealOutputs(db,candidate,collector,new(),null!,null!,run.Blobs,new(db,run.Record.Time),run.Record.Time,scope);
        CompletionPublication? publication=null;
        var access=new CompletionAccessState(db,collector,()=>publication!,run.Record.Time);
        var notifications=new CompletionNotificationJobs(db,access,new(run.Record.Keys),()=>run.Delivered.Ready.Signals,new(){Enabled=true},new(db,run.Record.Time),run.Record.Time);
        publication=new(db,candidate,seals,collector,null!,new(db,run.Record.Time),run.Record.Time,new(),null!,scope,()=>notifications);
        var handler=new CompletionWorkHandler(db,new(db,run.Record.Time),scope,()=>new(candidate,seals,publication),run.Record.Time){HoldAdmission=completion};
        Assert.Equal(WorkOutcome.Retry,(await handler.ExecuteAsync(lease,default)).Outcome);Assert.Equal(1,effects.CandidateCalls);
        Assert.False(await db.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==run.Id));Assert.False(await db.CompletionSealOutputs.AnyAsync(x=>x.EnvelopeId==run.Id));
        Assert.False(await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==run.Id));Assert.Equal(objects,run.Blobs.Objects.Count);Assert.Equal(deletes,run.Blobs.Deletes);
        var work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id);Assert.Equal(WorkStatus.Leased,work.Status);Assert.Equal(lease.Until,work.LeaseExpiresAt);Assert.Equal(1,work.Attempts);
        var saved=await run.Record.Journal.ReadAsync(run.Id);Assert.Equal(lease.Owner,saved.OutstandingOperation);Assert.NotNull(saved.Completions![lease.Owner].ClaimAcknowledged);
        Assert.False(saved.HandlerOutcomes?.ContainsKey(lease.Owner)==true);Assert.Equal(1,run.Delivered.Sender.Calls);
    }

    [Fact]
    public async Task A_new_hold_intent_keeps_the_queued_completion_unattempted_without_resolving_effects()
    {
        await using var run=await Solo();var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);var render=await ClaimRender(run,accepted.Acceptance!.Id);
        await using(var rendering=fixture.Open())Assert.Equal(WorkOutcome.Completed,(await Handler(run,rendering).ExecuteAsync(render,default)).Outcome);
        await run.FinishWork(render);var command=Place(run.Id);
        await run.Record.Journal.IntentAsync(Authority(run.Record.Time,command.Permission),Operators,command,Guid.NewGuid());
        var effects=new RejectEffects();var completion=new ProductionCompletionAdmission(run.Record.Admission,effects);
        await using var db=fixture.Open();var store=new WorkStore(db,new(){Enabled=true},run.Record.Time,new ProductionWorkAdmission(fixture.Open,run.Record.Admission){Completion=completion});
        var claim=await store.ClaimAsync(CompletionJobs.WorkId(run.Id),default);Assert.Null(claim.Lease);Assert.NotNull(claim.RetryAt);
        var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==CompletionJobs.WorkId(run.Id));Assert.Equal(WorkStatus.Queued,row.Status);Assert.Equal(0,row.Attempts);
        Assert.Null(row.LeaseOwner);Assert.Null(row.LeaseExpiresAt);Assert.Equal(0,effects.CandidateCalls);Assert.Equal(0,run.Blobs.Deletes);
        Assert.True((await run.Record.Journal.ReadAsync(run.Id)).Frozen);
    }

    [Fact]
    public async Task A_whole_second_original_publication_decision_needs_no_timer_and_preserves_its_exact_UTC()
    {
        var clock=new PublicationClock(new(2030,1,1,12,0,0,TimeSpan.Zero),true);var checks=0;
        var at=await ProductionCompletionAdmission.SelectPublicationTimeAsync(clock,_=>{checks++;return Task.CompletedTask;},default);
        Assert.Equal(clock.Now,at);Assert.Equal(0,clock.Timers);Assert.Equal(2,checks);
    }
    [Fact]
    public async Task A_fractional_decision_waits_for_the_next_UTC_second_before_freezing_any_publication_clock()
    {
        var initial=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero).AddTicks(TimeSpan.TicksPerSecond-1000);
        var clock=new PublicationClock(initial,true);var checks=0;
        var at=await ProductionCompletionAdmission.SelectPublicationTimeAsync(clock,_=>{checks++;return Task.CompletedTask;},default);
        Assert.Equal(initial.AddTicks(1000),at);Assert.Equal(0,at.Ticks%TimeSpan.TicksPerSecond);Assert.Equal(2,checks);Assert.Equal(1,clock.Timers);
    }
    [Fact]
    public async Task A_timer_without_elapsed_original_clock_cannot_publish_a_future_decision()
    {
        var initial=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero).AddTicks(TimeSpan.TicksPerSecond-1000);
        var clock=new PublicationClock(initial,false);var checks=0;
        await Assert.ThrowsAsync<InvalidDataException>(()=>ProductionCompletionAdmission.SelectPublicationTimeAsync(clock,_=>{checks++;return Task.CompletedTask;},default));
        Assert.Equal(initial,clock.Now);Assert.Equal(2,checks);Assert.Equal(1,clock.Timers);
    }
    [Fact]
    public async Task Cancellation_before_clock_selection_mints_no_decision_or_timer()
    {
        var clock=new PublicationClock(new(2030,1,1,12,0,0,TimeSpan.Zero),true);using var stop=new CancellationTokenSource();stop.Cancel();var checks=0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>ProductionCompletionAdmission.SelectPublicationTimeAsync(clock,_=>{checks++;return Task.CompletedTask;},stop.Token));
        Assert.Equal(0,checks);Assert.Equal(0,clock.Timers);
    }
    [Fact]
    public async Task An_original_scope_expiring_during_precision_wait_is_rejected_before_any_result_is_returned()
    {
        var initial=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero).AddTicks(TimeSpan.TicksPerSecond-1000);
        var clock=new PublicationClock(initial,true);var until=initial.AddTicks(500);var checks=0;
        await Assert.ThrowsAsync<InvalidDataException>(()=>ProductionCompletionAdmission.SelectPublicationTimeAsync(clock,_=>{
            checks++;if(clock.Now>=until)throw new InvalidDataException("The original finite lease expired.");return Task.CompletedTask;},default));
        Assert.True(clock.Now>=initial.AddTicks(1000));Assert.Equal(2,checks);Assert.Equal(1,clock.Timers);
    }
    [Fact]
    public async Task Cancellation_at_the_timer_boundary_returns_no_future_decision_or_second_admission()
    {
        using var stop=new CancellationTokenSource();var checks=0;var clock=new CancelPublicationClock(stop);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>ProductionCompletionAdmission.SelectPublicationTimeAsync(clock,_=>{checks++;return Task.CompletedTask;},stop.Token));
        Assert.Equal(1,checks);Assert.Equal(1,clock.Timers);
    }
    private sealed class CancelPublicationClock(CancellationTokenSource stop):TimeProvider
    {
        internal int Timers;
        public override DateTimeOffset GetUtcNow()=>new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero).AddTicks(1);
        public override ITimer CreateTimer(TimerCallback callback,object? state,TimeSpan dueTime,TimeSpan period)
        {Timers++;stop.Cancel();return base.CreateTimer(callback,state,dueTime,period);}
    }    private sealed class PublicationClock:TimeProvider
    {
        private readonly DateTimeOffset initial;private readonly bool advances;
        internal PublicationClock(DateTimeOffset initial,bool advances){this.initial=initial;this.advances=advances;Now=initial;}
        internal DateTimeOffset Now;internal int Timers;
        public override DateTimeOffset GetUtcNow()=>Now;
        public override ITimer CreateTimer(TimerCallback callback,object? state,TimeSpan dueTime,TimeSpan period)
        {
            Timers++;return base.CreateTimer(value=>{if(advances)Now=initial+dueTime;callback(value);},state,dueTime,period);
        }
    }
    private sealed class RejectEffects:IProductionCompletionEffects
    {
        internal int CandidateCalls;
        public Task<CompletionOwnedRowPlan> CandidateLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionCandidate row,PreparedCompletionPacket packet,CancellationToken ct)
        {CandidateCalls++;throw new IOException("Synthetic missing authenticated candidate effect implementation.");}
        public Task<CompletionOwnedSeal> SealLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionCandidateData candidate,CompletionSealKind kind,
            CompletionSealTargets targets,byte[] source,CompletionSealData? executed,CancellationToken ct)=>throw new InvalidOperationException();
        public Task<CompletionOwnedRowPlan> IntentLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionPublicationIntent row,CancellationToken ct)=>throw new InvalidOperationException();
        public Task<CompletionPublicationFiles> PublicationLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionPublicationIntent intent,CompletionSealPair pair,
            DateTimeOffset recordedAt,DateTimeOffset? until,CancellationToken ct)=>throw new InvalidOperationException();
        public Task<CompletionOwnedRowPlan> ResultLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionPublicationTransition transition,CancellationToken ct)=>throw new InvalidOperationException();
    }

    private async Task<ProductionSignerReviewRuntimeContractTests.Flow> Solo()
    {
        var marks=await ProductionSignaturePreviewAdmissionTests.Flow.Create(fixture);var preview=(await marks.Prepare())!;
        Assert.Equal(SignatureAdoptionResult.Adopted,await marks.Adopt(preview));var field=(await marks.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
        Assert.Equal(SignerFieldOutcome.Applied,(await marks.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:preview.Id))).Outcome);
        return new(fixture,marks,marks.Blobs);
    }
    private async Task<WorkLease> ClaimRender(ProductionSignerReviewRuntimeContractTests.Flow run,Guid finishId)
    {
        await using var db=fixture.Open();
        var store=new WorkStore(db,new(){Enabled=true},run.Record.Time,new ProductionWorkAdmission(fixture.Open,run.Record.Admission));
        return (await store.ClaimAsync(finishId,default)).Lease??throw new InvalidOperationException("The genuine Rendering work was not admitted.");
    }
    private SignerCheckpointHandler Handler(ProductionSignerReviewRuntimeContractTests.Flow run,QuillSignDbContext db)
    {
        var completion=new CompletionJobs(db,new(db,run.Record.Time),()=>run.Delivered.Ready.Signals,new(){Enabled=true},run.Record.Time){HoldAdmission=run.Record.Admission};
        return new(db,new(db,run.Record.Time),new(run.Blobs,run.Record.Time),
            new(db,()=>run.Delivered.Ready.Signals,new(){Enabled=true},new(){Enabled=true},new(run.Record.Keys),run.Record.Time),new(db,run.Record.Time),run.Record.Time,completion)
            {HoldAdmission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission)};
    }
}

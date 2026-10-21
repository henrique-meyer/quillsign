using System.Data.Common;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionSequentialCheckpointAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Disabled_completion_repair_is_rejected_before_SQL_or_a_reservation()
    {
        var run=new ProductionRecordOperationAdmissionTests.Run(fixture);await using var db=fixture.Open();
        var signals=new ProductionRecordSendAdmissionTests.Signals();
        var jobs=new CompletionJobs(db,new(db,run.Clock),()=>signals,new(){Enabled=false},run.Clock){HoldAdmission=run.Gate()};
        await Assert.ThrowsAsync<InvalidOperationException>(()=>jobs.ResumeAsync(Guid.NewGuid()));
        Assert.Empty(run.Store.Rows);Assert.Empty(signals.Hints);Assert.Equal(System.Data.ConnectionState.Closed,db.Database.GetDbConnection().State);
    }
    [Fact]
    public async Task The_actual_last_checkpoint_reuses_its_review_and_queues_one_unattempted_completion_job()
    {
        await using var run=await Solo();var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);
        var lease=await run.Claim(accepted.Acceptance!.Id);
        await using(var db=fixture.Open())Assert.Equal(WorkOutcome.Completed,(await Handler(run,db).ExecuteAsync(lease,default)).Outcome);
        await run.FinishWork(lease);
        await using var check=fixture.Open();var record=await check.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id);
        var finish=await check.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==lease.Id);
        var work=await check.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==CompletionJobs.WorkId(run.Id));
        Assert.Equal(1,record.CurrentCopyVersion);Assert.Equal(finish.Id,record.CurrentFinishId);Assert.Null(finish.NextInvitationId);Assert.NotNull(finish.ProcessedAt);
        Assert.Equal(review.PdfSha256,Convert.ToHexStringLower(finish.PdfSha256));Assert.Equal(EnvelopeStatus.Sent,record.Status);
        Assert.Equal(WorkKind.Sealing,work.Kind);Assert.Equal(WorkStatus.Queued,work.Status);Assert.Equal(0,work.Attempts);Assert.Null(work.LeaseOwner);Assert.Null(work.LeaseExpiresAt);
        Assert.Equal(JsonSerializer.Serialize(new CompletionWorkPayload(CompletionJobs.Version,finish.Id,1,review.PdfSha256,Convert.ToHexStringLower(record.ErsdSha256!))),work.PayloadJson);
        var jobs=Jobs(run,check);var hints=run.Delivered.Ready.Signals.Hints.Count;var head=(await run.Record.Journal.ReadAsync(run.Id)).HeadHash;
        Assert.Equal(work.Id,await jobs.ResumeAsync(run.Id));Assert.Equal(hints,run.Delivered.Ready.Signals.Hints.Count);
        Assert.Equal(head,(await run.Record.Journal.ReadAsync(run.Id)).HeadHash);
        var rejected=await run.Work(check).ClaimAsync(work.Id,default);Assert.Null(rejected.Lease);Assert.NotNull(rejected.RetryAt);
        Assert.Equal(0,(await check.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==work.Id)).Attempts);
        Assert.Equal(1,run.Delivered.Sender.Calls);Assert.Equal(2,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.Deletes);
        Assert.False(await check.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==run.Id));Assert.False(await check.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==run.Id));
        Assert.Null((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task A_completion_hint_failure_rolls_back_the_last_progress_but_retains_the_admitted_worker()
    {
        await using var run=await Solo();var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);var lease=await run.Claim(accepted.Acceptance!.Id);
        run.Delivered.Ready.Signals.OnHint=()=>throw new IOException("Synthetic completion hint failure.");
        await using(var db=fixture.Open())Assert.Equal(WorkOutcome.Retry,(await Handler(run,db).ExecuteAsync(lease,default)).Outcome);
        await using var check=fixture.Open();Assert.False(await check.WorkItems.AnyAsync(x=>x.Id==CompletionJobs.WorkId(run.Id)));
        Assert.Equal(0,(await check.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id)).CurrentCopyVersion);
        Assert.Null((await check.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==lease.Id)).ProcessedAt);
        Assert.NotNull((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);Assert.Equal(0,run.Blobs.Deletes);Assert.Equal(1,run.Delivered.Sender.Calls);
    }

    [Fact]
    public async Task Missing_previously_witnessed_completion_work_is_not_repaired_from_restored_SQL_absence()
    {
        await using var run=await Solo();var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);var lease=await run.Claim(accepted.Acceptance!.Id);
        await using(var db=fixture.Open())Assert.Equal(WorkOutcome.Completed,(await Handler(run,db).ExecuteAsync(lease,default)).Outcome);await run.FinishWork(lease);
        var head=(await run.Record.Journal.ReadAsync(run.Id)).HeadHash;var hints=run.Delivered.Ready.Signals.Hints.Count;
        await using var restore=fixture.Open();await restore.WorkItems.Where(x=>x.Id==CompletionJobs.WorkId(run.Id)).ExecuteDeleteAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>Jobs(run,restore).ResumeAsync(run.Id));
        Assert.False(await restore.WorkItems.AnyAsync(x=>x.Id==CompletionJobs.WorkId(run.Id)));Assert.Equal(hints,run.Delivered.Ready.Signals.Hints.Count);
        Assert.Equal(head,(await run.Record.Journal.ReadAsync(run.Id)).HeadHash);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Lost_last_handler_SQL_acknowledgement_reconciles_exact_receipt_without_running_handler_again()
    {
        await using var run=await Solo();var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);var lease=await run.Claim(accepted.Acceptance!.Id);
        await using(var db=Intercepted(new LostCheckpointCommit()))Assert.Equal(WorkOutcome.Retry,(await Handler(run,db).ExecuteAsync(lease,default)).Outcome);
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.True(state.HandlerOutcomes!.ContainsKey(lease.Owner));Assert.NotNull(state.OutstandingOperation);
        // WorkStore demands the exact already-sealed handler state before it
        // performs only its own final bookkeeping. No handler/provider replay.
        await run.FinishWork(lease);
        await using var check=fixture.Open();Assert.Equal(WorkStatus.Completed,(await check.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id)).Status);
        Assert.Single(await check.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==run.Id&&x.Kind==WorkKind.Sealing).ToArrayAsync());
        Assert.Null((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);Assert.Equal(1,run.Delivered.Sender.Calls);Assert.Equal(2,run.Blobs.ReviewWrites);
    }

    [Fact]
    public async Task Frozen_accepted_checkpoint_reads_stop_before_any_saved_PDF_or_mark_copy()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);await run.Process(accepted.Acceptance!.Id);
        await using(var db=fixture.Open())Assert.Equal(review.PdfSha256,Convert.ToHexStringLower(SHA256.HashData((await Reads(run,db).ReadAsync(run.Principal,run.PublicId,review.Receipt))!.Pdf)));
        var command=Place(run.Id);await run.Record.Journal.IntentAsync(Authority(run.Record.Time,command.Permission),Operators,command,Guid.NewGuid());var copies=run.Blobs.Copies;
        await using var frozen=fixture.Open();await Assert.ThrowsAsync<DocumentRejectedException>(()=>Reads(run,frozen).ReadAsync(run.Principal,run.PublicId,review.Receipt));
        Assert.Equal(copies,run.Blobs.Copies);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task A_hold_during_accepted_readonly_commit_cannot_expose_fresh_checkpoint_bytes()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);await run.Process(accepted.Acceptance!.Id);
        var command=Place(run.Id);var interceptor=new CommitAction(()=>run.Record.Journal.IntentAsync(Authority(run.Record.Time,command.Permission),Operators,command,Guid.NewGuid()));
        await using var db=Intercepted(interceptor);await Assert.ThrowsAsync<DocumentRejectedException>(()=>Reads(run,db).ReadAsync(run.Principal,run.PublicId,review.Receipt));
        Assert.True(interceptor.Called);Assert.Equal(0,run.Blobs.Deletes);Assert.Equal(review.ExpiresAt,(await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==review.Id)).ExpiresAt);
    }

    [Fact]
    public async Task Original_session_expiry_after_the_checkpoint_PDF_copy_prevents_returning_bytes_or_reading_marks()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);await run.Process(accepted.Acceptance!.Id);var copies=run.Blobs.Copies;
        run.Blobs.AfterCopy=()=>{run.Record.Time.Now=run.Identity.SessionExpiresAt;return Task.CompletedTask;};
        await using var db=fixture.Open();await Assert.ThrowsAsync<DocumentRejectedException>(()=>Reads(run,db).ReadAsync(run.Principal,run.PublicId,review.Receipt));
        Assert.Equal(copies+1,run.Blobs.Copies);Assert.Equal(0,run.Blobs.Deletes);
    }

    private async Task<ProductionSignerReviewRuntimeContractTests.Flow> Solo()
    {
        var marks=await ProductionSignaturePreviewAdmissionTests.Flow.Create(fixture);var preview=(await marks.Prepare())!;
        Assert.Equal(SignatureAdoptionResult.Adopted,await marks.Adopt(preview));var field=(await marks.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
        Assert.Equal(SignerFieldOutcome.Applied,(await marks.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:preview.Id))).Outcome);
        return new(fixture,marks,marks.Blobs);
    }
    private CompletionJobs Jobs(ProductionSignerReviewRuntimeContractTests.Flow run,QuillSignDbContext db)=>new(db,new(db,run.Record.Time),()=>run.Delivered.Ready.Signals,new(){Enabled=true},run.Record.Time){HoldAdmission=run.Record.Admission};
    private SignerCheckpointHandler Handler(ProductionSignerReviewRuntimeContractTests.Flow run,QuillSignDbContext db)=>new(db,new(db,run.Record.Time),new(run.Blobs,run.Record.Time),
        new(db,()=>run.Delivered.Ready.Signals,new(){Enabled=true},new(){Enabled=true},new(run.Record.Keys),run.Record.Time),new(db,run.Record.Time),run.Record.Time,Jobs(run,db))
        {HoldAdmission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission)};
    private static SignerCheckpointReads Reads(ProductionSignerReviewRuntimeContractTests.Flow run,QuillSignDbContext db)=>new(db,ProductionSignerMutationAdmissionTests.Access(run.Delivered,db),
        new(db,run.Record.Time),new(run.Blobs,run.Record.Time),new(run.Record.Keys,run.Record.Time),run.Record.Time){HoldAdmission=new(run.Record.Admission)};
    private QuillSignDbContext Intercepted(DbTransactionInterceptor interceptor)
    {using var original=fixture.Open();return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(original.Database.GetConnectionString()).AddInterceptors(interceptor).Options);}
    private sealed class LostCheckpointCommit:DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)
            =>eventData.Context?.ChangeTracker.Entries<AuditEvent>().Any(x=>x.Entity.Event=="signer_completed")==true
                ?throw new IOException("Synthetic lost last checkpoint commit."):Task.CompletedTask;
    }
    private sealed class CommitAction(Func<Task> action):DbTransactionInterceptor
    {
        internal bool Called;
        public override async Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)
        {if(!Called){Called=true;await action();}}
    }
}

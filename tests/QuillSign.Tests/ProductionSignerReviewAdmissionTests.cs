using System.Data.Common;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionSignerReviewAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_first_review_Finish_and_processed_checkpoint_each_preserve_complete_bundles_under_two_independent_holds()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        var candidate=(await run.Prepare())!;Assert.NotNull(candidate);
        var original=(await run.Read(candidate.Receipt))!;Assert.NotNull(original);
        Assert.Equal(candidate.PdfSha256,Convert.ToHexStringLower(SHA256.HashData(original.Pdf)));
        Assert.Equal(2,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.UnwitnessedWrites);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        async Task PreservePair(long revision)
        {
            var before=holds.Provider.Files.Count;var first=await holds.Place(revision);var second=await holds.Place(revision+1);
            Assert.Equal(before+18,holds.Provider.Files.Count);
            Assert.True(await holds.Release(first,revision+2));Assert.False(await holds.Release(second,revision+3));
        }
        await PreservePair(0);
        Assert.Equal(candidate.ExpiresAt,(await run.Read(candidate.Receipt))!.Candidate.ExpiresAt);
        var accepted=await run.Finish(candidate.Receipt);Assert.Equal(SignerFinishOutcome.Accepted,accepted.Outcome);
        Assert.Equal(SignerFinishOutcome.AlreadyAccepted,(await run.Finish(candidate.Receipt)).Outcome);
        await PreservePair(4);
        await run.Process(accepted.Acceptance!.Id);
        await PreservePair(8);
        await using var db=fixture.Open();var record=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id);
        var finish=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==accepted.Acceptance.Id);
        Assert.Equal(1,record.CurrentCopyVersion);Assert.Equal(finish.Id,record.CurrentFinishId);Assert.NotNull(finish.ProcessedAt);
        Assert.Equal(candidate.PdfSha256,Convert.ToHexStringLower(finish.PdfSha256));
        var date=await db.Fields.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Id&&x.SignerId==run.Identity.SignerId&&x.Type==FieldType.DateSigned);
        Assert.Equal(candidate.ProspectiveDate.ToString("yyyy-MM-dd",System.Globalization.CultureInfo.InvariantCulture),date.Value);
        Assert.Equal(finish.FinishedAt,date.FilledAt);Assert.Equal(PartyType.Signer,date.FilledBy);
        var secondSigner=await db.Signers.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Id&&x.Order==2);
        Assert.Equal(SignerStatus.Pending,secondSigner.Status);Assert.Null(secondSigner.ConsentAt);Assert.Null(secondSigner.SignatureAdoptionId);
        Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==run.Id&&x.PartyId==secondSigner.Id));
        var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==finish.NextInvitationId);
        Assert.Equal(EmailStatus.Queued,mail.Status);Assert.Equal(0,mail.Attempts);Assert.Null(mail.ProviderMessageId);
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==finish.Id)).Status);
        Assert.Equal(1,run.Delivered.Sender.Calls);Assert.Equal(0,run.Blobs.Deletes);Assert.Equal(2,run.Blobs.ReviewWrites);
        Assert.All(holds.Provider.Files.Values,x=>Assert.False(x.Held));
        Assert.Null((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    [Theory]
    [InlineData(1)][InlineData(2)]
    public async Task Unknown_review_input_or_PDF_acknowledgement_preserves_original_once_only_intent_and_never_replays_or_cleans_up(int lostAt)
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        run.Blobs.LoseReviewAcknowledgementAt=lostAt;
        await Assert.ThrowsAsync<IOException>(()=>run.Prepare());Assert.Equal(lostAt,run.Blobs.ReviewWrites);
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.NotNull(state.OutstandingOperation);
        await using(var db=fixture.Open())Assert.False(await db.SignerReviewCandidates.AnyAsync(x=>x.EnvelopeId==run.Id));
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Prepare());
        Assert.Equal(lostAt,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.Deletes);
        Assert.Equal(state.HeadHash,(await run.Record.Journal.ReadAsync(run.Id)).HeadHash);
    }

    [Fact]
    public async Task Equal_review_input_bytes_under_another_version_refuse_preservation_before_any_archive()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);Assert.NotNull(await run.Prepare());
        run.Blobs.ReviewVersionSuffix="-foreign";using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        var place=Place(run.Id);await holds.Coordinator().SubmitAsync(Authority(run.Record.Time,place.Permission),Operators,place);
        await Assert.ThrowsAsync<InvalidDataException>(()=>holds.Coordinator().PreserveAsync(run.Id,place.HoldId,Guid.NewGuid()));
        Assert.Empty(holds.Provider.Files);Assert.False((await run.Record.Journal.ReadAsync(run.Id)).Holds[place.HoldId].Effective);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Old_admitted_review_drains_a_new_hold_without_exposing_a_fresh_receipt()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);var place=Place(run.Id);
        run.Blobs.AfterReviewWrite=async n=>{if(n==1){using var pending=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
            await pending.Coordinator().SubmitAsync(Authority(run.Record.Time,place.Permission),Operators,place);}};
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Prepare());Assert.Equal(2,run.Blobs.ReviewWrites);
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.Equal(place,state.Unacknowledged);Assert.Null(state.OutstandingOperation);
        await using(var db=fixture.Open())Assert.Single(await db.SignerReviewCandidates.AsNoTracking().Where(x=>x.EnvelopeId==run.Id).ToArrayAsync());
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);await holds.Preserve(place);Assert.Equal(9,holds.Provider.Files.Count);
        Assert.False(await holds.Release(place,1));Assert.NotNull(await run.Prepare());Assert.Equal(2,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Hold_published_during_readonly_review_commit_denies_a_fresh_receipt()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);var candidate=(await run.Prepare())!;
        var place=Place(run.Id);var interceptor=new CommitAction(async()=>await run.Record.Journal.IntentAsync(Authority(run.Record.Time,place.Permission),Operators,place,Guid.NewGuid()));
        await using var db=Intercepted(interceptor);
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Read(candidate.Receipt,db));Assert.True(interceptor.Published);
        Assert.Equal(2,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.Deletes);
        Assert.Null((await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==candidate.Id)).UsedAt);
    }

    [Fact]
    public async Task Lost_actual_review_SQL_commit_returns_no_proof_and_cannot_create_another_pair()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        await using var db=Intercepted(new LostReviewCommit());await Assert.ThrowsAsync<IOException>(()=>run.Prepare(db));
        Assert.Equal(2,run.Blobs.ReviewWrites);Assert.NotNull((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
        await using(var check=fixture.Open())Assert.Single(await check.SignerReviewCandidates.AsNoTracking().Where(x=>x.EnvelopeId==run.Id).ToArrayAsync());
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Prepare());Assert.Equal(2,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Later_field_edit_supersedes_a_review_without_losing_either_exact_original_input_or_PDF()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        var first=(await run.Prepare())!;var field=(await run.Marks.Fields())!.Fields.Single(x=>x.Type==FieldType.Text);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Marks.Change(new(field.Id,field.Version,SignerFieldAction.Apply,"Synthetic revised review input"))).Outcome);
        Assert.Null(await run.Read(first.Receipt));var second=(await run.Prepare())!;Assert.NotNull(second);Assert.NotEqual(first.Id,second.Id);
        Assert.NotEqual(first.SnapshotSha256,second.SnapshotSha256);Assert.Equal(4,run.Blobs.ReviewWrites);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);var hold=await holds.Place(0);
        Assert.Equal(11,holds.Provider.Files.Count);Assert.False(await holds.Release(hold,1));
        await using var db=fixture.Open();var old=await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==first.Id);
        Assert.NotNull(old.SupersededAt);Assert.Null(old.UsedAt);Assert.NotNull(await run.Read(second.Receipt));Assert.Equal(0,run.Blobs.Deletes);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Original_session_or_review_expiry_stops_the_exact_pair_without_cleanup_or_new_candidate(bool afterInput)
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        if(afterInput)run.Blobs.AfterReviewWrite=n=>{if(n==1)run.Record.Time.Now=run.Record.Time.Now.AddMinutes(10);return Task.CompletedTask;};
        else run.Blobs.BeforeReviewWrite=()=>{run.Record.Time.Now=run.Identity.SessionExpiresAt;return Task.CompletedTask;};
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Prepare());Assert.Equal(afterInput?1:0,run.Blobs.ReviewWrites);
        await using var db=fixture.Open();Assert.False(await db.SignerReviewCandidates.AnyAsync(x=>x.EnvelopeId==run.Id));
        Assert.NotNull((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task An_already_claimed_checkpoint_drains_a_new_hold_through_WorkStore_Finish_then_preserves_the_exact_copy()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        var candidate=(await run.Prepare())!;var accepted=await run.Finish(candidate.Receipt);Assert.Equal(SignerFinishOutcome.Accepted,accepted.Outcome);
        var lease=await run.Claim(accepted.Acceptance!.Id);var place=Place(run.Id);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        await holds.Coordinator().SubmitAsync(Authority(run.Record.Time,place.Permission),Operators,place);
        Assert.Equal(WorkOutcome.Completed,(await run.Handle(lease)).Outcome);Assert.NotNull((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
        await run.FinishWork(lease);Assert.Null((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
        await holds.Preserve(place);
        Assert.Equal(9,holds.Provider.Files.Count);Assert.False(await holds.Release(place,1));
        await using var db=fixture.Open();Assert.Equal(1,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id)).CurrentCopyVersion);
        Assert.Equal(1,run.Delivered.Sender.Calls);Assert.Equal(2,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Effective_holds_gate_new_review_Finish_and_checkpoint_claim_before_any_effect_and_exact_release_resumes_original_authority()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        using(var beforeReview=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered))
        {
            var hold=await beforeReview.Place(0);await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Prepare());
            Assert.Equal(0,run.Blobs.ReviewWrites);Assert.False(await beforeReview.Release(hold,1));
        }
        var candidate=(await run.Prepare())!;using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        var beforeFinish=await holds.Place(2);await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Finish(candidate.Receipt));
        await using(var db=fixture.Open())Assert.False(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==run.Id));
        Assert.False(await holds.Release(beforeFinish,3));
        var accepted=await run.Finish(candidate.Receipt);Assert.Equal(SignerFinishOutcome.Accepted,accepted.Outcome);
        var beforeClaim=await holds.Place(4);
        await using(var db=fixture.Open())
        {
            var result=await run.Work(db).ClaimAsync(accepted.Acceptance!.Id,default);Assert.Null(result.Lease);Assert.NotNull(result.RetryAt);
            var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==accepted.Acceptance.Id);Assert.Equal(0,row.Attempts);Assert.Null(row.LeaseOwner);
            Assert.Equal(WorkStatus.Queued,row.Status);
        }
        Assert.False(await holds.Release(beforeClaim,5));await run.Process(accepted.Acceptance!.Id);
        Assert.Equal(2,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.Deletes);Assert.Equal(1,run.Delivered.Sender.Calls);
    }

    [Fact]
    public async Task Frozen_review_bundle_reopens_after_old_capture_expiry_with_a_fresh_private_read_scope_and_the_same_original_input()
    {
        await using var run=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);var candidate=(await run.Prepare())!;
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);var place=Place(run.Id);var plan=Guid.NewGuid();
        await holds.Coordinator().SubmitAsync(Authority(run.Record.Time,place.Permission),Operators,place);
        holds.Provider.After=phase=>{if(phase=="download")throw new IOException("Synthetic interrupted preserved archive readback.");};
        await Assert.ThrowsAsync<IOException>(()=>holds.Coordinator().PreserveAsync(run.Id,place.HoldId,plan));
        Assert.Single(holds.Provider.Files);holds.Provider.After=null;run.Record.Time.Now=run.Record.Time.Now.AddMinutes(11);
        Assert.True((await holds.Coordinator().PreserveAsync(run.Id,place.HoldId,plan)).Holds[place.HoldId].Effective);
        Assert.Equal(9,holds.Provider.Files.Count);Assert.False(await holds.Release(place,1));
        Assert.Null(await run.Read(candidate.Receipt));Assert.Equal(2,run.Blobs.ReviewWrites);
        await using var db=fixture.Open();var row=await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==candidate.Id);
        Assert.Equal(candidate.ExpiresAt,row.ExpiresAt);Assert.Null(row.UsedAt);Assert.Equal(0,run.Blobs.Deletes);
    }

    private QuillSignDbContext Intercepted(DbTransactionInterceptor interceptor)
    {
        using var source=fixture.Open();return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(interceptor).Options);
    }
    private sealed class CommitAction(Func<Task> action):DbTransactionInterceptor
    {
        internal bool Published;
        public override async Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)
        {if(!Published){Published=true;await action();}}
    }
    private sealed class LostReviewCommit:DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)
            =>eventData.Context?.ChangeTracker.Entries<SignerReviewCandidate>().Any()==true
                ?throw new IOException("Synthetic lost review SQL acknowledgement."):Task.CompletedTask;
    }
    [Fact]
    public async Task Genuine_two_signer_preparation_delivers_only_first_invitation_and_preserves_first_owned_fields()
    {
        await using var run=await ProductionSignaturePreviewAdmissionTests.Flow.Create(fixture,twoSigners:true);
        var preview=(await run.Prepare())!;Assert.NotNull(preview);
        Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(preview));
        foreach(var field in (await run.Fields())!.Fields)
        {
            var change=field.Type switch {
                FieldType.Signature or FieldType.Initials=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:preview.Id),
                FieldType.FullName=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply),
                _=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply,"Synthetic first signer value")};
            Assert.Equal(field.Type==FieldType.DateSigned?SignerFieldOutcome.ReadOnly:SignerFieldOutcome.Applied,(await run.Change(change)).Outcome);
        }
        await using var db=fixture.Open();
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==run.Id).OrderBy(x=>x.Order).ToArrayAsync();
        Assert.Equal(2,signers.Length);Assert.Equal(run.Identity.SignerId,signers[0].Id);
        Assert.Equal(SignerStatus.Viewed,signers[0].Status);Assert.Equal(SignerStatus.Pending,signers[1].Status);
        Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==run.Id&&x.PartyId==signers[1].Id));
        Assert.Null(signers[1].ConsentAt);Assert.Null(signers[1].SignatureAdoptionId);
        Assert.Equal(0,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id)).CurrentCopyVersion);
        Assert.Equal(1,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Id&&x.Template=="signer-invitation"));
        Assert.False(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==run.Id));
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        var hold=await holds.Place(0);Assert.Equal(7,holds.Provider.Files.Count);Assert.False(await holds.Release(hold,1));
        Assert.Equal(0,run.Blobs.Deletes);Assert.Equal(2,run.Blobs.MarkWrites);
    }
}

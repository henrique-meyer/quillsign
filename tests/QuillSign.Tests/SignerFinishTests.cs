using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Storage;
using Run=QuillSign.Tests.SignerReviewCandidateTests.Run;

namespace QuillSign.Tests;

public sealed class SignerFinishTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Concurrent_explicit_Finish_accepts_exact_review_once_fills_only_server_date_and_freezes_without_claiming_completion()
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!; var source=(await r.H.Raw(new(r.H.Identity.EnvelopeId,DocumentBlobKind.Normalized,r.H.Identity.DocumentId)).DownloadContentAsync()).Value.Content.ToArray();
        var before=JsonSerializer.Deserialize<DocumentField[]>(await r.FieldVersions())!; r.H.Clock.Advance(TimeSpan.FromSeconds(3)); var actual=r.H.Clock.GetUtcNow();
        var results=await Task.WhenAll(Enumerable.Range(0,3).Select(_=>r.Finish(review.Receipt))); Assert.Single(results,x=>x.Outcome==SignerFinishOutcome.Accepted); Assert.Equal(2,results.Count(x=>x.Outcome==SignerFinishOutcome.AlreadyAccepted));
        var accepted=results[0].Acceptance!; Assert.All(results,x=>Assert.Equal(accepted,x.Acceptance)); Assert.True(accepted.ProcessingPending); Assert.Equal(actual,accepted.FinishedAt); Assert.Equal(review.PdfSha256,accepted.PdfSha256);
        await using var db=fixture.Open(); var record=Assert.Single(await db.SignerFinishAcceptances.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ToArrayAsync()); var candidate=await db.SignerReviewCandidates.SingleAsync(x=>x.Id==review.Id);
        Assert.Equal(actual,candidate.UsedAt); Assert.Equal(candidate.PdfObjectId,record.PdfObjectId); Assert.Equal(candidate.PdfSha256,record.PdfSha256); Assert.Equal(candidate.SnapshotSha256,record.SnapshotSha256); Assert.Equal(SignerFinishStatement.Text,record.Statement); Assert.Equal(SignerFinishStatement.Sha256,record.StatementSha256); Assert.Null(record.ProcessedAt);
        var after=JsonSerializer.Deserialize<DocumentField[]>(await r.FieldVersions())!; Assert.Equal(JsonSerializer.Serialize(before.Where(x=>x.Type!=FieldType.DateSigned)),JsonSerializer.Serialize(after.Where(x=>x.Type!=FieldType.DateSigned)));
        var date=Assert.Single(after,x=>x.Type==FieldType.DateSigned); Assert.Equal(actual.UtcDateTime.ToString("yyyy-MM-dd"),date.Value); Assert.Equal(actual,date.FilledAt); Assert.Equal(PartyType.Signer,date.FilledBy);
        Assert.Equal(JsonSerializer.Serialize(after.Where(x=>x.SignerId==r.H.Signer.Id)),record.FieldsJson); Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(record.FieldsJson)),record.FieldsSha256);
        var evidence=Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_finish_accepted").ToArrayAsync()); Assert.Equal(AuditHash.Compute(evidence),evidence.Hash); Assert.Equal(r.H.Signer.Id,evidence.ActorId); Assert.Contains("publication_pending",evidence.DataJson); Assert.Contains(SignerFinishStatement.Text,evidence.DataJson);
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_completed")); Assert.Equal(WorkKind.Rendering,Assert.Single(await db.WorkItems.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ToArrayAsync()).Kind); Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id));
        var signer=await db.Signers.SingleAsync(x=>x.Id==r.H.Signer.Id); Assert.Equal(SignerStatus.Viewed,signer.Status); Assert.Null(signer.SignedAt); Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.SingleAsync(x=>x.Id==r.H.Envelope.Id)).Status);
        Assert.Equal(source,(await r.H.Raw(new(r.H.Identity.EnvelopeId,DocumentBlobKind.Normalized,r.H.Identity.DocumentId)).DownloadContentAsync()).Value.Content.ToArray()); Assert.Null(await r.Read(review.Receipt)); Assert.Null(await r.Prepare());
    }
    [Theory]
    [InlineData(false,SignerFinishStatement.Version)][InlineData(true,null)][InlineData(true,"old")][InlineData(false,null)]
    public async Task Explicit_affirmation_and_exact_statement_version_are_required(bool affirm,string? version)
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!; var before=await r.FieldVersions(); Assert.Equal(SignerFinishOutcome.InvalidIntent,(await r.Finish(review.Receipt,affirm,version)).Outcome);
        Assert.Equal(before,await r.FieldVersions()); Assert.NotNull(await r.Read(review.Receipt)); await NoAcceptance(r);
    }
    [Theory]
    [InlineData("sender")][InlineData("mixed")][InlineData("nonce")][InlineData("request")][InlineData("missing")][InlineData("malformed")][InlineData("session")][InlineData("consent")][InlineData("voided")][InlineData("prior")][InlineData("expired-review")]
    public async Task Foreign_stale_or_ineligible_context_cannot_accept_Finish(string kind)
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!; var principal=r.H.Principal; var id=r.H.Envelope.PublicId; string? receipt=review.Receipt;
        if(kind=="sender")principal=BlobStorageTests.Sender(r.H.Envelope.Id);
        if(kind=="mixed")principal.AddIdentity(new ClaimsIdentity([new(EnvelopeStorageAuthorization.EnvelopeClaim,r.H.Envelope.Id.ToString())],EnvelopeStorageAuthorization.SenderScheme));
        if(kind=="nonce") { r.H.Identity=r.H.Identity with { SessionId=Guid.NewGuid() }; principal=r.H.Principal; }
        if(kind=="request")id=Guid.NewGuid().ToString("N"); if(kind=="missing")receipt=null; if(kind=="malformed")receipt="bad";
        if(kind=="session")r.H.Clock.Advance(TimeSpan.FromHours(2)); if(kind=="expired-review")r.H.Clock.Advance(TimeSpan.FromMinutes(11));
        await using(var db=fixture.Open()) {
            if(kind=="consent")await db.Signers.Where(x=>x.Id==r.H.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ConsentAt,(DateTimeOffset?)null));
            if(kind=="voided")await db.Envelopes.Where(x=>x.Id==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            if(kind=="prior") { await db.Signers.Where(x=>x.Id==r.H.Other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,3)); await db.Signers.Where(x=>x.Id==r.H.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,2)); await db.Signers.Where(x=>x.Id==r.H.Other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,1)); }
        }
        Assert.Contains((await r.Finish(receipt,p:principal,id:id)).Outcome,new[]{SignerFinishOutcome.InvalidContext,SignerFinishOutcome.InvalidReview}); await NoAcceptance(r);
    }
    [Theory]
    [InlineData("value")][InlineData("revision")][InlineData("clear")][InlineData("name")][InlineData("replacement")]
    public async Task Changed_saved_state_requires_a_new_review_before_Finish(string kind)
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!;
        if(kind=="clear")await r.Clear(r.H.Field(FieldType.Signature).Id); else if(kind=="replacement")await r.H.Adopt(100);
        else { await using var db=fixture.Open(); if(kind=="name")await db.Signers.Where(x=>x.Id==r.H.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FullName,"Changed synthetic")); else await db.Fields.Where(x=>x.Id==r.H.Field(FieldType.Text).Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Value,kind=="value" ? "Changed" : "Saved review text")); }
        Assert.Equal(SignerFinishOutcome.InvalidReview,(await r.Finish(review.Receipt)).Outcome); await NoAcceptance(r);
    }
    [Fact]
    public async Task Accepted_Finish_blocks_fields_preview_adoption_replacement_current_reads_and_new_link_redemption()
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!;
        // A preview still current at Finish must also become unusable after acceptance.
        SignaturePreviewData preview; await using(var db=r.H.Open())preview=(await r.H.Adoption(db).PrepareAsync(r.H.Principal,r.H.Envelope.PublicId,new(SignatureAdoptionTests.Mark(100),SignatureAdoptionTests.Mark(110),SignatureMethod.Drawn)))!;
        // Preparing a preview does not replace the adopted pair or invalidate the review.
        Assert.Equal(SignerFinishOutcome.Accepted,(await r.Finish(review.Receipt)).Outcome);
        var field=r.H.Field(FieldType.Text); Assert.Equal(SignerFieldOutcome.NotFound,(await r.H.Change(new(field.Id,Convert.ToBase64String(field.RowVersion),SignerFieldAction.Clear))).Outcome); Assert.Null(await r.H.Snapshot()); Assert.Null(await r.H.Current());
        await using var check=r.H.Open(); Assert.Null(await r.H.Access(check).GetContextAsync(r.H.Principal,r.H.Envelope.PublicId));
        Assert.Null(await r.H.Adoption(check).PrepareAsync(r.H.Principal,r.H.Envelope.PublicId,new(SignatureAdoptionTests.Mark(),SignatureAdoptionTests.Mark(),SignatureMethod.Drawn)));
        Assert.Equal(SignatureAdoptionResult.InvalidContext,await r.H.Adoption(check).AdoptAsync(r.H.Principal,r.H.Envelope.PublicId,preview.Receipt,true,SignatureAdoptionStatement.Version,null,null));
        var invitation=new SignerInvitationFactory(new(),r.H.Clock).Create(r.H.Envelope.Id,r.H.Signer.Id,r.H.Signer.Email,r.H.Envelope.ExpiresAt,r.H.Identity.DocumentId,Convert.FromHexString(r.H.Identity.DocumentHash),Convert.FromHexString(r.H.Identity.DisclosureHash)); check.Add(invitation.Record); await check.SaveChangesAsync();
        Assert.Null(await r.H.Access(check).RedeemAsync(invitation.RawToken,null,null)); Assert.Null((await check.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==invitation.Record.Id)).UsedAt);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Accepted_retry_survives_review_expiry_and_midnight_but_keeps_actual_date_and_evidence(bool midnight)
    {
        await using var r=await Run.Create(fixture,midnight); var review=(await r.Prepare())!; var first=await r.Finish(review.Receipt); Assert.Equal(SignerFinishOutcome.Accepted,first.Outcome);
        r.H.Clock.Advance(midnight ? TimeSpan.FromSeconds(11) : TimeSpan.FromMinutes(11)); var retry=await r.Finish(review.Receipt); Assert.Equal(SignerFinishOutcome.AlreadyAccepted,retry.Outcome); Assert.Equal(first.Acceptance,retry.Acceptance);
        await using var db=fixture.Open(); Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_finish_accepted").ToArrayAsync()); Assert.Equal(review.ProspectiveDate.ToString("yyyy-MM-dd"),(await db.Fields.SingleAsync(x=>x.Id==r.H.Field(FieldType.DateSigned).Id)).Value);
        r.H.Identity=r.H.Identity with { SessionId=Guid.NewGuid() }; Assert.Equal(SignerFinishOutcome.InvalidContext,(await r.Finish(review.Receipt)).Outcome);
    }
    [Theory]
    [InlineData("candidate")][InlineData("source")][InlineData("asset")]
    public async Task Expiry_during_storage_leaves_review_unconsumed_and_Date_Signed_empty(string stage)
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!;
        r.H.Blobs.ReadCompleted=b=> { if(stage=="candidate" && b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=r.H.Identity.DocumentId || stage=="source" && b.ObjectId==r.H.Identity.DocumentId || stage=="asset" && b.Kind==DocumentBlobKind.Signature)r.H.Clock.Advance(TimeSpan.FromMinutes(11)); };
        Assert.Contains((await r.Finish(review.Receipt)).Outcome,new[]{SignerFinishOutcome.InvalidReview,SignerFinishOutcome.InvalidContext}); await NoAcceptance(r);
    }
    [Theory]
    [InlineData("candidate")][InlineData("missing")][InlineData("source")][InlineData("asset")]
    public async Task Missing_or_corrupt_exact_bytes_cannot_be_accepted(string kind)
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!; await using var db=fixture.Open(); var candidate=await db.SignerReviewCandidates.SingleAsync(x=>x.Id==review.Id);
        var objectId=kind=="source" ? r.H.Identity.DocumentId : kind=="asset" ? Guid.Parse((await db.Signers.SingleAsync(x=>x.Id==r.H.Signer.Id)).SignatureImageBlob!) : candidate.PdfObjectId;
        var raw=r.H.Raw(new(r.H.Envelope.Id,kind=="asset" ? DocumentBlobKind.Signature : DocumentBlobKind.Normalized,objectId)); if(kind=="missing")await raw.DeleteAsync(); else await raw.UploadAsync(BinaryData.FromBytes(PdfFixtures.Create()),true);
        var error=await Record.ExceptionAsync(()=>r.Finish(review.Receipt)); Assert.NotNull(error); Assert.True(error is InvalidDataException or DocumentRejectedException or Azure.RequestFailedException); await NoAcceptance(r);
        Assert.NotNull(await r.H.Snapshot());
    }
    [Fact]
    public async Task Audit_failure_rolls_back_acceptance_Date_Signed_and_receipt_then_lost_commit_acknowledgment_recovers_once()
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!; var before=await r.FieldVersions(); r.H.Faults.FailAudit=true;
        await Assert.ThrowsAsync<DbUpdateException>(()=>r.Finish(review.Receipt)); await NoAcceptance(r); Assert.Equal(before,await r.FieldVersions()); Assert.NotNull(await r.Read(review.Receipt));
        r.H.Faults.FailAudit=false; r.H.Faults.Commits=0; r.H.Faults.FailCommitNumber=1; await Assert.ThrowsAsync<IOException>(()=>r.Finish(review.Receipt)); r.H.Faults.FailCommitNumber=0;
        var retry=await r.Finish(review.Receipt); Assert.Equal(SignerFinishOutcome.AlreadyAccepted,retry.Outcome);
        await using var db=fixture.Open(); Assert.Single(await db.SignerFinishAcceptances.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ToArrayAsync()); Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_finish_accepted").ToArrayAsync());
    }
    [Theory]
    [InlineData("fields")][InlineData("statement")][InlineData("candidate-used")][InlineData("evidence-missing")][InlineData("evidence-hash")][InlineData("prep-missing")]
    public async Task Accepted_replay_requires_exact_immutable_record_and_both_preparation_and_acceptance_evidence(string kind)
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!; var first=await r.Finish(review.Receipt); await using var db=fixture.Open();
        if(kind=="fields")await db.SignerFinishAcceptances.Where(x=>x.Id==first.Acceptance!.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FieldsJson,"[]"));
        if(kind=="statement")await db.SignerFinishAcceptances.Where(x=>x.Id==first.Acceptance!.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.StatementVersion,"changed"));
        if(kind=="candidate-used")await db.SignerReviewCandidates.Where(x=>x.Id==review.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.UsedAt,(DateTimeOffset?)null));
        if(kind=="evidence-missing")await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_finish_accepted").ExecuteDeleteAsync();
        if(kind=="evidence-hash")await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_finish_accepted").ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Hash,new byte[32]));
        if(kind=="prep-missing")await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_review_prepared").ExecuteDeleteAsync();
        Assert.Equal(SignerFinishOutcome.InvalidReview,(await r.Finish(review.Receipt)).Outcome);
    }
    [Fact]
    public async Task Accepted_receipt_cannot_be_replaced_with_an_older_review_or_used_after_session_expiry()
    {
        await using var r=await Run.Create(fixture); var old=(await r.Prepare())!;
        await using(var db=fixture.Open())await db.Fields.Where(x=>x.Id==r.H.Field(FieldType.Text).Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Value,"Newly reviewed text"));
        var current=(await r.Prepare())!; Assert.Equal(SignerFinishOutcome.Accepted,(await r.Finish(current.Receipt)).Outcome);
        Assert.Equal(SignerFinishOutcome.InvalidReview,(await r.Finish(old.Receipt)).Outcome); r.H.Clock.Advance(TimeSpan.FromHours(2)); Assert.Equal(SignerFinishOutcome.InvalidContext,(await r.Finish(current.Receipt)).Outcome);
        await using var check=fixture.Open(); Assert.Single(await check.SignerFinishAcceptances.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ToArrayAsync());
    }
    [Fact]
    public async Task Midnight_before_first_acceptance_requires_a_new_review()
    {
        await using var r=await Run.Create(fixture,midnight:true); var review=(await r.Prepare())!; r.H.Clock.Advance(TimeSpan.FromSeconds(11));
        Assert.Equal(SignerFinishOutcome.InvalidReview,(await r.Finish(review.Receipt)).Outcome); await NoAcceptance(r);
        var current=(await r.Prepare())!; Assert.Equal(new DateOnly(2026,10,17),current.ProspectiveDate); Assert.Equal(SignerFinishOutcome.Accepted,(await r.Finish(current.Receipt)).Outcome);
    }
    [Fact]
    public async Task Accepted_replay_never_confirms_changed_checkpoint_bytes()
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!; var accepted=(await r.Finish(review.Receipt)).Acceptance!;
        await using var db=fixture.Open(); var row=await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==accepted.Id); await r.H.Raw(new(row.EnvelopeId,DocumentBlobKind.Normalized,row.PdfObjectId)).UploadAsync(BinaryData.FromBytes(PdfFixtures.Create()),true);
        await Assert.ThrowsAsync<InvalidDataException>(()=>r.Finish(review.Receipt)); Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_finish_accepted").ToArrayAsync());
    }
    [Fact]
    public async Task Database_guards_immutable_ownership_unique_acceptance_and_retention_order()
    {
        await using var r=await Run.Create(fixture); var review=(await r.Prepare())!; var accepted=(await r.Finish(review.Receipt)).Acceptance!; await using var db=fixture.Open(); var row=await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==accepted.Id);
        row.FieldsJson="[]"; await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync()); db.ChangeTracker.Clear();
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.SignerFinishAcceptances.Where(x=>x.Id==accepted.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SignerId,r.H.Other.Id)));
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.SignerFinishAcceptances.Where(x=>x.Id==accepted.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FinishedAt,row.ReviewExpiresAt)));
        var duplicate=JsonSerializer.Deserialize<SignerFinishAcceptance>(JsonSerializer.Serialize(await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==accepted.Id)))!; duplicate.Id=Guid.NewGuid(); duplicate.RowVersion=[]; db.Add(duplicate); await Assert.ThrowsAsync<DbUpdateException>(()=>db.SaveChangesAsync()); db.ChangeTracker.Clear();
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.SignerReviewCandidates.Where(x=>x.Id==review.Id).ExecuteDeleteAsync());
        await db.SignerFinishAcceptances.Where(x=>x.Id==accepted.Id).ExecuteDeleteAsync(); await db.SignerReviewCandidates.Where(x=>x.Id==review.Id).ExecuteDeleteAsync();
    }
    private async Task NoAcceptance(Run r)
    {
        await using var db=fixture.Open(); Assert.False(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id)); Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_finish_accepted"));
        Assert.Null((await db.Fields.SingleAsync(x=>x.Id==r.H.Field(FieldType.DateSigned).Id)).FilledAt); Assert.False(await db.SignerReviewCandidates.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.UsedAt!=null));
    }
}

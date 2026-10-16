using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using PigDocument=UglyToad.PdfPig.PdfDocument;
using Run=QuillSign.Tests.SignerReviewCandidateTests.Run;

namespace QuillSign.Tests;

public sealed class SignerCheckpointTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Two_signers_follow_exact_reviewed_checkpoints_with_bound_invitation_consent_adoption_and_once_only_progression()
    {
        await using var h=await Harness.Create(fixture); var firstIdentity=h.R.H.Identity; var firstPrincipal=h.R.H.Principal;
        var firstReview=(await h.R.Prepare())!; var firstPdf=(await h.R.Read(firstReview.Receipt))!.Pdf; var sent=await h.RawPdf(firstIdentity.DocumentId);
        var firstFinish=(await h.R.Finish(firstReview.Receipt)).Acceptance!; Assert.True((await h.Confirm(firstPrincipal,firstReview.Receipt))!.ProcessingPending); Assert.Null(await h.Read(firstPrincipal,firstReview.Receipt));
        h.R.H.Clock.Advance(TimeSpan.FromSeconds(3)); Assert.True(await h.Once());
        var firstCopy=(await h.Read(firstPrincipal,firstReview.Receipt))!; Assert.False(firstCopy.Acceptance.ProcessingPending); Assert.Equal(firstPdf,firstCopy.Pdf); Assert.Equal(firstFinish.FinishedAt,firstCopy.Acceptance.FinishedAt);
        Assert.Equal(SignerFinishOutcome.AlreadyAccepted,(await h.R.Finish(firstReview.Receipt)).Outcome); Assert.Null(await h.R.H.Snapshot());
        await using(var db=fixture.Open()) {
            var f=await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==firstFinish.Id); var e=await db.Envelopes.SingleAsync(x=>x.Id==h.EnvelopeId); var signer=await db.Signers.SingleAsync(x=>x.Id==firstIdentity.SignerId);
            Assert.Equal(firstFinish.Id,e.CurrentFinishId); Assert.Equal(1,e.CurrentCopyVersion); Assert.Equal(firstFinish.FinishedAt,signer.SignedAt); Assert.Equal(SignerStatus.Signed,signer.Status); Assert.Equal("127.0.0.1",signer.SignedIp);
            var invitation=await db.EmailOutbox.SingleAsync(x=>x.Id==f.NextInvitationId); var payload=new SignerInvitationProtection(h.R.H.Protection).Read(invitation.PayloadJson);
            Assert.Equal(f.PdfObjectId,payload.DocumentId); Assert.Equal(firstReview.PdfSha256,payload.DocumentSha256); Assert.Equal(firstIdentity.DisclosureHash,payload.DisclosureSha256); Assert.Null(payload.LastTokenId); Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==e.Id));
            var audit=Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==e.Id && x.Event=="signer_completed").ToArrayAsync()); Assert.Equal(AuditHash.Compute(audit),audit.Hash); Assert.Contains(firstReview.PdfSha256,audit.DataJson); Assert.Contains("checkpoint_sha256",audit.DataJson);
        }
        Assert.True(await h.Once()); Assert.Equal(1,h.Sender.Calls); var raw=Regex.Match(h.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value; Assert.Equal(43,raw.Length);
        await h.StartSecond(raw);
        Assert.NotEqual(firstIdentity.DocumentId,h.R.H.Identity.DocumentId); Assert.Equal(firstReview.PdfSha256,h.R.H.Identity.DocumentHash);
        var secondReview=(await h.R.Prepare())!; var secondPdf=(await h.R.Read(secondReview.Receipt))!.Pdf;
        using(var pdf=PigDocument.Open(secondPdf)) { Assert.Contains("Saved review text",pdf.GetPage(1).Text); Assert.Contains("Synthetic signer",pdf.GetPage(1).Text); Assert.Contains("Second saved synthetic",pdf.GetPage(2).Text); Assert.Contains("Other synthetic",pdf.GetPage(2).Text); }
        var secondFinish=(await h.R.Finish(secondReview.Receipt)).Acceptance!; Assert.True(await h.Once());
        Assert.Equal(secondPdf,(await h.Read(h.R.H.Principal,secondReview.Receipt))!.Pdf); Assert.Equal(firstPdf,(await h.Read(firstPrincipal,firstReview.Receipt))!.Pdf); Assert.Equal(sent,await h.RawPdf(firstIdentity.DocumentId));
        await using var check=fixture.Open(); var envelope=await check.Envelopes.SingleAsync(x=>x.Id==h.EnvelopeId); Assert.Equal(2,envelope.CurrentCopyVersion); Assert.Equal(secondFinish.Id,envelope.CurrentFinishId); Assert.Equal(EnvelopeStatus.Sent,envelope.Status); Assert.Null(envelope.CompletedAt); Assert.Null(envelope.FinalBlob);
        Assert.All(await check.Signers.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync(),x=>Assert.Equal(SignerStatus.Signed,x.Status));
        Assert.Equal(2,await check.AuditEvents.CountAsync(x=>x.EnvelopeId==h.EnvelopeId && x.Event=="signer_completed")); Assert.Single(await check.EmailOutbox.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync()); Assert.Equal(3,await check.WorkItems.CountAsync(x=>x.EnvelopeId==h.EnvelopeId && x.Status==WorkStatus.Completed));
        var token=Assert.Single(await check.AuthTokens.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync()); Assert.Equal(h.R.H.Identity.DocumentId,token.DocumentId); Assert.Equal(h.R.H.Identity.DocumentHash,Convert.ToHexStringLower(token.DocumentSha256!)); Assert.NotNull(token.UsedAt);
        var chain=await check.AuditEvents.Where(x=>x.EnvelopeId==h.EnvelopeId).OrderBy(x=>x.Sequence).ToArrayAsync(); for(var i=0;i<chain.Length;i++) { Assert.Equal(AuditHash.Compute(chain[i]),chain[i].Hash); if(i>0)Assert.Equal(chain[i-1].Hash,chain[i].PrevHash); }
        // Simulate a lost work acknowledgment recovered only after later progress.
        await check.WorkItems.Where(x=>x.Id==firstFinish.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,WorkStatus.Queued).SetProperty(x=>x.LeaseOwner,(Guid?)null).SetProperty(x=>x.LeaseExpiresAt,(DateTimeOffset?)null));
        await h.Signals.PublishAsync(firstFinish.Id,TimeSpan.Zero,default); Assert.True(await h.Once()); Assert.Equal(2,await check.AuditEvents.CountAsync(x=>x.EnvelopeId==h.EnvelopeId && x.Event=="signer_completed")); Assert.Single(await check.EmailOutbox.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync()); Assert.Equal(1,h.Sender.Calls);
    }
    [Fact]
    public async Task Checkpoint_worker_outlives_original_session_and_uses_actual_accepted_signing_time()
    {
        await using var h=await Harness.Create(fixture); var identity=h.R.H.Identity; var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!;
        h.R.H.Clock.Advance(TimeSpan.FromHours(3)); Assert.True(await h.Once());
        await using var db=fixture.Open(); var signer=await db.Signers.SingleAsync(x=>x.Id==identity.SignerId); var f=await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==accepted.Id);
        Assert.Equal(SignerStatus.Signed,signer.Status); Assert.Equal(accepted.FinishedAt,signer.SignedAt); Assert.True(f.ProcessedAt>identity.SessionExpiresAt); Assert.Null(await h.Confirm(SignerAccessConfiguration.Principal(identity),review.Receipt));
        Assert.True(await h.Once()); Assert.Equal(1,h.Sender.Calls); var token=Assert.Single(await db.AuthTokens.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync()); Assert.True(token.ExpiresAt>h.R.H.Clock.GetUtcNow()); Assert.Equal(f.PdfObjectId,token.DocumentId);
    }
    [Fact]
    public async Task Next_invitation_can_deliver_only_to_local_Mailpit_with_the_current_copy_bound_at_dispatch()
    {
        await using var h=await Harness.Create(fixture,smtp:true); var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!; Assert.True(await h.Once()); Assert.True(await h.Once());
        await using var db=fixture.Open(); var email=Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync()); Assert.Equal(EmailStatus.Sent,email.Status);
        var record=await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==accepted.Id); var token=Assert.Single(await db.AuthTokens.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync()); Assert.Equal(record.PdfObjectId,token.DocumentId); Assert.Equal(record.PdfSha256,token.DocumentSha256);
        using var http=new HttpClient(); var json=await http.GetStringAsync("http://127.0.0.1:"+Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT")+"/api/v1/search?query=to:"+h.SecondEmail); Assert.Contains("Review your signing request",json);
    }
    [Theory]
    [InlineData("source")][InlineData("candidate")][InlineData("missing-candidate")][InlineData("asset")][InlineData("fields")][InlineData("date")]
    [InlineData("prep-evidence")][InlineData("finish-evidence")][InlineData("adoption-evidence")][InlineData("adoption")][InlineData("consumed")][InlineData("binding")]
    [InlineData("disclosure")][InlineData("void")][InlineData("expired")][InlineData("length")][InlineData("payload")][InlineData("oversize")][InlineData("prior-order")]
    public async Task Invalid_scope_integrity_or_saved_state_cannot_publish_or_invite(string kind)
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!;
        await using(var db=fixture.Open()) {
            var f=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==accepted.Id);
            if(kind is "source" or "candidate" or "missing-candidate") { var raw=h.R.H.Raw(new(h.EnvelopeId,DocumentBlobKind.Normalized,kind=="source" ? f.SourceObjectId : f.PdfObjectId)); if(kind=="missing-candidate")await raw.DeleteAsync(); else await raw.UploadAsync(BinaryData.FromBytes(PdfFixtures.Create()),true); }
            if(kind=="asset")await h.R.H.Raw(new(h.EnvelopeId,DocumentBlobKind.Signature,Guid.Parse((await db.Signers.SingleAsync(x=>x.Id==f.SignerId)).SignatureImageBlob!))).UploadAsync(BinaryData.FromBytes(SignatureAdoptionTests.Mark(100)),true);
            if(kind is "fields" or "date")await db.Fields.Where(x=>x.Id==h.R.H.Field(kind=="fields" ? FieldType.Text : FieldType.DateSigned).Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Value,"Changed after acceptance"));
            if(kind.EndsWith("evidence")) { var name=kind=="prep-evidence" ? "signer_review_prepared" : kind=="finish-evidence" ? "signer_finish_accepted" : "signature_adopted"; await db.AuditEvents.Where(x=>x.EnvelopeId==h.EnvelopeId && x.Event==name).ExecuteDeleteAsync(); }
            if(kind=="adoption")await db.Signers.Where(x=>x.Id==f.SignerId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SignatureImageSha256,new byte[32]));
            if(kind=="consumed")await db.SignerReviewCandidates.Where(x=>x.Id==review.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.UsedAt,(DateTimeOffset?)null));
            if(kind=="binding")await db.SignerReviewCandidates.Where(x=>x.Id==review.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SourceSha256,new byte[32]));
            if(kind=="disclosure")await db.Envelopes.Where(x=>x.Id==h.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ErsdText,"Changed disclosure"));
            if(kind=="void")await db.Envelopes.Where(x=>x.Id==h.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            if(kind=="expired")await db.Envelopes.Where(x=>x.Id==h.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,h.R.H.Clock.GetUtcNow()));
            if(kind=="payload")await db.WorkItems.Where(x=>x.Id==accepted.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
            if(kind=="prior-order") { await db.Signers.Where(x=>x.Id==h.R.H.Other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,3)); await db.Signers.Where(x=>x.Id==h.R.H.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,2)); await db.Signers.Where(x=>x.Id==h.R.H.Other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,1)); }
        }
        h.R.H.Blobs.WrongReviewLength=kind=="length"; h.R.H.Blobs.OversizeReviewRead=kind=="oversize"; Assert.True(await h.Once()); await NoPublication(h,accepted.Id); Assert.Equal(0,h.Sender.Calls);
    }
    [Theory]
    [InlineData("audit")][InlineData("hint")][InlineData("email-disabled")][InlineData("commit")]
    public async Task Publication_failure_or_lost_ack_recovers_one_checkpoint_and_one_next_invitation(string kind)
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!;
        h.R.H.Faults.FailAudit=kind=="audit"; h.Signals.FailHint=kind=="hint"; h.App.Services.GetRequiredService<EmailOptions>().Enabled=kind!="email-disabled";
        if(kind=="commit") { h.R.H.Faults.Commits=0; h.R.H.Faults.FailCommitNumber=2; }
        if(kind=="audit")await Assert.ThrowsAsync<DbUpdateException>(()=>h.Once()); else if(kind=="hint")await Assert.ThrowsAsync<IOException>(()=>h.Once()); else Assert.True(await h.Once());
        if(kind!="commit")await NoPublication(h,accepted.Id);
        h.R.H.Faults.FailAudit=false; h.R.H.Faults.FailCommitNumber=0; h.Signals.FailHint=false; h.App.Services.GetRequiredService<EmailOptions>().Enabled=true;
        h.R.H.Clock.Advance(TimeSpan.FromMinutes(6)); await h.Signals.RecoverAsync(h.R.H.Clock.GetUtcNow(),default);
        for(var i=0;i<8;i++) { await h.Once(); await using var db=fixture.Open(); if(await db.WorkItems.AnyAsync(x=>x.Id==accepted.Id && x.Status==WorkStatus.Completed) && await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==h.EnvelopeId && x.Status==EmailStatus.Sent))break; }
        await using var check=fixture.Open(); Assert.Equal(WorkStatus.Completed,(await check.WorkItems.SingleAsync(x=>x.Id==accepted.Id)).Status); Assert.Single(await check.AuditEvents.Where(x=>x.EnvelopeId==h.EnvelopeId && x.Event=="signer_completed").ToArrayAsync()); Assert.Single(await check.EmailOutbox.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync()); Assert.Equal(1,h.Sender.Calls);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Lost_wakeup_after_Finish_or_checkpoint_commit_recovers_from_blob_hints(bool checkpoint)
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; h.Signals.FailPublish=!checkpoint;
        var accepted=(await h.R.Finish(review.Receipt)).Acceptance!; if(checkpoint) { h.Signals.FailPublish=true; Assert.True(await h.Once()); }
        Assert.False(await h.Once()); h.Signals.FailPublish=false; h.R.H.Clock.Advance(TimeSpan.FromSeconds(1)); Assert.True(await h.Signals.RecoverAsync(h.R.H.Clock.GetUtcNow(),default)>0);
        Assert.True(await h.Once()); if(!checkpoint)Assert.True(await h.Once());
        await using var db=fixture.Open(); Assert.NotNull((await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==accepted.Id)).ProcessedAt); Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==h.EnvelopeId && x.Status==EmailStatus.Sent).ToArrayAsync()); Assert.Equal(1,h.Sender.Calls);
    }
    [Fact]
    public async Task Lease_expiry_during_blob_read_rolls_back_and_a_fresh_claim_can_publish()
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!;
        h.R.H.Blobs.ReadCompleted=b=> { if(b.Kind==DocumentBlobKind.Normalized)h.R.H.Clock.Advance(TimeSpan.FromMinutes(6)); };
        await Assert.ThrowsAsync<InvalidOperationException>(()=>h.Once()); await NoPublication(h,accepted.Id); h.R.H.Blobs.ReadCompleted=null;
        await h.Signals.RecoverAsync(h.R.H.Clock.GetUtcNow(),default); Assert.True(await h.Once()); await using var db=fixture.Open(); Assert.NotNull((await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==accepted.Id)).ProcessedAt);
    }
    [Theory]
    [InlineData("owner")][InlineData("attempt")][InlineData("until")][InlineData("kind")]
    public async Task A_forged_or_stale_lease_has_no_publication_authority(string kind)
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!;
        await using var scope=h.App.Services.CreateAsyncScope(); var lease=(await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(accepted.Id,default)).Lease!;
        var forged=kind switch { "owner"=>lease with { Owner=Guid.NewGuid() },"attempt"=>lease with { Attempt=lease.Attempt+1 },"until"=>lease with { Until=lease.Until.AddHours(1) },_=>lease with { Kind=WorkKind.Sealing } };
        Assert.NotEqual(WorkOutcome.Completed,(await scope.ServiceProvider.GetServices<IWorkHandler>().Single(x=>x.Kind==WorkKind.Rendering).ExecuteAsync(forged,default)).Outcome); await NoPublication(h,accepted.Id);
    }
    [Theory]
    [InlineData("sender")][InlineData("mixed")][InlineData("nonce")][InlineData("document")][InlineData("disclosure")][InlineData("session")][InlineData("void")][InlineData("envelope-expiry")]
    public async Task Own_checkpoint_confirmation_and_download_preserve_original_isolated_scope(string kind)
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; await h.R.Finish(review.Receipt); Assert.True(await h.Once()); var principal=h.R.H.Principal;
        if(kind=="sender")principal=BlobStorageTests.Sender(h.EnvelopeId);
        if(kind=="mixed")principal.AddIdentity((ClaimsIdentity)BlobStorageTests.Sender(h.EnvelopeId).Identity!);
        if(kind=="nonce")principal=SignerAccessConfiguration.Principal(h.R.H.Identity with { SessionId=Guid.NewGuid() });
        if(kind=="document")principal=SignerAccessConfiguration.Principal(h.R.H.Identity with { DocumentId=Guid.NewGuid() });
        if(kind=="disclosure")principal=SignerAccessConfiguration.Principal(h.R.H.Identity with { DisclosureHash=new string('0',64) });
        if(kind=="session")h.R.H.Clock.Advance(TimeSpan.FromHours(3));
        await using(var db=fixture.Open()) { if(kind=="void")await db.Envelopes.Where(x=>x.Id==h.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided)); if(kind=="envelope-expiry")await db.Envelopes.Where(x=>x.Id==h.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,h.R.H.Clock.GetUtcNow())); }
        Assert.Null(await h.Read(principal,review.Receipt)); Assert.Null(await h.Confirm(principal,review.Receipt));
    }
    [Theory]
    [InlineData("pointer")][InlineData("processed")][InlineData("hash")][InlineData("published-evidence")]
    public async Task Missing_or_corrupt_prior_checkpoint_never_falls_back_to_the_original_sent_copy(string kind)
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!; Assert.True(await h.Once());
        await using(var db=fixture.Open()) {
            if(kind=="pointer")await db.Envelopes.Where(x=>x.Id==h.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CurrentFinishId,(Guid?)null).SetProperty(x=>x.CurrentCopyVersion,0));
            if(kind=="processed")await db.SignerFinishAcceptances.Where(x=>x.Id==accepted.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ProcessedAt,(DateTimeOffset?)null).SetProperty(x=>x.NextInvitationId,(Guid?)null));
            if(kind=="hash")await db.SignerFinishAcceptances.Where(x=>x.Id==accepted.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PdfSha256,new byte[32]));
            if(kind=="published-evidence")await db.AuditEvents.Where(x=>x.EnvelopeId==h.EnvelopeId && x.Event=="signer_completed").ExecuteDeleteAsync();
        }
        Assert.Null(await h.Read(h.R.H.Principal,review.Receipt)); Assert.True(await h.Once()); Assert.Equal(0,h.Sender.Calls);
        await using var check=fixture.Open(); Assert.False(await check.AuthTokens.AnyAsync(x=>x.EnvelopeId==h.EnvelopeId)); Assert.Equal(SignerStatus.Pending,(await check.Signers.SingleAsync(x=>x.Id==h.R.H.Other.Id)).Status);
    }
    [Theory]
    [InlineData("document")][InlineData("hash")][InlineData("disclosure")][InlineData("legacy")]
    public async Task Dispatched_tokens_are_pinned_to_exact_current_document_and_disclosure(string kind)
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; await h.R.Finish(review.Receipt); Assert.True(await h.Once()); Assert.True(await h.Once());
        var raw=Regex.Match(h.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        await using var db=fixture.Open(); var token=await db.AuthTokens.SingleAsync(x=>x.EnvelopeId==h.EnvelopeId);
        if(kind=="document")token.DocumentId=Guid.NewGuid(); if(kind=="hash")token.DocumentSha256=new byte[32]; if(kind=="disclosure")token.DisclosureSha256=new byte[32]; if(kind=="legacy") { token.DocumentId=null; token.DocumentSha256=null; token.DisclosureSha256=null; } await db.SaveChangesAsync();
        Assert.Null(await h.R.H.Access(db).RedeemAsync(raw,null,null)); Assert.Null((await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==token.Id)).UsedAt);
    }
    [Fact]
    public async Task Suppressed_next_recipient_gets_no_invitation_token_or_provider_submission()
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; await h.R.Finish(review.Receipt);
        await using(var db=fixture.Open()) { db.Suppressions.Add(new() { Email=h.SecondEmail,Reason=SuppressionReason.Bounce }); await db.SaveChangesAsync(); }
        Assert.True(await h.Once()); Assert.True(await h.Once()); Assert.Equal(0,h.Sender.Calls);
        await using var check=fixture.Open(); Assert.Equal(SignerStatus.Signed,(await check.Signers.SingleAsync(x=>x.Id==h.R.H.Signer.Id)).Status); Assert.False(await check.AuthTokens.AnyAsync(x=>x.EnvelopeId==h.EnvelopeId)); Assert.Equal(EmailStatus.Failed,Assert.Single(await check.EmailOutbox.Where(x=>x.EnvelopeId==h.EnvelopeId).ToArrayAsync()).Status);
    }
    [Fact]
    public async Task Accepted_checkpoint_read_capability_cannot_be_copied_mutated_or_retargeted_and_expires()
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!; Assert.True(await h.Once()); Assert.NotNull(await h.Read(h.R.H.Principal,review.Receipt));
        await using var db=fixture.Open(); var f=await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==accepted.Id); var blob=new DocumentBlob(h.EnvelopeId,DocumentBlobKind.Normalized,f.PdfObjectId); var capability=h.R.H.Blobs.LastReviewRead!;
        EnvelopeStorageAuthorization.DemandRead(capability,blob); Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(h.R.H.Principal,blob)); Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(new ClaimsPrincipal(capability.Identities),blob));
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(capability,blob with { ObjectId=Guid.NewGuid() })); Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.Demand(capability,blob)); Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandDelete(capability,blob));
        h.R.H.Clock.Advance(TimeSpan.FromMinutes(2)); Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(capability,blob));
    }
    [Fact]
    public async Task Own_checkpoint_read_rechecks_session_after_buffering_bytes()
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; await h.R.Finish(review.Receipt); Assert.True(await h.Once());
        h.R.H.Blobs.ReadCompleted=b=> { if(b.Kind==DocumentBlobKind.Normalized)h.R.H.Clock.Advance(TimeSpan.FromHours(3)); };
        Assert.Null(await h.Read(h.R.H.Principal,review.Receipt)); Assert.Null(await h.Confirm(h.R.H.Principal,review.Receipt));
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Disabled_work_or_failed_initial_hint_rolls_back_Finish_and_remains_retryable(bool hint)
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; h.R.Work.Enabled=hint; h.Signals.FailHint=hint;
        if(hint)await Assert.ThrowsAsync<IOException>(()=>h.R.Finish(review.Receipt)); else await Assert.ThrowsAsync<InvalidOperationException>(()=>h.R.Finish(review.Receipt));
        await using var db=fixture.Open(); Assert.False(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==h.EnvelopeId)); Assert.False(await db.WorkItems.AnyAsync(x=>x.EnvelopeId==h.EnvelopeId)); Assert.Null((await db.SignerReviewCandidates.SingleAsync(x=>x.Id==review.Id)).UsedAt); Assert.Null((await db.Fields.SingleAsync(x=>x.Id==h.R.H.Field(FieldType.DateSigned).Id)).FilledAt);
        h.R.Work.Enabled=true; h.Signals.FailHint=false; Assert.Equal(SignerFinishOutcome.Accepted,(await h.R.Finish(review.Receipt)).Outcome); Assert.True(await h.Once());
    }
    [Fact]
    public async Task Current_reference_is_owned_and_requires_explicit_clearing_before_retention_deletes()
    {
        await using var h=await Harness.Create(fixture); var review=(await h.R.Prepare())!; var accepted=(await h.R.Finish(review.Receipt)).Acceptance!; Assert.True(await h.Once());
        await using var db=fixture.Open(); var other=new Envelope { SenderEmail="other@example.invalid" }; db.Add(other); await db.SaveChangesAsync();
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.Envelopes.Where(x=>x.Id==other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CurrentFinishId,accepted.Id).SetProperty(x=>x.CurrentCopyVersion,1)));
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.SignerFinishAcceptances.Where(x=>x.Id==accepted.Id).ExecuteDeleteAsync());
        await db.Envelopes.Where(x=>x.Id==h.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CurrentFinishId,(Guid?)null).SetProperty(x=>x.CurrentCopyVersion,0)); await db.SignerFinishAcceptances.Where(x=>x.Id==accepted.Id).ExecuteDeleteAsync();
    }
    private async Task NoPublication(Harness h,Guid finishId)
    {
        await using var db=fixture.Open(); var f=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==finishId); Assert.Null(f.ProcessedAt); Assert.Null(f.NextInvitationId);
        Assert.Equal(SignerStatus.Viewed,(await db.Signers.SingleAsync(x=>x.Id==f.SignerId)).Status); Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==h.EnvelopeId && x.Event=="signer_completed")); Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==h.EnvelopeId));
    }

    private sealed class Harness : IAsyncDisposable
    {
        public Run R=null!; public WebApplication App=null!; public Signals Signals=null!; public Sender Sender=new();
        private QueueClient queue=null!; private BlobContainerClient hints=null!; private SqlDatabaseFixture fixture=null!;
        public Guid EnvelopeId=>R.H.Envelope.Id; public string SecondEmail="";
        public static async Task<Harness> Create(SqlDatabaseFixture fixture,bool smtp=false)
        {
            var h=new Harness { R=await Run.Create(fixture),fixture=fixture }; var name="checkpoint-"+Guid.NewGuid().ToString("N"); var storage=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;
            h.SecondEmail=name+"@example.invalid";
            await using(var db=fixture.Open()) {
                await db.Signers.Where(x=>x.Id==h.R.H.Other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Email,h.SecondEmail)); h.R.H.Other.Email=h.SecondEmail;
                foreach(var type in new[]{FieldType.Text,FieldType.FullName,FieldType.DateSigned})db.Fields.Add(new() { EnvelopeId=h.EnvelopeId,SignerId=h.R.H.Other.Id,Type=type,Page=2,X=.1m,Y=type==FieldType.Text ? .5m : type==FieldType.FullName ? .65m : .8m,Width=.7m,Height=.08m,Required=true }); await db.SaveChangesAsync();
            }
            h.queue=new(storage,name,new QueueClientOptions(QueueClientOptions.ServiceVersion.V2023_11_03)); h.hints=new BlobServiceClient(storage,new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)).GetBlobContainerClient(name);
            h.Signals=new(new AzureWorkSignals(h.queue,h.hints,h.R.Work,true)); h.R.Signals=h.Signals;
            using var original=fixture.Open(); var connection=original.Database.GetConnectionString();
            var builder=WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName=typeof(SignerCheckpointHandler).Assembly.FullName,EnvironmentName="Development",ContentRootPath=AppContext.BaseDirectory }); builder.Logging.ClearProviders();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> { ["Storage:Provider"]="Azurite",["Storage:ConnectionString"]=storage,["Work:Enabled"]="true",["Work:QueueName"]=name,["Work:HintContainer"]=name,
                ["Email:Enabled"]="true",["Email:Provider"]="Smtp",["Email:FromEmail"]="noreply@example.invalid",["Email:BaseUrl"]="http://localhost:5084",["Email:Smtp:Host"]="127.0.0.1",["Email:Smtp:Port"]=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_SMTP_PORT"),["Email:Smtp:UseStartTls"]="false" });
            builder.Services.AddRazorPages(); builder.Services.AddDbContext<QuillSignDbContext>(o=>o.UseSqlServer(connection).AddInterceptors(h.R.H.Faults)); builder.Services.AddQuillSignEmail(builder.Configuration,builder.Environment); builder.Services.AddQuillSignWork(builder.Configuration,builder.Environment);
            builder.Services.AddSingleton<TimeProvider>(h.R.H.Clock); builder.Services.AddSingleton<IBlobStore>(h.R.H.Blobs); builder.Services.AddSingleton<IDataProtectionProvider>(h.R.H.Protection); builder.Services.AddSingleton<IWorkSignals>(h.Signals); builder.Services.AddSingleton(h.R.Work);
            builder.Services.AddSingleton(new DocumentOptions()); builder.Services.AddQuillSignSignerConsent(); builder.Services.AddScoped<SignerReviewProtection>(); builder.Services.AddScoped<SignerCheckpointReads>(); if(!smtp)builder.Services.AddSingleton<IEmailSender>(h.Sender);
            h.App=builder.Build(); return h;
        }
        public async Task<bool> Once() { await using var scope=App.Services.CreateAsyncScope(); return await scope.ServiceProvider.GetRequiredService<WorkProcessor>().RunOnceAsync(default); }
        public async Task<byte[]> RawPdf(Guid id)=>(await R.H.Raw(new(EnvelopeId,DocumentBlobKind.Normalized,id)).DownloadContentAsync()).Value.Content.ToArray();
        public async Task<SignerFinishAccepted?> Confirm(ClaimsPrincipal principal,string receipt) { await using var scope=App.Services.CreateAsyncScope(); return await scope.ServiceProvider.GetRequiredService<SignerCheckpointReads>().ConfirmAsync(principal,R.H.Envelope.PublicId,receipt); }
        public async Task<SignerOwnCheckpoint?> Read(ClaimsPrincipal principal,string receipt) { await using var scope=App.Services.CreateAsyncScope(); return await scope.ServiceProvider.GetRequiredService<SignerCheckpointReads>().ReadAsync(principal,R.H.Envelope.PublicId,receipt); }
        public async Task StartSecond(string raw)
        {
            await using(var scope=App.Services.CreateAsyncScope()) {
                var access=scope.ServiceProvider.GetRequiredService<SignerAccess>(); var identity=(await access.RedeemAsync(raw,"127.0.0.1","Synthetic second signer"))!; Assert.NotNull(identity); Assert.Null(await access.RedeemAsync(raw,null,null)); R.H.Identity=identity; R.H.Blobs.SourceId=identity.DocumentId;
                var context=(await access.GetContextAsync(R.H.Principal,R.H.Envelope.PublicId))!; var pdf=await scope.ServiceProvider.GetRequiredService<SignerPdfAccess>().PrepareAsync(R.H.Principal,context); Assert.Equal(identity.DocumentHash,Convert.ToHexStringLower(SHA256.HashData(pdf)));
                var receipt=scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(identity); Assert.Equal(ConsentResult.Accepted,await scope.ServiceProvider.GetRequiredService<SignerConsent>().AcceptAsync(R.H.Principal,R.H.Envelope.PublicId,receipt,true,true,"download",null,null));
            }
            await using(var db=fixture.Open()) { R.H.Signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==R.H.Identity.SignerId); R.H.Fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==EnvelopeId && x.SignerId==R.H.Signer.Id).ToListAsync(); }
            var adopted=await R.H.Adopt(100); foreach(var f in R.H.Fields.Where(x=>x.Type!=FieldType.DateSigned))Assert.Equal(SignerFieldOutcome.Applied,(await R.H.Apply(f,f.Type==FieldType.Text ? "Second saved synthetic" : null,f.Type is FieldType.Signature or FieldType.Initials ? adopted.Id : null)).Outcome);
        }
        public async ValueTask DisposeAsync() { await App.DisposeAsync(); await R.DisposeAsync(); await queue.DeleteIfExistsAsync(); await hints.DeleteIfExistsAsync(); }
    }
    private sealed class Sender : IEmailSender
    {
        public int Calls; public OutgoingEmail? Last;
        public Task<EmailDelivery> SendAsync(OutgoingEmail email,CancellationToken ct) { Calls++; Last=email; return Task.FromResult(new EmailDelivery("Synthetic","synthetic-checkpoint-receipt")); }
    }
    private sealed class Signals(IWorkSignals inner) : IWorkSignals
    {
        public bool FailHint,FailPublish;
        public Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct) { if(FailHint)throw new IOException("Synthetic checkpoint hint failure"); return inner.PutHintAsync(id,due,ct); }
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct) { if(FailPublish)throw new IOException("Synthetic checkpoint publish failure"); return inner.PublishAsync(id,delay,ct); }
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>inner.RemoveHintAsync(id,ct);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>inner.ReceiveAsync(ct);
        public Task DeferAsync(WorkDelivery delivery,TimeSpan delay,CancellationToken ct)=>inner.DeferAsync(delivery,delay,ct);
        public Task AcknowledgeAsync(WorkDelivery delivery,CancellationToken ct)=>inner.AcknowledgeAsync(delivery,ct);
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>inner.RecoverAsync(now,ct);
        public Task VerifyAsync(CancellationToken ct)=>inner.VerifyAsync(ct);
    }
}

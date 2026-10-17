using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;
using Run=QuillSign.Tests.SignerReviewCandidateTests.Run;
using Flow=QuillSign.Tests.SignerReviewPageTests.Flow;

namespace QuillSign.Tests;

public sealed class PostConsentDeclineTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private static SignerConsent Consent(Run r,QuillSignDbContext db)=>new(db,r.H.Access(db),new(r.H.Protection,r.H.Clock),new(db,r.H.Clock),
        new(db,()=>throw new InvalidOperationException("External sending disabled"),new(),new(r.H.Protection),r.H.Clock),r.H.Clock);
    private async Task<SignerReadContext?> Decline(Run r) {await using var db=r.H.Open();return await Consent(r,db).DeclineAsync(r.H.Principal,r.H.Envelope.PublicId,"Synthetic refusal",null,null);}
    [Fact]
    public async Task Saved_marks_entries_and_review_can_be_declined_while_all_prior_evidence_and_files_remain_unchanged()
    {
        await using var r=await Run.Create(fixture);var review=(await r.Prepare())!;var fields=await r.FieldVersions();
        await using var db=fixture.Open();var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==r.H.Signer.Id);
        var adoptions=JsonSerializer.Serialize(await db.SignaturePreviews.AsNoTracking().Where(x=>x.EnvelopeId==r.H.Envelope.Id).ToArrayAsync());
        var candidate=JsonSerializer.Serialize(await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==review.Id));
        Assert.NotNull(await Decline(r));Assert.Null(await Decline(r));Assert.Equal(fields,await r.FieldVersions());
        var after=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==signer.Id);Assert.Equal(signer.ConsentAt,after.ConsentAt);Assert.Equal(signer.SignatureAdoptionId,after.SignatureAdoptionId);Assert.Equal(SignerStatus.Declined,after.Status);
        Assert.Equal(adoptions,JsonSerializer.Serialize(await db.SignaturePreviews.AsNoTracking().Where(x=>x.EnvelopeId==r.H.Envelope.Id).ToArrayAsync()));
        Assert.Equal(candidate,JsonSerializer.Serialize(await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==review.Id)));
        Assert.Equal(SignerFinishOutcome.InvalidContext,(await r.Finish(review.Receipt)).Outcome);Assert.False(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id));
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="declined"));
        Assert.True((await r.H.Raw(new(r.H.Envelope.Id,QuillSign.Storage.DocumentBlobKind.Normalized,r.H.Identity.DocumentId)).ExistsAsync()).Value);
    }
    [Fact]
    public async Task Already_accepted_Finish_cannot_be_declined_or_changed_even_before_worker_publication()
    {
        await using var r=await Run.Create(fixture);var review=(await r.Prepare())!;Assert.Equal(SignerFinishOutcome.Accepted,(await r.Finish(review.Receipt)).Outcome);
        var fields=await r.FieldVersions();Assert.Null(await Decline(r));Assert.Equal(fields,await r.FieldVersions());
        await using var db=fixture.Open();Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.SingleAsync(x=>x.Id==r.H.Envelope.Id)).Status);Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="declined"));
    }
    [Fact]
    public async Task Concurrent_Finish_and_decline_accept_exactly_one_terminal_choice_under_the_parent_lock()
    {
        await using var r=await Run.Create(fixture);var review=(await r.Prepare())!;
        var finish=r.Finish(review.Receipt);var decline=Decline(r);await Task.WhenAll(finish,decline);
        var accepted=(await finish).Outcome==SignerFinishOutcome.Accepted;Assert.Equal(!accepted,(await decline) is not null);
        await using var db=fixture.Open();Assert.Equal(accepted ? 1 : 0,await db.SignerFinishAcceptances.CountAsync(x=>x.EnvelopeId==r.H.Envelope.Id));
        Assert.Equal(accepted ? 0 : 1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="declined"));
        Assert.Equal(accepted ? EnvelopeStatus.Sent : EnvelopeStatus.Declined,(await db.Envelopes.SingleAsync(x=>x.Id==r.H.Envelope.Id)).Status);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Failed_audit_rolls_back_then_lost_commit_recovers_without_another_decline(bool lostCommit)
    {
        await using var r=await Run.Create(fixture);var fields=await r.FieldVersions();
        if(lostCommit){r.H.Faults.Commits=0;r.H.Faults.FailCommitNumber=1;await Assert.ThrowsAsync<IOException>(()=>Decline(r));r.H.Faults.FailCommitNumber=0;}
        else {r.H.Faults.FailAudit=true;await Assert.ThrowsAsync<DbUpdateException>(()=>Decline(r));r.H.Faults.FailAudit=false;Assert.NotNull(await r.H.Snapshot());Assert.NotNull(await Decline(r));}
        Assert.Null(await Decline(r));Assert.Equal(fields,await r.FieldVersions());await using var db=fixture.Open();Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="declined"));Assert.Equal(1,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==r.H.Envelope.Id));
    }
    [Fact]
    public async Task New_page_is_available_from_all_saved_signing_steps_and_recovers_a_lost_acceptance_response()
    {
        await using var f=await Flow.Create(fixture);var path="/sign/"+f.H.R.H.Envelope.PublicId;var decline=path+"/decline";
        foreach(var step in new[]{"","/signature","/fields","/review"})Assert.Contains(decline,await f.Page(path+step));
        var page=await f.Page(decline);Assert.DoesNotContain("checked=",page);
        f.H.R.H.Faults.Commits=0;f.H.R.H.Faults.FailCommitNumber=2;
        using(var response=await f.Client.PostAsync(decline,new FormUrlEncodedContent(new Dictionary<string,string>{["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page),["ConfirmDecline"]="true"})))
        {f.Take(response);Assert.Equal(System.Net.HttpStatusCode.Redirect,response.StatusCode);Assert.Equal(path+"/declined",response.Headers.Location!.OriginalString);}
        f.H.R.H.Faults.FailCommitNumber=0;
        await using var db=fixture.Open();Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==f.H.EnvelopeId && x.Event=="declined"));Assert.Equal(0,f.H.Sender.Calls);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Retained_post_consent_page_and_audit_boundary_deny_exact_cutoff_without_mutation(bool duringAudit)
    {
        await using var r=await SignerRetentionAccessTests.Run.Create(fixture);await r.Consent();await r.SignIn();
        var path=r.Signing+"/decline";var page=await r.Flow!.Page(path);var before=await r.Counts();
        if(duringAudit){r.H.Faults.Event="declined";r.H.Faults.BeforeAudit=_=>{r.Expire();return Task.CompletedTask;};}
        else r.Expire();
        using(var denied=await r.Flow.Post(path,page,new(){["ConfirmDecline"]="true"})) {
            Assert.Equal(System.Net.HttpStatusCode.Gone,denied.StatusCode);Assert.DoesNotContain(r.H.Envelope.Title!,await denied.Content.ReadAsStringAsync());
        }
        Assert.Equal(before,await r.Counts());Assert.Equal(0,r.H.Sender.Calls);
    }
    public sealed class BrowserSession:IAsyncDisposable
    {
        private readonly SignerRetentionAccessTests.Run r;private readonly SqlDatabaseFixture fixture;private readonly string fields;private readonly DateTimeOffset? consent;
        private BrowserSession(SignerRetentionAccessTests.Run r,SqlDatabaseFixture fixture,string fields,DateTimeOffset? consent)
        {this.r=r;this.fixture=fixture;this.fields=fields;this.consent=consent;}
        public string PublicId=>r.PublicId;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port)
        {
            var r=await SignerRetentionAccessTests.Run.Create(fixture,port:port);
            try {
                _=await r.PrepareThroughHttp();await using var db=fixture.Open();
                var fields=JsonSerializer.Serialize(await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==r.H.Envelope.Id).OrderBy(x=>x.Id).ToArrayAsync());
                var consent=(await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==r.H.First.Id)).ConsentAt;
                return new(r,fixture,fields,consent);
            }catch{await r.DisposeAsync();throw;}
        }
        public async Task<string> Verify()
        {
            await using var db=fixture.Open();var id=r.H.Envelope.Id;
            Assert.Equal(fields,JsonSerializer.Serialize(await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync()));
            var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==r.H.First.Id);Assert.Equal(consent,signer.ConsentAt);Assert.Equal(SignerStatus.Declined,signer.Status);
            Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==id && x.Event=="declined"));Assert.False(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==id));
            Assert.False(await db.SignerReviewCandidates.AnyAsync(x=>x.EnvelopeId==id && x.UsedAt!=null));Assert.Equal(0,r.H.Sender.Calls);
            return "Verified one decline, unchanged consent/fields, no Finish and no outbound email.";
        }
        public ValueTask DisposeAsync()=>r.DisposeAsync();
    }
}

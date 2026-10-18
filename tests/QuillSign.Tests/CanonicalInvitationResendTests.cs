using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Run=QuillSign.Tests.InvitationLineageTests.Run;

namespace QuillSign.Tests;

public sealed class CanonicalInvitationResendTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string AdmissionEvent="invitation_resend_current_contact_requested";
    private sealed class CorrectionPolicy:IInvitationSuccessorPolicy
    {
        public InvitationSuccessorReason Reason=>InvitationSuccessorReason.ContactCorrection;
        public bool Enabled=>true;
        public Task<bool> ValidateLockedAsync(Envelope e,InvitationSuccessorScope p,CancellationToken ct)=>Task.FromResult(true);
    }
    private static Task<Run> Create(SqlDatabaseFixture fixture,bool smtp=false,int? port=null,bool browser=false,
        InvitationResendProtection? legacy=null,InvitationSuccessorProtection? successors=null)=>Run.Create(fixture,browserPort:port,smtp:smtp,browser:browser,
            configure:s=>{s.AddSingleton<IInvitationSuccessorPolicy>(new CorrectionPolicy());if(legacy is not null)s.AddSingleton(legacy);if(successors is not null)s.AddSingleton(successors);});

    [Fact]
    public async Task Corrected_recipient_gets_a_canonical_deliberate_replacement_with_the_same_epoch()
    {
        await using var r=await Create(fixture);var revision=await Correct(r,Corrected(r));
        var old=Token(r.H.Sender.Last!.Text);var review=(await Review(r))!;Assert.Equal(new(revision.Id,revision.Number),review.Contact);Assert.NotNull(review.PreviousId);
        var id=Guid.NewGuid();Assert.Equal(InvitationResendOutcome.Queued,await Request(r,id,review));
        using(var scope=r.H.App.Services.CreateScope())Assert.Null(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(old,null,null));
        Assert.Equal(InvitationResendOutcome.AlreadyRequested,await Request(r,id,review));Assert.Equal(WorkOutcome.Completed,(await Dispatch(r,id)).Outcome);
        Assert.Equal(3,r.H.Sender.Calls);Assert.Equal(revision.NewEmail,r.H.Sender.Last!.To);Assert.Contains("replacement signing invitation",r.H.Sender.Last.Subject);
        using(var scope=r.H.App.Services.CreateScope())Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(Token(r.H.Sender.Last.Text),null,null));
        var latest=(await r.Read())!.Latest;Assert.Equal(id,latest.Id);Assert.Equal(review.Contact,latest.Contact);Assert.Equal(InvitationSuccessorReason.ManualResend,latest.Reason);
    }

    [Fact]
    public async Task Same_contact_resend_preserves_open_session_but_later_correction_retires_it()
    {
        await using var r=await Create(fixture);await Correct(r,Corrected(r));VerifiedSigner identity;
        using(var scope=r.H.App.Services.CreateScope())identity=(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(Token(r.H.Sender.Last!.Text),null,null))!;
        Assert.NotNull(identity);var principal=SignerAccessConfiguration.Principal(identity);var id=Guid.NewGuid();
        Assert.Equal(InvitationResendOutcome.Queued,await Request(r,id,(await Review(r))!));Assert.Equal(WorkOutcome.Completed,(await Dispatch(r,id)).Outcome);
        using(var scope=r.H.App.Services.CreateScope())Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SignerAccess>().GetContextAsync(principal,identity.PublicId));
        await Correct(r,"other@example.invalid");await Correct(r,Corrected(r));
        using(var scope=r.H.App.Services.CreateScope())Assert.Null(await scope.ServiceProvider.GetRequiredService<SignerAccess>().GetContextAsync(principal,identity.PublicId));
    }

    [Theory][InlineData("legacy")][InlineData("corrected")]
    public async Task A_returned_address_does_not_revive_an_old_review_or_proof(string captured)
    {
        await using var r=await Create(fixture);var original=r.H.First.Email;InvitationResendReview old;
        if(captured=="corrected") {await Correct(r,"b@example.invalid");old=(await Review(r))!;await Correct(r,"c@example.invalid");await Correct(r,"b@example.invalid");}
        else {old=(await Review(r))!;await Correct(r,"b@example.invalid");await Correct(r,original);}
        Assert.Equal(InvitationResendOutcome.Conflict,await Request(r,Guid.NewGuid(),old));
        var current=(await Review(r))!;Assert.NotEqual(old.Contact,current.Contact);Assert.Equal(InvitationResendOutcome.Queued,await Request(r,Guid.NewGuid(),current));
    }

    [Fact]
    public async Task Legacy_and_canonical_manual_admissions_share_one_cap_pool()
    {
        await using var r=await Create(fixture);Assert.Equal(InvitationResendOutcome.Queued,await r.RequestResend());Assert.True(await r.H.Once());
        await Correct(r,Corrected(r));var limits=r.H.App.Services.GetRequiredService<InvitationResendOptions>();
        limits.DailyRequests=limits.DailyAddressRequests=limits.DailyIpRequests=limits.DailySenderRequests=1;
        Assert.Equal(InvitationResendOutcome.Capped,await Request(r,Guid.NewGuid(),(await Review(r))!));
        limits.DailyRequests=limits.DailyAddressRequests=limits.DailyIpRequests=limits.DailySenderRequests=2;
        var id=Guid.NewGuid();Assert.Equal(InvitationResendOutcome.Queued,await Request(r,id,(await Review(r))!));Assert.Equal(WorkOutcome.Completed,(await Dispatch(r,id)).Outcome);
        Assert.Equal(InvitationResendOutcome.Capped,await Request(r,Guid.NewGuid(),(await Review(r))!));
    }

    [Fact]
    public async Task Legacy_producer_cannot_ignore_a_canonical_reservation_on_another_envelope()
    {
        var keys=new EphemeralDataProtectionProvider();var legacy=new InvitationResendProtection(keys);var successors=new InvitationSuccessorProtection(keys);
        await using var first=await Create(fixture,legacy:legacy,successors:successors);await Correct(first,Corrected(first));
        var id=Guid.NewGuid();Assert.Equal(InvitationResendOutcome.Queued,await Request(first,id,(await Review(first))!));
        await using var second=await Create(fixture,legacy:legacy,successors:successors);var limits=second.H.App.Services.GetRequiredService<InvitationResendOptions>();
        limits.DailyRequests=limits.DailyAddressRequests=limits.DailyIpRequests=limits.DailySenderRequests=1;
        Assert.Equal(InvitationResendOutcome.Capped,await second.RequestResend());
    }

    [Theory][InlineData("pending")][InlineData("unknown")]
    public async Task Canonical_predecessor_pending_or_ambiguous_state_cannot_be_bypassed(string prior)
    {
        await using var r=await Create(fixture);await Correct(r,Corrected(r));
        var id=Guid.NewGuid();Assert.Equal(InvitationResendOutcome.Queued,await Request(r,id,(await Review(r))!));
        if(prior=="unknown") {r.H.Sender.Failure=new IOException("synthetic unknown acceptance");await Assert.ThrowsAsync<IOException>(()=>Dispatch(r,id));r.H.Sender.Failure=null;}
        Assert.Equal(InvitationResendOutcome.Busy,await Request(r,Guid.NewGuid(),(await Review(r))!));
    }

    [Theory][InlineData("definite")][InlineData("unknown")][InlineData("receipt")]
    public async Task Canonical_manual_delivery_uses_supported_no_blind_retry_semantics(string outcome)
    {
        await using var r=await Create(fixture);await Correct(r,Corrected(r));
        var id=Guid.NewGuid();var review=(await Review(r))!;Assert.Equal(InvitationResendOutcome.Queued,await Request(r,id,review));
        if(outcome=="definite")r.H.Sender.Failure=new EmailNotSubmittedException(true);
        if(outcome=="unknown")r.H.Sender.Failure=new IOException("synthetic unknown acceptance");
        if(outcome=="receipt") {r.H.Faults.Event=InvitationSuccessorProtection.ReceiptEvent;r.H.Faults.FailCommit=true;}
        if(outcome=="definite")Assert.Equal(WorkOutcome.Retry,(await Dispatch(r,id)).Outcome);else await Assert.ThrowsAsync<IOException>(()=>Dispatch(r,id));
        r.H.Sender.Failure=null;r.H.Faults.FailCommit=false;r.H.Clock.Advance(TimeSpan.FromMinutes(6));
        if(outcome=="definite")Assert.Equal(WorkOutcome.Completed,(await Dispatch(r,id)).Outcome);
        else {using var scope=r.H.App.Services.CreateScope();Assert.True((await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(id,default)).Terminal);}
        Assert.Equal(outcome=="definite" ? 4 : 3,r.H.Sender.Calls);
    }

    [Theory][InlineData("suppressed")][InlineData("terminal")][InlineData("epoch")][InlineData("audit")][InlineData("outbox")][InlineData("deadline")]
    public async Task Dispatch_fails_closed_when_current_authority_or_admission_evidence_changes(string changed)
    {
        await using var r=await Create(fixture);await Correct(r,Corrected(r));
        var id=Guid.NewGuid();Assert.Equal(InvitationResendOutcome.Queued,await Request(r,id,(await Review(r))!));
        if(changed=="epoch")await r.Correct("new@example.invalid");
        if(changed=="deadline")r.H.Clock.Advance(TimeSpan.FromDays(1));
        await using(var db=fixture.Open()) {
            if(changed=="suppressed")db.Suppressions.Add(new() {Email=Corrected(r),Reason=SuppressionReason.Complaint});
            if(changed=="terminal")await db.Envelopes.Where(x=>x.Id==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            if(changed=="audit")await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==AdmissionEvent).ExecuteDeleteAsync();
            if(changed=="outbox")await db.EmailOutbox.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.To,"other@example.invalid"));
            await db.SaveChangesAsync();
        }
        Assert.Equal(WorkOutcome.Failed,(await Dispatch(r,id)).Outcome);Assert.Equal(2,r.H.Sender.Calls);
    }

    [Theory][InlineData("contact")][InlineData("predecessor")][InlineData("source")][InlineData("statement")][InlineData("confirmation")]
    public async Task Exact_review_and_deliberate_affirmation_cannot_be_forged_or_relaxed(string changed)
    {
        await using var r=await Create(fixture);await Correct(r,Corrected(r));var review=(await Review(r))!;
        if(changed=="contact")review=review with {Contact=SignerContactEpoch.Legacy};
        if(changed=="predecessor")review=review with {PreviousId=Guid.NewGuid()};
        if(changed=="source")review=review with {DocumentSha256=new string('a',64)};
        using var scope=r.H.App.Services.CreateScope();var id=Guid.NewGuid();
        var result=await scope.ServiceProvider.GetRequiredService<InvitationResends>().RequestAsync(r.H.Principal,r.H.Envelope.PublicId,r.H.Clock.GetUtcNow().AddHours(2),
            id,review,changed!="confirmation",changed=="statement" ? "forged" : InvitationResendStatement.Version,"127.0.0.1","synthetic");
        Assert.Contains(result,new[] {InvitationResendOutcome.Conflict,InvitationResendOutcome.InvalidConfirmation});
        await using var db=fixture.Open();Assert.False(await db.EmailOutbox.AnyAsync(x=>x.Id==id));Assert.Equal(2,r.H.Sender.Calls);
    }

    [Theory][InlineData("hint")][InlineData("audit")][InlineData("commit")]
    public async Task Rollback_or_lost_acknowledgement_preserves_one_idempotent_canonical_admission(string fault)
    {
        await using var r=await Create(fixture);await Correct(r,Corrected(r));var review=(await Review(r))!;var id=Guid.NewGuid();
        if(fault=="hint")r.H.Signals.FailHint=true;
        if(fault=="audit") {r.H.Faults.Event=AdmissionEvent;r.H.Faults.FailAudit=true;}
        if(fault=="commit") {r.H.Faults.Event=AdmissionEvent;r.H.Faults.FailCommit=true;}
        await Assert.ThrowsAnyAsync<Exception>(()=>Request(r,id,review));r.H.Signals.FailHint=false;r.H.Faults.FailAudit=false;r.H.Faults.FailCommit=false;
        Assert.Equal(fault=="commit" ? InvitationResendOutcome.AlreadyRequested : InvitationResendOutcome.Queued,await Request(r,id,review));
        Assert.Equal(WorkOutcome.Completed,(await Dispatch(r,id)).Outcome);Assert.Equal(3,r.H.Sender.Calls);
        await using var db=fixture.Open();Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==AdmissionEvent).ToArrayAsync());
    }

    [Fact]
    public async Task Real_browser_handler_review_is_epoch_bound_read_only_CSRF_and_deliberate()
    {
        await using var r=await Create(fixture,browser:true);await Correct(r,Corrected(r));
        using var client=r.H.App.GetTestClient();var cookies=new Dictionary<string,string>();
        using var session=await client.GetAsync("/test-session");Take(session);
        var path="/draft/"+r.H.Envelope.PublicId+"/resend";
        using var get=await client.GetAsync(path);Take(get);Assert.Equal(HttpStatusCode.OK,get.StatusCode);var page=await get.Content.ReadAsStringAsync();
        Assert.Contains(Corrected(r),page);Assert.True(get.Headers.CacheControl!.NoStore);Assert.DoesNotContain("rel=\"canonical\"",page);
        var proof=SenderSendPageTests.Flow.Value(page,"ReviewProof");
        var form=new Dictionary<string,string>{{"ReviewProof",proof},{"Confirmed","true"},{"StatementVersion",InvitationResendStatement.Version}};
        using(var csrf=await client.PostAsync(path,new FormUrlEncodedContent(form)))Assert.Equal(HttpStatusCode.BadRequest,csrf.StatusCode);
        form["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page);
        using(var send=await client.PostAsync(path,new FormUrlEncodedContent(form))) {Take(send);Assert.Equal(HttpStatusCode.Redirect,send.StatusCode);Assert.DoesNotContain("?",send.Headers.Location!.OriginalString);}
        using(var replay=await client.PostAsync(path,new FormUrlEncodedContent(form)))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
        Assert.Equal(2,r.H.Sender.Calls);await using var db=fixture.Open();Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==AdmissionEvent).ToArrayAsync());
        void Take(HttpResponseMessage response) {
            if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values) {var p=value.Split(';')[0].Split('=',2);cookies[p[0]]=p[1];}
            client.DefaultRequestHeaders.Remove("Cookie");client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value)));
        }
    }

    [Fact]
    public async Task Local_Mailpit_delivers_only_new_redeemable_link_for_corrected_mailbox()
    {
        await using var r=await Create(fixture,smtp:true);var revision=await Correct(r,"corrected-"+Guid.NewGuid().ToString("N")+"@example.invalid");
        var id=Guid.NewGuid();Assert.Equal(InvitationResendOutcome.Queued,await Request(r,id,(await Review(r))!));Assert.Equal(WorkOutcome.Completed,(await Dispatch(r,id)).Outcome);
        using var http=new HttpClient {BaseAddress=new Uri("http://127.0.0.1:"+Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT"))};
        using var search=JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query="+Uri.EscapeDataString("to:"+revision.NewEmail)));
        Assert.Equal(2,search.RootElement.GetProperty("messages").GetArrayLength());var valid=0;
        foreach(var item in search.RootElement.GetProperty("messages").EnumerateArray()) {
            using var detail=JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/"+item.GetProperty("ID").GetString()));
            using var scope=r.H.App.Services.CreateScope();var identity=await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(Token(detail.RootElement.GetProperty("Text").GetString()!),null,null);
            if(identity is not null) {valid++;Assert.Equal(revision.NewEmail,identity.Email);}
        }
        Assert.Equal(1,valid);
    }

    private static async Task<SignerContactRevision> Correct(Run r,string address)
    {
        var revision=await r.Correct(address);Guid id;
        using(var scope=r.H.App.Services.CreateScope()) {
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();await using var tx=await db.Database.BeginTransactionAsync();
            var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==r.H.Envelope.Id);
            id=await scope.ServiceProvider.GetRequiredService<InvitationSuccessorJobs>().PrepareCorrectionAsync(e,revision.Id);await tx.CommitAsync();
        }
        Assert.Equal(WorkOutcome.Completed,(await Dispatch(r,id)).Outcome);return revision;
    }
    private static async Task<InvitationResendReview?> Review(Run r)
    {using var scope=r.H.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<InvitationResends>().ReviewAsync(r.H.Principal,r.H.Envelope.PublicId,r.H.Clock.GetUtcNow().AddHours(2));}
    private static async Task<InvitationResendOutcome> Request(Run r,Guid id,InvitationResendReview review)
    {using var scope=r.H.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<InvitationResends>().RequestAsync(r.H.Principal,r.H.Envelope.PublicId,
        // Each request in a fixed-clock stage uses the same original ticket.
        r.H.Clock.GetUtcNow().AddHours(2),id,review,true,InvitationResendStatement.Version,"127.0.0.1","synthetic");}
    private static async Task<WorkResult> Dispatch(Run r,Guid id)
    {using var scope=r.H.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(id,default)).Lease!;
        Assert.NotNull(lease);var result=await scope.ServiceProvider.GetRequiredService<InvitationSuccessorDelivery>().ExecuteAsync(lease,default);await store.FinishAsync(lease,result,default);return result;}
    private static string Token(string text)=>Regex.Match(text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
    private static string Corrected(Run r)=>"corrected-"+r.H.Envelope.PublicId+"@example.invalid";

    // Disposable loopback host for the real page/captured-mail browser flow.
    public sealed class BrowserSession:IAsyncDisposable
    {
        private readonly Run run;private readonly SqlDatabaseFixture fixture;private readonly string recipient;
        private BrowserSession(Run run,SqlDatabaseFixture fixture,string recipient) {this.run=run;this.fixture=fixture;this.recipient=recipient;}
        public string PublicId=>run.H.Envelope.PublicId;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port)
        {
            var r=await Create(fixture,smtp:true,port:port);var revision=await Correct(r,"corrected-"+Guid.NewGuid().ToString("N")+"@example.invalid");
            var result=new BrowserSession(r,fixture,revision.NewEmail);
            r.H.App.MapGet("/test-captured-replacement",async()=>Microsoft.AspNetCore.Http.Results.Content(await result.Html(),"text/html"));
            r.H.Clock.TrackElapsed();return result;
        }
        public async Task DispatchPending()
        {
            await using var db=fixture.Open();var row=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.H.Envelope.Id && x.Event==AdmissionEvent);
            using var data=JsonDocument.Parse(row.DataJson);var id=data.RootElement.GetProperty("request").GetProperty("id").GetGuid();
            Assert.Equal(WorkOutcome.Completed,(await Dispatch(run,id)).Outcome);
        }
        private async Task<string> Html()
        {
            using var http=new HttpClient {BaseAddress=new Uri("http://127.0.0.1:"+Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT"))};
            using var found=JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query="+Uri.EscapeDataString("to:"+recipient)));
            var message=found.RootElement.GetProperty("messages").EnumerateArray().Single(x=>x.GetProperty("Subject").GetString()=="Review your replacement signing invitation");
            using var detail=JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/"+message.GetProperty("ID").GetString()));return detail.RootElement.GetProperty("HTML").GetString()!;
        }
        public ValueTask DisposeAsync()=>run.DisposeAsync();
    }
}

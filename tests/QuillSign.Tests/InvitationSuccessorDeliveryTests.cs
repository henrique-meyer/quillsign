using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Work;
using Run = QuillSign.Tests.InvitationLineageTests.Run;

namespace QuillSign.Tests;

public sealed class InvitationSuccessorDeliveryTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private sealed class Policy(InvitationSuccessorReason reason):IInvitationSuccessorPolicy
    {
        public InvitationSuccessorReason Reason=>reason;
        public bool Enabled {get;set;}=true;
        public bool Allowed=true;
        public int Checks;
        public Func<InvitationSuccessorScope,Task>? BeforeCheck;
        public async Task<bool> ValidateLockedAsync(Envelope envelope,InvitationSuccessorScope scope,CancellationToken ct)
        { Checks++;if(BeforeCheck is not null)await BeforeCheck(scope);return Allowed; }
    }
    private static Policy Reminder()=>new(InvitationSuccessorReason.Reminder);
    private static async Task<WorkResult> Execute(Run r,Guid id)
    {
        using var scope=r.H.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();
        var lease=(await store.ClaimAsync(id,default)).Lease!;Assert.NotNull(lease);
        var result=await scope.ServiceProvider.GetRequiredService<InvitationSuccessorDelivery>().ExecuteAsync(lease,default);
        await store.FinishAsync(lease,result,default);return result;
    }

    [Fact]
    public async Task Default_has_no_feature_policy_and_cannot_create_a_token_or_call_transport()
    {
        await using var r=await Run.Create(fixture);var p=await r.Admit();
        Assert.Equal(new(WorkOutcome.Retry,"successor-delivery-disabled"),await Execute(r,p.Id));
        Assert.Equal(1,r.H.Sender.Calls);await using var db=fixture.Open();
        Assert.Single(await db.AuthTokens.Where(x=>x.EnvelopeId==p.EnvelopeId).ToArrayAsync());
        Assert.Null((await db.EmailOutbox.SingleAsync(x=>x.Id==p.Id)).SubmissionStartedAt);
    }

    [Fact]
    public async Task Reminder_replaces_unused_links_preserves_redeemed_authority_and_has_exact_receipt()
    {
        var policy=Reminder();await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));
        var original=Token(r.H.Sender.Last!.Text);using(var scope=r.H.App.Services.CreateScope()) {
            Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(original,null,null));
        }
        var p=await r.Admit();Assert.Equal(WorkOutcome.Completed,(await Execute(r,p.Id)).Outcome);
        Assert.Equal(2,r.H.Sender.Calls);Assert.Contains("Reminder: review your signing request",r.H.Sender.Last!.Subject);
        Assert.Contains("saved progress in an already opened session remains available",r.H.Sender.Last.Text);Assert.DoesNotContain("<b>Synthetic message</b>",r.H.Sender.Last.Html);
        Assert.True(policy.Checks>=2);var chain=await r.Read();Assert.Equal(p.Id,chain!.Latest.Id);
        using var lineageScope=r.H.App.Services.CreateScope();var db=lineageScope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
        await using var tx=await db.Database.BeginTransactionAsync();
        var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==p.EnvelopeId);
        var old=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==e.Id && x.UsedAt!=null);
        Assert.True(old.ExpiresAt>r.H.Clock.GetUtcNow());
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==e.Id && x.Event==InvitationSuccessorProtection.ReceiptEvent).ToArrayAsync());
        Assert.True(await lineageScope.ServiceProvider.GetRequiredService<InvitationLineage>().SettledLockedAsync(chain.Latest));
    }

    [Theory]
    [InlineData("disabled")][InlineData("work-disabled")][InlineData("policy-disabled")][InlineData("policy-refused")]
    [InlineData("suppressed")][InlineData("changed-contact")][InlineData("terminal")][InlineData("deadline")]
    public async Task Changed_authority_before_intent_never_reaches_transport(string changed)
    {
        var policy=Reminder();await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));
        var p=await r.Admit();
        if(changed=="disabled")r.H.App.Services.GetRequiredService<EmailOptions>().Enabled=false;
        if(changed=="work-disabled")r.H.App.Services.GetRequiredService<WorkOptions>().Enabled=false;
        if(changed=="policy-disabled")policy.Enabled=false;
        if(changed=="policy-refused")policy.Allowed=false;
        if(changed=="changed-contact")await r.Correct("changed@example.invalid");
        if(changed=="deadline")r.H.Clock.Advance(TimeSpan.FromHours(2));
        await using(var db=fixture.Open()) {
            if(changed=="suppressed")db.Suppressions.Add(new() {Email=p.Recipient,Reason=SuppressionReason.Complaint});
            if(changed=="terminal")await db.Envelopes.Where(x=>x.Id==p.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            await db.SaveChangesAsync();
        }
        var result=await Execute(r,p.Id);Assert.NotEqual(WorkOutcome.Completed,result.Outcome);Assert.Equal(1,r.H.Sender.Calls);
        await using var inspect=fixture.Open();Assert.Null((await inspect.EmailOutbox.SingleAsync(x=>x.Id==p.Id)).SubmissionStartedAt);
        Assert.Single(await inspect.AuthTokens.Where(x=>x.EnvelopeId==p.EnvelopeId).ToArrayAsync());
    }

    [Theory][InlineData("definite")][InlineData("unknown")][InlineData("intent")][InlineData("receipt")]
    public async Task Only_known_non_submission_is_retried_and_unknown_intent_never_resends(string kind)
    {
        var policy=Reminder();await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));var p=await r.Admit();
        if(kind=="definite")r.H.Sender.Failure=new EmailNotSubmittedException(true);
        if(kind=="unknown")r.H.Sender.Failure=new IOException("synthetic unknown acceptance");
        if(kind=="receipt") {r.H.Faults.Event=InvitationSuccessorProtection.ReceiptEvent;r.H.Faults.FailCommit=true;}
        if(kind=="definite")Assert.Equal(WorkOutcome.Retry,(await Execute(r,p.Id)).Outcome);
        else if(kind=="intent") {
            using var scope=r.H.App.Services.CreateScope();var lease=(await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(p.Id,default)).Lease!;
            r.H.Faults.FailCommit=true;
            await Assert.ThrowsAsync<IOException>(()=>scope.ServiceProvider.GetRequiredService<InvitationSuccessorDelivery>().ExecuteAsync(lease,default));
        }
        else await Assert.ThrowsAsync<IOException>(()=>Execute(r,p.Id));
        r.H.Sender.Failure=null;r.H.Faults.FailCommit=false;r.H.Clock.Advance(TimeSpan.FromMinutes(6));
        if(kind=="definite")Assert.Equal(WorkOutcome.Completed,(await Execute(r,p.Id)).Outcome);
        else {using var scope=r.H.App.Services.CreateScope();Assert.True((await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(p.Id,default)).Terminal);}
        Assert.Equal(kind=="definite" ? 3 : kind=="intent" ? 1 : 2,r.H.Sender.Calls);
        await using var db=fixture.Open();var row=await db.EmailOutbox.SingleAsync(x=>x.Id==p.Id);
        Assert.Equal(kind is "unknown" or "intent" ? EmailStatus.Failed : EmailStatus.Sent,row.Status);
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Lease_loss_or_policy_change_during_render_rolls_back_all_intent(bool lostLease)
    {
        var policy=Reminder();await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));var p=await r.Admit();
        policy.BeforeCheck=async _=> {
            if(policy.Checks==2) {
                if(lostLease)r.H.Clock.Advance(TimeSpan.FromMinutes(6));else policy.Allowed=false;
            }
            await Task.CompletedTask;
        };
        using var scope=r.H.App.Services.CreateScope();var lease=(await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(p.Id,default)).Lease!;
        Assert.Equal(WorkOutcome.Failed,(await scope.ServiceProvider.GetRequiredService<InvitationSuccessorDelivery>().ExecuteAsync(lease,default)).Outcome);
        Assert.Equal(1,r.H.Sender.Calls);await using var db=fixture.Open();Assert.Null((await db.EmailOutbox.SingleAsync(x=>x.Id==p.Id)).SubmissionStartedAt);
        Assert.Single(await db.AuthTokens.Where(x=>x.EnvelopeId==p.EnvelopeId).ToArrayAsync());
    }

    [Fact]
    public async Task Correction_preparation_requires_reason_policy_and_is_exactly_idempotent_after_commit()
    {
        var policy=new Policy(InvitationSuccessorReason.ContactCorrection);await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));
        var revision=await r.Correct("corrected@example.invalid");var id=await Prepare(r,revision.Id);var hints=r.H.Signals.HintCalls;
        Assert.Equal(id,await Prepare(r,revision.Id));Assert.Equal(hints,r.H.Signals.HintCalls);
        Assert.Equal(InvitationSuccessorJobs.CorrectionWorkId(revision.Id),id);Assert.Equal(WorkOutcome.Completed,(await Execute(r,id)).Outcome);
        Assert.Equal(2,r.H.Sender.Calls);Assert.Equal(revision.NewEmail,r.H.Sender.Last!.To);
        Assert.Contains("corrected signing invitation",r.H.Sender.Last.Subject);Assert.Contains("Review the disclosure and document again",r.H.Sender.Last.Text);
        await using var db=fixture.Open();var token=await db.AuthTokens.SingleAsync(x=>x.EnvelopeId==revision.EnvelopeId && x.SignerContactRevisionId==revision.Id);
        Assert.Equal(revision.NewEmail,token.Email);Assert.Equal(id,(await r.Read())!.Latest.Id);
    }

    [Theory][InlineData("none")][InlineData("refused")][InlineData("hint")][InlineData("audit")]
    public async Task Failed_correction_preparation_leaves_no_partial_mail_or_admission(string fault)
    {
        var policy=new Policy(InvitationSuccessorReason.ContactCorrection);await using var r=await Run.Create(fixture,
            configure:s=>{if(fault!="none")s.AddSingleton<IInvitationSuccessorPolicy>(policy);});
        var revision=await r.Correct("corrected@example.invalid");if(fault=="refused")policy.Allowed=false;
        if(fault=="hint")r.H.Signals.FailHint=true;
        if(fault=="audit") {r.H.Faults.Event=InvitationSuccessorProtection.Event;r.H.Faults.FailAudit=true;}
        await Assert.ThrowsAnyAsync<Exception>(()=>Prepare(r,revision.Id));await using var db=fixture.Open();
        var id=InvitationSuccessorJobs.CorrectionWorkId(revision.Id);Assert.False(await db.EmailOutbox.AnyAsync(x=>x.Id==id));
        Assert.False(await db.WorkItems.AnyAsync(x=>x.Id==id));Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==revision.EnvelopeId && x.Event==InvitationSuccessorProtection.Event));
        Assert.Equal(1,r.H.Sender.Calls);
    }

    [Fact]
    public async Task Lost_preparation_commit_reuses_exact_saved_revision_work_and_durable_hint()
    {
        var policy=new Policy(InvitationSuccessorReason.ContactCorrection);await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));
        var revision=await r.Correct("corrected@example.invalid");r.H.Faults.Event=InvitationSuccessorProtection.Event;r.H.Faults.FailCommit=true;
        await Assert.ThrowsAsync<IOException>(()=>Prepare(r,revision.Id));r.H.Faults.FailCommit=false;
        var hints=r.H.Signals.HintCalls;var id=await Prepare(r,revision.Id);Assert.Equal(hints,r.H.Signals.HintCalls);
        Assert.NotNull(await r.H.Signals.ReadDueAsync(id,default));
        r.H.Signals.FailPublish=true;using(var scope=r.H.App.Services.CreateScope())await scope.ServiceProvider.GetRequiredService<InvitationSuccessorJobs>().PublishAsync(id);
        r.H.Signals.FailPublish=false;Assert.Equal(WorkOutcome.Completed,(await Execute(r,id)).Outcome);Assert.Equal(2,r.H.Sender.Calls);
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task A_stolen_or_replayed_lease_never_submits_another_message(bool replay)
    {
        var policy=Reminder();await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));var p=await r.Admit();
        using var scope=r.H.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(p.Id,default)).Lease!;
        var delivery=scope.ServiceProvider.GetRequiredService<InvitationSuccessorDelivery>();
        using(var competing=r.H.App.Services.CreateScope())Assert.Null((await competing.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(p.Id,default)).Lease);
        if(replay) {var done=await delivery.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,done.Outcome);await store.FinishAsync(lease,done,default);}
        Assert.Equal(WorkOutcome.Failed,(await delivery.ExecuteAsync(replay ? lease : lease with {Owner=Guid.NewGuid()},default)).Outcome);
        Assert.Equal(replay ? 2 : 1,r.H.Sender.Calls);
    }

    [Fact]
    public async Task Feedback_received_during_provider_submission_is_not_rewritten_as_delivered()
    {
        var policy=Reminder();await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));var p=await r.Admit();
        r.H.Sender.BeforeReturn=async()=> {await using var db=fixture.Open();await db.EmailOutbox.Where(x=>x.Id==p.Id)
            .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EmailStatus.Bounced));};
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,p.Id)).Outcome);await using var inspect=fixture.Open();
        Assert.Equal(EmailStatus.Bounced,(await inspect.EmailOutbox.SingleAsync(x=>x.Id==p.Id)).Status);Assert.Equal(2,r.H.Sender.Calls);
    }

    [Theory][InlineData("queued")][InlineData("leased")][InlineData("intent")][InlineData("ambiguous")][InlineData("settled")][InlineData("wrong-id")]
    public async Task Retirement_only_cancels_definitely_unsubmitted_predecessor(string state)
    {
        await using var r=await Run.Create(fixture,dispatch:state=="settled");var id=r.Sent.InvitationWorkId;
        if(state is "leased" or "intent") {using var scope=r.H.App.Services.CreateScope();Assert.NotNull((await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(id,default)).Lease);}
        if(state is "intent" or "ambiguous")await using(var db=fixture.Open()) {
            await db.EmailOutbox.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,state=="intent" ? r.H.Clock.GetUtcNow() : (DateTimeOffset?)null)
                .SetProperty(x=>x.LastError,state=="ambiguous" ? "submission-ambiguous" : null));
        }
        using(var scope=r.H.App.Services.CreateScope()) {
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();await using var tx=await db.Database.BeginTransactionAsync();
            var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==r.H.Envelope.Id);
            var result=await scope.ServiceProvider.GetRequiredService<InvitationSuccessorJobs>().RetirePredecessorLockedAsync(e,r.H.First.Id,state=="wrong-id" ? Guid.NewGuid() : id);
            Assert.Equal(state switch {"settled"=>InvitationPredecessorRetirement.Settled,"wrong-id"=>InvitationPredecessorRetirement.Conflict,
                "intent" or "ambiguous"=>InvitationPredecessorRetirement.Busy,_=>InvitationPredecessorRetirement.Retired},result);
            await tx.CommitAsync();
        }
        await using var check=fixture.Open();var row=await check.EmailOutbox.SingleAsync(x=>x.Id==id);
        if(state is "queued" or "leased") {Assert.Equal(EmailStatus.Failed,row.Status);Assert.Null(row.SubmissionStartedAt);Assert.Equal("contact-corrected-before-submission",row.LastError);}
        if(state=="intent")Assert.NotNull(row.SubmissionStartedAt);
    }

    [Fact]
    public async Task Local_Mailpit_captures_reminder_copy_and_only_new_unused_link_redeems()
    {
        var policy=Reminder();await using var r=await Run.Create(fixture,smtp:true,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));
        var p=await r.Admit();Assert.Equal(WorkOutcome.Completed,(await Execute(r,p.Id)).Outcome);
        using var http=new HttpClient {BaseAddress=new Uri("http://127.0.0.1:"+Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT"))};
        using var found=JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query="+Uri.EscapeDataString("to:"+r.H.First.Email)));
        Assert.Equal(2,found.RootElement.GetProperty("messages").GetArrayLength());var valid=0;var reminders=0;
        foreach(var message in found.RootElement.GetProperty("messages").EnumerateArray()) {
            using var detail=JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/"+message.GetProperty("ID").GetString()));
            var text=detail.RootElement.GetProperty("Text").GetString()!;if(text.Contains("Reminder: review"))reminders++;
            using var scope=r.H.App.Services.CreateScope();if(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(Token(text),null,null)is not null)valid++;
        }
        Assert.Equal(1,valid);Assert.Equal(1,reminders);
    }

    private async Task<Guid> Prepare(Run r,Guid revision)
    {
        using var scope=r.H.App.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
        await using var tx=await db.Database.BeginTransactionAsync();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==r.H.Envelope.Id);
        var id=await scope.ServiceProvider.GetRequiredService<InvitationSuccessorJobs>().PrepareCorrectionAsync(e,revision);
        await tx.CommitAsync();return id;
    }

    // Loopback-only browser host fixture. No production route or fake policy.
    public sealed class BrowserSession:IAsyncDisposable
    {
        private readonly Run run;
        private BrowserSession(Run run)=>this.run=run;
        public string PublicId=>run.H.Envelope.PublicId;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port)
        {
            var policy=Reminder();var r=await Run.Create(fixture,browserPort:port,smtp:true,configure:s=>s.AddSingleton<IInvitationSuccessorPolicy>(policy));
            var p=await r.Admit();Assert.Equal(WorkOutcome.Completed,(await Execute(r,p.Id)).Outcome);
            using var http=new HttpClient {BaseAddress=new Uri("http://127.0.0.1:"+Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT"))};
            using var found=JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query="+Uri.EscapeDataString("to:"+r.H.First.Email)));
            var message=found.RootElement.GetProperty("messages").EnumerateArray().Single(x=>x.GetProperty("Subject").GetString()!.StartsWith("Reminder:"));
            using var detail=JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/"+message.GetProperty("ID").GetString()));
            var html=detail.RootElement.GetProperty("HTML").GetString()!;
            r.H.App.MapGet("/test-captured-email",()=>Microsoft.AspNetCore.Http.Results.Content(html,"text/html"));
            r.H.Clock.TrackElapsed();return new(r);
        }
        public ValueTask DisposeAsync()=>run.DisposeAsync();
    }
    private static string Token(string text)=>Regex.Match(text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
}

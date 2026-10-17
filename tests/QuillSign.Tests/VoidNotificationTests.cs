using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Work;
using MimeKit;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;
using SigningRun=QuillSign.Tests.CompletionEvidenceCollectorTests.Run;

namespace QuillSign.Tests;

public sealed class VoidNotificationTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Partially_signed_void_groups_sender_and_signers_excludes_completion_recipients_and_dispatches_after_session_expiry()
    {
        await using var run=await SigningRun.Create(fixture,demo:true,finishLast:false);var h=run.H;var e=await run.Refresh();var created=h.Blobs.Created.Count;var deleted=h.Blobs.Deleted.Count;
        var tokens=await TokenCount(e.Id);var reason="Synthetic <script>reason()</script>\nNO AGREEMENT";
        Assert.Equal(SenderVoidOutcome.Voided,(await Void(h,e,run.Sender,reason)).Outcome);var emails=await Emails(e.Id);Assert.Equal(3,emails.Length);
        await using(var db=fixture.Open()) {
            var recipient=await db.Recipients.SingleAsync(x=>x.EnvelopeId==e.Id);Assert.DoesNotContain(emails,x=>x.To==recipient.Email);
            Assert.Equal(3,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==e.Id && x.Event=="void_notification_queued"));
        }
        h.Clock.Advance(TimeSpan.FromDays(3));h.Sender.Calls=0;
        foreach(var email in emails) {
            using var scope=h.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(email.Id,default)).Lease!;
            var result=await scope.ServiceProvider.GetServices<IWorkHandler>().Single(x=>x.Kind==WorkKind.Email).ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
            Assert.Contains(reason,h.Sender.Last!.Text);Assert.DoesNotContain("<script>",h.Sender.Last.Html);Assert.Contains("&lt;script&gt;",h.Sender.Last.Html);
            Assert.Contains("Demo instance",h.Sender.Last.Text);Assert.DoesNotContain("href=",h.Sender.Last.Html);Assert.DoesNotContain("token=",h.Sender.Last.Text);Assert.Empty(h.Sender.Last.Attachments??[]);
        }
        Assert.Equal(3,h.Sender.Calls);Assert.Equal(tokens,await TokenCount(e.Id));Assert.Equal(created,h.Blobs.Created.Count);Assert.Equal(deleted,h.Blobs.Deleted.Count);
        using(var scope=h.App.Services.CreateScope())Assert.Equal(0,await scope.ServiceProvider.GetRequiredService<VoidNotificationJobs>().ResumeAsync(e.Id));
        await using var check=fixture.Open();Assert.Equal(1,await check.Signers.CountAsync(x=>x.EnvelopeId==e.Id && x.Status==SignerStatus.Signed));
        Assert.Equal(3,await check.AuditEvents.CountAsync(x=>x.EnvelopeId==e.Id && x.Event=="void_notification_submitted"));
    }
    [Fact]
    public async Task Sender_who_also_signs_receives_one_informative_message_and_resume_is_concurrently_idempotent()
    {
        await using var run=await SigningRun.Create(fixture,senderAlsoSigns:true,finishLast:false);var e=await run.Refresh();
        Assert.Equal(SenderVoidOutcome.Voided,(await Void(run.H,e,run.Sender)).Outcome);var emails=await Emails(e.Id);Assert.Equal(2,emails.Length);Assert.Single(emails,x=>x.To==e.SenderEmail);
        await Task.WhenAll(Enumerable.Range(0,2).Select(async _=> {using var scope=run.H.App.Services.CreateScope();Assert.Equal(2,await scope.ServiceProvider.GetRequiredService<VoidNotificationJobs>().ResumeAsync(e.Id));}));
        Assert.Equal(emails.Select(x=>x.Id),(await Emails(e.Id)).Select(x=>x.Id));
        using var services=run.H.App.Services.CreateScope();var row=emails.Single(x=>x.To==e.SenderEmail);
        using var payload=JsonDocument.Parse(services.ServiceProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector("QuillSign.VoidNotification.v1")
            .Unprotect(JsonSerializer.Deserialize<ProtectedWorkPayload>(row.PayloadJson)!.Protected));
        Assert.Equal((int)PartyType.Sender,payload.RootElement.GetProperty("Party").GetInt32());Assert.Equal(JsonValueKind.Null,payload.RootElement.GetProperty("PartyId").ValueKind);
    }
    [Theory]
    [InlineData("audit")][InlineData("hint")][InlineData("lost-commit")][InlineData("publish")]
    public async Task Void_and_queue_are_atomic_and_hints_recover_lost_publication_without_recreating_notifications(string fault)
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);
        h.Faults.Event="void_notification_queued";h.Faults.FailAudit=fault=="audit";h.Faults.FailCommit=fault=="lost-commit";
        h.Signals.FailHint=fault=="hint";h.Signals.FailPublish=fault=="publish";
        if(fault=="audit")await Assert.ThrowsAsync<DbUpdateException>(()=>Void(h,e));
        else if(fault is "hint" or "lost-commit")await Assert.ThrowsAsync<IOException>(()=>Void(h,e));
        else Assert.Equal(SenderVoidOutcome.Voided,(await Void(h,e)).Outcome);
        var committed=fault is "lost-commit" or "publish";
        Assert.Equal(committed ? EnvelopeStatus.Voided : EnvelopeStatus.Sent,(await Load(e.Id)).Status);Assert.Equal(committed ? 3 : 0,(await Emails(e.Id)).Length);
        h.Faults.FailAudit=false;h.Faults.FailCommit=false;h.Signals.FailHint=false;h.Signals.FailPublish=false;
        Assert.Equal(committed ? SenderVoidOutcome.AlreadyVoided : SenderVoidOutcome.Voided,(await Void(h,e)).Outcome);
        var ids=(await Emails(e.Id)).Select(x=>x.Id).ToArray();using(var scope=h.App.Services.CreateScope())Assert.Equal(3,await scope.ServiceProvider.GetRequiredService<VoidNotificationJobs>().ResumeAsync(e.Id));
        Assert.Equal(ids,(await Emails(e.Id)).Select(x=>x.Id));Assert.Equal(4,await h.Signals.RecoverAsync(h.Clock.GetUtcNow(),default));
        await using var db=fixture.Open();Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided"));Assert.Equal(3,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==e.Id && x.Event=="void_notification_queued"));
    }
    [Fact]
    public async Task Disabled_work_records_no_queue_and_explicit_trusted_resume_can_prepare_an_old_void()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);var options=h.App.Services.GetRequiredService<WorkOptions>();options.Enabled=false;
        Assert.Equal(SenderVoidOutcome.Voided,(await Void(h,e)).Outcome);Assert.Empty(await Emails(e.Id));
        using(var scope=h.App.Services.CreateScope())await Assert.ThrowsAsync<InvalidOperationException>(()=>scope.ServiceProvider.GetRequiredService<VoidNotificationJobs>().ResumeAsync(e.Id));
        options.Enabled=true;h.Clock.Advance(TimeSpan.FromDays(3));using(var scope=h.App.Services.CreateScope())Assert.Equal(3,await scope.ServiceProvider.GetRequiredService<VoidNotificationJobs>().ResumeAsync(e.Id));
        Assert.Equal(3,(await Emails(e.Id)).Length);
    }
    [Fact]
    public async Task Disabled_and_suppressed_delivery_never_submits_and_resume_preserves_live_or_terminal_leases()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);Assert.Equal(SenderVoidOutcome.Voided,(await Void(h,e)).Outcome);var emails=await Emails(e.Id);var options=h.App.Services.GetRequiredService<EmailOptions>();
        for(var i=0;i<emails.Length;i++) {
            using var scope=h.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(emails[i].Id,default)).Lease!;
            if(i==0)options.Enabled=false;if(i==1) {await using var db=fixture.Open();db.Suppressions.Add(new() {Email=emails[i].To,Reason=SuppressionReason.Unsubscribe});await db.SaveChangesAsync();}
            if(i==2) {using var other=h.App.Services.CreateScope();Assert.Equal(2,await other.ServiceProvider.GetRequiredService<VoidNotificationJobs>().ResumeAsync(e.Id));await using var db=fixture.Open();var current=await db.WorkItems.SingleAsync(x=>x.Id==lease.Id);Assert.Equal(lease.Owner,current.LeaseOwner);continue;}
            var result=await scope.ServiceProvider.GetRequiredService<VoidNotificationDelivery>().ExecuteAsync(lease,default);Assert.Equal(i==0 ? WorkOutcome.Retry : WorkOutcome.Failed,result.Outcome);await store.FinishAsync(lease,result,default);options.Enabled=true;
        }
        Assert.Equal(0,h.Sender.Calls);await using var check=fixture.Open();Assert.False(await check.EmailOutbox.AnyAsync(x=>x.EnvelopeId==e.Id && x.Template==VoidNotificationJobs.Template && x.SubmissionStartedAt!=null));
    }
    [Fact]
    public async Task Definite_provider_rejection_retries_but_unknown_acceptance_never_resends()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);await Void(h,e);var emails=await Emails(e.Id);
        for(var i=0;i<emails.Length;i++) {
            using var scope=h.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(emails[i].Id,default)).Lease!;
            h.Sender.Failure=i switch {0=>new EmailNotSubmittedException(true),1=>new EmailNotSubmittedException(false),_=>new IOException("Synthetic unknown provider acceptance")};
            var service=scope.ServiceProvider.GetRequiredService<VoidNotificationDelivery>();
            if(i<2) {var result=await service.ExecuteAsync(lease,default);Assert.Equal(i==0 ? WorkOutcome.Retry : WorkOutcome.Failed,result.Outcome);await store.FinishAsync(lease,result,default);}
            else await Assert.ThrowsAsync<IOException>(()=>service.ExecuteAsync(lease,default));
        }
        h.Sender.Failure=null;h.Clock.Advance(TimeSpan.FromMinutes(6));
        for(var i=0;i<emails.Length;i++) {
            using var scope=h.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var claim=await store.ClaimAsync(emails[i].Id,default);
            if(i==0) {Assert.NotNull(claim.Lease);var result=await scope.ServiceProvider.GetRequiredService<VoidNotificationDelivery>().ExecuteAsync(claim.Lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(claim.Lease,result,default);}
            else {Assert.True(claim.Terminal);Assert.Null(claim.Lease);}
        }
        Assert.Equal(4,h.Sender.Calls);using(var scope=h.App.Services.CreateScope())Assert.Equal(0,await scope.ServiceProvider.GetRequiredService<VoidNotificationJobs>().ResumeAsync(e.Id));
    }
    [Theory]
    [InlineData("audit")][InlineData("lost-commit")][InlineData("rejected-commit")][InlineData("lease")]
    public async Task Provider_receipt_uncertainty_or_lease_expiry_keeps_submission_intent_and_never_resends(string fault)
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);await Void(h,e);var email=(await Emails(e.Id))[0];
        using var scope=h.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(email.Id,default)).Lease!;
        h.Faults.Event="void_notification_submitted";h.Faults.FailAudit=fault=="audit";h.Faults.FailCommit=fault=="lost-commit";h.Faults.RejectCommit=fault=="rejected-commit";
        h.Sender.BeforeReturn=()=> {if(fault=="lease")h.Clock.Advance(TimeSpan.FromMinutes(6));return Task.CompletedTask;};
        await Assert.ThrowsAnyAsync<Exception>(()=>scope.ServiceProvider.GetRequiredService<VoidNotificationDelivery>().ExecuteAsync(lease,default));
        h.Faults.FailAudit=false;h.Faults.FailCommit=false;h.Faults.RejectCommit=false;h.Clock.Advance(TimeSpan.FromMinutes(6));
        var claim=await store.ClaimAsync(email.Id,default);Assert.True(claim.Terminal);Assert.Null(claim.Lease);Assert.Equal(1,h.Sender.Calls);
        await using var db=fixture.Open();var current=await db.EmailOutbox.SingleAsync(x=>x.Id==email.Id);Assert.NotNull(current.SubmissionStartedAt);Assert.Equal(fault=="lost-commit" ? EmailStatus.Sent : EmailStatus.Failed,current.Status);
    }
    [Theory]
    [InlineData("audit")][InlineData("lost-commit")][InlineData("lease")][InlineData("cancel")]
    public async Task Failed_preparation_or_elapsed_lease_never_calls_provider_and_clears_known_unused_intent(string fault)
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);await Void(h,e);var email=(await Emails(e.Id))[0];
        using var scope=h.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(email.Id,default)).Lease!;
        using var canceled=new CancellationTokenSource();h.Faults.Event="void_notification_attempt";h.Faults.FailAudit=fault=="audit";h.Faults.FailCommit=fault=="lost-commit";
        h.Faults.BeforeAudit=_=> {if(fault=="lease")h.Clock.Advance(TimeSpan.FromMinutes(6));if(fault=="cancel")canceled.Cancel();return Task.CompletedTask;};
        var service=scope.ServiceProvider.GetRequiredService<VoidNotificationDelivery>();
        if(fault=="cancel")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>service.ExecuteAsync(lease,canceled.Token));
        else {var result=await service.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Retry,result.Outcome);}
        Assert.Equal(0,h.Sender.Calls);h.Faults.FailAudit=false;h.Faults.FailCommit=false;h.Faults.BeforeAudit=null;
        await using var db=fixture.Open();Assert.Null((await db.EmailOutbox.SingleAsync(x=>x.Id==email.Id)).SubmissionStartedAt);
    }
    [Theory]
    [InlineData("void-audit")][InlineData("queue-audit")][InlineData("source")][InlineData("party")][InlineData("recipient")]
    [InlineData("work")][InlineData("owner")][InlineData("destination")][InlineData("template")][InlineData("attachment")]
    public async Task Changed_canonical_scope_membership_queue_or_owned_lease_never_calls_provider(string fault)
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);await Void(h,e);var email=(await Emails(e.Id))[0];
        using var scope=h.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(email.Id,default)).Lease!;
        await using(var db=fixture.Open()) {
            if(fault=="void-audit")await db.AuditEvents.Where(x=>x.EnvelopeId==e.Id && x.Event=="voided").ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));
            if(fault=="queue-audit")await db.AuditEvents.Where(x=>x.EnvelopeId==e.Id && x.Event=="void_notification_queued" && x.DataJson!.Contains(email.Id.ToString())).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));
            if(fault=="source")await db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfBlob,Guid.NewGuid().ToString("N")));
            if(fault=="party")await db.Signers.Where(x=>x.Id==h.Second.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FullName,"Changed party"));
            if(fault=="recipient") {db.Recipients.Add(new() {EnvelopeId=e.Id,Name="Changed completion party",Email="changed@example.invalid"});await db.SaveChangesAsync();}
            if(fault=="work")await db.WorkItems.Where(x=>x.Id==email.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
            if(fault=="owner")await db.WorkItems.Where(x=>x.Id==email.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.LeaseOwner,Guid.NewGuid()));
            if(fault=="destination")await db.EmailOutbox.Where(x=>x.Id==email.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.To,"changed@example.invalid"));
            if(fault=="template")await db.EmailOutbox.Where(x=>x.Id==email.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Template,"sender-verification"));
            if(fault=="attachment")await db.EmailOutbox.Where(x=>x.Id==email.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.AttachmentsJson,"[{}]"));
        }
        var result=await scope.ServiceProvider.GetRequiredService<VoidNotificationDelivery>().ExecuteAsync(lease,default);Assert.NotEqual(WorkOutcome.Completed,result.Outcome);Assert.Equal(0,h.Sender.Calls);
        await using var check=fixture.Open();Assert.Null((await check.EmailOutbox.SingleAsync(x=>x.Id==email.Id)).SubmissionStartedAt);
    }
    [Fact]
    public async Task Actual_loopback_Mailpit_messages_are_plain_and_escaped_without_files_or_access_links()
    {
        await using var h=await Shared.Create(fixture,smtp:true,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);await Void(h,e,reason:"Synthetic <script>NO AGREEMENT</script>");var emails=await Emails(e.Id);Assert.Equal(3,emails.Length);
        foreach(var email in emails) {
            using var scope=h.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(email.Id,default)).Lease!;
            var result=await scope.ServiceProvider.GetServices<IWorkHandler>().Single(x=>x.Kind==WorkKind.Email).ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
            using var http=new HttpClient {BaseAddress=new Uri("http://127.0.0.1:"+Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT"))};string? id=null;
            for(var i=0;i<20 && id is null;i++) {
                using var list=JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query="+Uri.EscapeDataString("to:"+email.To+" subject:\"A QuillSign signing request was voided\"")));
                var rows=list.RootElement.GetProperty("messages").EnumerateArray().Where(x=>x.GetProperty("To").EnumerateArray().Any(to=>to.GetProperty("Address").GetString()==email.To)).ToArray();
                if(rows.Length>0) {Assert.Single(rows);id=rows[0].GetProperty("ID").GetString();}else await Task.Delay(100);
            }
            Assert.NotNull(id);using var captured=await MimeMessage.LoadAsync(new MemoryStream(await http.GetByteArrayAsync("/api/v1/message/"+id+"/raw")));
            Assert.Equal(email.To,Assert.Single(captured.To.Mailboxes).Address);Assert.Empty(captured.Attachments);Assert.Contains("<script>NO AGREEMENT</script>",captured.TextBody);Assert.DoesNotContain("<script>",captured.HtmlBody);
            Assert.Contains("&lt;script&gt;",captured.HtmlBody);Assert.DoesNotContain("href=",captured.HtmlBody);Assert.DoesNotContain("token=",captured.TextBody);Assert.DoesNotContain("Demo instance",captured.TextBody);
        }
    }
    private async Task<Envelope> Load(Guid id) {await using var db=fixture.Open();return await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id);}
    private async Task<int> TokenCount(Guid id) {await using var db=fixture.Open();return await db.AuthTokens.CountAsync(x=>x.EnvelopeId==id);}
    private async Task<EmailOutbox[]> Emails(Guid id) {await using var db=fixture.Open();return await db.EmailOutbox.AsNoTracking().Where(x=>x.EnvelopeId==id && x.Template==VoidNotificationJobs.Template).OrderBy(x=>x.Id).ToArrayAsync();}
    private static async Task<SenderVoidResult> Void(Shared h,Envelope e,System.Security.Claims.ClaimsPrincipal? principal=null,string? reason=null) {
        using var scope=h.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(principal??h.Principal,e.PublicId,h.Clock.GetUtcNow().AddHours(1),e.RowVersion,true,SenderVoidStatement.Version,reason,null,null);
    }
}

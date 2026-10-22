using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MimeKit;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Work;
using Flow=QuillSign.Tests.CompletionDownloadTests.Flow;
using static QuillSign.Tests.CompletionReaderPageTests;

namespace QuillSign.Tests;

public sealed class CompletionNotificationTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Publication_atomically_queues_each_destination_then_real_work_sends_exact_pair_and_live_readonly_links_after_queue_delay()
    {
        await using var f=await Flow.Create(fixture,completionReaders:true,completionNotifications:true);var acquired=f.Run.Seal.Certificates.Calls;
        string[] recipients;
        await using(var db=fixture.Open()) {
            var emails=await db.EmailOutbox.AsNoTracking().Where(x=>x.EnvelopeId==f.Id && x.Template==CompletionNotificationJobs.Template).ToArrayAsync();Assert.Equal(4,emails.Length);
            Assert.Equal(4,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==f.Id && x.Event=="completion_notification_queued"));
            Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==f.Id && x.Purpose==TokenPurpose.CompletionAccess));
            recipients=emails.Select(x=>x.To).ToArray();Assert.Equal(4,recipients.Distinct().Count());Assert.All(emails,x=>Assert.DoesNotContain("#token=",x.PayloadJson));
        }
        f.Clock.Advance(f.Run.Signing.Envelope.ExpiresAt!.Value.AddMinutes(20)-f.Clock.GetUtcNow());f.Run.Seal.Options.Pfx.Path="unavailable";
        var dispatchedAt=f.Clock.GetUtcNow();var steps=await Drain(f);Assert.Equal(5,steps); // existing sealing wakeup plus four completion messages
        await using(var db=fixture.Open()) {
            Assert.Equal(4,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==f.Id && x.Template==CompletionNotificationJobs.Template && x.Status==EmailStatus.Sent));
            var tokens=await db.AuthTokens.Where(x=>x.EnvelopeId==f.Id && x.Purpose==TokenPurpose.CompletionAccess).ToArrayAsync();Assert.Equal(4,tokens.Length);
            Assert.All(tokens,x=> {Assert.Equal(dispatchedAt.AddHours(24),x.ExpiresAt);Assert.Null(x.UsedAt);});
        }
        using(var scope=f.App.Services.CreateScope())Assert.Equal(0,await scope.ServiceProvider.GetRequiredService<CompletionNotificationJobs>().ResumeAsync(f.Id));
        Assert.Equal(0,await Drain(f));
        foreach(var recipient in recipients) {
            using var message=await Captured(recipient);Assert.Equal($"Your completed QuillSign records [QS-{f.Id:N}]",message.Subject);Assert.Single(message.To.Mailboxes);
            Assert.Contains("Demo instance",message.TextBody);Assert.DoesNotContain("Attachment-size warning",message.TextBody);
            var parts=message.Attachments.Cast<MimePart>().ToArray();Assert.Equal(2,parts.Length);
            foreach(var (bytes,part) in new[]{f.Published.ExecutedBytes,f.Published.CertificateBytes}.Zip(parts)) {
                using var decoded=new MemoryStream();await part.Content!.DecodeToAsync(decoded);Assert.Equal(bytes,decoded.ToArray());
            }
            var link=System.Text.RegularExpressions.Regex.Match(message.TextBody!,"https://example\\.invalid/complete/access#token=([A-Za-z0-9_-]{43})");Assert.True(link.Success);
            await using(var db=fixture.Open())Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==f.Id && x.DataJson!=null && x.DataJson.Contains(link.Groups[1].Value)));
            Assert.Contains("Open your private completed records",message.HtmlBody);f.Restore([]);
            var pending=await Begin(f,link.Groups[1].Value);using(var open=await Post(f,"/complete/access?handler=Redeem",pending,new() {{"nonce",Nonce(pending)}}))Assert.Equal(System.Net.HttpStatusCode.Redirect,open.StatusCode);
            var page=await Get(f,"/complete/"+f.PublicId);
            using(var prep=await Download(f,page,"executed"))Assert.Equal(System.Net.HttpStatusCode.Redirect,prep.StatusCode);
            using(var pdf=await f.Client.GetAsync(Resource(f,"executed"))) {Assert.Equal(System.Net.HttpStatusCode.OK,pdf.StatusCode);Assert.Equal(f.Published.ExecutedBytes,await pdf.Content.ReadAsByteArrayAsync());}
        }
        Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);Assert.Equal(acquired,f.Run.Seal.Certificates.Calls);
        await using(var db=fixture.Open())Assert.Equal(4,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==f.Id && x.Event=="completion_notification_submitted"));
    }

    [Fact]
    public async Task Disabled_suppressed_corrupt_and_missing_packets_never_submit_or_fall_back()
    {
        await using var f=await Flow.Create(fixture,completionNotifications:true);
        var emails=await Emails(f);var options=f.App.Services.GetRequiredService<EmailOptions>();var sender=new SendDraftWorkflowTests.FakeSender();
        for(var i=0;i<emails.Length;i++) {
            using var scope=f.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(emails[i].Id,default)).Lease!;
            if(i==0)options.Enabled=false;
            if(i==1) {await using var db=fixture.Open();db.Suppressions.Add(new() {Email=emails[i].To,Reason=SuppressionReason.Unsubscribe});await db.SaveChangesAsync();}
            f.Store.Fault=i==2 ? "corrupt" : i==3 ? "missing" : null;
            var result=await ActivatorUtilities.CreateInstance<CompletionNotificationDelivery>(scope.ServiceProvider,sender).ExecuteAsync(lease,default);
            Assert.Equal(i is 0 or 3 ? WorkOutcome.Retry : WorkOutcome.Failed,result.Outcome);await store.FinishAsync(lease,result,default);options.Enabled=true;
        }
        Assert.Equal(0,sender.Calls);
        await using(var db=fixture.Open()) {Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==f.Id && x.Purpose==TokenPurpose.CompletionAccess));Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==f.Id && x.Template==CompletionNotificationJobs.Template && x.SubmissionStartedAt!=null));}
        f.Store.Fault=null;
        using(var scope=f.App.Services.CreateScope())Assert.Equal(2,await scope.ServiceProvider.GetRequiredService<CompletionNotificationJobs>().ResumeAsync(f.Id));
        Assert.Equal(4,(await Emails(f)).Length);Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);
    }

    [Fact]
    public async Task Known_rejection_can_retry_with_fresh_link_but_unknown_acceptance_is_never_resent()
    {
        await using var f=await Flow.Create(fixture,completionNotifications:true);var emails=await Emails(f);var sender=new SendDraftWorkflowTests.FakeSender();
        for(var i=0;i<emails.Length;i++) {
            using var scope=f.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(emails[i].Id,default)).Lease!;
            sender.Failure=i switch {0=>new EmailNotSubmittedException(true),1=>new EmailNotSubmittedException(false),2=>new IOException("Synthetic unknown acceptance"),_=>new OperationCanceledException("Synthetic cancellation after submission")};
            var delivery=ActivatorUtilities.CreateInstance<CompletionNotificationDelivery>(scope.ServiceProvider,sender);
            if(i<2) {var result=await delivery.ExecuteAsync(lease,default);Assert.Equal(i==0 ? WorkOutcome.Retry : WorkOutcome.Failed,result.Outcome);await store.FinishAsync(lease,result,default);}
            else if(i==2)await Assert.ThrowsAsync<IOException>(()=>delivery.ExecuteAsync(lease,default));
            else await Assert.ThrowsAsync<OperationCanceledException>(()=>delivery.ExecuteAsync(lease,default));
        }
        Assert.Equal(4,sender.Calls);DateTimeOffset[] expirations;
        await using(var db=fixture.Open()) {var rows=await db.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==f.Id && x.Purpose==TokenPurpose.CompletionAccess).OrderBy(x=>x.Id).ToArrayAsync();Assert.Equal(4,rows.Length);expirations=rows.Select(x=>x.ExpiresAt).ToArray();Assert.All(rows,x=>Assert.Null(x.UsedAt));}
        f.Clock.Advance(TimeSpan.FromMinutes(6));sender.Failure=null;
        for(var i=0;i<emails.Length;i++) {
            using var scope=f.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var claim=await store.ClaimAsync(emails[i].Id,default);
            if(i==0) {Assert.NotNull(claim.Lease);var result=await ActivatorUtilities.CreateInstance<CompletionNotificationDelivery>(scope.ServiceProvider,sender).ExecuteAsync(claim.Lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(claim.Lease,result,default);}
            else {Assert.Null(claim.Lease);Assert.True(claim.Terminal);}
        }
        Assert.Equal(5,sender.Calls);
        await using(var db=fixture.Open()) {
            var tokens=await db.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==f.Id && x.Purpose==TokenPurpose.CompletionAccess).ToArrayAsync();Assert.Equal(5,tokens.Length);
            Assert.Equal(4,tokens.Count(x=>expirations.Contains(x.ExpiresAt)));Assert.Single(tokens,x=>x.ExpiresAt==f.Clock.GetUtcNow().AddHours(24));
            Assert.Equal(2,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==f.Id && x.LastError=="submission-ambiguous"));
        }
        using(var scope=f.App.Services.CreateScope())Assert.Equal(0,await scope.ServiceProvider.GetRequiredService<CompletionNotificationJobs>().ResumeAsync(f.Id));
    }

    [Fact]
    public async Task Decoded_or_encoded_size_limit_warns_every_party_and_preserves_private_exact_downloads()
    {
        await using var f=await Flow.Create(fixture,completionNotifications:true);var emails=await Emails(f);var sender=new SendDraftWorkflowTests.FakeSender();var options=f.App.Services.GetRequiredService<EmailOptions>();var links=new HashSet<string>();
        for(var i=0;i<emails.Length;i++) {
            options.Attachments.MaximumDecodedBytes=i%2==0 ? 1 : 20*1024*1024;options.Attachments.MaximumMessageBytes=i%2==0 ? 32*1024*1024 : 100*1024;
            using var scope=f.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(emails[i].Id,default)).Lease!;
            var result=await ActivatorUtilities.CreateInstance<CompletionNotificationDelivery>(scope.ServiceProvider,sender).ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
            Assert.Empty(sender.Last!.Attachments!);Assert.Contains("Attachment-size warning",sender.Last.Text);Assert.Contains("Attachment-size warning",sender.Last.Html);Assert.DoesNotContain("Attached:",sender.Last.Text);
            var link=System.Text.RegularExpressions.Regex.Match(sender.Last.Text,"#token=([A-Za-z0-9_-]{43})");Assert.True(link.Success);Assert.True(links.Add(link.Groups[1].Value));
        }
        Assert.Equal(4,sender.Calls);Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);
        await using var db=fixture.Open();Assert.Equal(4,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==f.Id && x.Event=="completion_notification_submitted" && x.DataJson!.Contains("\"linkOnly\":true")));
    }

    private async Task<EmailOutbox[]> Emails(Flow f) {await using var db=fixture.Open();return await db.EmailOutbox.AsNoTracking().Where(x=>x.EnvelopeId==f.Id && x.Template==CompletionNotificationJobs.Template).OrderBy(x=>x.Id).ToArrayAsync();}

    [Fact]
    public async Task Sender_who_also_signs_gets_one_message_with_sender_only_backup_authority()
    {
        await using var f=await Flow.Create(fixture,completionNotifications:true,senderAlsoSigns:true);var emails=await Emails(f);Assert.Equal(3,emails.Length);
        var primary=Assert.Single(emails,x=>x.To==f.Run.Signing.Envelope.SenderEmail);
        using var scope=f.App.Services.CreateScope();
        var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(primary.Id,default)).Lease!;var sender=new SendDraftWorkflowTests.FakeSender();
        Assert.Equal(WorkOutcome.Completed,(await ActivatorUtilities.CreateInstance<CompletionNotificationDelivery>(scope.ServiceProvider,sender).ExecuteAsync(lease,default)).Outcome);Assert.Equal(1,sender.Calls);Assert.Equal(2,sender.Last!.Attachments!.Count);
        await using(var db=fixture.Open()) {var token=await db.AuthTokens.SingleAsync(x=>x.EnvelopeId==f.Id && x.Purpose==TokenPurpose.CompletionAccess);Assert.Equal(PartyType.Sender,token.PartyType);Assert.Null(token.PartyId);}
        var html=await scope.ServiceProvider.GetRequiredService<RazorEmailViews>().RenderAsync("/Views/Email/Completion.html.cshtml",new CompletionEmailModel("<script>synthetic()</script>",f.Clock.GetUtcNow(),null,new Uri("https://example.invalid/complete/access"),f.Clock.GetUtcNow().AddHours(1),false,false));
        Assert.DoesNotContain("<script>",html);Assert.Contains("&lt;script&gt;",html);Assert.DoesNotContain("Demo instance",html);Assert.DoesNotContain("Server retention ends",html);
    }

    [Theory]
    [InlineData("audit")][InlineData("hint")][InlineData("lost-commit")][InlineData("publish")]
    public async Task Publication_queue_is_atomic_on_rollback_and_lost_commit_reuses_exact_packet(string fault)
    {
        await using var f=await Flow.Create(fixture,completionNotifications:true,publish:false);
        var committed=fault is "lost-commit" or "publish";
        f.Faults.Event="completion_notification_queued";f.Faults.RejectAudit=fault=="audit";f.Faults.LoseCommit=fault=="lost-commit";
        f.Run.Signing.H.Signals.FailHint=fault=="hint";f.Run.Signing.H.Signals.FailPublish=fault=="publish";
        using(var scope=f.App.Services.CreateScope()) {
            var publication=scope.ServiceProvider.GetRequiredService<QuillSign.Completion.CompletionPublication>();
            if(committed)Assert.NotNull(await publication.PublishAsync(f.Id));else if(fault=="audit")await Assert.ThrowsAsync<DbUpdateException>(()=>publication.PublishAsync(f.Id));else await Assert.ThrowsAsync<IOException>(()=>publication.PublishAsync(f.Id));
        }
        await using(var db=fixture.Open()) {Assert.Equal(committed ? 4 : 0,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==f.Id && x.Template==CompletionNotificationJobs.Template));Assert.Equal(committed,await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==f.Id));}
        f.Faults.RejectAudit=false;f.Faults.LoseCommit=false;f.Run.Signing.H.Signals.FailHint=false;f.Run.Signing.H.Signals.FailPublish=false;
        using(var scope=f.App.Services.CreateScope())Assert.NotNull(await scope.ServiceProvider.GetRequiredService<QuillSign.Completion.CompletionPublication>().PublishAsync(f.Id));
        Assert.Equal(4,(await Emails(f)).Length);
        await Task.WhenAll(Enumerable.Range(0,2).Select(async _=> {using var scope=f.App.Services.CreateScope();Assert.Equal(4,await scope.ServiceProvider.GetRequiredService<CompletionNotificationJobs>().ResumeAsync(f.Id));}));
        Assert.Equal(4,(await Emails(f)).Length);Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);
    }

    [Fact]
    public async Task Work_party_queue_evidence_and_lost_lease_are_rechecked_after_file_io_before_submission()
    {
        await using var f=await Flow.Create(fixture,completionNotifications:true);var emails=await Emails(f);var sender=new SendDraftWorkflowTests.FakeSender();
        for(var i=0;i<emails.Length;i++) {
            using var scope=f.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(emails[i].Id,default)).Lease!;
            var once=false;f.Store.AfterRead=async ()=> {if(once)return;once=true;await using var db=fixture.Open();
                if(i==0)await db.WorkItems.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
                if(i==1)await db.WorkItems.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.LeaseOwner,Guid.NewGuid()));
                if(i==2)await db.EmailOutbox.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.To,"other@example.invalid"));
                if(i==3)await db.AuditEvents.Where(x=>x.EnvelopeId==f.Id && x.Event=="completion_notification_queued" && x.DataJson!.Contains(lease.Id.ToString())).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));
            };
            var result=await ActivatorUtilities.CreateInstance<CompletionNotificationDelivery>(scope.ServiceProvider,sender).ExecuteAsync(lease,default);Assert.NotEqual(WorkOutcome.Completed,result.Outcome);Assert.True(once);
        }
        Assert.Equal(0,sender.Calls);await using var check=fixture.Open();Assert.False(await check.AuthTokens.AnyAsync(x=>x.EnvelopeId==f.Id && x.Purpose==TokenPurpose.CompletionAccess));
    }

    [Fact]
    public async Task Intent_rollback_lost_acknowledgement_lease_expiry_and_preparation_cancellation_do_not_call_provider()
    {
        await using var f=await Flow.Create(fixture,completionNotifications:true);var emails=await Emails(f);var sender=new SendDraftWorkflowTests.FakeSender();
        for(var i=0;i<emails.Length;i++) {
            using var scope=f.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(emails[i].Id,default)).Lease!;
            f.Faults.Event="completion_notification_attempt";f.Faults.RejectAudit=i==0;f.Faults.LoseCommit=i==1;using var canceled=new CancellationTokenSource();var once=false;
            f.Store.AfterRead=()=> {if(once)return Task.CompletedTask;once=true;if(i==2)f.Clock.Advance(TimeSpan.FromMinutes(6));if(i==3)canceled.Cancel();return Task.CompletedTask;};
            var delivery=ActivatorUtilities.CreateInstance<CompletionNotificationDelivery>(scope.ServiceProvider,sender);
            if(i==3)await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>delivery.ExecuteAsync(lease,canceled.Token));
            else {var result=await delivery.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Retry,result.Outcome);}
            f.Faults.RejectAudit=false;f.Faults.LoseCommit=false;
        }
        Assert.Equal(0,sender.Calls);await using var check=fixture.Open();Assert.False(await check.EmailOutbox.AnyAsync(x=>x.EnvelopeId==f.Id && x.Template==CompletionNotificationJobs.Template && x.SubmissionStartedAt!=null));
        Assert.Equal(1,await check.AuthTokens.CountAsync(x=>x.EnvelopeId==f.Id && x.Purpose==TokenPurpose.CompletionAccess));
        Assert.Equal(1,await check.AuditEvents.CountAsync(x=>x.EnvelopeId==f.Id && x.Event=="completion_notification_not_submitted"));
    }

    [Fact]
    public async Task Provider_receipt_commit_uncertainty_and_post_submission_lease_loss_never_resend()
    {
        await using var f=await Flow.Create(fixture,completionNotifications:true);var emails=await Emails(f);var sender=new SendDraftWorkflowTests.FakeSender();
        for(var i=0;i<emails.Length;i++) {
            f.Faults=new() {Event="completion_notification_submitted",RejectAudit=i==0,LoseCommit=i==1,RejectCommit=i==2};
            using var scope=f.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(emails[i].Id,default)).Lease!;
            sender.BeforeReturn=()=> {if(i==3)f.Clock.Advance(TimeSpan.FromMinutes(6));return Task.CompletedTask;};
            await Assert.ThrowsAnyAsync<Exception>(()=>ActivatorUtilities.CreateInstance<CompletionNotificationDelivery>(scope.ServiceProvider,sender).ExecuteAsync(lease,default));
            f.Faults.RejectAudit=false;f.Faults.LoseCommit=false;f.Faults.RejectCommit=false;
            f.Clock.Advance(TimeSpan.FromMinutes(6));var claim=await store.ClaimAsync(lease.Id,default);Assert.Null(claim.Lease);Assert.True(claim.Terminal);
            await using var db=fixture.Open();var email=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==lease.Id);Assert.Equal(i==1 ? EmailStatus.Sent : EmailStatus.Failed,email.Status);Assert.NotNull(email.SubmissionStartedAt);
        }
        Assert.Equal(4,sender.Calls);using(var scope=f.App.Services.CreateScope())Assert.Equal(0,await scope.ServiceProvider.GetRequiredService<CompletionNotificationJobs>().ResumeAsync(f.Id));
    }

    internal static async Task<int> Drain(Flow f) {
        var count=0;for(var i=0;i<32;i++) {using var scope=f.App.Services.CreateScope();if(!await scope.ServiceProvider.GetRequiredService<WorkProcessor>().RunOnceAsync(default))return count;count++;}
        throw new InvalidOperationException("Synthetic completion work did not drain.");
    }
    internal static async Task<MimeMessage> Captured(string recipient) {
        using var http=new HttpClient {BaseAddress=new Uri("http://127.0.0.1:"+Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT"))};string? id=null;
        for(var i=0;i<20 && id is null;i++) {
            using var list=JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query="+Uri.EscapeDataString("to:"+recipient+" subject:\"Your completed QuillSign records\"")));
            var rows=list.RootElement.GetProperty("messages").EnumerateArray().Where(x=>x.GetProperty("To").EnumerateArray().Any(to=>to.GetProperty("Address").GetString()==recipient)).ToArray();if(rows.Length>0) {Assert.Single(rows);id=rows[0].GetProperty("ID").GetString();}else await Task.Delay(100);
        }
        Assert.NotNull(id);return await MimeMessage.LoadAsync(new MemoryStream(await http.GetByteArrayAsync("/api/v1/message/"+id+"/raw")));
    }
}

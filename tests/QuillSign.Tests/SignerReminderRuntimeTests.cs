using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Run=QuillSign.Tests.InvitationLineageTests.Run;

namespace QuillSign.Tests;

public sealed class SignerReminderRuntimeTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private static Task<Run> Create(SqlDatabaseFixture f,bool smtp=false,int? port=null)=>Run.Create(f,smtp:smtp,browserPort:port,configure:s=>s.AddSingleton(new SignerReminderOptions {
        Enabled=true,DailyRequests=1000,DailyAddressRequests=1000,DailySenderRequests=1000}));
    [Fact]
    public async Task Send_atomically_schedules_two_verified_legacy_epoch_offsets_without_sending_early()
    {
        await using var r=await Create(fixture);var rows=await Scheduled(r);Assert.Equal(2,rows.Length);
        Assert.Equal(new[]{3,7},rows.Select(x=>JsonSerializer.Deserialize<ReminderWork>(x.PayloadJson,new JsonSerializerOptions{PropertyNameCaseInsensitive=true})!.Day));
        await using var db=fixture.Open();Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Kind==WorkKind.Reminder));
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.ScheduleEvent).ToArrayAsync());
        Assert.Equal(1,r.H.Sender.Calls);using var scope=r.H.App.Services.CreateScope();
        var early=await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(rows[0].Id,default);Assert.Null(early.Lease);Assert.Equal(rows[0].AvailableAt,early.RetryAt);
        await Prepare(r);Assert.Equal(rows.Select(x=>x.Id),(await Scheduled(r)).Select(x=>x.Id));Assert.Equal(1,r.H.Sender.Calls);
    }
    [Fact]
    public async Task An_approved_offset_outside_the_frozen_deadline_creates_no_work_or_hint()
    {
        await using var r=await Run.Create(fixture,configure:s=>s.AddSingleton(new SignerReminderOptions {
            Enabled=true,Days=[30],DailyRequests=1000,DailyAddressRequests=1000,DailySenderRequests=1000}));
        Assert.Empty(await Scheduled(r));await using var db=fixture.Open();
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.ScheduleEvent));
        Assert.Equal(2,r.H.Signals.HintCalls);Assert.Equal(1,r.H.Sender.Calls);
    }
    [Fact]
    public async Task Failure_after_writing_the_first_reminder_hint_rolls_back_the_whole_Send()
    {
        await using var h=await SendDraftWorkflowTests.Harness.Create(fixture,configure:s=>s.AddSingleton(new SignerReminderOptions {
            Enabled=true,DailyRequests=1000,DailyAddressRequests=1000,DailySenderRequests=1000}));
        using(var scope=h.App.Services.CreateScope()) {
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();await using var tx=await db.Database.BeginTransactionAsync();
            await scope.ServiceProvider.GetRequiredService<AuditWriter>().AppendAsync(h.Envelope.Id,"signer_added",h.Envelope.SenderEmail,null,null,default,
                JsonSerializer.Serialize(new {signers=new[]{h.First,h.Second}.Select(x=>new{x.Id,x.Order,x.FullName,x.Email,x.Role})}));await tx.CommitAsync();
        }
        h.Signals.FailHintAfterWriteAt=3;await Assert.ThrowsAsync<IOException>(()=>h.Send());await h.AssertUnsent(fixture);
        await using var check=fixture.Open();Assert.False(await check.WorkItems.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id));Assert.Single(h.Blobs.Deleted);
        Assert.Equal(3,h.Signals.HintCalls);Assert.Equal(0,h.Sender.Calls);
    }
    [Fact]
    public async Task Due_reminder_creates_one_exact_system_reservation_and_a_fresh_link_preserving_an_open_session()
    {
        await using var r=await Create(fixture);var original=Token(r.H.Sender.Last!.Text);VerifiedSigner opened;
        using(var scope=r.H.App.Services.CreateScope())opened=(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(original,null,null))!;
        var first=(await Scheduled(r))[0];r.H.Clock.Advance(first.AvailableAt-r.H.Clock.GetUtcNow());
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,first.Id)).Outcome);var id=SignerReminderEvidence.EmailId(first.Id);
        await using(var db=fixture.Open()) {
            var row=Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.AdmissionEvent).ToArrayAsync());
            var a=SignerReminderEvidence.ReadAdmission(row);Assert.Equal(first.Id,a.WorkId);Assert.Equal(id,a.Id);Assert.Equal(SignerContactEpoch.Legacy,a.Contact);
            Assert.Equal(PartyType.System,row.ActorType);Assert.Null(row.ActorEmail);Assert.Null(row.Ip);Assert.Null(row.UserAgent);
            Assert.Equal(1,await db.EmailOutbox.CountAsync(x=>x.Id==id));Assert.Equal(1,r.H.Sender.Calls);
        }
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,id)).Outcome);Assert.Equal(2,r.H.Sender.Calls);
        Assert.Contains("reminder",r.H.Sender.Last!.Subject,StringComparison.OrdinalIgnoreCase);var fresh=Token(r.H.Sender.Last.Text);Assert.NotEqual(original,fresh);
        using(var scope=r.H.App.Services.CreateScope()) {
            var access=scope.ServiceProvider.GetRequiredService<SignerAccess>();
            // This session has already expired naturally after three days; the
            // reminder neither resurrects it nor grants consent to the fresh one.
            Assert.Null(await access.GetContextAsync(SignerAccessConfiguration.Principal(opened),opened.PublicId));
            var identity=(await access.RedeemAsync(fresh,null,null))!;Assert.NotNull(identity);
            Assert.Null((await access.GetContextAsync(SignerAccessConfiguration.Principal(identity),identity.PublicId))!.ConsentAt);
        }
        Assert.True((await Claim(r,id)).Terminal);Assert.Equal(2,r.H.Sender.Calls);
    }
    [Fact]
    public async Task An_open_session_near_due_time_survives_replacement_without_resetting_the_schedule()
    {
        await using var r=await Create(fixture);var job=(await Scheduled(r))[0];
        r.H.Clock.Advance(job.AvailableAt-r.H.Clock.GetUtcNow()-TimeSpan.FromMinutes(1));
        // A deliberate resend shortly before due opens a fresh session without
        // resetting the original reminder clock.
        Assert.Equal(InvitationResendOutcome.Queued,await r.RequestResend());Assert.True(await r.H.Once());
        VerifiedSigner identity;using(var scope=r.H.App.Services.CreateScope())identity=(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(Token(r.H.Sender.Last!.Text),null,null))!;
        r.H.Clock.Advance(TimeSpan.FromMinutes(1));Assert.Equal(WorkOutcome.Completed,(await Execute(r,job.Id)).Outcome);
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,SignerReminderEvidence.EmailId(job.Id))).Outcome);
        using(var scope=r.H.App.Services.CreateScope())Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SignerAccess>().GetContextAsync(SignerAccessConfiguration.Principal(identity),identity.PublicId));
    }
    [Fact]
    public async Task A_delayed_day_seven_run_coalesces_day_three_instead_of_sending_a_burst()
    {
        await using var r=await Create(fixture);var jobs=await Scheduled(r);r.H.Clock.Advance(jobs[1].AvailableAt-r.H.Clock.GetUtcNow()+TimeSpan.FromHours(1));
        var first=await Execute(r,jobs[0].Id);Assert.Equal(WorkOutcome.Completed,first.Outcome);Assert.Equal("reminder-overdue-offset-coalesced",first.Code);
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,jobs[1].Id)).Outcome);Assert.Equal(WorkOutcome.Completed,(await Execute(r,SignerReminderEvidence.EmailId(jobs[1].Id))).Outcome);
        Assert.Equal(2,r.H.Sender.Calls);await using var db=fixture.Open();Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.AdmissionEvent).ToArrayAsync());
    }
    [Theory][InlineData("disabled")][InlineData("email")][InlineData("work")][InlineData("terminal")][InlineData("expiry")][InlineData("suppressed")][InlineData("epoch")]
    public async Task Obsolete_or_disabled_due_jobs_do_not_admit_mail(string change)
    {
        await using var r=await Create(fixture);var job=(await Scheduled(r))[0];r.H.Clock.Advance(job.AvailableAt-r.H.Clock.GetUtcNow());
        if(change=="disabled")r.H.App.Services.GetRequiredService<SignerReminderOptions>().Enabled=false;
        if(change=="email")r.H.App.Services.GetRequiredService<EmailOptions>().Enabled=false;
        if(change=="work")r.H.App.Services.GetRequiredService<WorkOptions>().Enabled=false;
        await using(var db=fixture.Open()) {
            if(change=="terminal")await db.Envelopes.Where(x=>x.Id==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            if(change=="expiry")r.H.Clock.Advance(TimeSpan.FromDays(31));
            if(change=="suppressed")db.Suppressions.Add(new() {Email=r.H.First.Email,Reason=SuppressionReason.Complaint});
            if(change=="epoch")await db.Signers.Where(x=>x.Id==r.H.First.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Email,"changed@example.invalid"));
            await db.SaveChangesAsync();
        }
        var result=await Execute(r,job.Id);Assert.Contains(result.Outcome,new[]{WorkOutcome.Completed,WorkOutcome.Failed});
        await using var check=fixture.Open();Assert.False(await check.EmailOutbox.AnyAsync(x=>x.Id==SignerReminderEvidence.EmailId(job.Id)));Assert.Equal(1,r.H.Sender.Calls);
    }
    [Theory][InlineData("payload")][InlineData("audit")][InlineData("lease")]
    public async Task Damaged_schedule_or_unowned_lease_cannot_admit_mail(string change)
    {
        await using var r=await Create(fixture);var job=(await Scheduled(r))[0];r.H.Clock.Advance(job.AvailableAt-r.H.Clock.GetUtcNow());
        var claim=await Claim(r,job.Id);Assert.NotNull(claim.Lease);
        await using(var db=fixture.Open()) {
            if(change=="payload")await db.WorkItems.Where(x=>x.Id==job.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
            if(change=="audit")await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.ScheduleEvent).ExecuteDeleteAsync();
        }
        using var scope=r.H.App.Services.CreateScope();var result=await new SignerReminderHandler(scope.ServiceProvider.GetRequiredService<SignerReminderJobs>()).ExecuteAsync(change=="lease" ? claim.Lease! with {Owner=Guid.NewGuid()} : claim.Lease!,default);
        Assert.NotEqual(WorkOutcome.Completed,result.Outcome);Assert.Equal(1,r.H.Sender.Calls);
    }
    [Theory][InlineData("definite")][InlineData("unknown")][InlineData("receipt")]
    public async Task Reminder_delivery_uses_supported_no_blind_retry_semantics(string failure)
    {
        await using var r=await Create(fixture);var job=(await Scheduled(r))[0];r.H.Clock.Advance(job.AvailableAt-r.H.Clock.GetUtcNow());
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,job.Id)).Outcome);var id=SignerReminderEvidence.EmailId(job.Id);
        if(failure=="definite")r.H.Sender.Failure=new EmailNotSubmittedException(true);
        if(failure=="unknown")r.H.Sender.Failure=new IOException("Synthetic uncertain provider outcome");
        if(failure=="receipt") {r.H.Faults.Event=InvitationSuccessorProtection.ReceiptEvent;r.H.Faults.FailCommit=true;}
        if(failure=="definite")Assert.Equal(WorkOutcome.Retry,(await Execute(r,id)).Outcome);else await Assert.ThrowsAsync<IOException>(()=>Execute(r,id));
        r.H.Sender.Failure=null;r.H.Faults.FailCommit=false;r.H.Clock.Advance(TimeSpan.FromMinutes(6));
        if(failure=="definite")Assert.Equal(WorkOutcome.Completed,(await Execute(r,id)).Outcome);else Assert.True((await Claim(r,id)).Terminal);
        Assert.Equal(failure=="definite" ? 3 : 2,r.H.Sender.Calls);
    }
    [Fact]
    public async Task Uncertain_admission_commit_recovers_the_same_id_and_cap_reservation()
    {
        await using var r=await Create(fixture);var job=(await Scheduled(r))[0];r.H.Clock.Advance(job.AvailableAt-r.H.Clock.GetUtcNow());
        r.H.Faults.Event=SignerReminderEvidence.AdmissionEvent;r.H.Faults.FailCommit=true;
        Assert.Equal(WorkOutcome.Retry,(await Execute(r,job.Id)).Outcome);r.H.Faults.FailCommit=false;r.H.Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,job.Id)).Outcome);Assert.Equal(WorkOutcome.Completed,(await Execute(r,SignerReminderEvidence.EmailId(job.Id))).Outcome);
        await using var db=fixture.Open();Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.AdmissionEvent).ToArrayAsync());Assert.Equal(2,r.H.Sender.Calls);
    }
    [Fact]
    public async Task Submission_day_caps_are_reserved_once_and_checked_again_before_dispatch()
    {
        await using var r=await Create(fixture);var job=(await Scheduled(r))[0];r.H.Clock.Advance(job.AvailableAt-r.H.Clock.GetUtcNow());
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,job.Id)).Outcome);var limits=r.H.App.Services.GetRequiredService<SignerReminderOptions>();
        limits.DailyRequests=limits.DailySenderRequests=limits.DailyAddressRequests=1;
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,SignerReminderEvidence.EmailId(job.Id))).Outcome);
        await using var db=fixture.Open();var admission=SignerReminderEvidence.ReadAdmission(await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.AdmissionEvent));
        Assert.Equal(job.AvailableAt,admission.AdmittedAt);Assert.Equal(SignerReminderEvidence.DayEnd(admission.AdmittedAt),admission.Deadline);
    }
    [Fact]
    public async Task Concurrent_envelopes_share_one_actual_day_global_reservation_limit()
    {
        var keys=new EphemeralDataProtectionProvider();
        async Task<Run> Make()=>await Run.Create(fixture,configure:s=> {
            s.AddSingleton<IDataProtectionProvider>(keys);s.AddSingleton(new SignerReminderOptions {Enabled=true,DailyRequests=1,DailySenderRequests=1,DailyAddressRequests=1});
        });
        await using var first=await Make();await using var second=await Make();var a=(await Scheduled(first))[0];var b=(await Scheduled(second))[0];
        first.H.Clock.Advance(a.AvailableAt-first.H.Clock.GetUtcNow());second.H.Clock.Advance(b.AvailableAt-second.H.Clock.GetUtcNow());
        var outcomes=await Task.WhenAll(Execute(first,a.Id),Execute(second,b.Id));Assert.All(outcomes,x=>Assert.Equal(WorkOutcome.Completed,x.Outcome));
        Assert.Single(outcomes,x=>x.Code=="reminder-daily-limit");await using var db=fixture.Open();
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>(x.EnvelopeId==first.H.Envelope.Id || x.EnvelopeId==second.H.Envelope.Id) && x.Event==SignerReminderEvidence.AdmissionEvent));
        Assert.Equal(1,first.H.Sender.Calls);Assert.Equal(1,second.H.Sender.Calls);
    }
    [Fact]
    public async Task Actual_day_deadline_does_not_allow_next_day_dispatch_or_a_second_admission()
    {
        await using var r=await Create(fixture);var job=(await Scheduled(r))[0];
        var late=SignerReminderEvidence.DayEnd(job.AvailableAt).AddSeconds(-1);r.H.Clock.Advance(late-r.H.Clock.GetUtcNow());
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,job.Id)).Outcome);var id=SignerReminderEvidence.EmailId(job.Id);
        r.H.Clock.Advance(TimeSpan.FromSeconds(2));Assert.Equal(WorkOutcome.Failed,(await Execute(r,id)).Outcome);
        Assert.Equal(1,r.H.Sender.Calls);await using var db=fixture.Open();
        var a=SignerReminderEvidence.ReadAdmission(await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.AdmissionEvent));
        Assert.Equal(late,a.AdmittedAt);Assert.Equal(late.AddSeconds(1),a.Deadline);Assert.True((await Claim(r,job.Id)).Terminal);
    }
    [Fact]
    public async Task Verified_contact_correction_and_address_cycle_retire_the_original_schedule_without_restarting_it()
    {
        await using var r=await Create(fixture);var jobs=await Scheduled(r);var original=r.H.First.Email;
        await r.Correct("corrected-"+original);await r.Correct(original);await Prepare(r);
        r.H.Clock.Advance(jobs[0].AvailableAt-r.H.Clock.GetUtcNow());var result=await Execute(r,jobs[0].Id);
        Assert.Equal(WorkOutcome.Completed,result.Outcome);Assert.Equal("reminder-no-longer-current",result.Code);
        Assert.Equal(jobs.Select(x=>x.Id),(await Scheduled(r)).Select(x=>x.Id));Assert.Equal(1,r.H.Sender.Calls);
    }
    [Fact]
    public async Task Accepted_Finish_stops_reminders_before_publication_and_checkpoint_schedules_only_the_next_current_copy()
    {
        await using var r=await Run.Create(fixture,browser:true,configure:s=>s.AddSingleton(new SignerReminderOptions {Enabled=true,DailyRequests=1000,DailySenderRequests=1000,DailyAddressRequests=1000}));
        var jobs=await Scheduled(r);var raw=Token(r.H.Sender.Last!.Text);var publicId=r.H.Envelope.PublicId;
        async Task<T> Use<S,T>(Func<S,Task<T>> call) where S:notnull {using var scope=r.H.App.Services.CreateScope();return await call(scope.ServiceProvider.GetRequiredService<S>());}
        var identity=(await Use((SignerAccess s)=>s.RedeemAsync(raw,null,null)))!;var principal=SignerAccessConfiguration.Principal(identity);
        var context=(await Use((SignerAccess s)=>s.GetContextAsync(principal,publicId)))!;
        Assert.NotNull(await Use((SignerPdfAccess s)=>s.PrepareAsync(principal,context)));
        string receipt;using(var scope=r.H.App.Services.CreateScope())receipt=scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(identity);
        Assert.Equal(ConsentResult.Accepted,await Use((SignerConsent s)=>s.AcceptAsync(principal,publicId,receipt,true,true,"download",null,null)));
        var preview=(await Use((SignatureAdoption s)=>s.PrepareAsync(principal,publicId,new(SignatureAdoptionTests.Mark(),SignatureAdoptionTests.Mark(60),SignatureMethod.Drawn))))!;
        Assert.Equal(SignatureAdoptionResult.Adopted,await Use((SignatureAdoption s)=>s.AdoptAsync(principal,publicId,preview.Receipt,true,SignatureAdoptionStatement.Version,null,null)));
        var fields=(await Use((SignerFields s)=>s.GetAsync(principal,publicId)))!;var signature=Assert.Single(fields.Fields);
        Assert.Equal(SignerFieldOutcome.Applied,(await Use((SignerFields s)=>s.ChangeAsync(principal,publicId,new(signature.Id,signature.Version,SignerFieldAction.Apply,AdoptionId:fields.AdoptionId),null,null))).Outcome);
        var review=(await Use((SignerReviewCandidates s)=>s.PrepareAsync(principal,publicId)))!;
        var finish=(await Use((SignerFinish s)=>s.AcceptAsync(principal,publicId,review.Receipt,true,SignerFinishStatement.Version,null,null))).Acceptance!;Assert.NotNull(finish);
        r.H.Clock.Advance(jobs[0].AvailableAt-r.H.Clock.GetUtcNow());Assert.Equal("reminder-no-longer-current",(await Execute(r,jobs[0].Id)).Code);
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,finish.Id)).Outcome);
        await using var db=fixture.Open();var current=await db.SignerFinishAcceptances.SingleAsync(x=>x.Id==finish.Id);Assert.NotNull(current.ProcessedAt);
        var all=await Scheduled(r);Assert.Equal(4,all.Length);var next=all.Where(x=>!jobs.Any(y=>y.Id==x.Id)).OrderBy(x=>x.AvailableAt).ToArray();
        Assert.Equal(current.ProcessedAt!.Value.AddDays(3),next[0].AvailableAt);
        var scheduled=await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==SignerReminderEvidence.ScheduleEvent).OrderBy(x=>x.Sequence).ToArrayAsync();Assert.Equal(2,scheduled.Length);
        Assert.Contains(current.PdfObjectId.ToString(),scheduled[1].DataJson);Assert.Contains(r.H.Second.Id.ToString(),scheduled[1].DataJson);
        Assert.Equal(WorkOutcome.Completed,(await ExecuteOriginal(r,current.NextInvitationId!.Value)).Outcome);
        r.H.Clock.Advance(next[0].AvailableAt-r.H.Clock.GetUtcNow());Assert.Equal(WorkOutcome.Completed,(await Execute(r,next[0].Id)).Outcome);
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,SignerReminderEvidence.EmailId(next[0].Id))).Outcome);
        Assert.Equal(r.H.Second.Email,r.H.Sender.Last!.To);
    }
    [Fact]
    public async Task Captured_Mailpit_reminder_has_a_redeemable_current_source_link_and_no_consent()
    {
        await using var r=await Create(fixture,smtp:true);var job=(await Scheduled(r))[0];r.H.Clock.Advance(job.AvailableAt-r.H.Clock.GetUtcNow());
        Assert.Equal(WorkOutcome.Completed,(await Execute(r,job.Id)).Outcome);var id=SignerReminderEvidence.EmailId(job.Id);Assert.Equal(WorkOutcome.Completed,(await Execute(r,id)).Outcome);
        using var http=new HttpClient();var port=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT");
        using var list=JsonDocument.Parse(await http.GetStringAsync("http://127.0.0.1:"+port+"/api/v1/search?query=to:"+r.H.First.Email));
        var message=list.RootElement.GetProperty("messages").EnumerateArray().First(x=>x.GetProperty("Subject").GetString()!.Contains("reminder",StringComparison.OrdinalIgnoreCase));
        using var mail=JsonDocument.Parse(await http.GetStringAsync("http://127.0.0.1:"+port+"/api/v1/message/"+message.GetProperty("ID").GetString()));var token=Token(mail.RootElement.GetProperty("Text").GetString()!);
        using var scope=r.H.App.Services.CreateScope();var access=scope.ServiceProvider.GetRequiredService<SignerAccess>();var identity=(await access.RedeemAsync(token,null,null))!;
        Assert.Equal(r.Sent.DocumentHash,identity.DocumentHash);Assert.Null((await access.GetContextAsync(SignerAccessConfiguration.Principal(identity),identity.PublicId))!.ConsentAt);
    }
    private async Task<WorkItem[]> Scheduled(Run r) {await using var db=fixture.Open();return await db.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Kind==WorkKind.Reminder).OrderBy(x=>x.AvailableAt).ToArrayAsync();}
    private static async Task Prepare(Run r) {using var scope=r.H.App.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();await using var tx=await db.Database.BeginTransactionAsync();await scope.ServiceProvider.GetRequiredService<SignerReminderJobs>().PrepareCurrentLockedAsync(r.H.Envelope.Id,default);await tx.CommitAsync();}
    private static async Task<WorkClaim> Claim(Run r,Guid id) {using var scope=r.H.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(id,default);}
    private static async Task<WorkResult> Execute(Run r,Guid id)
    {
        using var scope=r.H.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(id,default)).Lease!;Assert.NotNull(lease);
        var result=lease.Kind switch {
            WorkKind.Reminder=>await new SignerReminderHandler(scope.ServiceProvider.GetRequiredService<SignerReminderJobs>()).ExecuteAsync(lease,default),
            WorkKind.Rendering=>await scope.ServiceProvider.GetServices<IWorkHandler>().Single(x=>x.Kind==WorkKind.Rendering).ExecuteAsync(lease,default),
            _=>await scope.ServiceProvider.GetRequiredService<InvitationSuccessorDelivery>().ExecuteAsync(lease,default)};
        await store.FinishAsync(lease,result,default);return result;
    }
    private static async Task<WorkResult> ExecuteOriginal(Run r,Guid id)
    {
        using var scope=r.H.App.Services.CreateScope();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(id,default)).Lease!;Assert.NotNull(lease);
        var result=await scope.ServiceProvider.GetRequiredService<SignerInvitationDelivery>().ExecuteAsync(lease,default);await store.FinishAsync(lease,result,default);return result;
    }
    private static string Token(string text)=>Regex.Match(text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
}

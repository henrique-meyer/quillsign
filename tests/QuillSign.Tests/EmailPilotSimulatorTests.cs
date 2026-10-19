using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MimeKit;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotSimulatorTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";
    [Fact]
    public async Task Default_disabled_and_wrong_capability_resolve_no_database_keys_or_transport()
    {
        var services=new ServiceCollection();services.AddEmailPilotSimulatorFoundation(new ConfigurationBuilder().Build());
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        Assert.Null(await scope.ServiceProvider.GetRequiredService<EmailPilotSimulatorAdmission>().RequestAsync(Capability,EmailPilotSimulatorKind.Success));
        var enabled=new EmailPilotOptions{Enabled=true};var admission=new EmailPilotAdmissionOptions{CapabilitySha256=Hash(Capability)};
        var request=new EmailPilotSimulatorAdmission(enabled,new(),new(){Enabled=true},admission,()=>throw new Exception("SQL"),()=>throw new Exception("Signals"));
        Assert.Null(await request.RequestAsync("wrong",EmailPilotSimulatorKind.Success));
        Assert.Null(await request.RequestAsync(new string('x',43),EmailPilotSimulatorKind.Success));
        Assert.Null(await request.RequestAsync(Capability,(EmailPilotSimulatorKind)5));
        var sender=new EmailPilotSimulatorSender(new(),new(),new(),()=>throw new Exception("Authority"),()=>throw new Exception("Ledger"),
            ()=>throw new Exception("SQL"),_=>throw new Exception("Credentials"),TimeProvider.System);
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>sender.SendAsync(null!));
    }
    [Fact]
    public async Task Three_concurrent_protocol_kinds_create_exactly_three_null_parent_items_and_recover_same_identity()
    {
        await using var h=New();await h.Ledger.CreateAsync(Capability);
        var results=await Task.WhenAll(Enumerable.Range(0,9).Select(async i=>{
            await using var db=fixture.Open();return await h.AdmissionFor(db).RequestAsync(Capability,(EmailPilotSimulatorKind)(i%3+1));
        }));
        Assert.All(results,x=>Assert.NotNull(x));Assert.Equal(3,results.Select(x=>x!.WorkId).Distinct().Count());
        foreach(var result in results) {
            var item=await h.Db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==result!.WorkId);
            var row=await h.Db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==result!.WorkId);
            Assert.Null(item.EnvelopeId);Assert.Null(row.EnvelopeId);Assert.Equal(WorkKind.Email,item.Kind);
            Assert.Equal("pilot-ses-simulator-v1",row.Template);Assert.DoesNotContain(Capability,row.PayloadJson);
            Assert.Null(row.SubmissionStartedAt);Assert.Equal(EmailStatus.Queued,row.Status);
        }
        Assert.False(await h.Db.EmailPilotEnrollments.AnyAsync(x=>x.RunId==h.RunId));
        Assert.Equal(0,(await h.Ledger.ReadBudgetAsync())!.SimulatorAttempts);Assert.False(h.Email.Enabled);
    }
    [Fact]
    public async Task Lost_commit_and_publication_acknowledgements_recover_the_same_committed_item()
    {
        await using var h=New();await h.Ledger.CreateAsync(Capability);
        await using(var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(h.Db.Database.GetConnectionString())
            .AddInterceptors(new LostCommit(2)).Options))
            await Assert.ThrowsAsync<IOException>(()=>h.AdmissionFor(db).RequestAsync(Capability,EmailPilotSimulatorKind.Success));
        h.Signals.FailPublish=true;
        var result=Assert.IsType<EmailPilotSimulatorResult>(await h.AdmissionFor(h.Db).RequestAsync(Capability,EmailPilotSimulatorKind.Success));
        Assert.True(result.Recovered);Assert.False(result.WakeupPublished);
        h.Signals.FailPublish=false;
        Assert.Equal(result.WorkId,(await h.AdmissionFor(h.Db).RequestAsync(Capability,EmailPilotSimulatorKind.Success))!.WorkId);
    }
    [Theory]
    [InlineData("hint")][InlineData("expiry")][InlineData("work")][InlineData("capability")]
    public async Task Hint_failure_or_admission_cutoff_rolls_back_both_rows(string change)
    {
        await using var h=New();await h.Ledger.CreateAsync(Capability);h.Signals.FailHint=change=="hint";
        h.Signals.OnHint=()=>{if(change=="expiry")h.Clock.Now=h.Clock.Now.AddHours(1);if(change=="work")h.Work.Enabled=false;
            if(change=="capability")h.Admission.CapabilitySha256=Hash(new string('a',43));};
        await Assert.ThrowsAnyAsync<Exception>(()=>h.AdmissionFor(h.Db).RequestAsync(Capability,EmailPilotSimulatorKind.Success));
        h.Signals.OnHint=null;h.Signals.FailHint=false;h.Clock.Now=h.Start;h.Work.Enabled=true;h.Admission.CapabilitySha256=Hash(Capability);
        var recovered=Assert.IsType<EmailPilotSimulatorResult>(await h.AdmissionFor(h.Db).RequestAsync(Capability,EmailPilotSimulatorKind.Success));
        Assert.False(recovered.Recovered);
    }
    [Theory]
    [InlineData("work-payload")][InlineData("email-payload")][InlineData("recipient")][InlineData("template")]
    [InlineData("attachments")][InlineData("envelope")][InlineData("lease")][InlineData("attempt")]
    [InlineData("expired")][InlineData("disabled")][InlineData("work-disabled")][InlineData("public-email")]
    [InlineData("run")][InlineData("operator")][InlineData("suppression")]
    public async Task Corrupt_source_stale_lease_and_config_never_resolve_provider(string change)
    {
        await using var h=New();var lease=await h.Claim();var id=lease.Id;
        if(change=="work-payload")await h.Db.WorkItems.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
        if(change=="email-payload")await h.Db.EmailOutbox.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
        if(change=="recipient")await h.Db.EmailOutbox.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.To,h.Options.Mailboxes.Sender));
        if(change=="template")await h.Db.EmailOutbox.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Template,"sender-verification"));
        if(change=="attachments")await h.Db.EmailOutbox.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.AttachmentsJson,"[{}]"));
        if(change=="envelope") {var e=new Envelope{SenderEmail=h.Options.Mailboxes.Sender};h.Db.Envelopes.Add(e);await h.Db.SaveChangesAsync();
            await h.Db.EmailOutbox.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.EnvelopeId,e.Id));}
        if(change=="lease")lease=lease with{Owner=Guid.NewGuid()};if(change=="attempt")lease=lease with{Attempt=lease.Attempt+1};
        if(change=="expired")h.Clock.Now=lease.Until;if(change=="disabled")h.Options.Enabled=false;
        if(change=="work-disabled")h.Work.Enabled=false;if(change=="public-email")h.Email.Enabled=true;
        if(change=="run")h.Options.RunId=Guid.NewGuid().ToString("N");if(change=="operator")h.Admission.CapabilitySha256=Hash(new string('a',43));
        if(change=="suppression"){h.Db.Suppressions.Add(new(){Email=Target(EmailPilotSimulatorKind.Success)});await h.Db.SaveChangesAsync();}
        var factories=0;var sender=h.Sender(_=>{factories++;throw new Exception("Credentials must not resolve");});
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>sender.SendAsync(lease));Assert.Equal(0,factories);
    }
    [Theory]
    [InlineData(EmailPilotSimulatorKind.Success)][InlineData(EmailPilotSimulatorKind.Bounce)][InlineData(EmailPilotSimulatorKind.Complaint)]
    public async Task Normal_delivery_records_exact_reserved_bytes_and_feedback_advances_normal_receipt(EmailPilotSimulatorKind kind)
    {
        await using var h=New();var lease=await h.Claim(kind);var captured=new Capture();var factories=0;
        var delivery=h.Delivery(_=>{factories++;return captured;});
        Assert.Equal(WorkOutcome.Completed,(await delivery.ExecuteAsync(lease)).Outcome);Assert.Equal(1,factories);Assert.Equal(1,captured.Calls);
        var receipt=await h.Db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==lease.Id);Assert.Equal("Ses",receipt.Provider);Assert.Equal(captured.Id,receipt.ProviderMessageId);
        Assert.Equal(EmailStatus.Sent,receipt.Status);Assert.NotNull(receipt.SubmissionStartedAt);Assert.Null(receipt.EnvelopeId);
        var reservation=await h.Db.EmailPilotReservations.SingleAsync(x=>x.RunId==h.RunId);
        Assert.Null(reservation.SubjectEnvelopeId);Assert.Equal(EmailPilotAttemptKind.Simulator,reservation.Kind);Assert.Equal(EmailPilotRole.Simulator,reservation.Role);
        Assert.Equal(captured.Bytes!.Length,reservation.EncodedBytes);Assert.Equal(SHA256.HashData(captured.Bytes),reservation.RequestSha256);
        using var raw=new MemoryStream(captured.Bytes);using var mime=await MimeMessage.LoadAsync(raw);
        Assert.Equal(Target(kind),Assert.Single(mime.To.Mailboxes).Address);Assert.Empty(mime.Cc);Assert.Empty(mime.Bcc);Assert.Empty(mime.Attachments);
        Assert.False(mime.Headers.Contains("X-QuillSign-Envelope"));Assert.DoesNotContain(Capability,Encoding.UTF8.GetString(captured.Bytes));
        var status=kind switch{EmailPilotSimulatorKind.Bounce=>EmailStatus.Bounced,EmailPilotSimulatorKind.Complaint=>EmailStatus.Complained,_=>EmailStatus.Sent};
        SuppressionReason? reason=kind switch{EmailPilotSimulatorKind.Bounce=>SuppressionReason.Bounce,EmailPilotSimulatorKind.Complaint=>SuppressionReason.Complaint,_=>null};
        await new SesFeedbackProcessor(h.Db,h.Clock).ApplyAsync(new(captured.Id,[receipt.To],status,reason),default);
        Assert.Equal(status,await h.Db.EmailOutbox.Where(x=>x.Id==lease.Id).Select(x=>x.Status).SingleAsync());
        Assert.Equal(reason is not null,await h.Db.Suppressions.AnyAsync(x=>x.Email==receipt.To));
    }
    [Fact]
    public async Task Unknown_outcome_preserves_intent_and_claim_recovery_cannot_reinvoke()
    {
        await using var h=New();var lease=await h.Claim();var captured=new Capture{Failure=new IOException("Synthetic lost provider acknowledgement")};
        var delivery=h.Delivery(_=>captured);await Assert.ThrowsAsync<IOException>(()=>delivery.ExecuteAsync(lease));
        Assert.Equal(1,captured.Calls);Assert.Equal(1,(await h.Ledger.ReadBudgetAsync())!.SimulatorAttempts);
        Assert.Equal(WorkOutcome.Ambiguous,(await delivery.ExecuteAsync(lease)).Outcome);Assert.Equal(1,captured.Calls);
        h.Clock.Now=lease.Until.AddSeconds(1);Assert.True((await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(lease.Id,default)).Terminal);
        Assert.Equal("submission-ambiguous",await h.Db.WorkItems.Where(x=>x.Id==lease.Id).Select(x=>x.LastError).SingleAsync());
    }
    [Fact]
    public async Task Definite_rejection_clears_only_intent_and_next_owned_attempt_consumes_new_budget()
    {
        await using var h=New();var lease=await h.Claim();var captured=new Capture{Failure=new EmailNotSubmittedException(true)};
        var delivery=h.Delivery(_=>captured);var rejected=await delivery.ExecuteAsync(lease);Assert.Equal(WorkOutcome.Retry,rejected.Outcome);
        Assert.Null(await h.Db.EmailOutbox.Where(x=>x.Id==lease.Id).Select(x=>x.SubmissionStartedAt).SingleAsync());
        var due=await new WorkStore(h.Db,h.Work,h.Clock).FinishAsync(lease,rejected,default);h.Clock.Now=due!.Value;
        var next=(await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(lease.Id,default)).Lease!;captured.Failure=null;
        Assert.Equal(WorkOutcome.Completed,(await delivery.ExecuteAsync(next)).Outcome);Assert.Equal(2,captured.Calls);
        Assert.Equal(2,(await h.Ledger.ReadBudgetAsync())!.SimulatorAttempts);
    }
    [Fact]
    public async Task Same_attempt_replay_never_resolves_second_transport()
    {
        await using var h=New();var lease=await h.Claim();await h.Intent(lease);var capture=new Capture();var factories=0;
        await h.Sender(_=>{factories++;return capture;}).SendAsync(lease);
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>h.Sender(_=>{factories++;return capture;}).SendAsync(lease));
        Assert.Equal(1,factories);Assert.Equal(1,capture.Calls);
    }
    [Fact]
    public async Task Concurrent_same_attempt_resolves_exactly_one_raw_transport()
    {
        await using var h=New();var lease=await h.Claim();await h.Intent(lease);var factories=0;var capture=new Capture();
        var results=await Task.WhenAll(Enumerable.Range(0,2).Select(async _=>{
            await using var db=fixture.Open();
            try{await h.SenderFor(db,_=>{Interlocked.Increment(ref factories);return capture;}).SendAsync(lease);return true;}
            catch(EmailPilotTransportRefusedException){return false;}
        }));
        Assert.Equal(1,results.Count(x=>x));Assert.Equal(1,factories);Assert.Equal(1,capture.Calls);
        Assert.Equal(1,(await h.Ledger.ReadBudgetAsync())!.SimulatorAttempts);
    }
    [Fact]
    public async Task Ten_consumed_simulator_attempts_refuse_before_credentials_without_refund()
    {
        await using var h=New();var lease=await h.Claim();await h.Intent(lease);
        for(var i=0;i<10;i++)Assert.Equal(EmailPilotReservationOutcome.Reserved,await h.Ledger.ReserveAsync(new(Guid.NewGuid(),null,Guid.NewGuid(),
            EmailPilotAttemptKind.Simulator,EmailPilotRole.Simulator,100,new string('a',64)),null));
        var factories=0;
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>h.Sender(_=>{factories++;return new Capture();}).SendAsync(lease));
        Assert.Equal(0,factories);Assert.Equal(10,(await h.Ledger.ReadBudgetAsync())!.SimulatorAttempts);
        Assert.NotNull(await h.Db.EmailOutbox.Where(x=>x.Id==lease.Id).Select(x=>x.SubmissionStartedAt).SingleAsync());
    }
    [Fact]
    public async Task Lost_reservation_commit_acknowledgement_never_resolves_factory_or_replays()
    {
        await using var h=New();var lease=await h.Claim();await h.Intent(lease);var factories=0;
        await using(var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(h.Db.Database.GetConnectionString())
            .AddInterceptors(new LostCommit(1)).Options)) {
            var sender=new EmailPilotSimulatorSender(h.Options,h.Email,h.Work,()=>h.Authority,()=>h.LedgerFor(db),()=>h.Db,
                _=>{factories++;return new Capture();},h.Clock);
            await Assert.ThrowsAsync<IOException>(()=>sender.SendAsync(lease));
        }
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>h.Sender(_=>{factories++;return new Capture();}).SendAsync(lease));
        Assert.Equal(0,factories);Assert.Equal(1,(await h.Ledger.ReadBudgetAsync())!.SimulatorAttempts);
    }
    [Fact]
    public async Task Lost_submission_intent_commit_acknowledgement_preserves_intent_without_provider_call()
    {
        await using var h=New();var lease=await h.Claim();var factories=0;
        await using(var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(h.Db.Database.GetConnectionString())
            .AddInterceptors(new LostCommit(1)).Options)) {
            var authority=new EmailPilotSimulatorAuthority(h.Options,h.Email,h.Work,h.Admission,()=>h.LedgerFor(db),h.Clock);
            var delivery=new EmailPilotSimulatorDelivery(db,authority,()=>{factories++;throw new Exception("No provider after lost intent acknowledgement");},h.Clock);
            await Assert.ThrowsAsync<IOException>(()=>delivery.ExecuteAsync(lease));
        }
        Assert.NotNull(await h.Db.EmailOutbox.Where(x=>x.Id==lease.Id).Select(x=>x.SubmissionStartedAt).SingleAsync());
        Assert.Equal(WorkOutcome.Ambiguous,(await h.Delivery(_=>{factories++;return new Capture();}).ExecuteAsync(lease)).Outcome);
        Assert.Equal(0,factories);Assert.Equal(0,(await h.Ledger.ReadBudgetAsync())!.SimulatorAttempts);
    }
    [Theory]
    [InlineData("expiry")][InlineData("operator")][InlineData("public-email")][InlineData("settings")]
    public async Task Changes_after_reservation_commit_consume_attempt_but_never_resolve_credentials(string change)
    {
        await using var h=New();var lease=await h.Claim();await h.Intent(lease);var factories=0;
        await using var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(h.Db.Database.GetConnectionString())
            .AddInterceptors(new CommitAction(()=>{
                if(change=="expiry")h.Clock.Now=lease.Until;if(change=="operator")h.Admission.CapabilitySha256=Hash(new string('a',43));
                if(change=="public-email")h.Email.Enabled=true;if(change=="settings")h.Email.Ses.ConfigurationSet="changed";
            })).Options);
        var sender=new EmailPilotSimulatorSender(h.Options,h.Email,h.Work,()=>h.Authority,()=>h.LedgerFor(db),()=>h.Db,
            _=>{factories++;return new Capture();},h.Clock);
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>sender.SendAsync(lease));
        Assert.Equal(0,factories);Assert.Equal(1,await h.Db.EmailPilotReservations.CountAsync(x=>x.RunId==h.RunId));
        Assert.NotNull(await h.Db.EmailOutbox.Where(x=>x.Id==lease.Id).Select(x=>x.SubmissionStartedAt).SingleAsync());
    }
    [Fact]
    public async Task Normal_worker_routes_simulator_before_envelope_gate_with_public_email_disabled()
    {
        await using var h=New();var lease=await h.Claim();var captured=new Capture();var ordinary=new ForbiddenSender();
        var dispatch=new EmailPilotDispatch(h.Db,h.Email,()=>throw new Exception("Envelope authority must not resolve"),
            (_,_,_)=>throw new Exception("Application sender must not resolve"),ordinary);
        var missing=new EmailWorkHandler(h.Db,h.Email,null!,null!,ordinary,h.Clock,pilot:dispatch);
        Assert.Equal("pilot-simulator-unavailable",(await missing.ExecuteAsync(lease,default)).Code);
        var handler=new EmailWorkHandler(h.Db,h.Email,null!,null!,ordinary,h.Clock,pilot:dispatch,simulators:()=>h.Delivery(_=>captured));
        Assert.Equal(WorkOutcome.Completed,(await handler.ExecuteAsync(lease,default)).Outcome);Assert.Equal(1,captured.Calls);Assert.False(h.Email.Enabled);
    }
    [Fact]
    public async Task Disabled_default_worker_remains_lazy_but_installed_expired_simulator_stops_terminally()
    {
        var ordinary=new ForbiddenSender();var disabled=new EmailWorkHandler(null!,new(),null!,null!,ordinary,TimeProvider.System);
        Assert.Equal("delivery-disabled",(await disabled.ExecuteAsync(null!,default)).Code);
        await using var h=New();var lease=await h.Claim();h.Options.Enabled=false;
        var handler=new EmailWorkHandler(h.Db,h.Email,null!,null!,ordinary,h.Clock,simulators:()=>h.Delivery(_=>throw new Exception("Credentials")));
        var result=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Failed,result.Outcome);Assert.Equal("pilot-simulator-unavailable",result.Code);
        Assert.Null(await h.Db.EmailOutbox.Where(x=>x.Id==lease.Id).Select(x=>x.SubmissionStartedAt).SingleAsync());
    }
    private Harness New()=>new(fixture.Open());
    private static string Hash(string value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(value)));
    private static string Target(EmailPilotSimulatorKind kind)=>kind.ToString().ToLowerInvariant()+"@simulator.amazonses.com";
    private sealed class Capture:IPreparedEmailTransport
    {
        internal int Calls;internal byte[]? Bytes;internal Exception? Failure;internal readonly string Id=Guid.NewGuid().ToString("N");
        public async Task<EmailDelivery> SendAsync(PreparedRawMime message,CancellationToken ct)
        {Calls++;using var raw=message.OpenRead();using var output=new MemoryStream();await raw.CopyToAsync(output,ct);Bytes=output.ToArray();if(Failure is not null)throw Failure;return new("Ses",Id);}
    }
    private sealed class ForbiddenSender:IEmailSender
    {public Task<EmailDelivery> SendAsync(OutgoingEmail message,CancellationToken ct=default)=>throw new Exception("Ordinary sending must remain disabled.");}
    private sealed class LostCommit(int number):DbTransactionInterceptor
    {private int commits;public override Task TransactionCommittedAsync(DbTransaction t,TransactionEndEventData e,CancellationToken ct=default){if(++commits==number)throw new IOException("Synthetic lost simulator commit");return Task.CompletedTask;}}
    private sealed class CommitAction(Action action):DbTransactionInterceptor
    {public override Task TransactionCommittedAsync(DbTransaction t,TransactionEndEventData e,CancellationToken ct=default){action();return Task.CompletedTask;}}
    private sealed class Harness:IAsyncDisposable
    {
        internal readonly QuillSignDbContext Db;internal readonly EmailPilotOptions Options=new(){Enabled=true,RunId=Guid.NewGuid().ToString("N"),
            Mailboxes=new("sender@example.invalid","first@example.invalid","second@example.invalid","recipient@example.invalid")};
        internal readonly EmailOptions Email=new(){Provider="Ses",FromEmail="outbound@example.invalid",FromName="Synthetic test",Ses=new(){Region="us-east-2",ConfigurationSet="synthetic-test"}};
        internal readonly EmailPilotAdmissionOptions Admission=new(){CapabilitySha256=Hash(Capability)};internal readonly WorkOptions Work=new(){Enabled=true};
        internal readonly EmailPilotAdmissionTests.Clock Clock=new();internal readonly EmailPilotAdmissionTests.Signals Signals=new();
        internal readonly DateTimeOffset Start;private readonly IDataProtectionProvider keys=new EphemeralDataProtectionProvider();
        internal Guid RunId=>Guid.ParseExact(Options.RunId,"N");
        internal EmailPilotLedger Ledger=>LedgerFor(Db);
        internal EmailPilotLedger LedgerFor(QuillSignDbContext db)=>new(Options,Email,()=>db,()=>new(keys),Clock);
        internal EmailPilotSimulatorAdmission AdmissionFor(QuillSignDbContext db)=>new(Options,Email,Work,Admission,()=>LedgerFor(db),()=>Signals);
        internal EmailPilotSimulatorAuthority Authority=>new(Options,Email,Work,Admission,()=>Ledger,Clock);
        internal EmailPilotSimulatorSender Sender(Func<EmailPilotSesSettings,IPreparedEmailTransport> factory)=>SenderFor(Db,factory);
        internal EmailPilotSimulatorSender SenderFor(QuillSignDbContext db,Func<EmailPilotSesSettings,IPreparedEmailTransport> factory)=>new(Options,Email,Work,
            ()=>new(Options,Email,Work,Admission,()=>LedgerFor(db),Clock),()=>LedgerFor(db),()=>db,factory,Clock);
        internal EmailPilotSimulatorDelivery Delivery(Func<EmailPilotSesSettings,IPreparedEmailTransport> factory)=>new(Db,Authority,()=>Sender(factory),Clock);
        internal Harness(QuillSignDbContext db){Db=db;Start=Clock.Now;}
        internal async Task<WorkLease> Claim(EmailPilotSimulatorKind kind=EmailPilotSimulatorKind.Success)
        {var result=Assert.IsType<EmailPilotSimulatorResult>(await AdmissionFor(Db).RequestAsync(Capability,kind));return (await new WorkStore(Db,Work,Clock).ClaimAsync(result.WorkId,default)).Lease!;}
        internal Task Intent(WorkLease lease)=>Db.EmailOutbox.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,Clock.Now).SetProperty(x=>x.Attempts,lease.Attempt));
        public async ValueTask DisposeAsync(){await Db.Suppressions.Where(x=>x.Email==Target(EmailPilotSimulatorKind.Success)||x.Email==Target(EmailPilotSimulatorKind.Bounce)||x.Email==Target(EmailPilotSimulatorKind.Complaint)).ExecuteDeleteAsync();await Db.DisposeAsync();}
    }
}

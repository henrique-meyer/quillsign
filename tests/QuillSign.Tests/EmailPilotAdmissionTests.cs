using System.Collections.Concurrent;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";

    [Fact]
    public async Task Default_host_and_wrong_capability_resolve_no_SQL_keys_outbox_or_availability()
    {
        var services=new ServiceCollection();services.AddEmailPilotAdmissionFoundation(new ConfigurationBuilder().Build());
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        Assert.Null(await scope.ServiceProvider.GetRequiredService<EmailPilotAdmission>().RequestAsync(Capability,EmailPilotScenario.Completion));
        var pilot=new EmailPilotOptions{Enabled=true};var options=new EmailPilotAdmissionOptions{CapabilitySha256=Hash(Capability)};
        var service=new EmailPilotAdmission(pilot,options,new(),new(){Enabled=true},new(),
            ()=>throw new Exception("Availability must stay lazy."),()=>throw new Exception("SQL must stay lazy."),
            ()=>throw new Exception("Outbox must stay lazy."),()=>throw new Exception("Key ring must stay lazy."),TimeProvider.System);
        Assert.Null(await service.RequestAsync(new string('a',43),EmailPilotScenario.Completion));
        Assert.Null(await service.RequestAsync("malformed",EmailPilotScenario.Completion));
        Assert.Null(await service.RequestAsync(Capability,(EmailPilotScenario)100));
    }

    [Fact]
    public async Task Admission_is_unverified_and_uses_the_normal_protected_verification_work_format()
    {
        await using var h=New();var admitted=Assert.IsType<EmailPilotAdmissionResult>(await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion,"127.0.0.1","Synthetic pilot"));
        Assert.False(admitted.Recovered);Assert.True(admitted.WakeupPublished);Assert.False(h.Email.Enabled);
        var envelope=await h.Db.Envelopes.SingleAsync(x=>x.Id==admitted.EnvelopeId);
        Assert.Null(envelope.SenderVerifiedAt);Assert.Equal(EnvelopeStatus.Draft,envelope.Status);Assert.True(envelope.IsDemo);
        Assert.Equal(h.Options.Mailboxes.Sender,envelope.SenderEmail);
        Assert.False(await h.Db.AuthTokens.AnyAsync(x=>x.EnvelopeId==envelope.Id));
        var outbox=await h.Db.EmailOutbox.SingleAsync(x=>x.Id==admitted.VerificationWorkId);
        var payload=h.Payload.Unprotect(outbox.PayloadJson);
        Assert.Equal(43,payload.Token.Length);Assert.NotEqual(Guid.Empty,payload.TokenId);Assert.DoesNotContain(payload.Token,outbox.PayloadJson);
        Assert.Equal("sender-verification",outbox.Template);Assert.Equal(h.Options.Mailboxes.Sender,outbox.To);
        var work=await h.Db.WorkItems.SingleAsync(x=>x.Id==outbox.Id);Assert.Equal(WorkKind.Email,work.Kind);Assert.Equal(envelope.Id,work.EnvelopeId);
        Assert.Equal(new[]{"draft_created","sender_verification_requested"},await h.Db.AuditEvents.Where(x=>x.EnvelopeId==envelope.Id).OrderBy(x=>x.Sequence).Select(x=>x.Event).ToArrayAsync());
        Assert.Null(await new SenderWorkflow(h.Db,h.Sender,h.Availability,()=>h.Writer,new(h.Db,h.Clock),h.Clock).VerifyAsync(payload.Token,null,null));
        await using var tx=await h.Db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<EmailDisabledException>(()=>h.Writer.PrepareVerificationAsync(envelope.Id,outbox.To));
    }

    [Fact]
    public async Task Concurrent_same_scenario_and_other_slots_create_exactly_three_drafts_and_three_outboxes()
    {
        await using var h=New();await h.Ledger.CreateAsync(Capability);
        var results=await Task.WhenAll(Enumerable.Range(0,6).Select(async i=>{
            await using var db=fixture.Open();return await h.For(db).RequestAsync(Capability,(EmailPilotScenario)(i%3+1));
        }));
        Assert.All(results,x=>Assert.NotNull(x));Assert.Equal(3,results.Select(x=>x!.EnvelopeId).Distinct().Count());
        Assert.Equal(3,await h.Db.EmailPilotEnrollments.CountAsync(x=>x.RunId==h.RunId));
        Assert.Equal(3,await h.Db.Envelopes.CountAsync(x=>x.SenderEmail==h.Options.Mailboxes.Sender));
        Assert.Equal(3,await h.Db.EmailOutbox.CountAsync(x=>x.To==h.Options.Mailboxes.Sender));
    }

    [Fact]
    public async Task Lost_commit_acknowledgement_recovers_the_same_authenticated_draft_and_work()
    {
        await using var h=New();await h.Ledger.CreateAsync(Capability);
        await using(var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(h.Db.Database.GetConnectionString())
            .AddInterceptors(new LostCommit(2)).Options))
            await Assert.ThrowsAsync<IOException>(()=>h.For(db).RequestAsync(Capability,EmailPilotScenario.Completion));
        // Existing CreateAsync itself commits one read-only transaction; admission is commit two.
        Assert.Single(await h.Db.Envelopes.Where(x=>x.SenderEmail==h.Options.Mailboxes.Sender).ToListAsync());
        var recovered=Assert.IsType<EmailPilotAdmissionResult>(await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion));
        Assert.True(recovered.Recovered);Assert.True(recovered.WakeupPublished);
        Assert.Equal(1,await h.Db.EmailOutbox.CountAsync(x=>x.To==h.Options.Mailboxes.Sender));
    }

    [Fact]
    public async Task Lost_publication_is_recoverable_but_failure_before_commit_rolls_back_every_row()
    {
        await using var h=New();h.Signals.FailHint=true;
        await Assert.ThrowsAsync<IOException>(()=>h.Service.RequestAsync(Capability,EmailPilotScenario.Void));
        Assert.False(await h.Db.Envelopes.AnyAsync(x=>x.SenderEmail==h.Options.Mailboxes.Sender));
        Assert.False(await h.Db.EmailPilotEnrollments.AnyAsync(x=>x.RunId==h.RunId));
        Assert.False(await h.Db.EmailOutbox.AnyAsync(x=>x.To==h.Options.Mailboxes.Sender));
        h.Signals.FailHint=false;h.Signals.FailPublish=true;
        var first=Assert.IsType<EmailPilotAdmissionResult>(await h.Service.RequestAsync(Capability,EmailPilotScenario.Void));
        Assert.False(first.WakeupPublished);h.Signals.FailPublish=false;
        var second=Assert.IsType<EmailPilotAdmissionResult>(await h.Service.RequestAsync(Capability,EmailPilotScenario.Void));
        Assert.True(second.Recovered);Assert.True(second.WakeupPublished);Assert.Equal(first.EnvelopeId,second.EnvelopeId);
    }

    [Fact]
    public async Task Expiry_after_hint_persistence_rolls_back_whole_admission_and_never_renews()
    {
        await using var h=New();h.Signals.OnHint=()=>h.Clock.Now+=TimeSpan.FromHours(1);
        await Assert.ThrowsAsync<InvalidDataException>(()=>h.Service.RequestAsync(Capability,EmailPilotScenario.Decline));
        Assert.False(await h.Db.Envelopes.AnyAsync(x=>x.SenderEmail==h.Options.Mailboxes.Sender));
        Assert.False(await h.Db.EmailPilotEnrollments.AnyAsync(x=>x.RunId==h.RunId));
        await Assert.ThrowsAsync<InvalidDataException>(()=>h.Service.RequestAsync(Capability,EmailPilotScenario.Decline));
        Assert.Empty(h.Signals.Published);
    }

    [Theory]
    [InlineData("suppression")][InlineData("daily-cap")][InlineData("public-enabled")][InlineData("work-disabled")][InlineData("storage-disabled")]
    public async Task Existing_safety_gates_remain_effective(string gate)
    {
        await using var h=New();
        if(gate=="suppression"){h.Db.Suppressions.Add(new(){Email=h.Options.Mailboxes.Sender});await h.Db.SaveChangesAsync();}
        if(gate=="daily-cap"){h.Sender.DailyRequests=1;Assert.NotNull(await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion));}
        if(gate=="public-enabled")h.Email.Enabled=true;
        if(gate=="work-disabled")h.Work.Enabled=false;
        if(gate=="storage-disabled")h.Config["Storage:Provider"]="Disabled";
        Assert.Null(await h.Service.RequestAsync(Capability,EmailPilotScenario.Void));
        Assert.False(await h.Db.EmailPilotEnrollments.AnyAsync(x=>x.RunId==h.RunId && x.Scenario==EmailPilotScenario.Void));
    }

    [Theory]
    [InlineData("draft")][InlineData("payload")][InlineData("work")][InlineData("audit")]
    public async Task Recovery_refuses_changed_source_instead_of_creating_a_new_draft(string target)
    {
        await using var h=New();var first=(await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion))!;
        if(target=="draft")await h.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE Envelopes SET PublicId={Guid.NewGuid().ToString("N")} WHERE Id={first.EnvelopeId}");
        if(target=="payload")await h.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE EmailOutbox SET PayloadJson='{{}}' WHERE Id={first.VerificationWorkId}");
        if(target=="work")await h.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE WorkItems SET PayloadJson='{{}}' WHERE Id={first.VerificationWorkId}");
        if(target=="audit")await h.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE AuditEvents SET DataJson='{{\"changed\":true}}' WHERE EnvelopeId={first.EnvelopeId} AND Sequence=1");
        await Assert.ThrowsAsync<InvalidDataException>(()=>h.Service.RequestAsync(Capability,EmailPilotScenario.Completion));
        Assert.Equal(1,await h.Db.Envelopes.CountAsync(x=>x.SenderEmail==h.Options.Mailboxes.Sender));
    }

    private Harness New()=>new(fixture.Open());
    private static string Hash(string value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(value)));
    private sealed class Clock:TimeProvider{public DateTimeOffset Now=new(2026,10,18,10,0,0,TimeSpan.Zero);public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed class LostCommit(int number):DbTransactionInterceptor
    {private int commits;public override Task TransactionCommittedAsync(DbTransaction t,TransactionEndEventData e,CancellationToken ct=default){if(++commits==number)throw new IOException("Synthetic lost admission commit acknowledgement.");return Task.CompletedTask;}}
    private sealed class Harness: IAsyncDisposable
    {
        internal readonly QuillSignDbContext Db;internal readonly EmailPilotOptions Options=new(){Enabled=true,RunId=Guid.NewGuid().ToString("N")};
        internal readonly EmailPilotAdmissionOptions Admission=new(){CapabilitySha256=Hash(Capability)};
        internal readonly EmailOptions Email=new();internal readonly WorkOptions Work=new(){Enabled=true};internal readonly SenderOptions Sender=new();
        internal readonly Clock Clock=new();internal readonly Signals Signals=new();internal readonly IConfigurationRoot Config;
        private readonly IDataProtectionProvider keys=new EphemeralDataProtectionProvider();
        internal Guid RunId=>Guid.ParseExact(Options.RunId,"N");internal EmailPayloadProtection Payload=>new(keys);
        internal SenderAvailability Availability=>new(Email,Work,Config);
        internal EmailPilotLedger Ledger=>new(Options,Email,()=>Db,()=>new(keys),Clock);
        internal EmailOutboxWriter Writer=>new(Db,Signals,Payload,Work,Email,Clock);
        internal EmailPilotAdmission Service=>For(Db);
        internal EmailPilotAdmission For(QuillSignDbContext db)=>new(Options,Admission,Email,Work,Sender,()=>Availability,
            ()=>new(Options,Email,()=>db,()=>new(keys),Clock),()=>new(db,Signals,Payload,Work,Email,Clock),()=>Payload,Clock);
        internal Harness(QuillSignDbContext db)
        {Db=db;Options.Mailboxes=new("sender-"+Options.RunId+"@example.invalid","first@example.invalid","second@example.invalid","recipient@example.invalid");
            Config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"ConnectionStrings:Database","configured"},{"Storage:Provider","Azurite"}}).Build();}
        public ValueTask DisposeAsync()=>Db.DisposeAsync();
    }
    private sealed class Signals:IWorkSignals
    {
        internal readonly ConcurrentBag<Guid> Published=[];internal bool FailHint,FailPublish;internal Action? OnHint;
        public Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct){OnHint?.Invoke();if(FailHint)throw new IOException("Synthetic hint failure.");return Task.CompletedTask;}
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct){if(FailPublish)throw new IOException("Synthetic publish failure.");Published.Add(id);return Task.CompletedTask;}
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>Task.CompletedTask;
        public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>Task.FromResult<DateTimeOffset?>(null);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>Task.FromResult<WorkDelivery?>(null);
        public Task DeferAsync(WorkDelivery d,TimeSpan delay,CancellationToken ct)=>Task.CompletedTask;
        public Task AcknowledgeAsync(WorkDelivery d,CancellationToken ct)=>Task.CompletedTask;
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>Task.FromResult(0);
        public Task VerifyAsync(CancellationToken ct)=>Task.CompletedTask;
    }
}

using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Data.Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;

namespace QuillSign.Tests;

public sealed class EmailPilotProtectionTests
{
    [Fact]
    public async Task Disabled_foundation_needs_no_database_key_ring_or_provider()
    {
        var services = new ServiceCollection();
        services.AddEmailPilotFoundation(new ConfigurationBuilder().Build());
        using var provider = services.BuildServiceProvider(); using var scope = provider.CreateScope();
        var ledger = scope.ServiceProvider.GetRequiredService<EmailPilotLedger>();
        Assert.Null(await ledger.ReadBudgetAsync());
        Assert.False(await ledger.EnrollAsync("", Guid.NewGuid(), EmailPilotScenario.Completion));
        Assert.Equal(EmailPilotReservationOutcome.Refused, await ledger.ReserveAsync(null!, null));
        await Assert.ThrowsAsync<EmailDisabledException>(() => ledger.CreateAsync(""));
    }

    [Fact]
    public void Enabled_configuration_requires_one_run_and_four_exact_distinct_normalized_roles()
    {
        var options = new EmailPilotOptions { Enabled = true };
        Assert.Throws<InvalidOperationException>(options.Validate);
        options.RunId = Guid.NewGuid().ToString("N"); options.Mailboxes = Mailboxes(); options.Validate();
        options.Mailboxes = options.Mailboxes with { Recipient = options.Mailboxes.Sender };
        Assert.Throws<InvalidOperationException>(options.Validate);
        options.Mailboxes = Mailboxes() with { Sender = "SENDER@example.invalid" };
        Assert.Throws<InvalidOperationException>(options.Validate);
        options.Mailboxes = null!; Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Encrypted_manifest_is_bound_to_run_purpose_key_ring_and_bounded_payload()
    {
        var protection = new EmailPilotProtection(new EphemeralDataProtectionProvider()); var run = Guid.NewGuid();
        var value = new EmailPilotEnrollment(run, Guid.NewGuid(), EmailPilotScenario.Completion, DateTimeOffset.UtcNow);
        var encoded = protection.Protect(run, "enrollment", value);
        Assert.Equal(value, protection.Read<EmailPilotEnrollment>(run, "enrollment", encoded, 2048));
        Assert.Throws<InvalidDataException>(() => protection.Read<EmailPilotEnrollment>(Guid.NewGuid(), "enrollment", encoded, 2048));
        Assert.Throws<InvalidDataException>(() => protection.Read<EmailPilotEnrollment>(run, "manifest", encoded, 2048));
        Assert.Throws<InvalidDataException>(() => protection.Read<EmailPilotEnrollment>(run, "enrollment", encoded, 2));
        Assert.Throws<InvalidDataException>(() => new EmailPilotProtection(new EphemeralDataProtectionProvider()).Read<EmailPilotEnrollment>(run, "enrollment", encoded, 2048));
    }

    internal static EmailPilotMailboxes Mailboxes() => new("sender@example.invalid", "first@example.invalid", "second@example.invalid", "recipient@example.invalid");
}

public sealed class EmailPilotLedgerTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private const string Capability = "1234567890123456789012345678901234567890123";
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public async Task Restart_returns_original_deadline_and_cannot_renew_expired_run_or_change_configuration()
    {
        await using var run = New(); var manifest = await run.Ledger.CreateAsync(Capability);
        run.Clock.Now += TimeSpan.FromMinutes(5);
        Assert.Equal(manifest, await run.Ledger.CreateAsync(Capability));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Ledger.CreateAsync(new string('a', 43)));
        run.Options.Mailboxes = run.Options.Mailboxes with { Sender = "other@example.invalid" };
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Ledger.ReadBudgetAsync());
        run.Options.Mailboxes = EmailPilotProtectionTests.Mailboxes();
        run.Clock.Now = manifest.ExpiresAt;
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Ledger.CreateAsync(Capability));
        Assert.Equal(1, await run.Db.EmailPilotRuns.CountAsync(x => x.Id == manifest.RunId));
    }

    [Fact]
    public async Task Three_scenario_slots_require_owned_demo_drafts_and_exact_capability()
    {
        await using var run = New(); await run.Ledger.CreateAsync(Capability);
        var first = await run.Draft();
        Assert.False(await run.Ledger.EnrollAsync(new string('a',43), first.Id, EmailPilotScenario.Completion));
        Assert.True(await run.Ledger.EnrollAsync(Capability, first.Id, EmailPilotScenario.Completion));
        Assert.True(await run.Ledger.EnrollAsync(Capability, first.Id, EmailPilotScenario.Completion));
        Assert.False(await run.Ledger.EnrollAsync(Capability, first.Id, EmailPilotScenario.Void));
        Assert.False(await run.Ledger.EnrollAsync(Capability, (await run.Draft()).Id, EmailPilotScenario.Completion));
        var wrong = await run.Draft("other@example.invalid");
        Assert.False(await run.Ledger.EnrollAsync(Capability, wrong.Id, EmailPilotScenario.Void));
        var ordinary = await run.Draft(demo:false);
        Assert.False(await run.Ledger.EnrollAsync(Capability, ordinary.Id, EmailPilotScenario.Void));
        Assert.True(await run.Ledger.EnrollAsync(Capability, (await run.Draft()).Id, EmailPilotScenario.Void));
        Assert.True(await run.Ledger.EnrollAsync(Capability, (await run.Draft()).Id, EmailPilotScenario.Decline));
        Assert.Equal(3, await run.Db.EmailPilotEnrollments.CountAsync(x => x.RunId == run.Id));
    }

    [Fact]
    public async Task Replays_are_consumed_status_only_and_never_refund_or_issue_another_provider_permit()
    {
        await using var run = New(); var envelope = await run.Start(); var request = App(envelope);
        Assert.Equal(EmailPilotReservationOutcome.Reserved, await run.Ledger.ReserveAsync(request, run.Options.Mailboxes.Sender));
        Assert.Equal(EmailPilotReservationOutcome.AlreadyConsumed, await run.Ledger.ReserveAsync(request, run.Options.Mailboxes.Sender));
        Assert.Equal(EmailPilotReservationOutcome.Refused, await run.Ledger.ReserveAsync(request with { EncodedBytes = 50 }, run.Options.Mailboxes.Sender));
        Assert.Equal(EmailPilotReservationOutcome.Refused, await run.Ledger.ReserveAsync(request with { Id = Guid.NewGuid() }, run.Options.Mailboxes.Sender));
        Assert.Equal(EmailPilotReservationOutcome.Refused, await run.Ledger.ReserveAsync(App(envelope), "other@example.invalid"));
        Assert.Equal(new EmailPilotBudget(1,0,0,100), await run.Ledger.ReadBudgetAsync());
    }

    [Theory]
    [InlineData(EmailPilotAttemptKind.Application,20)]
    [InlineData(EmailPilotAttemptKind.Simulator,10)]
    [InlineData(EmailPilotAttemptKind.Timestamp,4)]
    public async Task Cross_context_concurrent_reservations_obey_nonrefunded_attempt_limit(EmailPilotAttemptKind kind, int limit)
    {
        await using var run = New(); var envelope = await run.Start();
        var results = await Task.WhenAll(Enumerable.Range(0,limit+3).Select(async _ => {
            await using var db = fixture.Open(); var ledger = run.For(db);
            var request = kind switch {
                EmailPilotAttemptKind.Application => App(envelope),
                EmailPilotAttemptKind.Simulator => new(Guid.NewGuid(), null, Guid.NewGuid(), kind, EmailPilotRole.Simulator, 100, Hash),
                _ => new EmailPilotReservation(Guid.NewGuid(), envelope, Guid.NewGuid(), kind, EmailPilotRole.None, 0, Hash)
            };
            return await ledger.ReserveAsync(request, kind == EmailPilotAttemptKind.Application ? run.Options.Mailboxes.Sender : null);
        }));
        Assert.Equal(limit, results.Count(x => x == EmailPilotReservationOutcome.Reserved));
        Assert.Equal(3, results.Count(x => x == EmailPilotReservationOutcome.Refused));
        Assert.Equal(limit, await run.Db.EmailPilotReservations.CountAsync(x => x.RunId == run.Id));
    }

    [Fact]
    public async Task Encoded_message_and_aggregate_limits_are_enforced_before_reservation()
    {
        await using var run = New(); var envelope = await run.Start(); var address = run.Options.Mailboxes.Sender;
        Assert.Equal(EmailPilotReservationOutcome.Refused, await run.Ledger.ReserveAsync(App(envelope) with { EncodedBytes = 1048577 }, address));
        for(var i=0;i<20;i++) Assert.Equal(EmailPilotReservationOutcome.Reserved,await run.Ledger.ReserveAsync(App(envelope) with { EncodedBytes = EmailPilotLimits.MessageBytes },address));
        for(var i=0;i<10;i++) Assert.Equal(EmailPilotReservationOutcome.Reserved,await run.Ledger.ReserveAsync(new(Guid.NewGuid(),null,Guid.NewGuid(),EmailPilotAttemptKind.Simulator,EmailPilotRole.Simulator,EmailPilotLimits.MessageBytes,Hash),null));
        Assert.Equal(30L*1048576,(await run.Ledger.ReadBudgetAsync())!.EncodedBytes);
    }

    [Fact]
    public async Task Expiry_crossing_UTC_midnight_uses_original_instant_and_disabling_public_gate_closes_pilot()
    {
        await using var run = New(); run.Clock.Now = new(2026,10,18,23,45,0,TimeSpan.Zero); var envelope = await run.Start();
        run.Clock.Now += TimeSpan.FromMinutes(30);
        Assert.Equal(EmailPilotReservationOutcome.Reserved,await run.Ledger.ReserveAsync(App(envelope),run.Options.Mailboxes.Sender));
        run.Email.Enabled = true;
        Assert.Equal(EmailPilotReservationOutcome.Refused,await run.Ledger.ReserveAsync(App(envelope),run.Options.Mailboxes.Sender));
        run.Email.Enabled = false; run.Clock.Now += TimeSpan.FromMinutes(30);
        Assert.Equal(EmailPilotReservationOutcome.Refused,await run.Ledger.ReserveAsync(App(envelope),run.Options.Mailboxes.Sender));
    }

    [Theory]
    [InlineData("manifest")]
    [InlineData("enrollment")]
    [InlineData("reservation")]
    public async Task Corrupt_protected_evidence_fails_closed(string target)
    {
        await using var run = New(); var envelope = await run.Start();
        await run.Ledger.ReserveAsync(App(envelope),run.Options.Mailboxes.Sender);
        if(target=="manifest") await run.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE EmailPilotSecrets SET ProtectedManifest='corrupt' WHERE RunId={run.Id}");
        if(target=="enrollment") await run.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE EmailPilotEnrollments SET ProtectedBinding='corrupt' WHERE RunId={run.Id}");
        if(target=="reservation") await run.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE EmailPilotReservations SET ProtectedReceipt='corrupt' WHERE RunId={run.Id}");
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Ledger.ReserveAsync(App(envelope),run.Options.Mailboxes.Sender));
        Assert.Equal(1,await run.Db.EmailPilotReservations.CountAsync(x=>x.RunId==run.Id));
    }

    [Fact]
    public async Task Accounting_refuses_to_discard_pending_application_edits_or_join_implicit_transaction()
    {
        await using var run=New(); await run.Ledger.CreateAsync(Capability);
        run.Db.Envelopes.Add(new(){SenderEmail=run.Options.Mailboxes.Sender});
        await Assert.ThrowsAsync<InvalidOperationException>(()=>run.Ledger.ReadBudgetAsync());
        Assert.True(run.Db.ChangeTracker.HasChanges()); run.Db.ChangeTracker.Clear();
        await using var transaction=await run.Db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(()=>run.Ledger.ReadBudgetAsync());
    }

    [Fact]
    public async Task Recovered_unknown_commit_can_only_report_consumption_and_expired_secrets_cannot_reopen_run()
    {
        await using var run=New(); var envelope=await run.Start(); var request=App(envelope);
        await run.Ledger.ReserveAsync(request,run.Options.Mailboxes.Sender);
        // A fresh context models recovery after the caller lost the committed acknowledgement.
        await using var restarted=fixture.Open();
        Assert.Equal(EmailPilotReservationOutcome.AlreadyConsumed,await run.For(restarted).ReserveAsync(request,run.Options.Mailboxes.Sender));
        run.Clock.Now+=TimeSpan.FromDays(7);
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Ledger.ReadBudgetAsync());
        Assert.Equal(1,await run.Db.EmailPilotRuns.CountAsync(x=>x.Id==run.Id));
        Assert.Equal(1,await run.Db.EmailPilotReservations.CountAsync(x=>x.RunId==run.Id));
    }

    [Fact]
    public async Task Expiry_during_save_rolls_back_without_provider_permit()
    {
        await using var run=New();var envelope=await run.Start();var before=run.Clock.Now;
        var fault=new SaveDeadline(run.Clock);
        await using var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(run.Db.Database.GetConnectionString()).AddInterceptors(fault).Options);
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.For(db).ReserveAsync(App(envelope),run.Options.Mailboxes.Sender));
        Assert.Equal(0,await run.Db.EmailPilotReservations.CountAsync(x=>x.RunId==run.Id));
        run.Clock.Now=before;
        Assert.Equal(new EmailPilotBudget(0,0,0,0),await run.Ledger.ReadBudgetAsync());
    }

    [Fact]
    public async Task Real_lost_commit_acknowledgement_is_consumed_once_after_restart()
    {
        await using var run=New();var envelope=await run.Start();var request=App(envelope);
        await using(var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(run.Db.Database.GetConnectionString()).AddInterceptors(new LostAcknowledgement()).Options))
            await Assert.ThrowsAsync<IOException>(()=>run.For(db).ReserveAsync(request,run.Options.Mailboxes.Sender));
        Assert.Equal(1,await run.Db.EmailPilotReservations.CountAsync(x=>x.RunId==run.Id));
        Assert.Equal(EmailPilotReservationOutcome.AlreadyConsumed,await run.Ledger.ReserveAsync(request,run.Options.Mailboxes.Sender));
    }

    [Fact]
    public async Task Operational_tombstones_survive_document_purge_and_EF_rejects_mutation()
    {
        await using var run=New();var envelope=await run.Start();
        await run.Ledger.ReserveAsync(App(envelope),run.Options.Mailboxes.Sender);
        await run.Db.Envelopes.Where(x=>x.Id==envelope).ExecuteDeleteAsync();
        Assert.Equal(1,await run.Db.EmailPilotEnrollments.CountAsync(x=>x.RunId==run.Id));
        Assert.Equal(EmailPilotReservationOutcome.Refused,await run.Ledger.ReserveAsync(App(envelope),run.Options.Mailboxes.Sender));
        var row=await run.Db.EmailPilotRuns.SingleAsync(x=>x.Id==run.Id);row.ExpiresAt+=TimeSpan.FromMinutes(1);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>run.Db.SaveChangesAsync());
    }

    [Fact]
    public async Task Guarded_secret_cleanup_requires_actual_seven_day_expiry_and_preserves_counter_tombstone()
    {
        await using var run=New();await run.Ledger.CreateAsync(Capability);
        var connection=run.Db.Database.GetDbConnection();
        await run.Db.Database.ExecuteSqlRawAsync("IF DATABASE_PRINCIPAL_ID('app_worker') IS NULL CREATE USER [app_worker] WITHOUT LOGIN");
        await DatabasePermissions.GrantEmailPilotRetentionAsync((Microsoft.Data.SqlClient.SqlConnection)connection);
        await DatabasePermissions.GrantEmailPilotRetentionAsync((Microsoft.Data.SqlClient.SqlConnection)connection);
        await run.Db.Database.ExecuteSqlInterpolatedAsync($"EXEC dbo.RemoveExpiredEmailPilotSecrets @RunId={run.Id}");
        Assert.Equal(1,await run.Db.EmailPilotSecrets.CountAsync(x=>x.RunId==run.Id));
        // Age only this private fixture run; the procedure uses database UTC, not a caller deadline.
        await run.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE EmailPilotRuns SET CreatedAt=DATEADD(day,-8,SYSUTCDATETIME()),ExpiresAt=DATEADD(minute,60,DATEADD(day,-8,SYSUTCDATETIME())) WHERE Id={run.Id}");
        await run.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE s SET DeleteAfter=DATEADD(day,7,r.CreatedAt) FROM EmailPilotSecrets s JOIN EmailPilotRuns r ON r.Id=s.RunId WHERE s.RunId={run.Id}");
        await using var command=connection.CreateCommand();command.CommandText="EXECUTE AS USER = 'app_worker'";await command.ExecuteNonQueryAsync();
        try { await run.Db.Database.ExecuteSqlInterpolatedAsync($"EXEC dbo.RemoveExpiredEmailPilotSecrets @RunId={run.Id}"); }
        finally { command.CommandText="REVERT";await command.ExecuteNonQueryAsync(); }
        Assert.Equal(0,await run.Db.EmailPilotSecrets.CountAsync(x=>x.RunId==run.Id));
        Assert.Equal(1,await run.Db.EmailPilotRuns.CountAsync(x=>x.Id==run.Id));
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Ledger.CreateAsync(Capability));
    }

    private Run New()=>new(fixture.Open());
    private static EmailPilotReservation App(Guid envelope)=>new(Guid.NewGuid(),envelope,Guid.NewGuid(),EmailPilotAttemptKind.Application,EmailPilotRole.Sender,100,Hash);
    private sealed class Clock:TimeProvider { public DateTimeOffset Now=new(2026,10,18,10,0,0,TimeSpan.Zero);public override DateTimeOffset GetUtcNow()=>Now; }
    private sealed class SaveDeadline(Clock clock):SaveChangesInterceptor
    {
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData e,int result,CancellationToken ct=default)
        { clock.Now+=TimeSpan.FromHours(1);return ValueTask.FromResult(result); }
    }
    private sealed class LostAcknowledgement:DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default)
            =>throw new IOException("Synthetic lost pilot reservation acknowledgement.");
    }
    private sealed class Run(QuillSignDbContext db):IAsyncDisposable
    {
        internal readonly QuillSignDbContext Db=db;
        internal readonly EmailPilotOptions Options=new(){Enabled=true,RunId=Guid.NewGuid().ToString("N"),Mailboxes=EmailPilotProtectionTests.Mailboxes()};
        internal readonly EmailOptions Email=new(); internal readonly Clock Clock=new();
        private readonly EmailPilotProtection protection=new(new EphemeralDataProtectionProvider());
        internal Guid Id=>Guid.ParseExact(Options.RunId,"N");
        internal EmailPilotLedger Ledger=>For(Db);
        internal EmailPilotLedger For(QuillSignDbContext context)=>new(Options,Email,()=>context,()=>protection,Clock);
        internal async Task<Envelope> Draft(string? sender=null,bool demo=true)
        { var value=new Envelope{SenderEmail=sender??Options.Mailboxes.Sender,IsDemo=demo};Db.Add(value);await Db.SaveChangesAsync();return value; }
        internal async Task<Guid> Start()
        { await Ledger.CreateAsync(Capability);var value=await Draft();Assert.True(await Ledger.EnrollAsync(Capability,value.Id,EmailPilotScenario.Completion));return value.Id; }
        public ValueTask DisposeAsync()=>Db.DisposeAsync();
    }
}

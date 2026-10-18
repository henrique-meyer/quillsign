using System.Data.Common;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class DocumentLookupDeliveryTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Delayed_empty_mailbox_delivery_issues_only_at_dispatch_and_repeated_requests_or_wakes_do_not_resend()
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid();
        Assert.Equal(LookupRequestOutcome.Neutral, await h.Request(id)); await h.Request(id);
        await using (var db = fixture.Open()) {
            Assert.False(await h.Tokens(db).AnyAsync());
            var email = await db.EmailOutbox.SingleAsync(x => x.Id == id); var work = await db.WorkItems.SingleAsync(x => x.Id == id);
            Assert.Null(email.EnvelopeId); Assert.Null(work.EnvelopeId); Assert.DoesNotContain(h.Address, email.PayloadJson);
            Assert.DoesNotContain(h.Address, work.PayloadJson); Assert.DoesNotContain(h.Ip, email.PayloadJson); Assert.Equal(1, h.Signals.Puts);
        }
        h.Clock.Advance(TimeSpan.FromHours(3)); Assert.True(await h.Once()); Assert.Equal(1, h.Transport.Calls);
        var message = h.Transport.Last!; var code = Code(message); Assert.Contains("/find/access#token=", message.Html);
        Assert.DoesNotContain("?token=", message.Text); Assert.Null(message.EnvelopeId); Assert.Empty(message.Attachments ?? []);
        Assert.Contains("Open my documents", message.Text); Assert.Contains("access code", message.Text); Assert.Contains("Not for legally significant", message.Text);
        using (var scope = h.App.Services.CreateScope()) {
            var lookup = scope.ServiceProvider.GetRequiredService<DocumentLookup>(); var session = (await lookup.RedeemAsync(code))!;
            Assert.Equal(h.Address, session.Identity.Email); Assert.Equal(h.Clock.GetUtcNow().AddMinutes(15), session.Identity.LinkExpiresAt);
            Assert.Empty((await lookup.ListAsync(DocumentLookupProtection.Principal(session.Identity), session.Receipt))!.Entries);
            Assert.Null(await lookup.RedeemAsync(code));
        }
        await h.Signals.PublishAsync(id, TimeSpan.Zero, default); Assert.True(await h.Once()); Assert.Equal(1, h.Transport.Calls);
        await h.Request(id, "other@example.invalid", "192.0.2.2"); Assert.Equal(1, h.Transport.Calls);
        await using var verify = fixture.Open(); Assert.Equal(h.Address, (await verify.EmailOutbox.SingleAsync(x => x.Id == id)).To);
        Assert.Equal(WorkStatus.Completed, (await verify.WorkItems.SingleAsync(x => x.Id == id)).Status);
        Assert.False(await verify.Envelopes.AnyAsync());
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Disabled_gates_do_not_open_SQL_resolve_signals_or_create_tokens(bool work)
    {
        await using var h = new Harness(fixture);
        if (work) h.Work.Enabled = false; else h.Email.Enabled = false;
        var before = h.Connections.Opens;
        Assert.Equal(LookupRequestOutcome.Unavailable, await h.Request(Guid.NewGuid()));
        Assert.Equal(before, h.Connections.Opens); Assert.Equal(0, h.Signals.Puts); Assert.Equal(0, h.Transport.Calls);
    }

    [Fact]
    public async Task Concurrent_address_cap_is_atomic_and_resets_only_with_the_UTC_request_day()
    {
        await using var h = new Harness(fixture); h.Limits.DailyRequests = 20; h.Limits.DailyIpRequests = 10; h.Limits.DailyAddressRequests = 2;
        var ids = Enumerable.Range(0, 8).Select(_ => Guid.NewGuid()).ToArray();
        Assert.All(await Task.WhenAll(ids.Select(x => h.Request(x))), x => Assert.Equal(LookupRequestOutcome.Neutral, x));
        await using var db = fixture.Open(); Assert.Equal(2, await db.EmailOutbox.CountAsync(x => ids.Contains(x.Id))); Assert.Equal(2, h.Signals.Puts);
        h.Clock.Advance(TimeSpan.FromDays(1)); var tomorrow = Guid.NewGuid(); await h.Request(tomorrow);
        Assert.True(await db.EmailOutbox.AnyAsync(x => x.Id == tomorrow)); Assert.Equal(0, h.Transport.Calls);
    }

    [Fact]
    public async Task Distinct_addresses_cannot_bypass_IP_or_global_caps()
    {
        await using var h = new Harness(fixture); h.Limits.DailyRequests = 3; h.Limits.DailyAddressRequests = 3; h.Limits.DailyIpRequests = 2;
        var ids = Enumerable.Range(0, 5).Select(_ => Guid.NewGuid()).ToArray();
        await h.Request(ids[0], "one@example.invalid"); await h.Request(ids[1], "two@example.invalid"); await h.Request(ids[2], "three@example.invalid", "::ffff:192.0.2.1");
        await h.Request(ids[3], "three@example.invalid", "192.0.2.3"); await h.Request(ids[4], "four@example.invalid", "192.0.2.4");
        await using var db = fixture.Open(); var saved = await db.EmailOutbox.Where(x => ids.Contains(x.Id)).Select(x => x.Id).ToArrayAsync();
        Assert.Equal(ids.Where((_, i) => i is 0 or 1 or 3).Order(), saved.Order());
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Suppression_before_admission_or_dispatch_never_issues_a_link_or_calls_a_provider(bool queued)
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); if (queued) await h.Request(id);
        await h.Suppress(); if (queued) Assert.True(await h.Once()); else await h.Request(id);
        Assert.Equal(0, h.Transport.Calls); await using var db = fixture.Open(); Assert.False(await h.Tokens(db).AnyAsync());
        Assert.Equal(queued, await db.EmailOutbox.AnyAsync(x => x.Id == id));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Definitely_unsubmitted_mail_invalidates_the_exact_old_token_and_only_retryable_failure_can_get_a_fresh_link(bool retry)
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id); h.Transport.Failure = new EmailNotSubmittedException(retry);
        Assert.True(await h.Once()); var oldCode = Code(h.Transport.Last!);
        await using (var db = fixture.Open()) { var token = await h.Tokens(db).SingleAsync(); Assert.Equal(h.Clock.GetUtcNow(), token.ExpiresAt); Assert.Null((await db.EmailOutbox.SingleAsync(x => x.Id == id)).SubmissionStartedAt); }
        using (var scope = h.App.Services.CreateScope()) Assert.Null(await scope.ServiceProvider.GetRequiredService<DocumentLookup>().RedeemAsync(oldCode));
        h.Transport.Failure = null; h.Clock.Advance(TimeSpan.FromMinutes(2)); await h.Signals.PublishAsync(id, TimeSpan.Zero, default); Assert.True(await h.Once());
        Assert.Equal(retry ? 2 : 1, h.Transport.Calls);
        if (retry) Assert.NotEqual(oldCode, Code(h.Transport.Last!));
    }

    [Fact]
    public async Task Unknown_provider_acceptance_keeps_intent_and_recovery_never_replays_the_message()
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id); h.Transport.Failure = new IOException("Synthetic unknown provider acknowledgement.");
        await Assert.ThrowsAsync<IOException>(() => h.Once());
        await using (var db = fixture.Open()) Assert.NotNull((await db.EmailOutbox.SingleAsync(x => x.Id == id)).SubmissionStartedAt);
        h.Transport.Failure = null; h.Clock.Advance(TimeSpan.FromMinutes(6)); await h.Signals.PublishAsync(id, TimeSpan.Zero, default); Assert.True(await h.Once());
        Assert.Equal(1, h.Transport.Calls); await using var verify = fixture.Open();
        Assert.Equal("submission-ambiguous", (await verify.WorkItems.SingleAsync(x => x.Id == id)).LastError);
        Assert.Equal(EmailStatus.Failed, (await verify.EmailOutbox.SingleAsync(x => x.Id == id)).Status);
    }

    [Theory]
    [InlineData("owner")][InlineData("recipient")][InlineData("payload")]
    public async Task Stale_lease_or_changed_scope_cannot_issue_or_send(string fault)
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id);
        using var scope = h.App.Services.CreateScope(); var store = scope.ServiceProvider.GetRequiredService<WorkStore>(); var lease = (await store.ClaimAsync(id, default)).Lease!;
        await using (var db = fixture.Open()) {
            if (fault == "owner") await db.WorkItems.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.LeaseOwner, Guid.NewGuid()));
            if (fault == "recipient") await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.To, "other@example.invalid"));
            if (fault == "payload") await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, "{}"));
        }
        var handler = scope.ServiceProvider.GetRequiredService<LookupLinkDelivery>();
        if (fault == "owner") await Assert.ThrowsAsync<InvalidOperationException>(() => handler.ExecuteAsync(lease, default));
        else Assert.Equal(WorkOutcome.Failed, (await handler.ExecuteAsync(lease, default)).Outcome);
        Assert.Equal(0, h.Transport.Calls); await using var verify = fixture.Open(); Assert.False(await h.Tokens(verify).AnyAsync());
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task A_saved_request_deadline_is_never_extended_and_a_tighter_current_bound_is_respected(bool increase)
    {
        await using var h = new Harness(fixture); h.Limits.RequestHours = increase ? 1 : 24; var id = Guid.NewGuid(); await h.Request(id);
        h.Limits.RequestHours = increase ? 24 : 1; h.Clock.Advance(TimeSpan.FromHours(2)); Assert.True(await h.Once());
        Assert.Equal(0, h.Transport.Calls); await using var db = fixture.Open(); Assert.False(await h.Tokens(db).AnyAsync());
        Assert.Equal("lookup-request-expired", (await db.WorkItems.SingleAsync(x => x.Id == id)).LastError);
    }

    [Theory]
    [InlineData("hint")][InlineData("request-rejected")][InlineData("request-lost")]
    public async Task Hint_and_admission_commit_failures_recover_without_duplicate_requests_or_phantom_sends(string fault)
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); h.Signals.FailHint = fault == "hint"; h.Faults.Mode = fault;
        await Assert.ThrowsAsync<IOException>(() => h.Request(id)); h.Signals.FailHint = false; h.Faults.Mode = "";
        await h.Signals.RecoverAsync(h.Clock.GetUtcNow(), default); Assert.True(await h.Once());
        Assert.Equal(fault == "request-lost" ? 1 : 0, h.Transport.Calls);
        await using var db = fixture.Open(); Assert.Equal(fault == "request-lost" ? 1 : 0, await db.EmailOutbox.CountAsync(x => x.Id == id));
    }

    [Theory]
    [InlineData("intent-rejected")][InlineData("intent-lost")][InlineData("issue-lost")]
    public async Task Unknown_or_rejected_preparation_commits_never_call_the_provider_and_recovery_respects_persisted_intent(string fault)
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id); h.Faults.Mode = fault;
        await Assert.ThrowsAsync<IOException>(() => h.Once()); Assert.Equal(0, h.Transport.Calls);
        h.Faults.Mode = ""; h.Clock.Advance(TimeSpan.FromMinutes(6)); await h.Signals.PublishAsync(id, TimeSpan.Zero, default); Assert.True(await h.Once());
        Assert.Equal(fault == "intent-lost" ? 0 : 1, h.Transport.Calls);
        await using var db = fixture.Open(); var work = await db.WorkItems.SingleAsync(x => x.Id == id);
        Assert.Equal(fault == "intent-lost" ? WorkStatus.Failed : WorkStatus.Completed, work.Status);
    }

    [Fact]
    public async Task Current_day_delivery_caps_include_old_queued_requests_without_double_spending_on_retry()
    {
        await using var h = new Harness(fixture); h.Clock.Advance(TimeSpan.FromHours(23)); var first = Guid.NewGuid(); var second = Guid.NewGuid();
        await h.Request(first); await h.Request(second); h.Limits.DailyAddressRequests = h.Limits.DailyIpRequests = h.Limits.DailyRequests = 1;
        Assert.True(await h.Once()); Assert.True(await h.Once()); Assert.Equal(1, h.Transport.Calls);
        h.Clock.Advance(TimeSpan.FromHours(2)); await h.Signals.PublishAsync(second, TimeSpan.Zero, default); Assert.True(await h.Once()); Assert.Equal(2, h.Transport.Calls);
        await using var db = fixture.Open(); Assert.Equal(2, await h.Tokens(db).CountAsync());
    }

    [Fact]
    public async Task A_consumed_token_cannot_be_invalidated_or_silently_replaced_after_a_claimed_definite_failure()
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id);
        h.Transport.BeforeSend = async message => { using var scope = h.App.Services.CreateScope(); Assert.NotNull(await scope.ServiceProvider.GetRequiredService<DocumentLookup>().RedeemAsync(Code(message))); };
        h.Transport.Failure = new EmailNotSubmittedException(true); await Assert.ThrowsAsync<InvalidDataException>(() => h.Once());
        h.Transport.Failure = null; h.Clock.Advance(TimeSpan.FromMinutes(6)); await h.Signals.PublishAsync(id, TimeSpan.Zero, default); Assert.True(await h.Once());
        Assert.Equal(1, h.Transport.Calls); await using var db = fixture.Open(); Assert.Single(await h.Tokens(db).ToArrayAsync());
        Assert.Equal("submission-ambiguous", (await db.WorkItems.SingleAsync(x => x.Id == id)).LastError);
    }

    [Theory]
    [InlineData("disabled")][InlineData("suppressed")][InlineData("recipient")][InlineData("token")][InlineData("lease")]
    public async Task Policy_scope_token_and_lease_are_rechecked_after_issuance(string change)
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id);
        h.Faults.AfterIssue = async () => {
            if (change == "disabled") h.Email.Enabled = false;
            if (change == "suppressed") await h.Suppress();
            if (change == "lease") h.Clock.Advance(TimeSpan.FromSeconds(301));
            await using var db = fixture.Open();
            if (change == "recipient") await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.To, "changed@example.invalid"));
            if (change == "token") await h.Tokens(db).ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, x => x.ExpiresAt));
        };
        if (change == "lease") await Assert.ThrowsAsync<InvalidOperationException>(() => h.Once()); else Assert.True(await h.Once());
        Assert.Equal(0, h.Transport.Calls); await using var verify = fixture.Open();
        Assert.Equal(1, await h.Tokens(verify).CountAsync()); Assert.Null((await verify.EmailOutbox.SingleAsync(x => x.Id == id)).SubmissionStartedAt);
    }

    [Fact]
    public async Task A_lost_provider_receipt_acknowledgement_recovers_the_actual_saved_sent_state_without_resending()
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id); h.Faults.Mode = "receipt-lost";
        await Assert.ThrowsAsync<IOException>(() => h.Once()); h.Clock.Advance(TimeSpan.FromMinutes(6));
        await h.Signals.PublishAsync(id, TimeSpan.Zero, default); Assert.True(await h.Once()); Assert.Equal(1, h.Transport.Calls);
        await using var db = fixture.Open(); Assert.Equal(EmailStatus.Sent, (await db.EmailOutbox.SingleAsync(x => x.Id == id)).Status);
        Assert.Equal(WorkStatus.Completed, (await db.WorkItems.SingleAsync(x => x.Id == id)).Status);
    }

    [Fact]
    public async Task Unavailable_payload_keys_do_not_issue_tokens_or_touch_a_provider_and_can_recover_explicitly()
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id); h.KeysUnavailable = true;
        Assert.True(await h.Once()); Assert.Equal(0, h.Transport.Calls);
        await using (var db = fixture.Open()) Assert.False(await h.Tokens(db).AnyAsync());
        h.KeysUnavailable = false; h.Clock.Advance(TimeSpan.FromMinutes(2)); await h.Signals.PublishAsync(id, TimeSpan.Zero, default);
        Assert.True(await h.Once()); Assert.Equal(1, h.Transport.Calls);
    }

    [Fact]
    public async Task A_changed_protected_intent_is_not_accepted_through_SQL_whitespace_equivalence()
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id);
        h.Transport.BeforeSend = async _ => { await using var db = fixture.Open(); await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, x => x.PayloadJson + " ")); };
        await Assert.ThrowsAsync<InvalidDataException>(() => h.Once()); h.Transport.BeforeSend = null;
        h.Clock.Advance(TimeSpan.FromMinutes(6)); await h.Signals.PublishAsync(id, TimeSpan.Zero, default); Assert.True(await h.Once());
        Assert.Equal(1, h.Transport.Calls); await using var verify = fixture.Open(); Assert.Equal("submission-ambiguous", (await verify.WorkItems.SingleAsync(x => x.Id == id)).LastError);
    }

    [Fact]
    public async Task A_receipt_preserves_feedback_that_arrives_during_provider_submission()
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id);
        h.Transport.BeforeSend = async _ => { await using var db = fixture.Open(); await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, EmailStatus.Complained)); };
        Assert.True(await h.Once()); await using var verify = fixture.Open(); var email = await verify.EmailOutbox.SingleAsync(x => x.Id == id);
        Assert.Equal(EmailStatus.Complained, email.Status); Assert.Equal("Smtp", email.Provider); Assert.NotNull(email.ProviderMessageId);
        Assert.Equal(WorkStatus.Completed, (await verify.WorkItems.SingleAsync(x => x.Id == id)).Status);
    }

    private static string Code(OutgoingEmail message) { var match = Regex.Match(message.Text, @"#token=([A-Za-z0-9_-]+)"); Assert.True(match.Success); return match.Groups[1].Value; }
    private sealed class Harness : IAsyncDisposable
    {
        private static int sequence; private readonly QueueClient queue; private readonly BlobContainerClient hints; private readonly BlobClient key;
        public WebApplication App; public Clock Clock; public readonly DateTimeOffset Start; public Capture Transport = new(); public SignalFaults Signals; public CommitFaults Faults = new(); public Connections Connections = new(); public bool KeysUnavailable;
        public string Address = "lookup-" + Guid.NewGuid().ToString("N") + "@example.invalid", Ip = "192.0.2.1";
        public EmailOptions Email => App.Services.GetRequiredService<EmailOptions>(); public WorkOptions Work => App.Services.GetRequiredService<WorkOptions>(); public LookupDeliveryOptions Limits => App.Services.GetRequiredService<LookupDeliveryOptions>();
        public Harness(SqlDatabaseFixture fixture) {
            // Each harness has a later UTC day, isolating global daily counters in the shared fixture database.
            Start = new DateTimeOffset(DateTimeOffset.UtcNow.UtcDateTime.Date, TimeSpan.Zero).AddDays(Interlocked.Increment(ref sequence) * 5); Clock = new(Start);
            var connection = Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!; var name = "lookup-test-" + Guid.NewGuid().ToString("N");
            queue = new(connection, name, new QueueClientOptions(QueueClientOptions.ServiceVersion.V2023_11_03));
            var blobs = new BlobServiceClient(connection, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)); hints = blobs.GetBlobContainerClient(name); key = blobs.GetBlobContainerClient("keys").GetBlobClient(name + ".xml");
            Assert.True(queue.Uri.IsLoopback && hints.Uri.IsLoopback);
            Signals = new(new AzureWorkSignals(queue, hints, new() { Enabled = true, QueueName = name, HintContainer = name }, true));
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(EmailOptions).Assembly.FullName, ContentRootPath = AppContext.BaseDirectory, EnvironmentName = "Development" }); builder.Logging.ClearProviders();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> {
                ["Storage:Provider"]="Azurite",["Storage:ConnectionString"]=connection,["DataProtection:ApplicationName"]=name,["DataProtection:KeyRingBlobName"]=name+".xml",
                ["Work:Enabled"]="true",["Work:QueueName"]=name,["Work:HintContainer"]=name,["Email:Enabled"]="true",["Email:Provider"]="Smtp",
                ["Email:FromEmail"]="noreply@example.invalid",["Email:BaseUrl"]="https://example.invalid/",["Email:Smtp:Host"]="127.0.0.1",["Email:Smtp:UseStartTls"]="false" });
            using var source = fixture.Open(); var database = source.Database.GetConnectionString();
            builder.Services.AddDbContext<QuillSignDbContext>(o => o.UseSqlServer(database).AddInterceptors(Connections, Faults, Faults.Commands));
            builder.Services.AddRazorPages(); builder.Services.AddQuillSignStorage(builder.Configuration, builder.Environment); builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment); builder.Services.AddQuillSignWork(builder.Configuration, builder.Environment);
            builder.Services.AddSingleton<TimeProvider>(Clock); builder.Services.AddSingleton<IWorkSignals>(Signals); builder.Services.AddScoped<Func<IEmailTransport>>(_ => () => Transport);
            builder.Services.AddScoped(sp => new LookupDeliveryProtection(KeysUnavailable ? new UnavailableKeys(sp.GetRequiredService<IDataProtectionProvider>()) : sp.GetRequiredService<IDataProtectionProvider>())); App = builder.Build();
        }
        public async Task<LookupRequestOutcome> Request(Guid id, string? address = null, string? ip = null) { using var scope = App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<DocumentLookupRequests>().RequestAsync(id, address ?? Address, ip ?? Ip); }
        public IQueryable<AuthToken> Tokens(QuillSignDbContext db) => db.AuthTokens.Where(x => x.Purpose == TokenPurpose.Lookup && x.ExpiresAt >= Start && x.ExpiresAt < Start.AddDays(5));
        public async Task<bool> Once() { using var scope = App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<WorkProcessor>().RunOnceAsync(default); }
        public async Task Suppress() { using var scope = App.Services.CreateScope(); var db = scope.ServiceProvider.GetRequiredService<QuillSignDbContext>(); db.Suppressions.Add(new() { Email = Address, Reason = SuppressionReason.Complaint }); await db.SaveChangesAsync(); }
        public async ValueTask DisposeAsync() { await App.DisposeAsync(); await queue.DeleteIfExistsAsync(); await hints.DeleteIfExistsAsync(); await key.DeleteIfExistsAsync(); }
    }
    private sealed class Clock(DateTimeOffset start) : TimeProvider { private DateTimeOffset now = start; public override DateTimeOffset GetUtcNow() => now; public void Advance(TimeSpan span) => now += span; }
    private sealed class Capture : IEmailTransport {
        public int Calls; public OutgoingEmail? Last; public Exception? Failure; public Func<OutgoingEmail,Task>? BeforeSend;
        public async Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken ct) { Calls++; Last = message; if (BeforeSend is not null) await BeforeSend(message); if (Failure is not null) throw Failure; return new("Smtp", "synthetic-" + Guid.NewGuid().ToString("N")); }
    }
    private sealed class Connections : DbConnectionInterceptor { public int Opens; public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection c, ConnectionEventData e, InterceptionResult result, CancellationToken ct = default) { Opens++; return ValueTask.FromResult(result); } }
    private sealed class CommitFaults : DbTransactionInterceptor, ISaveChangesInterceptor {
        public string Mode = ""; private bool armed, issued; public readonly CommandFault Commands; public Func<Task>? AfterIssue;
        public CommitFaults() => Commands = new(this);
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e, InterceptionResult<int> result, CancellationToken ct = default) {
            if (Mode.StartsWith("request-") && e.Context!.ChangeTracker.Entries<EmailOutbox>().Any(x => x.State == EntityState.Added)) armed = true;
            if (Mode == "issue-lost" && e.Context!.ChangeTracker.Entries<AuthToken>().Any(x => x.State == EntityState.Added)) armed = true;
            if (AfterIssue is not null && e.Context!.ChangeTracker.Entries<AuthToken>().Any(x => x.State == EntityState.Added)) issued = true;
            return ValueTask.FromResult(result);
        }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction tx, TransactionEventData e, InterceptionResult result, CancellationToken ct = default) { if (armed && Mode.EndsWith("rejected")) { armed = false; throw new IOException("Synthetic rejected commit."); } return ValueTask.FromResult(result); }
        public override async Task TransactionCommittedAsync(DbTransaction tx, TransactionEndEventData e, CancellationToken ct = default) { if (issued && AfterIssue is { } callback) { issued = false; AfterIssue = null; await callback(); } if (armed && Mode.EndsWith("lost")) { armed = false; throw new IOException("Synthetic lost commit acknowledgement."); } }
        public sealed class CommandFault(CommitFaults owner) : DbCommandInterceptor { public override ValueTask<int> NonQueryExecutedAsync(DbCommand c, CommandExecutedEventData e, int result, CancellationToken ct = default) { if (owner.Mode.StartsWith("intent-") && c.CommandText.Contains("EmailOutbox") && c.CommandText.Contains("SubmissionStartedAt") && c.CommandText.Contains("PayloadJson")) owner.armed = true; if (owner.Mode == "receipt-lost" && c.CommandText.Contains("UPDATE") && c.CommandText.Contains("ProviderMessageId")) owner.armed = true; return ValueTask.FromResult(result); } }
    }
    private sealed class UnavailableKeys(IDataProtectionProvider inner) : IDataProtectionProvider {
        public IDataProtector CreateProtector(string purpose) => new Unavailable(inner.CreateProtector(purpose));
        private sealed class Unavailable(IDataProtector inner) : IDataProtector { public IDataProtector CreateProtector(string purpose) => new Unavailable(inner.CreateProtector(purpose)); public byte[] Protect(byte[] data) => inner.Protect(data); public byte[] Unprotect(byte[] data) => throw new CryptographicException("Synthetic missing lookup key."); }
    }
    private sealed class SignalFaults(IWorkSignals inner) : IWorkSignals {
        public int Puts; public bool FailHint;
        public async Task PutHintAsync(Guid id, DateTimeOffset at, CancellationToken ct) { Interlocked.Increment(ref Puts); await inner.PutHintAsync(id, at, ct); if (FailHint) throw new IOException("Synthetic hint response loss."); }
        public Task RemoveHintAsync(Guid id, CancellationToken ct) => inner.RemoveHintAsync(id, ct);
        public Task<DateTimeOffset?> ReadDueAsync(Guid id, CancellationToken ct) => inner.ReadDueAsync(id, ct);
        public Task PublishAsync(Guid id, TimeSpan delay, CancellationToken ct) => inner.PublishAsync(id, delay, ct);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct) => inner.ReceiveAsync(ct);
        public Task DeferAsync(WorkDelivery d, TimeSpan delay, CancellationToken ct) => inner.DeferAsync(d, delay, ct);
        public Task AcknowledgeAsync(WorkDelivery d, CancellationToken ct) => inner.AcknowledgeAsync(d, ct);
        public Task<int> RecoverAsync(DateTimeOffset at, CancellationToken ct) => inner.RecoverAsync(at, ct);
        public Task VerifyAsync(CancellationToken ct) => inner.VerifyAsync(ct);
    }
}

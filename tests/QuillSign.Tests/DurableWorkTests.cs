using System.Data.Common;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class DurableWorkTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Delayed_verification_activates_only_at_dispatch_and_duplicate_wakeups_do_not_resend()
    {
        await using var run = new Harness(fixture);
        var queuedAt = run.Clock.GetUtcNow();
        var id = await run.EnqueueAsync();
        await using (var db = fixture.Open())
        {
            Assert.False(await db.AuthTokens.AnyAsync(x => x.EnvelopeId == run.EnvelopeId));
            var email = await db.EmailOutbox.SingleAsync(x => x.Id == id);
            using var scope = run.App.Services.CreateScope();
            var payload = scope.ServiceProvider.GetRequiredService<EmailPayloadProtection>();
            var token = payload.Unprotect(email.PayloadJson).Token;
            Assert.DoesNotContain(token, email.PayloadJson);
            Assert.DoesNotContain(token, (await db.WorkItems.SingleAsync(x => x.Id == id)).PayloadJson);
        }
        run.Clock.Advance(TimeSpan.FromHours(3));
        Assert.True(await run.OnceAsync());
        Assert.Equal(1, run.Sender.Calls);
        Assert.Contains("token=", run.Sender.Last!.Text);
        await using (var db = fixture.Open())
        {
            var token = await db.AuthTokens.SingleAsync(x => x.EnvelopeId == run.EnvelopeId);
            Assert.Equal(run.Clock.GetUtcNow().AddMinutes(15), token.ExpiresAt);
            Assert.True(token.ExpiresAt > queuedAt.AddHours(3));
            Assert.Equal(EmailStatus.Sent, (await db.EmailOutbox.SingleAsync(x => x.Id == id)).Status);
            Assert.Equal(WorkStatus.Completed, (await db.WorkItems.SingleAsync(x => x.Id == id)).Status);
        }
        await run.Signals.PublishAsync(id, TimeSpan.Zero, default);
        Assert.True(await run.OnceAsync());
        Assert.Equal(1, run.Sender.Calls);
    }

    [Fact]
    public async Task Lost_queue_publication_is_recovered_from_hint_without_sql_polling()
    {
        await using var run = new Harness(fixture);
        run.Signals.FailPublish = true;
        var id = await run.EnqueueAsync(expectedPublished: false);
        Assert.False(await run.OnceAsync());
        run.Signals.FailPublish = false;
        Assert.Equal(1, await run.Signals.RecoverAsync(run.Clock.GetUtcNow(), default));
        Assert.True(await run.OnceAsync());
        Assert.Equal(1, run.Sender.Calls);
        Assert.Equal(0, await run.Signals.RecoverAsync(run.Clock.GetUtcNow(), default));
    }

    [Fact]
    public async Task Hint_failure_rolls_back_sql_and_orphan_hint_from_rollback_is_safe()
    {
        await using var run = new Harness(fixture);
        run.Signals.FailAfterHint = true;
        await Assert.ThrowsAsync<IOException>(() => run.EnqueueAsync());
        await using var db = fixture.Open();
        Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == run.EnvelopeId));
        Assert.False(await db.WorkItems.AnyAsync(x => x.EnvelopeId == run.EnvelopeId));
        run.Signals.FailAfterHint = false;
        Assert.Equal(1, await run.Signals.RecoverAsync(run.Clock.GetUtcNow(), default));
        Assert.True(await run.OnceAsync());
        Assert.Equal(0, run.Sender.Calls);
        Assert.Equal(0, await run.Signals.RecoverAsync(run.Clock.GetUtcNow(), default));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Locked_existence_check_waits_for_pending_insert_before_classifying_hint(bool commit)
    {
        await using var db = fixture.Open();
        var id = Guid.NewGuid();
        await using var transaction = await db.Database.BeginTransactionAsync();
        db.WorkItems.Add(new() { Id = id, Kind = WorkKind.Purge });
        await db.SaveChangesAsync();
        await using var contender = fixture.Open();
        var claiming = new WorkStore(contender, new(), TimeProvider.System).ClaimAsync(id, default);
        await Task.Delay(200);
        Assert.False(claiming.IsCompleted);
        if (commit) await transaction.CommitAsync(); else await transaction.RollbackAsync();
        var result = await claiming;
        Assert.Equal(!commit, result.Terminal);
        Assert.Equal(commit, result.Lease is not null);
    }

    [Fact]
    public async Task Competing_workers_have_one_owner_and_stale_owner_cannot_finish()
    {
        var id = Guid.NewGuid();
        await using (var seed = fixture.Open())
        { seed.WorkItems.Add(new() { Id = id, Kind = WorkKind.Purge }); await seed.SaveChangesAsync(); }
        var clock = new TestClock();
        var tasks = Enumerable.Range(0, 8).Select(async _ =>
        {
            await using var db = fixture.Open();
            return await new WorkStore(db, new(), clock).ClaimAsync(id, default);
        });
        var claims = await Task.WhenAll(tasks);
        var lease = Assert.Single(claims, x => x.Lease is not null).Lease!;
        clock.Advance(TimeSpan.FromSeconds(301));
        await using var other = fixture.Open();
        var store = new WorkStore(other, new(), clock);
        var recovered = (await store.ClaimAsync(id, default)).Lease!;
        Assert.NotEqual(lease.Owner, recovered.Owner);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.FinishAsync(lease, new(WorkOutcome.Completed), default));
        await store.FinishAsync(recovered, new(WorkOutcome.Completed), default);
    }

    [Fact]
    public async Task Definite_rejection_retries_with_backoff_and_reactivates_token()
    {
        await using var run = new Harness(fixture);
        var id = await run.EnqueueAsync();
        run.Sender.Failure = new EmailNotSubmittedException(true);
        Assert.True(await run.OnceAsync());
        await using (var db = fixture.Open())
        {
            var work = await db.WorkItems.SingleAsync(x => x.Id == id);
            Assert.Equal(WorkStatus.Queued, work.Status);
            Assert.Equal(run.Clock.GetUtcNow().AddSeconds(15), work.AvailableAt);
            Assert.Null((await db.EmailOutbox.SingleAsync(x => x.Id == id)).SubmissionStartedAt);
            Assert.Equal(run.Clock.GetUtcNow(), (await db.AuthTokens.SingleAsync(x => x.EnvelopeId == run.EnvelopeId)).ExpiresAt);
        }
        run.Clock.Advance(TimeSpan.FromSeconds(16));
        run.Sender.Failure = null;
        // Delayed Azure visibility is real time; an additional duplicate wakeup is fine.
        await run.Signals.PublishAsync(id, TimeSpan.Zero, default);
        await run.OnceAsync();
        Assert.Equal(2, run.Sender.Calls);
        await using var final = fixture.Open();
        Assert.Equal(EmailStatus.Sent, (await final.EmailOutbox.SingleAsync(x => x.Id == id)).Status);
        Assert.Equal(run.Clock.GetUtcNow().AddMinutes(15), (await final.AuthTokens.SingleAsync(x => x.EnvelopeId == run.EnvelopeId)).ExpiresAt);
    }

    [Fact]
    public async Task Ambiguous_provider_failure_is_never_automatically_resubmitted_after_lease_expiry()
    {
        await using var run = new Harness(fixture);
        var id = await run.EnqueueAsync();
        run.Sender.Failure = new IOException("Synthetic failure after possible acceptance.");
        await Assert.ThrowsAsync<IOException>(() => run.OnceAsync());
        run.Clock.Advance(TimeSpan.FromSeconds(301));
        run.Sender.Failure = null;
        await run.Signals.PublishAsync(id, TimeSpan.Zero, default);
        await run.OnceAsync();
        Assert.Equal(1, run.Sender.Calls);
        await using var db = fixture.Open();
        var row = await db.WorkItems.SingleAsync(x => x.Id == id);
        Assert.Equal(WorkStatus.Failed, row.Status);
        Assert.Equal("submission-ambiguous", row.LastError);
    }

    [Fact]
    public async Task Crash_after_receipt_or_before_queue_ack_does_not_resend()
    {
        await using var run = new Harness(fixture);
        var id = await run.EnqueueAsync();
        run.Signals.FailAcknowledge = true;
        await Assert.ThrowsAsync<IOException>(() => run.OnceAsync());
        run.Signals.FailAcknowledge = false;
        await run.Signals.PublishAsync(id, TimeSpan.Zero, default);
        await run.OnceAsync();
        Assert.Equal(1, run.Sender.Calls);
        await using var db = fixture.Open();
        Assert.Equal(WorkStatus.Completed, (await db.WorkItems.SingleAsync(x => x.Id == id)).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Crash_before_submission_retries_but_crash_after_saved_receipt_does_not_resend(bool receiptSaved)
    {
        await using var run = new Harness(fixture);
        var id = await run.EnqueueAsync();
        await using (var scope = run.App.Services.CreateAsyncScope())
        {
            var lease = (await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(id, default)).Lease!;
            if (receiptSaved)
            {
                var handler = Assert.Single(scope.ServiceProvider.GetServices<IWorkHandler>());
                Assert.Equal(WorkOutcome.Completed, (await handler.ExecuteAsync(lease, default)).Outcome);
            }
            // Simulate process death without finishing its lease or acknowledging work.
        }
        run.Clock.Advance(TimeSpan.FromSeconds(301));
        await run.OnceAsync();
        Assert.Equal(1, run.Sender.Calls);
        await using var db = fixture.Open();
        Assert.Equal(WorkStatus.Completed, (await db.WorkItems.SingleAsync(x => x.Id == id)).Status);
    }

    [Fact]
    public async Task Payload_survives_key_provider_restart_and_rejects_tampering_or_wrong_purpose()
    {
        var connection = Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;
        var name = "payload-" + Guid.NewGuid().ToString("N");
        var settings = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Storage:Provider"] = "Azurite", ["Storage:ConnectionString"] = connection,
            ["DataProtection:ApplicationName"] = name, ["DataProtection:KeyRingBlobName"] = name + ".xml"
        }).Build();
        using var app = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" }).Build();
        ServiceProvider Provider()
        {
            var services = new ServiceCollection(); services.AddLogging();
            services.AddQuillSignStorage(settings, app.Environment);
            return services.BuildServiceProvider();
        }
        var original = new VerificationPayload(new string('a', 43), Guid.NewGuid());
        try
        {
            string protectedValue;
            using (var first = Provider()) protectedValue = new EmailPayloadProtection(first.GetRequiredService<IDataProtectionProvider>()).Protect(original);
            using var restarted = Provider();
            var protection = new EmailPayloadProtection(restarted.GetRequiredService<IDataProtectionProvider>());
            Assert.Equal(original, protection.Unprotect(protectedValue));
            var wrapper = System.Text.Json.JsonSerializer.Deserialize<ProtectedWorkPayload>(protectedValue)!;
            var wrong = restarted.GetRequiredService<IDataProtectionProvider>().CreateProtector("WrongPurpose").Protect("synthetic");
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => protection.Unprotect(System.Text.Json.JsonSerializer.Serialize(wrapper with { Protected = wrong })));
        }
        finally
        {
            var blobs = new BlobServiceClient(connection, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
            await blobs.GetBlobContainerClient("keys").GetBlobClient(name + ".xml").DeleteIfExistsAsync();
        }
    }

    [Fact]
    public async Task Suppressed_recipient_fails_without_provider_call_or_active_token()
    {
        await using var run = new Harness(fixture);
        var id = await run.EnqueueAsync();
        await using (var db = fixture.Open())
        { db.Suppressions.Add(new() { Email = run.Recipient, Reason = SuppressionReason.Complaint }); await db.SaveChangesAsync(); }
        await run.OnceAsync();
        Assert.Equal(0, run.Sender.Calls);
        await using var final = fixture.Open();
        Assert.Equal(EmailStatus.Failed, (await final.EmailOutbox.SingleAsync(x => x.Id == id)).Status);
        Assert.False(await final.AuthTokens.AnyAsync(x => x.EnvelopeId == run.EnvelopeId));
    }

    [Fact]
    public async Task Retry_exhaustion_is_terminal_and_empty_queue_does_not_connect_to_sql()
    {
        await using var run = new Harness(fixture, maximumAttempts: 1);
        Assert.False(await run.OnceAsync());
        Assert.Equal(0, run.Connections.Opens);
        var id = await run.EnqueueAsync();
        run.Sender.Failure = new EmailNotSubmittedException(true);
        await run.OnceAsync();
        await using var db = fixture.Open();
        var item = await db.WorkItems.SingleAsync(x => x.Id == id);
        Assert.Equal(WorkStatus.Failed, item.Status);
        Assert.Equal("attempts-exhausted", item.LastError);
    }

    [Fact]
    public async Task Durable_worker_delivers_actual_verification_email_to_local_mailpit()
    {
        await using var run = new Harness(fixture, realSmtp: true);
        var id = await run.EnqueueAsync();
        Assert.True(await run.OnceAsync());
        await using var db = fixture.Open();
        var row = await db.EmailOutbox.SingleAsync(x => x.Id == id);
        Assert.Equal(EmailStatus.Sent, row.Status);
        Assert.Equal("Smtp", row.Provider);
        Assert.False(string.IsNullOrWhiteSpace(row.ProviderMessageId));
        var port = int.Parse(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT")!);
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}") };
        using var list = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync("/api/v1/messages"));
        var captured = Assert.Single(list.RootElement.GetProperty("messages").EnumerateArray(),
            item => item.GetProperty("To").EnumerateArray().Any(to => to.GetProperty("Address").GetString() == run.Recipient));
        using var detail = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/" + captured.GetProperty("ID").GetString()));
        Assert.Contains("/sender/verify?token=", detail.RootElement.GetProperty("Text").GetString());
        Assert.Contains("Verify your email and continue", detail.RootElement.GetProperty("HTML").GetString());
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqlDatabaseFixture fixture;
        private readonly QueueClient queue;
        private readonly BlobContainerClient hints;
        private readonly BlobClient keyBlob;
        public WebApplication App { get; }
        public TestClock Clock { get; } = new();
        public FakeSender Sender { get; } = new();
        public FaultSignals Signals { get; }
        public ConnectionCounter Connections { get; } = new();
        public Guid EnvelopeId { get; } = Guid.NewGuid();
        public string Recipient { get; } = "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid";

        public Harness(SqlDatabaseFixture fixture, int maximumAttempts = 5, bool realSmtp = false)
        {
            this.fixture = fixture;
            var connection = Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;
            var name = "worktest-" + Guid.NewGuid().ToString("N");
            var options = new WorkOptions { Enabled = true, QueueName = name, HintContainer = name, MaximumAttempts = maximumAttempts };
            queue = new QueueClient(connection, name, new QueueClientOptions(QueueClientOptions.ServiceVersion.V2023_11_03));
            var blobs = new BlobServiceClient(connection, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
            hints = blobs.GetBlobContainerClient(name);
            keyBlob = blobs.GetBlobContainerClient("keys").GetBlobClient(name + ".xml");
            Signals = new(new AzureWorkSignals(queue, hints, options, true));
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            { ApplicationName = typeof(EmailOptions).Assembly.FullName, ContentRootPath = AppContext.BaseDirectory, EnvironmentName = "Development" });
            builder.Logging.ClearProviders();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Storage:Provider"] = "Azurite", ["Storage:ConnectionString"] = connection,
                ["DataProtection:ApplicationName"] = name, ["DataProtection:KeyRingBlobName"] = name + ".xml",
                ["Work:Enabled"] = "true", ["Work:QueueName"] = name, ["Work:HintContainer"] = name,
                ["Work:MaximumAttempts"] = maximumAttempts.ToString(),
                ["Email:Enabled"] = "true", ["Email:Provider"] = "Smtp", ["Email:FromEmail"] = "noreply@example.invalid",
                ["Email:BaseUrl"] = "https://example.invalid/", ["Email:Smtp:Host"] = "127.0.0.1", ["Email:Smtp:UseStartTls"] = "false",
                ["Email:Smtp:Port"] = Environment.GetEnvironmentVariable("QUILLSIGN_TEST_SMTP_PORT")
            });
            using var source = fixture.Open();
            var database = source.Database.GetDbConnection().ConnectionString;
            builder.Services.AddDbContext<QuillSignDbContext>(db => db.UseSqlServer(database).AddInterceptors(Connections));
            builder.Services.AddRazorPages();
            builder.Services.AddQuillSignStorage(builder.Configuration, builder.Environment);
            builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
            builder.Services.AddQuillSignWork(builder.Configuration, builder.Environment);
            builder.Services.AddSingleton<TimeProvider>(Clock);
            builder.Services.AddSingleton<IWorkSignals>(Signals);
            if (!realSmtp) builder.Services.AddScoped<IEmailSender>(_ => Sender);
            App = builder.Build();
        }

        public async Task<Guid> EnqueueAsync(bool expectedPublished = true)
        {
            await using (var db = fixture.Open())
            {
                if (!await db.Envelopes.AnyAsync(x => x.Id == EnvelopeId))
                { db.Envelopes.Add(new() { Id = EnvelopeId, SenderEmail = Recipient }); await db.SaveChangesAsync(); }
            }
            await using var scope = App.Services.CreateAsyncScope();
            var queued = await scope.ServiceProvider.GetRequiredService<EmailOutboxWriter>().EnqueueVerificationAsync(EnvelopeId, Recipient);
            Assert.Equal(expectedPublished, queued.WakeupPublished);
            return queued.Id;
        }

        public async Task<bool> OnceAsync()
        {
            await using var scope = App.Services.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<WorkProcessor>().RunOnceAsync(default);
        }

        public async ValueTask DisposeAsync()
        {
            await App.DisposeAsync();
            await queue.DeleteIfExistsAsync();
            await hints.DeleteIfExistsAsync();
            await keyBlob.DeleteIfExistsAsync();
        }
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan duration) => now += duration;
    }
    private sealed class FakeSender : IEmailSender
    {
        public int Calls { get; private set; }
        public OutgoingEmail? Last { get; private set; }
        public Exception? Failure { get; set; }
        public Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken = default)
        {
            Calls++; Last = message;
            if (Failure is not null) throw Failure;
            return Task.FromResult(new EmailDelivery("Smtp", "synthetic-receipt"));
        }
    }
    private sealed class ConnectionCounter : DbConnectionInterceptor
    {
        public int Opens { get; private set; }
        public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection connection, ConnectionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        { Opens++; return base.ConnectionOpeningAsync(connection, eventData, result, cancellationToken); }
    }
    private sealed class FaultSignals(IWorkSignals inner) : IWorkSignals
    {
        public bool FailPublish { get; set; }
        public bool FailAfterHint { get; set; }
        public bool FailAcknowledge { get; set; }
        public async Task PutHintAsync(Guid id, DateTimeOffset due, CancellationToken ct)
        { await inner.PutHintAsync(id, due, ct); if (FailAfterHint) throw new IOException("Synthetic hint response loss."); }
        public Task PublishAsync(Guid id, TimeSpan delay, CancellationToken ct)
            => FailPublish ? throw new IOException("Synthetic publication failure.") : inner.PublishAsync(id, delay, ct);
        public Task AcknowledgeAsync(WorkDelivery delivery, CancellationToken ct)
            => FailAcknowledge ? throw new IOException("Synthetic acknowledgement failure.") : inner.AcknowledgeAsync(delivery, ct);
        public Task RemoveHintAsync(Guid id, CancellationToken ct) => inner.RemoveHintAsync(id, ct);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct) => inner.ReceiveAsync(ct);
        public Task DeferAsync(WorkDelivery delivery, TimeSpan delay, CancellationToken ct) => inner.DeferAsync(delivery, delay, ct);
        public Task<int> RecoverAsync(DateTimeOffset now, CancellationToken ct) => inner.RecoverAsync(now, ct);
        public Task VerifyAsync(CancellationToken ct) => inner.VerifyAsync(ct);
    }
}

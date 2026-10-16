using System.Collections.Concurrent;
using System.Data.Common;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class SenderWorkflowTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private static string Address() => "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid";

    [Fact]
    public async Task Request_and_dispatch_protect_token_and_concurrent_verification_has_one_winner_with_valid_audit_chain()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var email = Address();
        Assert.Equal(SenderRequestOutcome.Neutral, await run.RequestAsync(" " + email.ToUpperInvariant() + " "));
        Guid envelopeId;
        await using (var db = fixture.Open())
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.SenderEmail == email);
            envelopeId = envelope.Id;
            Assert.Null(envelope.SenderVerifiedAt);
            Assert.False(await db.AuthTokens.AnyAsync(x => x.EnvelopeId == envelopeId));
            var row = await db.EmailOutbox.SingleAsync(x => x.EnvelopeId == envelopeId);
            using var scope = run.App.Services.CreateScope();
            var payload = scope.ServiceProvider.GetRequiredService<EmailPayloadProtection>().Unprotect(row.PayloadJson);
            Assert.DoesNotContain(payload.Token, row.PayloadJson);
            Assert.DoesNotContain(payload.Token, (await db.WorkItems.SingleAsync(x => x.Id == row.Id)).PayloadJson);
        }
        run.Clock.Advance(TimeSpan.FromHours(3));
        var token = await run.DispatchAsync();
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => run.VerifyAsync(token)));
        var sender = Assert.Single(results, x => x is not null)!;
        Assert.Equal(envelopeId, sender.EnvelopeId);
        Assert.Equal(email, sender.Email);
        Assert.Null(await run.VerifyAsync(token));
        await using var inspect = fixture.Open();
        var record = await inspect.AuthTokens.SingleAsync(x => x.EnvelopeId == envelopeId);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(token)), record.TokenSha256);
        Assert.Equal(run.Clock.GetUtcNow().AddMinutes(15), record.ExpiresAt);
        Assert.Equal(run.Clock.GetUtcNow(), record.UsedAt);
        var events = await inspect.AuditEvents.Where(x => x.EnvelopeId == envelopeId).OrderBy(x => x.Sequence).ToListAsync();
        Assert.Equal(new[] { "draft_created", "sender_verification_requested", "sender_email_verified" }, events.Select(x => x.Event));
        for (var i = 0; i < events.Count; i++)
        {
            Assert.Equal(i + 1, events[i].Sequence);
            Assert.Equal(i == 0 ? null : events[i - 1].Hash, events[i].PrevHash);
            Assert.Equal(AuditHash.Compute(events[i]), events[i].Hash);
            Assert.Equal(email, events[i].ActorEmail);
            Assert.Equal("127.0.0.1", events[i].Ip);
        }
    }

    [Fact]
    public async Task Verification_audit_failure_rolls_back_token_consumption_and_sender_verification()
    {
        await using var run = await Harness.CreateAsync(fixture);
        await run.RequestAsync(Address());
        var token = await run.DispatchAsync();
        run.AuditFailure.Enabled = true;
        var failure = await Assert.ThrowsAsync<DbUpdateException>(() => run.VerifyAsync(token));
        Assert.IsType<IOException>(failure.InnerException);
        await using (var db = fixture.Open())
        {
            var record = await db.AuthTokens.SingleAsync(x => x.TokenSha256 == SHA256.HashData(Encoding.UTF8.GetBytes(token)));
            Assert.Null(record.UsedAt);
            Assert.Null((await db.Envelopes.SingleAsync(x => x.Id == record.EnvelopeId)).SenderVerifiedAt);
        }
        run.AuditFailure.Enabled = false;
        Assert.NotNull(await run.VerifyAsync(token));
    }

    [Fact]
    public async Task Daily_cap_serializes_concurrent_case_variants_and_resets_at_utc_midnight()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var email = Address();
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 10).Select(i => run.RequestAsync(i % 2 == 0 ? email.ToUpperInvariant() : email)));
        Assert.All(outcomes, x => Assert.Equal(SenderRequestOutcome.Neutral, x));
        await using var db = fixture.Open();
        Assert.Equal(5, await db.Envelopes.CountAsync(x => x.SenderEmail == email));
        Assert.Equal(5, await db.EmailOutbox.CountAsync(x => x.To == email));
        run.Clock.Advance(TimeSpan.FromDays(1));
        await run.RequestAsync(email);
        Assert.Equal(6, await db.Envelopes.CountAsync(x => x.SenderEmail == email));
    }

    [Fact]
    public async Task Hint_failure_rolls_back_draft_audit_and_outbox_while_publication_failure_remains_recoverable()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var failed = Address();
        run.Signals.FailHint = true;
        await Assert.ThrowsAsync<IOException>(() => run.RequestAsync(failed));
        await using var db = fixture.Open();
        Assert.False(await db.Envelopes.AnyAsync(x => x.SenderEmail == failed));
        Assert.False(await db.AuditEvents.AnyAsync(x => x.ActorEmail == failed));
        Assert.False(await db.EmailOutbox.AnyAsync(x => x.To == failed));
        run.Signals.FailHint = false;
        run.Signals.FailPublish = true;
        var accepted = Address();
        Assert.Equal(SenderRequestOutcome.Neutral, await run.RequestAsync(accepted));
        Assert.True(await db.EmailOutbox.AnyAsync(x => x.To == accepted));
        run.Signals.FailPublish = false;
        await run.Signals.RecoverAsync(run.Clock.GetUtcNow(), default);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", await run.DispatchAsync());
    }

    [Fact]
    public async Task Suppression_returns_same_neutral_response_without_creating_draft()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var email = Address();
        await using var db = fixture.Open();
        db.Suppressions.Add(new() { Email = email, Reason = SuppressionReason.Complaint });
        await db.SaveChangesAsync();
        Assert.Equal(SenderRequestOutcome.Neutral, await run.RequestAsync(email));
        Assert.False(await db.Envelopes.AnyAsync(x => x.SenderEmail == email));
        Assert.False(await db.EmailOutbox.AnyAsync(x => x.To == email));
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("used")]
    [InlineData("purpose")]
    [InlineData("party")]
    [InlineData("email")]
    [InlineData("envelope")]
    [InlineData("verified")]
    [InlineData("status")]
    public async Task Invalid_token_scope_or_state_never_creates_verification(string reason)
    {
        await using var run = await Harness.CreateAsync(fixture);
        await run.RequestAsync(Address());
        var token = await run.DispatchAsync();
        await using var db = fixture.Open();
        var record = await db.AuthTokens.SingleAsync(x => x.TokenSha256 == SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        var envelope = await db.Envelopes.SingleAsync(x => x.Id == record.EnvelopeId);
        switch (reason)
        {
            case "expired": record.ExpiresAt = run.Clock.GetUtcNow(); break;
            case "used": record.UsedAt = run.Clock.GetUtcNow(); break;
            case "purpose": record.Purpose = TokenPurpose.SenderStatus; break;
            case "party": record.PartyType = PartyType.Recipient; break;
            case "email": record.Email = Address(); break;
            case "envelope":
                var other = new Envelope { SenderEmail = Address() };
                db.Envelopes.Add(other);
                record.EnvelopeId = other.Id;
                break;
            case "verified": envelope.SenderVerifiedAt = run.Clock.GetUtcNow(); break;
            case "status": envelope.Status = EnvelopeStatus.Voided; break;
        }
        await db.SaveChangesAsync();
        Assert.Null(await run.VerifyAsync(token));
        Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == envelope.Id && x.Event == "sender_email_verified"));
    }

    [Fact]
    public async Task Browser_antiforgery_notices_cookie_scope_replay_restart_and_expiry_work_together()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var browser = new Browser(run.App);
        using (var forbidden = await browser.Client.PostAsync("/", new FormUrlEncodedContent(new Dictionary<string, string> { ["Email"] = Address() })))
            Assert.Equal(HttpStatusCode.BadRequest, forbidden.StatusCode);
        var email = Address();
        using (var sent = await browser.SubmitAsync(email))
        {
            Assert.Equal(HttpStatusCode.Redirect, sent.StatusCode);
            Assert.Equal("/", sent.Headers.Location!.OriginalString);
            Assert.Contains(sent.Headers.GetValues("Set-Cookie"), x => x.StartsWith("QuillSign.Notice=") && x.Contains("httponly", StringComparison.OrdinalIgnoreCase));
        }
        Assert.Contains("Check your inbox", await browser.GetTextAsync("/"));
        Assert.DoesNotContain("Check your inbox", await browser.GetTextAsync("/"));
        var token = await run.DispatchAsync();
        string draft;
        using (var verified = await browser.GetAsync("/sender/verify?token=" + token))
        {
            Assert.Equal(HttpStatusCode.Redirect, verified.StatusCode);
            draft = verified.Headers.Location!.OriginalString;
            Assert.StartsWith("/draft/", draft);
            Assert.DoesNotContain("?", draft);
            Assert.True(verified.Headers.CacheControl!.NoStore);
            Assert.Contains(verified.Headers.GetValues("Set-Cookie"), x => x.StartsWith("QuillSign.Sender=") && x.Contains("httponly", StringComparison.OrdinalIgnoreCase) && x.Contains("samesite=lax", StringComparison.OrdinalIgnoreCase));
        }
        Assert.Contains(email, await browser.GetTextAsync(draft));
        using (var other = await browser.GetAsync("/draft/" + Guid.NewGuid().ToString("N"))) Assert.Equal(HttpStatusCode.NotFound, other.StatusCode);
        using (var replay = await new Browser(run.App).GetAsync("/sender/verify?token=" + token))
        {
            Assert.Equal("/", replay.Headers.Location!.OriginalString);
            Assert.DoesNotContain(replay.Headers.GetValues("Set-Cookie"), x => x.StartsWith("QuillSign.Sender="));
        }
        // A fresh app instance using the shared key ring accepts the existing scoped ticket.
        await using var replica = await Harness.CreateAsync(fixture, shared: run);
        var restarted = new Browser(replica.App, browser.Cookies);
        Assert.Contains(email, await restarted.GetTextAsync(draft));
        var tampered = new Browser(replica.App, browser.Cookies.Replace("QuillSign.Sender=", "QuillSign.Sender=x"));
        using (var rejected = await tampered.GetAsync(draft)) Assert.Equal("/", rejected.Headers.Location!.OriginalString);
        run.Clock.Advance(TimeSpan.FromHours(1));
        Assert.Contains(email, await browser.GetTextAsync(draft));
        run.Clock.Advance(TimeSpan.FromHours(1).Add(TimeSpan.FromSeconds(1)));
        using (var expired = await browser.GetAsync(draft)) Assert.Equal("/", expired.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Json_responses_are_neutral_invalid_input_is_rejected_and_no_notice_is_written()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var browser = new Browser(run.App);
        using (var bad = await browser.SubmitAsync("bad address", json: true)) Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        var email = Address();
        using var first = await browser.SubmitAsync(email, json: true);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var message = await first.Content.ReadAsStringAsync();
        Assert.DoesNotContain(first.Headers.TryGetValues("Set-Cookie", out var values) ? values : [], x => x.StartsWith("QuillSign.Notice="));
        await using (var db = fixture.Open())
        { db.Suppressions.Add(new() { Email = email, Reason = SuppressionReason.Complaint }); await db.SaveChangesAsync(); }
        using var blocked = await browser.SubmitAsync(email, json: true);
        Assert.Equal(message, await blocked.Content.ReadAsStringAsync());
        using var unknown = await browser.GetAsync("/sender/verify?token=" + new string('a', 43), json: true);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        using var unauthenticated = await browser.GetAsync("/draft/unknown", json: true);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
    }

    [Fact]
    public async Task Rate_limit_applies_after_unlimited_get_and_ignores_untrusted_forwarded_addresses()
    {
        await using var run = await Harness.CreateAsync(fixture, limit: 2);
        var browser = new Browser(run.App);
        await browser.GetTextAsync("/");
        for (var i = 0; i < 2; i++)
        {
            browser.Client.DefaultRequestHeaders.Remove("X-Forwarded-For");
            browser.Client.DefaultRequestHeaders.Add("X-Forwarded-For", "192.0.2." + (i + 1));
            using var accepted = await browser.SubmitAsync(Address());
            Assert.Equal(HttpStatusCode.Redirect, accepted.StatusCode);
        }
        browser.Client.DefaultRequestHeaders.Remove("X-Forwarded-For");
        browser.Client.DefaultRequestHeaders.Add("X-Forwarded-For", "192.0.2.99");
        using var limited = await browser.SubmitAsync(Address());
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        using var page = await browser.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
    }

    [Fact]
    public async Task Unconfigured_bootstrap_and_disabled_sending_never_resolve_sql_or_queue()
    {
        await using var run = await Harness.CreateAsync(fixture, bootstrap: true);
        var browser = new Browser(run.App);
        Assert.Contains("Email delivery is currently unavailable", await browser.GetTextAsync("/"));
        using var invalid = await browser.GetAsync("/sender/verify?token=bad");
        Assert.Equal("/", invalid.Headers.Location!.OriginalString);
    }

    private sealed class Harness : IAsyncDisposable
    {
        public WebApplication App { get; private set; } = null!;
        public Clock Clock { get; private init; } = new();
        public Signals Signals { get; } = new();
        public FailAudit AuditFailure { get; } = new();
        private readonly CaptureSender sender = new();
        private readonly string name = "sender-" + Guid.NewGuid().ToString("N");
        private BlobClient? key;
        private bool ownsKey;

        public static async Task<Harness> CreateAsync(SqlDatabaseFixture fixture, int limit = 100, bool bootstrap = false, Harness? shared = null)
        {
            var run = new Harness { Clock = shared?.Clock ?? new() };
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            { ApplicationName = typeof(SenderWorkflow).Assembly.FullName, ContentRootPath = AppContext.BaseDirectory, EnvironmentName = "Development" });
            builder.Logging.ClearProviders();
            builder.WebHost.UseTestServer();
            using var source = fixture.Open();
            var database = source.Database.GetDbConnection().ConnectionString;
            var storage = Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;
            var name = shared?.name ?? run.name;
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Database"] = bootstrap ? "" : database,
                ["Storage:Provider"] = bootstrap ? "" : "Azurite", ["Storage:ConnectionString"] = storage,
                ["DataProtection:ApplicationName"] = name, ["DataProtection:KeyRingBlobName"] = name + ".xml",
                ["Work:Enabled"] = (!bootstrap).ToString(), ["Work:QueueName"] = name, ["Work:HintContainer"] = name,
                ["Email:Enabled"] = (!bootstrap).ToString(), ["Email:Provider"] = "Smtp", ["Email:FromEmail"] = "noreply@example.invalid",
                ["Email:BaseUrl"] = "https://example.invalid/", ["Sender:RequestsPerWindow"] = limit.ToString(), ["CONTAINER_APP_NAME"] = "",
                ["Email:Smtp:Host"] = "127.0.0.1", ["Email:Smtp:Port"] = "1025", ["Email:Smtp:UseStartTls"] = "false"
            });
            builder.Services.AddRazorPages();
            builder.Services.AddScoped<QuillSignDbContext>(_ => bootstrap ? throw new InvalidOperationException("Bootstrap must not resolve SQL.") :
                new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(database).AddInterceptors(run.AuditFailure).Options));
            builder.Services.AddQuillSignStorage(builder.Configuration, builder.Environment);
            builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
            builder.Services.AddQuillSignWork(builder.Configuration, builder.Environment);
            builder.Services.AddQuillSignSender(builder.Configuration, builder.Environment);
            builder.Services.AddSingleton<TimeProvider>(run.Clock);
            builder.Services.AddSingleton<IWorkSignals>(run.Signals);
            builder.Services.AddSingleton<IEmailSender>(run.sender);
            run.App = builder.Build();
            run.App.UseForwardedHeaders();
            run.App.UseRouting(); run.App.UseRateLimiter(); run.App.UseAuthentication(); run.App.UseAuthorization();
            run.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
            await run.App.StartAsync();
            if (!bootstrap)
            {
                run.key = new BlobServiceClient(storage, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03))
                    .GetBlobContainerClient("keys").GetBlobClient(name + ".xml");
                run.ownsKey = shared is null;
            }
            return run;
        }

        public async Task<SenderRequestOutcome> RequestAsync(string email)
        {
            await using var scope = App.Services.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<SenderWorkflow>().RequestAsync(email, "127.0.0.1", "Synthetic browser");
        }
        public async Task<VerifiedSender?> VerifyAsync(string token)
        {
            await using var scope = App.Services.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<SenderWorkflow>().VerifyAsync(token, "127.0.0.1", "Synthetic browser");
        }
        public async Task<string> DispatchAsync()
        {
            await using var scope = App.Services.CreateAsyncScope();
            // An orphan rollback hint may precede the real work.
            while (await scope.ServiceProvider.GetRequiredService<WorkProcessor>().RunOnceAsync(default)) { }
            return Regex.Match(sender.Last!.Text, @"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        }
        public async ValueTask DisposeAsync()
        { await App.DisposeAsync(); if (ownsKey && key is not null) await key.DeleteIfExistsAsync(); }
    }

    private sealed class Browser
    {
        public HttpClient Client { get; }
        private readonly Dictionary<string, string> cookies = [];
        public string Cookies => string.Join("; ", cookies.Select(x => x.Key + "=" + x.Value));
        public Browser(WebApplication app, string? initialCookies = null)
        {
            Client = app.GetTestClient();
            if (initialCookies is not null) foreach (var pair in initialCookies.Split("; ")) Save(pair);
        }
        private void Save(string pair)
        { var split = pair.IndexOf('='); if (split > 0) cookies[pair[..split]] = pair[(split + 1)..]; }
        private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, bool json = false)
        {
            if (Cookies.Length > 0) request.Headers.Add("Cookie", Cookies);
            if (json) request.Headers.Add("Accept", "application/json");
            var response = await Client.SendAsync(request);
            if (response.Headers.TryGetValues("Set-Cookie", out var values)) foreach (var value in values) Save(value.Split(';')[0]);
            return response;
        }
        public Task<HttpResponseMessage> GetAsync(string path, bool json = false) => SendAsync(new(HttpMethod.Get, path), json);
        public async Task<string> GetTextAsync(string path)
        { using var response = await GetAsync(path); Assert.Equal(HttpStatusCode.OK, response.StatusCode); return await response.Content.ReadAsStringAsync(); }
        public async Task<HttpResponseMessage> SubmitAsync(string email, bool json = false)
        {
            var page = await GetTextAsync("/");
            var antiforgery = WebUtility.HtmlDecode(Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
            Assert.NotEmpty(antiforgery);
            return await SendAsync(new(HttpMethod.Post, "/") { Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["Email"] = email, ["__RequestVerificationToken"] = antiforgery }) }, json);
        }
    }
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan span) => now += span;
    }
    private sealed class FailAudit : DbCommandInterceptor
    {
        public bool Enabled { get; set; }
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (Enabled && command.CommandText.Contains("INSERT INTO [AuditEvents]", StringComparison.Ordinal))
            {
                await result.DisposeAsync();
                throw new IOException("Synthetic loss after audit write.");
            }
            return await base.ReaderExecutedAsync(command, eventData, result, cancellationToken);
        }
    }
    private sealed class CaptureSender : IEmailSender
    {
        public OutgoingEmail? Last { get; private set; }
        public Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken = default)
        { Last = message; return Task.FromResult(new EmailDelivery("Smtp", Guid.NewGuid().ToString("N"))); }
    }
    private sealed class Signals : IWorkSignals
    {
        private readonly ConcurrentQueue<WorkDelivery> queue = new();
        private readonly ConcurrentDictionary<Guid, DateTimeOffset> hints = new();
        public bool FailHint { get; set; }
        public bool FailPublish { get; set; }
        public Task PutHintAsync(Guid id, DateTimeOffset due, CancellationToken ct)
        { hints[id] = due; if (FailHint) throw new IOException("Synthetic hint failure."); return Task.CompletedTask; }
        public Task RemoveHintAsync(Guid id, CancellationToken ct) { hints.TryRemove(id, out _); return Task.CompletedTask; }
        public Task PublishAsync(Guid id, TimeSpan delay, CancellationToken ct)
        { if (FailPublish) throw new IOException("Synthetic publication failure."); queue.Enqueue(new(id.ToString(), "receipt", id)); return Task.CompletedTask; }
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct) => Task.FromResult(queue.TryDequeue(out var item) ? item : null);
        public Task DeferAsync(WorkDelivery delivery, TimeSpan delay, CancellationToken ct) => Task.CompletedTask;
        public Task AcknowledgeAsync(WorkDelivery delivery, CancellationToken ct) => Task.CompletedTask;
        public async Task<int> RecoverAsync(DateTimeOffset now, CancellationToken ct)
        { foreach (var id in hints.Keys) await PublishAsync(id, TimeSpan.Zero, ct); return hints.Count; }
        public Task VerifyAsync(CancellationToken ct) => Task.CompletedTask;
    }
}

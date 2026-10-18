using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class LookupRequestPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("email")][InlineData("work")][InlineData("retention")][InlineData("enabled")]
    public async Task Scanner_GETs_and_gated_POSTs_never_resolve_a_private_request_backend_or_query_membership(string gate)
    {
        await using var h = await Harness.Create(fixture); h.RejectBackend = true;
        if (gate == "email") h.Email.Enabled = false;
        if (gate == "work") h.Work.Enabled = false;
        if (gate == "retention") h.Retention.Days = null;
        var page = await h.Page("/find/request?email=" + Uri.EscapeDataString(h.Address) + "&code=SYNTHETIC_PRIVATE_CODE");
        Assert.Contains("Find your completed documents", page); Assert.DoesNotContain(h.Address, page); Assert.DoesNotContain("SYNTHETIC_PRIVATE_CODE", page);
        Assert.Equal(gate == "enabled", page.Contains("Email me a lookup link")); Assert.Contains("/find/access", page);
        if (gate != "enabled") {
            using var post = await h.Post("/find/request", new() { ["Email"] = h.Address }, json: true);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, post.StatusCode); Private(post);
        }
        Assert.Equal(0, h.Backends); Assert.Equal(0, h.Connections.Opens); Assert.Equal(0, h.SignalResolutions); Assert.Equal(0, h.TransportResolutions);
    }

    [Fact]
    public async Task Home_and_access_entry_offer_discoverable_links_to_the_public_request_page()
    {
        await using var h = await Harness.Create(fixture);
        Assert.Contains("href=\"/find/request\"", await h.Page("/"));
        Assert.Contains("href=\"/find/request\"", await h.Page("/find/access")); Assert.Equal(0, h.Backends); Assert.Equal(0, h.Connections.Opens);
    }

    [Theory]
    [InlineData("")][InlineData("invalid")][InlineData("one@example.invalid, two@example.invalid")][InlineData("\r\nbcc:other@example.invalid")]
    public async Task Invalid_addresses_and_query_only_input_never_reach_the_request_backend(string address)
    {
        await using var h = await Harness.Create(fixture); h.RejectBackend = true;
        using var response = await h.Post("/find/request", new() { ["Email"] = address }, json: true);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Private(response);
        using var query = await h.Post("/find/request?Email=" + Uri.EscapeDataString(h.Address), new(), json: true);
        Assert.Equal(HttpStatusCode.BadRequest, query.StatusCode); Assert.Equal(0, h.Backends); Assert.Equal(0, h.Connections.Opens);
    }

    [Fact]
    public async Task Oversized_addresses_and_missing_trusted_IP_are_rejected_before_backend_resolution()
    {
        await using var h = await Harness.Create(fixture); h.RejectBackend = true;
        using var tooLong = await h.Post("/find/request", new() { ["Email"] = new string('a', 310) + "@example.invalid" }, json: true);
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
        h.Ip = null; using var noIp = await h.Post("/find/request", new() { ["Email"] = h.Address }, json: true);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, noIp.StatusCode); Assert.Equal(0, h.Backends); Assert.Equal(0, h.Connections.Opens);
    }

    [Fact]
    public async Task CSRF_is_required_and_the_request_partition_does_not_spend_access_code_entry_limits()
    {
        await using var h = await Harness.Create(fixture, requestsPerWindow: 1);
        using var noCsrf = await h.Post("/find/request", new() { ["Email"] = h.Address }, csrf: false, json: true);
        Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode); Assert.Equal(0, h.Backends); Private(noCsrf);
        // A separate IP gets one request permit; rejected CSRF attempts also count.
        h.Ip = IPAddress.Parse("192.0.2.62");
        using var first = await h.Post("/find/request", new() { ["Email"] = h.Address }, json: true); Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var second = await h.Post("/find/request", new() { ["Email"] = h.Address }, json: false);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode); Private(second); Assert.Contains("href=\"/find/request\"", await second.Content.ReadAsStringAsync());
        using var access = await h.Post("/find/access/Begin", new() { ["code"] = "invalid" });
        Assert.Equal(HttpStatusCode.BadRequest, access.StatusCode); Assert.Equal(1, h.Backends);
    }

    [Fact]
    public async Task Neutral_request_returns_no_authority_and_uses_a_clean_redirect_with_a_single_use_private_notice()
    {
        await using var h = await Harness.Create(fixture); var supplied = Guid.NewGuid();
        using var post = await h.Post("/find/request", new() { ["Email"] = "  " + h.Address + "  ", ["requestId"] = supplied.ToString("N") });
        Assert.Equal(HttpStatusCode.Redirect, post.StatusCode); Assert.Equal("/find/request", post.Headers.Location?.OriginalString); Private(post);
        var cookie = Assert.Single(post.Headers.GetValues("Set-Cookie"), x => x.StartsWith("QuillSign.Notice="));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase); Assert.Contains("max-age=120", cookie, StringComparison.OrdinalIgnoreCase); Assert.DoesNotContain(h.Address, cookie);
        var page = await h.Page("/find/request"); Assert.Contains(BrowserNotices.Text(NoticeCode.LookupRequested), WebUtility.HtmlDecode(page)); Assert.DoesNotContain(h.Address, page);
        Assert.DoesNotContain(BrowserNotices.Text(NoticeCode.LookupRequested), WebUtility.HtmlDecode(await h.Page("/find/request")));
        Assert.DoesNotContain(DocumentLookupBrowser.ReceiptCookie, h.Cookies.Keys); Assert.DoesNotContain("QuillSign.DocumentLookup", h.Cookies.Keys);
        await using var db = fixture.Open(); var email = await db.EmailOutbox.SingleAsync(x => x.To == h.Address);
        Assert.NotEqual(supplied, email.Id); Assert.NotNull(await db.LookupContactRetentionSnapshots.SingleOrDefaultAsync(x => x.RequestId == email.Id));
        Assert.False(await h.Tokens(db).AnyAsync()); Assert.Equal(0, h.Commands.MembershipReads); Assert.Equal(0, h.TransportResolutions);
        Assert.Contains("lookup-contact-purge-v1", (await db.WorkItems.SingleAsync(x => x.Id == LookupContactRetention.WorkId(email.Id))).PayloadJson);
    }

    [Theory]
    [InlineData("suppressed")][InlineData("address")][InlineData("ip")][InlineData("global")]
    public async Task Unknown_suppressed_and_capped_addresses_get_the_same_neutral_anonymous_message(string cap)
    {
        await using var h = await Harness.Create(fixture);
        using var normal = await h.Post("/find/request", new() { ["Email"] = h.Address }, json: true);
        var neutral = await normal.Content.ReadAsStringAsync(); Assert.Equal(HttpStatusCode.OK, normal.StatusCode); Assert.DoesNotContain(h.Address, neutral);
        var next = cap == "address" ? h.Address : "blocked-" + Guid.NewGuid().ToString("N") + "@example.invalid";
        if (cap == "suppressed") { await using var db = fixture.Open(); db.Suppressions.Add(new() { Email = next, Reason = SuppressionReason.Complaint }); await db.SaveChangesAsync(); }
        if (cap == "address") h.Limits.DailyAddressRequests = 1;
        if (cap == "ip") h.Limits.DailyIpRequests = 1;
        if (cap == "global") h.Limits.DailyRequests = h.Limits.DailyIpRequests = h.Limits.DailyAddressRequests = 1;
        using var blocked = await h.Post("/find/request", new() { ["Email"] = next }, json: true);
        Assert.Equal(HttpStatusCode.OK, blocked.StatusCode); Assert.Equal(neutral, await blocked.Content.ReadAsStringAsync()); Private(blocked);
        await using var check = fixture.Open(); Assert.Equal(1, await check.EmailOutbox.CountAsync(x => x.AvailableAt == h.Start));
        Assert.Equal(0, h.Commands.MembershipReads); Assert.Equal(0, h.TransportResolutions);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Rejected_or_lost_admission_commit_reports_no_confirmed_send_and_refresh_never_repeats_the_action(bool lost)
    {
        await using var h = await Harness.Create(fixture); h.Fault.Mode = lost ? "lost" : "rejected";
        using var response = await h.Post("/find/request", new() { ["Email"] = h.Address }, json: true);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode); var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("couldn't confirm", body.Replace("\\u0027", "'")); Assert.DoesNotContain(h.Address, body); Private(response);
        h.Fault.Mode = ""; await h.Page("/find/request"); await h.Page("/find/request");
        await using var db = fixture.Open(); Assert.Equal(lost ? 1 : 0, await db.EmailOutbox.CountAsync(x => x.To == h.Address));
        Assert.Equal(1, h.Backends); Assert.Equal(0, h.TransportResolutions);
    }

    [Fact]
    public async Task An_empty_mailbox_receives_its_link_only_through_the_worker_then_explicitly_opens_an_empty_private_view()
    {
        await using var h = await Harness.Create(fixture);
        using var request = await h.Post("/find/request", new() { ["Email"] = h.Address }, json: true);
        Assert.Equal(HttpStatusCode.OK, request.StatusCode); Assert.Equal(0, h.TransportResolutions);
        Guid id; await using (var db = fixture.Open()) { id = (await db.EmailOutbox.SingleAsync(x => x.To == h.Address)).Id; Assert.False(await h.Tokens(db).AnyAsync()); }
        using (var scope = h.App.Services.CreateScope()) {
            var store = scope.ServiceProvider.GetRequiredService<WorkStore>(); var lease = (await store.ClaimAsync(id, default)).Lease!;
            var handler = scope.ServiceProvider.GetServices<IWorkHandler>().Single(x => x.Kind == WorkKind.Email); var result = await handler.ExecuteAsync(lease, default);
            Assert.Equal(WorkOutcome.Completed, result.Outcome); await store.FinishAsync(lease, result, default);
        }
        var code = Regex.Match(h.Capture.Last!.Text, @"#token=([A-Za-z0-9_-]+)").Groups[1].Value; Assert.NotEmpty(code);
        using (var begin = await h.Post("/find/access/Begin", new() { ["code"] = code })) Assert.Equal(HttpStatusCode.Redirect, begin.StatusCode);
        var page = await h.Page("/find/access"); var nonce = Regex.Match(page, "name=\"nonce\" value=\"([a-f0-9]{32})\"").Groups[1].Value;
        using (var redeem = await h.Post("/find/access/Redeem", new() { ["nonce"] = nonce })) Assert.Equal("/find/documents", redeem.Headers.Location?.OriginalString);
        var ticket = h.Cookies["QuillSign.DocumentLookup"]; var receipt = h.Cookies[DocumentLookupBrowser.ReceiptCookie];
        Assert.Contains("No retained completed documents are available", await h.Page("/find/documents"));
        using var another = await h.Post("/find/request", new() { ["Email"] = h.Address }, json: true);
        Assert.Equal(HttpStatusCode.OK, another.StatusCode); Assert.Equal(ticket, h.Cookies["QuillSign.DocumentLookup"]); Assert.Equal(receipt, h.Cookies[DocumentLookupBrowser.ReceiptCookie]);
        Assert.Contains("No retained completed documents are available", await h.Page("/find/documents"));
    }

    private static void Private(HttpResponseMessage response)
    {
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
    }
    private sealed class Harness : IAsyncDisposable
    {
        private static int sequence; private readonly QueueClient queue; private readonly BlobContainerClient hints;
        public WebApplication App = null!; public HttpClient Client = null!; public readonly Dictionary<string,string> Cookies = [];
        public readonly Connections Connections = new(); public readonly Commands Commands = new(); public readonly CommitFault Fault = new(); public readonly Capture Capture = new();
        public int Backends, SignalResolutions, TransportResolutions; public bool RejectBackend; public IPAddress? Ip = IPAddress.Parse("192.0.2.61");
        public readonly DateTimeOffset Start = new DateTimeOffset(DateTimeOffset.UtcNow.UtcDateTime.Date, TimeSpan.Zero).AddDays(Interlocked.Increment(ref sequence) * 5);
        public readonly string Address = "lookup-ui-" + Guid.NewGuid().ToString("N") + "@example.invalid";
        public EmailOptions Email => App.Services.GetRequiredService<EmailOptions>(); public WorkOptions Work => App.Services.GetRequiredService<WorkOptions>();
        public LookupDeliveryOptions Limits => App.Services.GetRequiredService<LookupDeliveryOptions>(); public LookupContactRetentionOptions Retention => App.Services.GetRequiredService<LookupContactRetentionOptions>();
        private Harness(string connection, string name) { queue = new(connection, name, new QueueClientOptions(QueueClientOptions.ServiceVersion.V2023_11_03)); hints = new BlobServiceClient(connection, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)).GetBlobContainerClient(name); }
        public static async Task<Harness> Create(SqlDatabaseFixture fixture, int requestsPerWindow = 20)
        {
            var connection = Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!; var name = "lookup-http-" + Guid.NewGuid().ToString("N"); var h = new Harness(connection, name);
            Assert.True(h.queue.Uri.IsLoopback && h.hints.Uri.IsLoopback);
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(DocumentLookup).Assembly.FullName, ContentRootPath = AppContext.BaseDirectory, EnvironmentName = "Development" });
            builder.Logging.ClearProviders(); builder.WebHost.UseTestServer();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> {
                ["Storage:Provider"]="Azurite",["Storage:ConnectionString"]=connection,["Work:Enabled"]="true",["Work:QueueName"]=name,["Work:HintContainer"]=name,
                ["Demo:PurgeAfterDays"]="7",["Email:Enabled"]="true",["Email:Provider"]="Smtp",["Email:FromEmail"]="noreply@example.invalid",["Email:BaseUrl"]="https://example.invalid",
                ["Email:Smtp:Host"]="127.0.0.1",["Email:Smtp:UseStartTls"]="false",["Sender:RequestsPerWindow"]=requestsPerWindow.ToString(System.Globalization.CultureInfo.InvariantCulture) });
            await using var source = fixture.Open(); var database = source.Database.GetConnectionString();
            builder.Services.AddDbContext<QuillSignDbContext>(o => o.UseSqlServer(database).AddInterceptors(h.Connections, h.Commands, h.Fault));
            builder.Services.AddRazorPages(); builder.Services.AddQuillSignStorage(builder.Configuration, builder.Environment); builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
            builder.Services.AddQuillSignWork(builder.Configuration, builder.Environment); builder.Services.AddQuillSignSender(builder.Configuration, builder.Environment); builder.Services.AddDocumentLookupBrowser(builder.Environment); builder.Services.AddCompletionReaderBrowser(builder.Environment);
            builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()); builder.Services.AddSingleton<TimeProvider>(new Clock(h.Start));
            builder.Services.AddSingleton<IWorkSignals>(_ => { h.SignalResolutions++; return new AzureWorkSignals(h.queue, h.hints, h.Work, true); });
            builder.Services.AddScoped<Func<DocumentLookupRequests>>(sp => () => { h.Backends++; if (h.RejectBackend) throw new InvalidOperationException("Synthetic private backend must remain lazy."); return sp.GetRequiredService<DocumentLookupRequests>(); });
            builder.Services.AddScoped<Func<IEmailTransport>>(_ => () => { h.TransportResolutions++; return h.Capture; });
            h.App = builder.Build(); h.App.Use((http, next) => { http.Connection.RemoteIpAddress = h.Ip; return next(); }); h.App.UseRouting(); h.App.UseDocumentLookupBrowser(); h.App.UseRateLimiter(); h.App.UseAuthentication(); h.App.UseAuthorization(); h.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
            await h.App.StartAsync(); h.Client = h.App.GetTestClient(); return h;
        }
        public IQueryable<AuthToken> Tokens(QuillSignDbContext db) => db.AuthTokens.Where(x => x.Purpose == TokenPurpose.Lookup && x.ExpiresAt >= Start && x.ExpiresAt < Start.AddDays(5));
        public async Task<string> Page(string path) { using var r = await Client.GetAsync(path); Take(r); Assert.Equal(HttpStatusCode.OK, r.StatusCode); if (path.StartsWith("/find")) Private(r); return await r.Content.ReadAsStringAsync(); }
        public async Task<HttpResponseMessage> Post(string path, Dictionary<string,string> fields, bool csrf = true, bool json = false) {
            if (csrf) fields["__RequestVerificationToken"] = SignaturePageTests.Browser.Token(await Page("/find/access"));
            using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new FormUrlEncodedContent(fields) }; if (json) request.Headers.Accept.ParseAdd("application/json");
            var r = await Client.SendAsync(request); Take(r); return r;
        }
        private void Take(HttpResponseMessage response) { if (response.Headers.TryGetValues("Set-Cookie", out var values)) foreach (var value in values) { var p = value.Split(';')[0].Split('=',2); if (p[1].Length == 0) Cookies.Remove(p[0]); else Cookies[p[0]] = p[1]; } Client.DefaultRequestHeaders.Remove("Cookie"); if (Cookies.Count > 0) Client.DefaultRequestHeaders.Add("Cookie", string.Join("; ", Cookies.Select(x => x.Key + "=" + x.Value))); }
        public async ValueTask DisposeAsync() { Client.Dispose(); await App.DisposeAsync(); await queue.DeleteIfExistsAsync(); await hints.DeleteIfExistsAsync(); }
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private sealed class Connections : DbConnectionInterceptor { public int Opens; public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection c, ConnectionEventData e, InterceptionResult r, CancellationToken ct = default) { Opens++; return ValueTask.FromResult(r); } }
    private sealed class Commands : DbCommandInterceptor { public int MembershipReads; public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand c, CommandEventData e, InterceptionResult<DbDataReader> r, CancellationToken ct = default) { if (c.CommandText.Contains("[Envelopes]")) MembershipReads++; return ValueTask.FromResult(r); } }
    private sealed class CommitFault : DbTransactionInterceptor, ISaveChangesInterceptor {
        public string Mode = ""; private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e, InterceptionResult<int> r, CancellationToken ct = default) { if (Mode != "" && e.Context!.ChangeTracker.Entries<EmailOutbox>().Any(x => x.State == EntityState.Added)) armed = true; return ValueTask.FromResult(r); }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction t, TransactionEventData e, InterceptionResult r, CancellationToken ct = default) { if (armed && Mode == "rejected") { armed = false; throw new IOException("Synthetic rejected admission."); } return ValueTask.FromResult(r); }
        public override Task TransactionCommittedAsync(DbTransaction t, TransactionEndEventData e, CancellationToken ct = default) { if (armed && Mode == "lost") { armed = false; throw new IOException("Synthetic lost admission acknowledgement."); } return Task.CompletedTask; }
    }
    private sealed class Capture : IEmailTransport { public OutgoingEmail? Last; public Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken ct) { Last = message; return Task.FromResult(new EmailDelivery("Smtp", "synthetic-" + Guid.NewGuid().ToString("N"))); } }
}

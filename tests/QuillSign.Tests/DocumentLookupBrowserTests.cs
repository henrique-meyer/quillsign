using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Sender;
using Flow = QuillSign.Tests.CompletionDownloadTests.Flow;

namespace QuillSign.Tests;

public sealed class DocumentLookupBrowserTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Scanner_GET_and_explicit_preparation_never_consume_links_or_disclose_proofs_and_only_confirmed_redemption_opens_a_private_list()
    {
        await using var f = await Create(); var link = await Issue(f); var before = await State(f);
        var page = await Get(f, "/find/access");
        Assert.DoesNotContain(link.Transport, page); Assert.DoesNotContain(f.Run.Signing.Envelope.SenderEmail, page);
        using (var noCsrf = await Post(f, "/find/access/Begin", page, new() { ["code"] = link.Transport }, false)) Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);
        Assert.Equal(before, await State(f));
        using (var begin = await Post(f, "/find/access/Begin", page, new() { ["code"] = link.Transport })) {
            Clean(begin, "/find/access"); Cookie(begin, DocumentLookupBrowser.PendingCookie, "/find/access");
        }
        page = await Get(f, "/find/access"); var nonce = Value(page, "nonce");
        Assert.DoesNotContain(link.Transport, page); Assert.Equal(before, await State(f));
        using (var noCsrf = await Post(f, "/find/access/Redeem", page, new() { ["nonce"] = nonce }, false)) Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);
        Assert.Equal(before, await State(f));
        using (var redeem = await Post(f, "/find/access/Redeem", page, new() { ["nonce"] = nonce })) {
            Clean(redeem, "/find/documents"); Cookie(redeem, DocumentLookupBrowser.ReceiptCookie, "/find");
            Assert.Contains("QuillSign.DocumentLookup", f.Cookies.Keys);
            Assert.DoesNotContain("QuillSign.CompletionReader", f.Cookies.Keys);
        }
        var saved = await State(f); Assert.NotEqual(before, saved);
        page = await Get(f, "/find/documents"); await Get(f, "/find/documents");
        Assert.Contains(f.Run.Signing.Envelope.Title!, page); Assert.Contains(f.PublicId, page);
        Assert.DoesNotContain(link.Transport, page); Assert.DoesNotContain(f.Cookies[DocumentLookupBrowser.ReceiptCookie], page);
        Assert.DoesNotContain(f.Run.Signing.Envelope.SenderEmail, page); Assert.Equal(saved, await State(f));
        Assert.Equal(2, f.Store.Writes); Assert.Equal(2, f.Run.Seal.Requests);
    }

    [Fact]
    public async Task Cross_tab_nonce_conflicts_preserve_new_pending_link_and_replays_never_replace_an_existing_session()
    {
        await using var f = await Create(); var first = await Prepare(f, await Issue(f));
        var next = await Prepare(f, await Issue(f));
        using (var conflict = await Post(f, "/find/access/Redeem", next, new() { ["nonce"] = Value(first, "nonce") })) {
            Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode); Private(conflict);
        }
        Assert.Equal(Value(next, "nonce"), Value(await Get(f, "/find/access"), "nonce"));
        using (var good = await Post(f, "/find/access/Redeem", next, new() { ["nonce"] = Value(next, "nonce") })) Clean(good, "/find/documents");
        var ticket = f.Cookies["QuillSign.DocumentLookup"]; var receipt = f.Cookies[DocumentLookupBrowser.ReceiptCookie];
        using var replay = await Post(f, "/find/access/Redeem", next, new() { ["nonce"] = Value(next, "nonce") });
        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode); Assert.Equal(ticket, f.Cookies["QuillSign.DocumentLookup"]);
        Assert.Equal(receipt, f.Cookies[DocumentLookupBrowser.ReceiptCookie]); await Get(f, "/find/documents");
    }

    [Theory]
    [InlineData("used")][InlineData("expired")][InlineData("completion")][InlineData("forged")]
    public async Task Used_expired_wrong_purpose_and_forged_links_issue_no_lookup_authority(string kind)
    {
        await using var f = await Create(); var link = await Issue(f); var code = link.Transport;
        if (kind == "used") { using var scope = f.App.Services.CreateScope(); Assert.NotNull(await scope.ServiceProvider.GetRequiredService<DocumentLookup>().RedeemAsync(code)); }
        if (kind == "expired") f.Clock.Advance(TimeSpan.FromMinutes(16));
        if (kind == "completion") { await using var db = fixture.Open(); code = (await CompletionAccessTests.Service(f, db).IssueAsync(f.Id, PartyType.Sender, null))!.RawToken; }
        if (kind == "forged") code += "x";
        var page = await Get(f, "/find/access");
        using var response = await Post(f, "/find/access/Begin", page, new() { ["code"] = code });
        Assert.DoesNotContain(code, await response.Content.ReadAsStringAsync());
        if (kind == "used") {
            Clean(response, "/find/access"); page = await Get(f, "/find/access");
            using var used = await Post(f, "/find/access/Redeem", page, new() { ["nonce"] = Value(page, "nonce") }); Assert.Equal(HttpStatusCode.BadRequest, used.StatusCode);
        } else Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("QuillSign.DocumentLookup", f.Cookies.Keys); Assert.DoesNotContain(DocumentLookupBrowser.ReceiptCookie, f.Cookies.Keys);
    }

    [Fact]
    public async Task Explicit_Open_requires_CSRF_owned_id_and_matching_receipt_then_downloads_the_exact_published_pair_without_extending_lookup()
    {
        await using var f = await Create(); await Open(f, await Issue(f)); var page = await Get(f, "/find/documents"); var before = await State(f);
        using (var csrf = await Post(f, "/find/documents/Open", page, new() { ["publicId"] = f.PublicId }, false)) Assert.Equal(HttpStatusCode.BadRequest, csrf.StatusCode);
        var reads = f.Store.Reads;
        foreach (var id in new[] { "../forged", Guid.NewGuid().ToString("N"), "" }) {
            using var bad = await Post(f, "/find/documents/Open", page, new() { ["publicId"] = id }); Assert.Equal(HttpStatusCode.NotFound, bad.StatusCode);
        }
        Assert.Equal(reads, f.Store.Reads); Assert.Equal(before, await State(f));
        f.Clock.Advance(TimeSpan.FromMinutes(20));
        using (var opened = await Post(f, "/find/documents/Open", page, new() { ["publicId"] = f.PublicId })) Clean(opened, "/complete/" + f.PublicId);
        var records = await Get(f, "/complete/" + f.PublicId);
        foreach (var kind in new[] { "executed", "certificate" }) {
            using var prepared = await Post(f, "/complete/" + f.PublicId + "?handler=Download", records, new() { ["kind"] = kind });
            Assert.Equal(HttpStatusCode.Redirect, prepared.StatusCode);
            using var file = await f.Client.GetAsync(prepared.Headers.Location); f.Take(file);
            Assert.Equal(HttpStatusCode.OK, file.StatusCode);
            Assert.Equal(kind == "executed" ? f.Published.ExecutedBytes : f.Published.CertificateBytes, await file.Content.ReadAsByteArrayAsync());
        }
        f.Clock.Advance(TimeSpan.FromMinutes(11));
        using (var expired = await f.Client.GetAsync("/find/documents")) { f.Take(expired); Clean(expired, "/find/access"); }
        Assert.Contains("expired or is unavailable", await Get(f, "/find/access"));
        Assert.DoesNotContain("expired or is unavailable", await Get(f, "/find/access"));
        using var narrow = await f.Client.GetAsync("/complete/" + f.PublicId); Assert.Equal(HttpStatusCode.NotFound, narrow.StatusCode);
    }

    [Theory]
    [InlineData("receipt")][InlineData("duplicate")][InlineData("ticket")][InlineData("sender")]
    public async Task Other_authority_or_mismatched_private_cookies_cannot_open_a_lookup_view(string fault)
    {
        await using var f = await Create(); await Open(f, await Issue(f));
        if (fault == "receipt") f.Set(DocumentLookupBrowser.ReceiptCookie, f.Cookies[DocumentLookupBrowser.ReceiptCookie] + "x");
        if (fault == "ticket") f.Set("QuillSign.DocumentLookup", null);
        if (fault == "sender") { f.Restore([]); await f.Session("sender"); }
        if (fault == "duplicate") f.Client.DefaultRequestHeaders.Add("Cookie", DocumentLookupBrowser.ReceiptCookie + "=" + f.Cookies[DocumentLookupBrowser.ReceiptCookie]);
        using var denied = await f.Client.GetAsync("/find/documents"); Clean(denied, "/find/access"); Assert.DoesNotContain(f.PublicId, await denied.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("missing")][InlineData("corrupt")][InlineData("source")][InlineData("retention")]
    public async Task Private_list_and_Open_handle_storage_source_and_retention_failures_without_new_files_or_authority(string fault)
    {
        await using var f = await Create(); await Open(f, await Issue(f)); var page = await Get(f, "/find/documents");
        if (fault is "missing" or "corrupt") f.Store.Fault = fault;
        if (fault == "source") { await using var db = fixture.Open(); await db.Recipients.Where(x => x.EnvelopeId == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Name, "Altered synthetic recipient")); }
        if (fault == "retention") { await using var db = fixture.Open(); await db.Envelopes.Where(x => x.Id == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PurgeAfter, f.Clock.GetUtcNow())); }
        using (var bad = await Post(f, "/find/documents/Open", page, new() { ["publicId"] = f.PublicId })) {
            Assert.Contains(bad.StatusCode, new[] { HttpStatusCode.NotFound, HttpStatusCode.ServiceUnavailable }); Private(bad);
            Assert.DoesNotContain("QuillSign.CompletionReader", f.Cookies.Keys); Assert.DoesNotContain("Stack Trace", await bad.Content.ReadAsStringAsync());
        }
        using (var badList = await f.Client.GetAsync("/find/documents")) {
            Assert.Contains(badList.StatusCode, new[] { HttpStatusCode.OK, HttpStatusCode.ServiceUnavailable });
            Assert.DoesNotContain(f.PublicId, await badList.Content.ReadAsStringAsync()); Private(badList);
        }
        if (fault is "missing" or "corrupt") { f.Store.Fault = null; page = await Get(f, "/find/documents"); using var recovered = await Post(f, "/find/documents/Open", page, new() { ["publicId"] = f.PublicId }); Clean(recovered, "/complete/" + f.PublicId); }
        Assert.Equal(2, f.Store.Writes); Assert.Equal(2, f.Run.Seal.Requests);
    }

    [Fact]
    public async Task Real_publications_page_by_private_cookie_and_reset_cleanly_while_cross_session_cursors_fail_closed()
    {
        var mailbox = "lookup-browser-" + Guid.NewGuid().ToString("N") + "@example.invalid";
        await using var f = await Create(mailbox); await using var other = await Flow.Create(fixture, mailbox: mailbox);
        Connect(f, other); f.App.Services.GetRequiredService<DocumentLookupOptions>().PageSize = 1;
        await Open(f, await Issue(f)); var first = await Get(f, "/find/documents"); var cursor = Value(first, "cursor"); var firstId = Value(first, "publicId");
        using (var csrf = await Post(f, "/find/documents/Next", first, new() { ["cursor"] = cursor }, false)) Assert.Equal(HttpStatusCode.BadRequest, csrf.StatusCode);
        using (var next = await Post(f, "/find/documents/Next", first, new() { ["cursor"] = cursor })) { Clean(next, "/find/documents"); Cookie(next, DocumentLookupBrowser.PageCookie, "/find/documents"); }
        var second = await Get(f, "/find/documents"); Assert.NotEqual(firstId, Value(second, "publicId")); Assert.DoesNotContain("name=\"cursor\"", second);
        using (var reset = await Post(f, "/find/documents/First", second, [])) Clean(reset, "/find/documents");
        Assert.Equal(firstId, Value(await Get(f, "/find/documents"), "publicId"));
        await Open(f, await Issue(f)); first = await Get(f, "/find/documents");
        using var stale = await Post(f, "/find/documents/Next", first, new() { ["cursor"] = cursor }); Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        f.Set(DocumentLookupBrowser.PageCookie, cursor); using var staleGet = await f.Client.GetAsync("/find/documents"); Assert.Equal(HttpStatusCode.Conflict, staleGet.StatusCode);
    }

    [Fact]
    public async Task Entry_rate_limits_and_antiforgery_errors_are_private_and_never_reflect_a_code()
    {
        await using var f = await Flow.Create(fixture, completionReaders: true, lookupBrowser: true); f.App.Services.GetRequiredService<SenderOptions>().RequestsPerWindow = 1;
        var page = await Get(f, "/find/access");
        using (var csrf = await Post(f, "/find/access/Begin", page, new() { ["code"] = "not-a-code" }, false)) { Assert.Equal(HttpStatusCode.BadRequest, csrf.StatusCode); Private(csrf); }
        using var limited = await Post(f, "/find/access/Begin", page, new() { ["code"] = "do-not-reflect" });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode); Private(limited); Assert.DoesNotContain("do-not-reflect", await limited.Content.ReadAsStringAsync());
    }

    private async Task<Flow> Create(string? mailbox = null) { var f = await Flow.Create(fixture, completionReaders: true, lookupBrowser: true, mailbox: mailbox); f.App.Services.GetRequiredService<SenderOptions>().RequestsPerWindow = 1000; return f; }
    private static async Task<DocumentLookupLink> Issue(Flow f, string? email = null) { using var scope = f.App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<DocumentLookup>().IssueAsync(email ?? f.Run.Signing.Envelope.SenderEmail); }
    private static async Task<string> Prepare(Flow f, DocumentLookupLink link) { var page = await Get(f, "/find/access"); using var begin = await Post(f, "/find/access/Begin", page, new() { ["code"] = link.Transport }); Clean(begin, "/find/access"); return await Get(f, "/find/access"); }
    private static async Task Open(Flow f, DocumentLookupLink link) { var page = await Prepare(f, link); using var response = await Post(f, "/find/access/Redeem", page, new() { ["nonce"] = Value(page, "nonce") }); Clean(response, "/find/documents"); }
    private async Task<string> State(Flow f) { await using var db = fixture.Open(); return System.Text.Json.JsonSerializer.Serialize(new { Tokens = await db.AuthTokens.OrderBy(x => x.Id).Select(x => new { x.Id, x.UsedAt, x.RowVersion }).ToArrayAsync(), Counts = await f.Run.Counts() }); }
    private static async Task<string> Get(Flow f, string path) { using var r = await f.Client.GetAsync(path); f.Take(r); var body = await r.Content.ReadAsStringAsync(); Assert.True(r.StatusCode == HttpStatusCode.OK, $"{path}: {r.StatusCode}: {body[..Math.Min(body.Length, 600)]}"); Private(r); return body; }
    private static async Task<HttpResponseMessage> Post(Flow f, string path, string page, Dictionary<string,string> values, bool csrf = true) { if (csrf) values["__RequestVerificationToken"] = SignaturePageTests.Browser.Token(page); var r = await f.Client.PostAsync(path, new FormUrlEncodedContent(values)); f.Take(r); return r; }
    private static string Value(string html, string name) { var match = Regex.Match(html, "name=\"" + name + "\"[^>]*value=\"([^\"]*)\""); Assert.True(match.Success, "Missing " + name); return WebUtility.HtmlDecode(match.Groups[1].Value); }
    private static void Private(HttpResponseMessage r) { Assert.True(r.Headers.CacheControl?.NoStore); Assert.Contains("no-referrer", r.Headers.GetValues("Referrer-Policy")); }
    private static void Clean(HttpResponseMessage r, string path) { Assert.Equal(HttpStatusCode.Redirect, r.StatusCode); Assert.Equal(path, r.Headers.Location?.OriginalString); Private(r); }
    private static void Cookie(HttpResponseMessage r, string name, string path) { var value = Assert.Single(r.Headers.GetValues("Set-Cookie"), x => x.StartsWith(name + "=", StringComparison.Ordinal)); Assert.Contains("httponly", value, StringComparison.OrdinalIgnoreCase); Assert.Contains("samesite=strict", value, StringComparison.OrdinalIgnoreCase); Assert.Contains("path=" + path, value); }
    private static void Connect(Flow f, Flow other) { f.Clock.Advance(new[] { f.Clock.GetUtcNow(), other.Clock.GetUtcNow() }.Max() - f.Clock.GetUtcNow()); f.Run.Seal.Options.TsaTrustedRootPaths = [.. f.Run.Seal.Options.TsaTrustedRootPaths, .. other.Run.Seal.Options.TsaTrustedRootPaths]; f.Store.Other = other.Store; }

    // Test-only loopback host with genuine completed synthetic packets and captured local TSA.
    public sealed class BrowserSession : IAsyncDisposable
    {
        private readonly Flow flow, other;
        private BrowserSession(Flow flow, Flow other) { this.flow = flow; this.other = other; }
        public string Url => flow.Client.BaseAddress!.ToString().TrimEnd('/');
        public string PublicId => flow.PublicId;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture, int port) {
            var mailbox = "lookup-browser-" + Guid.NewGuid().ToString("N") + "@example.invalid";
            var flow = await Flow.Create(fixture, completionReaders: true, lookupBrowser: true, mailbox: mailbox, browserPort: port);
            var other = await Flow.Create(fixture, mailbox: mailbox); Connect(flow, other); flow.App.Services.GetRequiredService<DocumentLookupOptions>().PageSize = 1;
            flow.App.Services.GetRequiredService<SenderOptions>().RequestsPerWindow = 1000; return new(flow, other);
        }
        public async Task<string> Link(bool empty = false) => Url + "/find/access#token=" + (await Issue(flow, empty ? "empty@example.invalid" : null)).Transport;
        public void Fault(bool missing) => flow.Store.Fault = missing ? "missing" : null;
        public void Expire() => flow.Clock.Advance(TimeSpan.FromHours(2));
        public async ValueTask DisposeAsync() { await other.DisposeAsync(); await flow.DisposeAsync(); }
    }
}

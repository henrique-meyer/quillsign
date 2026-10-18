using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Work;
using Flow = QuillSign.Tests.CompletionDownloadTests.Flow;
using Reader = QuillSign.Tests.CompletionReaderPageTests;

namespace QuillSign.Tests;

public sealed class LookupRequestPacketTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Public_request_through_captured_SMTP_and_explicit_lookup_opens_both_exact_completed_files()
    {
        await using var f = await Flow.Create(fixture, completionReaders: true, completionNotifications: true, lookupBrowser: true,
            requestIp: "198.51.100.19", mailbox: "request-packet-" + Guid.NewGuid().ToString("N") + "@example.invalid");
        var page = await Reader.Get(f, "/find/request");
        using (var request = await Reader.Post(f, "/find/request", page, new() { ["Email"] = f.Run.Signing.Envelope.SenderEmail })) {
            Assert.Equal(HttpStatusCode.Redirect, request.StatusCode); Assert.Equal("/find/request", request.Headers.Location?.OriginalString);
        }
        page = await Reader.Get(f, "/find/request"); Assert.Contains(BrowserNotices.Text(NoticeCode.LookupRequested), WebUtility.HtmlDecode(page));
        Assert.DoesNotContain(f.Run.Signing.Envelope.SenderEmail, page); Assert.DoesNotContain(f.PublicId, page);
        await Dispatch(f); var mail = await Captured(f); var code = Regex.Match(mail.Text, @"#token=([A-Za-z0-9_-]+)").Groups[1].Value; Assert.NotEmpty(code);
        page = await Reader.Get(f, "/find/access");
        using (var begin = await Reader.Post(f, "/find/access/Begin", page, new() { ["code"] = code })) Assert.Equal("/find/access", begin.Headers.Location?.OriginalString);
        page = await Reader.Get(f, "/find/access"); var nonce = Regex.Match(page, "name=\"nonce\" value=\"([a-f0-9]{32})\"").Groups[1].Value;
        using (var redeem = await Reader.Post(f, "/find/access/Redeem", page, new() { ["nonce"] = nonce })) Assert.Equal("/find/documents", redeem.Headers.Location?.OriginalString);
        page = await Reader.Get(f, "/find/documents"); Assert.Contains(f.PublicId, page);
        using (var open = await Reader.Post(f, "/find/documents/Open", page, new() { ["publicId"] = f.PublicId })) Assert.Equal("/complete/" + f.PublicId, open.Headers.Location?.OriginalString);
        page = await Reader.Get(f, "/complete/" + f.PublicId);
        foreach (var kind in new[] { "executed", "certificate" }) {
            using var prepare = await Reader.Download(f, page, kind); Assert.Equal(HttpStatusCode.Redirect, prepare.StatusCode);
            using var download = await f.Client.GetAsync(prepare.Headers.Location); Assert.Equal(HttpStatusCode.OK, download.StatusCode);
            Assert.Equal(kind == "executed" ? f.Published.ExecutedBytes : f.Published.CertificateBytes, await download.Content.ReadAsByteArrayAsync());
        }
        Assert.Equal(2, f.Run.Seal.Requests); Assert.Equal(2, f.Store.Writes);
    }

    private static async Task Dispatch(Flow f)
    {
        using var scope = f.App.Services.CreateScope(); var db = scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
        var id = (await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Template == LookupDeliveryProtection.Template && x.To == f.Run.Signing.Envelope.SenderEmail && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null)).Id;
        var store = scope.ServiceProvider.GetRequiredService<WorkStore>(); var lease = (await store.ClaimAsync(id, default)).Lease!;
        var handler = scope.ServiceProvider.GetServices<IWorkHandler>().Single(x => x.Kind == WorkKind.Email);
        var result = await handler.ExecuteAsync(lease, default); Assert.Equal(WorkOutcome.Completed, result.Outcome); await store.FinishAsync(lease, result, default);
    }
    private sealed record Mail(string Id, string Text);
    private static async Task<Mail> Captured(Flow f, IReadOnlySet<string>? seen = null)
    {
        using var http = new HttpClient { BaseAddress = new("http://127.0.0.1:" + Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT")) };
        using var found = JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query=" + Uri.EscapeDataString("to:" + f.Run.Signing.Envelope.SenderEmail)));
        var message = Assert.Single(found.RootElement.GetProperty("messages").EnumerateArray(), x => x.GetProperty("Subject").GetString() == "Your private document lookup link" && (seen is null || !seen.Contains(x.GetProperty("ID").GetString()!)));
        var id = message.GetProperty("ID").GetString()!; using var detail = JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/" + id));
        return new(id, detail.RootElement.GetProperty("Text").GetString()!);
    }

    // Private loopback browser harness: no public fixture route issues lookup links.
    public sealed class BrowserSession : IAsyncDisposable
    {
        private readonly Flow flow; private readonly HashSet<string> seen = []; public string Url => flow.Client.BaseAddress!.ToString().TrimEnd('/');
        public string Address => flow.Run.Signing.Envelope.SenderEmail; public string PublicId => flow.PublicId;
        private BrowserSession(Flow flow) => this.flow = flow;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture, int port)
        {
            var f = await Flow.Create(fixture, completionReaders: true, completionNotifications: true, lookupBrowser: true, browserPort: port,
                mailbox: "request-browser-" + Guid.NewGuid().ToString("N") + "@example.invalid");
            var session = new BrowserSession(f); f.App.Services.GetRequiredService<EmailOptions>().BaseUrl = session.Url; return session;
        }
        public async Task<string> DeliverRequestedAsync() { await Dispatch(flow); var mail = await Captured(flow, seen); seen.Add(mail.Id); return mail.Id; }
        public void EnableEmail(bool value) => flow.App.Services.GetRequiredService<EmailOptions>().Enabled = value;
        public ValueTask DisposeAsync() => flow.DisposeAsync();
    }
}

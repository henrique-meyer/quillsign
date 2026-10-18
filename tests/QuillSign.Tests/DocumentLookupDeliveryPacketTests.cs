using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Work;
using Flow = QuillSign.Tests.CompletionDownloadTests.Flow;
using Reader = QuillSign.Tests.CompletionReaderPageTests;

namespace QuillSign.Tests;

public sealed class DocumentLookupDeliveryPacketTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task A_genuine_completed_packet_is_retrieved_through_captured_SMTP_lookup_mail_and_the_supported_private_browser_handlers()
    {
        await using var f = await Flow.Create(fixture, completionReaders: true, completionNotifications: true, lookupBrowser: true,
            mailbox: "lookup-packet-" + Guid.NewGuid().ToString("N") + "@example.invalid");
        var mail = await Deliver(f); var code = Code(mail.Text);
        Assert.Contains(code, mail.Html); Assert.Contains("/find/access#token=", mail.Text); Assert.DoesNotContain("?token=", mail.Text);
        var page = await Reader.Get(f, "/find/access");
        using (var begin = await Reader.Post(f, "/find/access/Begin", page, new() { ["code"] = code })) Assert.Equal("/find/access", begin.Headers.Location?.OriginalString);
        page = await Reader.Get(f, "/find/access"); Assert.DoesNotContain(code, page);
        var nonce = Regex.Match(page, "name=\"nonce\" value=\"([a-f0-9]{32})\"").Groups[1].Value;
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

    private sealed record Captured(string Id, string Text, string Html);
    private static string Code(string text) { var match = Regex.Match(text, @"#token=([A-Za-z0-9_-]+)"); Assert.True(match.Success); return match.Groups[1].Value; }
    private static async Task<Captured> Deliver(Flow f)
    {
        using var scope = f.App.Services.CreateScope(); var services = scope.ServiceProvider;
        var id = Guid.NewGuid();
        Assert.Equal(LookupRequestOutcome.Neutral, await services.GetRequiredService<DocumentLookupRequests>()
            .RequestAsync(id, f.Run.Signing.Envelope.SenderEmail, "198.51.100.9"));
        var store = services.GetRequiredService<WorkStore>(); var lease = (await store.ClaimAsync(id, default)).Lease!;
        var handler = services.GetServices<IWorkHandler>().Single(x => x.Kind == WorkKind.Email);
        var result = await handler.ExecuteAsync(lease, default); Assert.Equal(WorkOutcome.Completed, result.Outcome); await store.FinishAsync(lease, result, default);
        var db = services.GetRequiredService<QuillSignDbContext>(); Assert.Equal(EmailStatus.Sent, (await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == id)).Status);
        var root = "http://127.0.0.1:" + Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT"); using var http = new HttpClient { BaseAddress = new(root) };
        using var found = JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query=" + Uri.EscapeDataString("to:" + f.Run.Signing.Envelope.SenderEmail)));
        var item = Assert.Single(found.RootElement.GetProperty("messages").EnumerateArray(), x => x.GetProperty("Subject").GetString() == "Your private document lookup link");
        var messageId = item.GetProperty("ID").GetString()!;
        using var detail = JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/" + messageId));
        return new(messageId, detail.RootElement.GetProperty("Text").GetString()!, detail.RootElement.GetProperty("HTML").GetString()!);
    }

    // Test-only loopback app and captured local SMTP, with a completed synthetic non-agreement packet.
    public sealed class BrowserSession : IAsyncDisposable
    {
        private readonly Flow flow; public string Url => flow.Client.BaseAddress!.ToString().TrimEnd('/'); public string MailId { get; private set; } = "";
        private BrowserSession(Flow flow) => this.flow = flow;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture, int port) {
            var f = await Flow.Create(fixture, completionReaders: true, completionNotifications: true, lookupBrowser: true, browserPort: port,
                mailbox: "lookup-browser-" + Guid.NewGuid().ToString("N") + "@example.invalid");
            var browser = new BrowserSession(f); f.App.Services.GetRequiredService<EmailOptions>().BaseUrl = browser.Url;
            browser.MailId = (await Deliver(f)).Id; return browser;
        }
        public ValueTask DisposeAsync() => flow.DisposeAsync();
    }
}

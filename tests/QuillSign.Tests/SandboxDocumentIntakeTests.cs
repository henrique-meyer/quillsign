using System.Net;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Documents;
using Browser = QuillSign.Tests.SenderDocumentRetentionTests.BrowserSession;

namespace QuillSign.Tests;

public sealed class SandboxDocumentIntakeTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Sandbox_upload_keeps_exact_hashes_private_download_and_affirmative_confirmation()
    {
        var h = new SandboxDocxTransportTests.Harness(); await using var browser = await Start(h);
        var before = await browser.run.H.StateAsync(); var page = await Page(browser); var source = GotenbergDocxConverterTests.Docx();
        Assert.Contains(",.docx", page); Assert.DoesNotContain(h.Options.SubscriptionId, page); Assert.Equal(0, h.Api.Calls);
        using (var upload = await browser.Upload(page, source, "synthetic.docx")) Assert.Equal(HttpStatusCode.Redirect, upload.StatusCode);
        var state = await browser.run.H.StateAsync(); Assert.Equal(SHA256.HashData(source), state.OriginalSha256);
        Assert.Equal(DocxDocumentWorkflow.Mime, state.OriginalMime); Assert.NotEqual(before.PdfBlob, state.PdfBlob); Assert.Null(state.PreviewConfirmedAt);
        using (var pdf = await browser.Get(browser.Path + "/document/" + state.PdfBlob))
        { Assert.Equal(HttpStatusCode.OK, pdf.StatusCode); Assert.True(pdf.Headers.CacheControl!.NoStore); Assert.Equal(state.PdfSha256, SHA256.HashData(await pdf.Content.ReadAsByteArrayAsync())); }
        page = await Page(browser); Assert.Contains("Review needed", page); Assert.DoesNotContain("Set up signers", page); Assert.DoesNotContain("googletagmanager", page);
        using (var confirm = await browser.Post(browser.Path + "?handler=Confirm", new()
        {
            ["__RequestVerificationToken"] = SignaturePageTests.Browser.Token(page), ["Version"] = SenderSendPageTests.Flow.Value(page, "Version"),
            ["DocumentId"] = state.PdfBlob!, ["PreviewMatches"] = "true"
        })) Assert.Equal(HttpStatusCode.Redirect, confirm.StatusCode);
        Assert.Contains("Set up signers", await Page(browser)); Assert.Empty(h.Api.Resources); Assert.Equal(1, h.Api.Conversions);
        await using var db = fixture.Open(); Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == state.Id));
        Assert.Equal(browser.run.Policy.DeleteAfter, (await db.DocumentRetentionSnapshots.SingleAsync(x => x.EnvelopeId == state.Id)).DeleteAfter);
    }

    [Theory]
    [InlineData("package")]
    [InlineData("csrf")]
    [InlineData("stale")]
    [InlineData("provider")]
    [InlineData("cleanup")]
    public async Task Rejected_or_failed_sandbox_upload_preserves_the_saved_source_and_retry_recovers(string mode)
    {
        var h = new SandboxDocxTransportTests.Harness(); await using var browser = await Start(h);
        var before = await browser.run.H.StateAsync(); var page = await Page(browser); var source = mode == "package" ? "not a package"u8.ToArray() : GotenbergDocxConverterTests.Docx();
        if (mode == "provider") h.Api.CreateFailure = "after-image";
        if (mode == "cleanup") h.Api.DeleteFailure = "before";
        using (var upload = await browser.Upload(page, source, "synthetic.docx", csrf: mode != "csrf", version: mode == "stale" ? Convert.ToBase64String(new byte[8]) : null))
        {
            Assert.Equal(mode switch { "provider" or "cleanup" => HttpStatusCode.ServiceUnavailable, "stale" => HttpStatusCode.Conflict, _ => HttpStatusCode.BadRequest }, upload.StatusCode);
            Assert.DoesNotContain("private", await upload.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        }
        var unchanged = await browser.run.H.StateAsync(); Assert.Equal(before.RowVersion, unchanged.RowVersion); Assert.Equal(before.PdfBlob, unchanged.PdfBlob); Assert.Equal(before.OriginalBlob, unchanged.OriginalBlob);
        Assert.Equal(mode is "provider" or "cleanup" ? 1 : 0, h.Api.ImageCreates);
        if (mode is "provider" or "cleanup")
        {
            h.Api.CreateFailure = ""; h.Api.DeleteFailure = "";
            using var retry = await browser.Upload(page, GotenbergDocxConverterTests.Docx(), "recovered.docx"); Assert.Equal(HttpStatusCode.Redirect, retry.StatusCode);
            Assert.Empty(h.Api.Resources); Assert.Null(h.Ledger.State.Run);
        }
    }
    private async Task<Browser> Start(SandboxDocxTransportTests.Harness h)
    {
        var browser = await Browser.Start(fixture, conversion: new() { Enabled = true, Transport = "Sandbox", Sandbox = h.Options },
            configure: services => services.AddSingleton<ISandboxDocxTransport>(h.Transport));
        using var session = await browser.Get("/test-session"); Assert.Equal(HttpStatusCode.OK, session.StatusCode); return browser;
    }
    private static async Task<string> Page(Browser browser)
    { using var page = await browser.Get(browser.Path); Assert.Equal(HttpStatusCode.OK, page.StatusCode); return await page.Content.ReadAsStringAsync(); }
}

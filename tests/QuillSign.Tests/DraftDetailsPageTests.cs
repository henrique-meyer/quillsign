using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class DraftDetailsPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Razor_forms_scope_validation_enforce_csrf_preserve_conflicts_encode_values_and_use_one_time_notices()
    {
        Envelope draft;
        await using (var db = fixture.Open())
        {
            draft = new Envelope { SenderEmail = "page-" + Guid.NewGuid().ToString("N") + "@example.invalid", Title = "Synthetic document",
                SenderVerifiedAt = DateTimeOffset.UtcNow, PreviewConfirmedAt = DateTimeOffset.UtcNow,
                PdfBlob = Guid.NewGuid().ToString("N"), PdfSha256 = SHA256.HashData([1]), PageCount = 1 };
            db.Envelopes.Add(draft); await db.SaveChangesAsync();
        }
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(DraftDetails).Assembly.FullName,
            EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders(); builder.WebHost.UseTestServer(); builder.Services.AddRazorPages();
        builder.Services.AddAuthentication(EnvelopeStorageAuthorization.SenderScheme).AddCookie(EnvelopeStorageAuthorization.SenderScheme,
            options => options.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; });
        builder.Services.AddAuthorization(); builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(new PreparationOptions()); builder.Services.AddScoped(_ => fixture.Open());
        builder.Services.AddScoped<AuditWriter>(); builder.Services.AddScoped<DraftDetails>(); builder.Services.AddScoped<BrowserNotices>();
        await using var app = builder.Build(); app.UseRouting(); app.UseAuthentication(); app.UseAuthorization(); app.MapRazorPages();
        app.MapGet("/test-session", async (Microsoft.AspNetCore.Http.HttpContext context) =>
        {
            await context.SignInAsync(EnvelopeStorageAuthorization.SenderScheme,
                SenderConfiguration.Principal(new VerifiedSender(draft.Id, draft.PublicId, draft.SenderEmail)));
            return "ok";
        });
        await app.StartAsync(); using var client = app.GetTestClient(); var browser = new Browser(client);
        var path = $"/draft/{draft.PublicId}/details";
        using (var unauthorized = await browser.GetAsync(path)) Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        using (await browser.GetAsync("/test-session")) { }
        using var initialResponse = await browser.GetAsync(path); var initial = await initialResponse.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, initialResponse.StatusCode);
        var token = Input(initial, "__RequestVerificationToken"); var version = Input(initial, "Version");
        using (var missingCsrf = await browser.PostAsync(path + "?handler=SaveRecipient", new() { ["Version"] = version,
            ["Recipient.Name"] = "Reviewer", ["Recipient.Email"] = "reviewer@example.invalid" })) Assert.Equal(HttpStatusCode.BadRequest, missingCsrf.StatusCode);
        using (var saved = await browser.PostAsync(path + "?handler=SaveRecipient", new() { ["Version"] = version,
            ["__RequestVerificationToken"] = token, ["Recipient.Name"] = "  Synthetic reviewer  ", ["Recipient.Email"] = "REVIEWER@EXAMPLE.INVALID" }))
        {
            var responseHtml = await saved.Content.ReadAsStringAsync();
            Assert.True(saved.StatusCode == HttpStatusCode.Redirect, "Unexpected status " + saved.StatusCode + ": " +
                Regex.Match(responseHtml, "<div[^>]*role=\"alert\"[^>]*>(.*?)</div>", RegexOptions.Singleline).Groups[1].Value);
            Assert.Equal(path, saved.Headers.Location!.ToString());
            Assert.Contains(saved.Headers.GetValues("Set-Cookie"), x => x.StartsWith("QuillSign.Notice=") && x.Contains("httponly", StringComparison.OrdinalIgnoreCase));
        }
        using var afterResponse = await browser.GetAsync(path); var after = await afterResponse.Content.ReadAsStringAsync();
        Assert.Contains("Completion recipient saved. Nothing has been sent.", after); Assert.Contains("reviewer@example.invalid", after);
        using (var second = await browser.GetAsync(path)) Assert.DoesNotContain("Completion recipient saved. Nothing has been sent.", await second.Content.ReadAsStringAsync());
        token = Input(after, "__RequestVerificationToken"); version = Input(after, "Version");
        using (var details = await browser.PostAsync(path + "?handler=SaveDetails", new() { ["Version"] = version,
            ["__RequestVerificationToken"] = token, ["Details.Title"] = "<script>literal</script>", ["Details.Message"] = "First line\n<em>literal message</em>" }, json: true))
        { Assert.Equal(HttpStatusCode.OK, details.StatusCode); Assert.Null(details.Headers.Location); Assert.Contains("Document details saved", await details.Content.ReadAsStringAsync()); }
        using (var stale = await browser.PostAsync(path + "?handler=SaveDetails", new() { ["Version"] = version,
            ["__RequestVerificationToken"] = token, ["Details.Title"] = "Attempted stale title", ["Details.Message"] = "Attempted message" }))
        {
            Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode); var html = await stale.Content.ReadAsStringAsync();
            Assert.Contains("Current saved details", html); Assert.Contains("Attempted stale title", html);
            Assert.Contains("&lt;script&gt;literal&lt;/script&gt;", html); Assert.DoesNotContain("<script>literal</script>", html);
            token = Input(html, "__RequestVerificationToken"); version = Input(html, "Version");
        }
        using (var duplicate = await browser.PostAsync(path + "?handler=SaveRecipient", new() { ["Version"] = version,
            ["__RequestVerificationToken"] = token, ["Recipient.Name"] = "Attempted duplicate", ["Recipient.Email"] = "REVIEWER@EXAMPLE.INVALID" }))
        {
            Assert.Equal(HttpStatusCode.BadRequest, duplicate.StatusCode); var html = await duplicate.Content.ReadAsStringAsync();
            Assert.Contains("Attempted duplicate", html); Assert.Contains("already a completion recipient", html);
            Assert.Contains("&lt;script&gt;literal&lt;/script&gt;", html);
        }
        await using var inspect = fixture.Open(); Assert.Single(await inspect.Recipients.Where(x => x.EnvelopeId == draft.Id).ToListAsync());
        Assert.Equal(2, await inspect.AuditEvents.CountAsync(x => x.EnvelopeId == draft.Id));
        Assert.False(await inspect.EmailOutbox.AnyAsync(x => x.EnvelopeId == draft.Id));
    }

    private static string Input(string html, string name)
    {
        var value = WebUtility.HtmlDecode(Regex.Match(html, "name=\"" + Regex.Escape(name) + "\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        Assert.NotEmpty(value); return value;
    }
    private sealed class Browser(HttpClient client)
    {
        private readonly Dictionary<string, string> cookies = [];
        private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            if (cookies.Count > 0) request.Headers.Add("Cookie", string.Join("; ", cookies.Select(x => x.Key + "=" + x.Value)));
            var response = await client.SendAsync(request);
            if (response.Headers.TryGetValues("Set-Cookie", out var values)) foreach (var cookie in values)
            { var pair = cookie.Split(';')[0]; var split = pair.IndexOf('='); cookies[pair[..split]] = pair[(split + 1)..]; }
            return response;
        }
        public Task<HttpResponseMessage> GetAsync(string path) => SendAsync(new(HttpMethod.Get, path));
        public Task<HttpResponseMessage> PostAsync(string path, Dictionary<string, string> fields, bool json = false)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new FormUrlEncodedContent(fields) };
            if (json) request.Headers.Add("Accept", "application/json"); return SendAsync(request);
        }
    }
}

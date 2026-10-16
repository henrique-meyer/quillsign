using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
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

public sealed class DraftReviewPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Review_requires_scoped_session_encodes_private_content_disables_cache_and_does_not_mutate()
    {
        Envelope draft;
        await using (var db = fixture.Open())
        {
            draft = new Envelope { SenderEmail = "review-page-" + Guid.NewGuid().ToString("N") + "@example.invalid", Title = "<script>literal title</script>",
                Message = "First line\n<em>literal message</em>", SenderVerifiedAt = DateTimeOffset.UtcNow, PreviewConfirmedAt = DateTimeOffset.UtcNow,
                PdfBlob = Guid.NewGuid().ToString("N"), PdfSha256 = SHA256.HashData([1]), PageCount = 1,
                PageSizesJson = JsonSerializer.Serialize(new[] { new PageGeometry(612,792,0,1,[0,0,612,792],[0,0,612,792]) }) };
            var signer = new Signer { EnvelopeId = draft.Id, FullName = "<img>literal signer", Email = "signer@example.invalid" };
            db.Envelopes.Add(draft); db.Signers.Add(signer);
            db.Fields.Add(new DocumentField { EnvelopeId = draft.Id, Type = FieldType.Checkbox, Value = "false", Label = "<b>literal label</b>",
                X = .1m, Y = .1m, Width = .2m, Height = .1m });
            db.Recipients.Add(new Recipient { EnvelopeId = draft.Id, Name = "<i>literal recipient</i>", Email = "recipient@example.invalid" });
            await db.SaveChangesAsync();
        }
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(DraftReview).Assembly.FullName,
            EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders(); builder.WebHost.UseTestServer(); builder.Services.AddRazorPages();
        builder.Services.AddAuthentication(EnvelopeStorageAuthorization.SenderScheme).AddCookie(EnvelopeStorageAuthorization.SenderScheme,
            options => options.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; });
        builder.Services.AddAuthorization(); builder.Services.AddScoped(_ => fixture.Open()); builder.Services.AddScoped<DraftReview>();
        await using var app = builder.Build(); app.UseRouting(); app.UseAuthentication(); app.UseAuthorization(); app.MapRazorPages();
        app.MapGet("/test-session", async (Microsoft.AspNetCore.Http.HttpContext context) =>
        {
            await context.SignInAsync(EnvelopeStorageAuthorization.SenderScheme,
                SenderConfiguration.Principal(new VerifiedSender(draft.Id, draft.PublicId, draft.SenderEmail)));
            return "ok";
        });
        await app.StartAsync(); using var client = app.GetTestClient(); var path = $"/draft/{draft.PublicId}/review";
        using (var anonymous = await client.GetAsync(path)) Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        using (var session = await client.GetAsync("/test-session"))
        { client.DefaultRequestHeaders.Add("Cookie", string.Join("; ", session.Headers.GetValues("Set-Cookie").Select(x => x.Split(';')[0]))); }
        using var response = await client.GetAsync(path); var html = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.Contains("Preparation checks passed", html); Assert.Contains("Warnings do not block preparation", html);
        Assert.Contains("Unchecked", html);
        foreach (var text in new[] { "<script>literal title</script>", "<em>literal message</em>", "<img>literal signer", "<b>literal label</b>", "<i>literal recipient</i>" })
        { Assert.Contains(WebUtility.HtmlEncode(text), html); Assert.DoesNotContain(text, html); }
        Assert.Contains(path.Replace("/review", "/fields"), html); Assert.Contains(path.Replace("/review", "/details"), html);
        using (var foreign = await client.GetAsync("/draft/" + Guid.NewGuid().ToString("N") + "/review")) Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        await using var inspect = fixture.Open(); var saved = await inspect.Envelopes.AsNoTracking().SingleAsync(x => x.Id == draft.Id);
        Assert.Equal(draft.RowVersion, saved.RowVersion); Assert.Equal(EnvelopeStatus.Draft, saved.Status);
        Assert.False(await inspect.AuditEvents.AnyAsync(x => x.EnvelopeId == draft.Id));
        Assert.False(await inspect.EmailOutbox.AnyAsync(x => x.EnvelopeId == draft.Id));
    }
}

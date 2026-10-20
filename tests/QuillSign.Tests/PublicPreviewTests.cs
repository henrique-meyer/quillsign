using System.Buffers.Binary;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Sharing;
using QuillSign.Verification;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class PublicPreviewTests
{
    [Theory]
    [InlineData(null)][InlineData("")][InlineData("http://public.example.invalid")]
    [InlineData("https://user:pass@public.example.invalid")][InlineData("https://public.example.invalid/private")]
    [InlineData("https://public.example.invalid/?token=private")][InlineData("https://public.example.invalid/#private")]
    [InlineData("javascript:alert(1)")][InlineData("//public.example.invalid")]
    public void Missing_or_invalid_origin_never_falls_back_to_request_host(string? origin)
    {
        var context = Context("/"); context.Request.Host = new("attacker.example.invalid");
        Assert.Null(PublicPreview.For(context, Config(origin)));
    }

    [Theory]
    [InlineData("/admin")][InlineData("/draft/private")][InlineData("/sign/access")]
    [InlineData("/find/access")][InlineData("/find/documents")][InlineData("/complete/access")]
    [InlineData("/completed/access")][InlineData("/final/private")][InlineData("/health")]
    [InlineData("/missing")][InlineData("/Index")][InlineData("/verify/")]
    public void Private_token_result_operational_and_unknown_routes_have_no_preview(string path)
        => Assert.Null(PublicPreview.For(Context(path), Config()));

    [Theory]
    [InlineData("POST", 200, "")][InlineData("GET", 400, "")][InlineData("GET", 302, "")]
    [InlineData("GET", 200, "?token=SYNTHETIC_PRIVATE")][InlineData("GET", 200, "?handler=Private")]
    public void Input_results_errors_redirects_and_query_state_have_no_preview(string method, int status, string query)
    {
        var context = Context("/verify"); context.Request.Method = method;
        context.Response.StatusCode = status; context.Request.QueryString = new(query);
        Assert.Null(PublicPreview.For(context, Config()));
    }

    [Theory]
    [InlineData("Demo")][InlineData("Production")]
    public async Task Real_public_Razor_pages_share_the_exact_supplied_PNG_without_private_backends(string mode)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions {
            ApplicationName = typeof(QuillSign.Pages.IndexModel).Assembly.FullName,
            EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders(); builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> {
            ["PublicSite:Origin"] = "https://public.example.invalid", ["ConnectionStrings:Database"] = "",
            ["Email:Enabled"] = "false", ["Work:Enabled"] = "false" });
        builder.Services.AddRazorPages(); builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
        builder.Services.AddQuillSignDatabase(builder.Configuration);
        builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
        builder.Services.AddQuillSignWork(builder.Configuration, builder.Environment, registerHandlers: false);
        builder.Services.AddQuillSignSender(builder.Configuration, builder.Environment);
        builder.Services.AddPdfVerificationBrowser(builder.Configuration);
        builder.Services.AddScoped<Func<UploadedPdfVerification>>(_ => () => throw new InvalidOperationException("Private backend resolved."));
        builder.Services.AddScoped<Func<DocumentLookupRequests>>(_ => () => throw new InvalidOperationException("Private backend resolved."));
        builder.Services.AddScoped<Func<BrowserNotices>>(sp => () => sp.GetRequiredService<BrowserNotices>());
        builder.Services.AddSingleton(new LookupContactRetentionOptions());
        builder.Services.AddSingleton(new QuillSign.Lifecycle.RecordLifecycleOptions {Mode=mode});
        await using var app = builder.Build();
        app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(Path.Combine(AppContext.BaseDirectory, "wwwroot")) });
        app.UseRouting(); app.UseRateLimiter(); app.UseAuthentication(); app.UseAuthorization(); app.MapRazorPages();
        await app.StartAsync(); using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Host = "attacker.example.invalid";
        var titles = new HashSet<string>(); var descriptions = new HashSet<string>();
        foreach (var path in new[] { "/", "/verify", "/find/request" }) {
            using var response = await client.GetAsync(path); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var html = await response.Content.ReadAsStringAsync();
            if(mode=="Demo")Assert.Contains("Demo instance",html);
            else {Assert.DoesNotContain("Demo instance",html);Assert.Contains("Retention and access follow this operator",html);}
            var title = WebUtility.HtmlDecode(Assert.Single(Regex.Matches(html, "<title>(.*?)</title>").Select(x => x.Groups[1].Value)));
            Assert.True(titles.Add(title)); var description = Meta(html, "description"); Assert.True(descriptions.Add(description));
            Assert.Equal(title, Meta(html, "og:title")); Assert.Equal(title, Meta(html, "twitter:title"));
            Assert.Equal(description, Meta(html, "og:description")); Assert.Equal(description, Meta(html, "twitter:description"));
            var canonical = "https://public.example.invalid" + path;
            Assert.Equal(canonical, Assert.Single(Regex.Matches(html, "<link rel=\"canonical\" href=\"([^\"]+)\"").Select(x => x.Groups[1].Value)));
            Assert.Equal(canonical, Meta(html, "og:url")); Assert.Equal("website", Meta(html, "og:type"));
            Assert.Equal("https://public.example.invalid/logo.png", Meta(html, "og:image"));
            Assert.Equal(Meta(html, "og:image"), Meta(html, "twitter:image")); Assert.Equal("summary", Meta(html, "twitter:card"));
            Assert.Equal("image/png", Meta(html, "og:image:type")); Assert.Equal("QuillSign", Meta(html, "og:image:alt"));
            Assert.Equal("1024", Meta(html, "og:image:width")); Assert.Equal("1024", Meta(html, "og:image:height"));
            Assert.Contains("href=\"/logo.svg\" type=\"image/svg+xml\"", html);
            Assert.DoesNotContain("attacker.example.invalid", html);
        }
        foreach (var path in new[] { "/?token=SYNTHETIC_PRIVATE", "/find/request?email=SYNTHETIC_PRIVATE", "/missing" }) {
            using var response = await client.GetAsync(path);
            var html = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("og:image", html); Assert.DoesNotContain("twitter:", html); Assert.DoesNotContain("rel=\"canonical\"", html);
            Assert.DoesNotContain("SYNTHETIC_PRIVATE", html);
        }
        builder.Configuration["PublicSite:Origin"] = "";
        Assert.DoesNotContain("og:image", await client.GetStringAsync("/"));
        using var png = await client.GetAsync("/logo.png"); Assert.Equal(HttpStatusCode.OK, png.StatusCode);
        Assert.Equal("image/png", png.Content.Headers.ContentType?.MediaType);
        var bytes = await png.Content.ReadAsByteArrayAsync();
        Assert.Equal(1024u, BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(16,4)));
        Assert.Equal(1024u, BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(20,4)));
        Assert.Equal(await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "wwwroot", "logo.png")), bytes);
    }

    private static string Meta(string html, string name) => WebUtility.HtmlDecode(Assert.Single(Regex.Matches(html,
        "<meta (?:name|property)=\"" + Regex.Escape(name) + "\" content=\"([^\"]*)\"").Select(x => x.Groups[1].Value)));
    private static DefaultHttpContext Context(string path) { var context = new DefaultHttpContext(); context.Request.Method = "GET"; context.Request.Path = path; return context; }
    private static IConfiguration Config(string? origin = "https://public.example.invalid/") => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string,string?> { ["PublicSite:Origin"] = origin }).Build();
}

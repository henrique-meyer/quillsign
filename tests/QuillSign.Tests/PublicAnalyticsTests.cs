using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Analytics;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Verification;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class PublicAnalyticsTests
{
    private const string SyntheticId = "G-TEST123456";

    [Theory]
    [InlineData("/draft/opaque")][InlineData("/draft/opaque/resend")][InlineData("/draft/opaque/sent")][InlineData("/sign/access")][InlineData("/find")]
    [InlineData("/find/request")][InlineData("/find/access")][InlineData("/find/documents")]
    [InlineData("/verify")][InlineData("/completed/access")][InlineData("/health")]
    [InlineData("/document.pdf")][InlineData("/error")][InlineData("/Index")][InlineData("//")]
    public void Every_path_except_the_exact_homepage_has_no_id_or_external_CSP(string path)
    {
        var context = new DefaultHttpContext(); context.Request.Method = "GET"; context.Request.Path = path;
        Assert.Null(PublicAnalytics.MeasurementId(context, Config()));
        Assert.Equal(PublicAnalytics.DefaultPolicy, PublicAnalytics.ContentSecurityPolicy(context, Config()));
    }

    [Theory]
    [InlineData(null)][InlineData("")][InlineData("G-bad")][InlineData("G-ABCD\n")]
    [InlineData("G-AAAA'; script-src *")][InlineData("G-" + "AAAAAAAAAAAAAAAAAAAAA")]
    public void Missing_or_invalid_identifiers_fail_closed(string? id)
    {
        var context = Home(); var config = Config(id);
        Assert.Null(PublicAnalytics.MeasurementId(context, config));
        Assert.Equal(PublicAnalytics.DefaultPolicy, PublicAnalytics.ContentSecurityPolicy(context, config));
    }

    [Theory]
    [InlineData("disabled")][InlineData("invalid-enabled")][InlineData("query")]
    [InlineData("post")][InlineData("head")][InlineData("error")][InlineData("redirect")]
    public void Disabled_ambiguous_non_GET_and_failed_requests_never_enable_tracking(string kind)
    {
        var context = Home(); var config = Config();
        if (kind == "disabled") config["Analytics:Enabled"] = "false";
        if (kind == "invalid-enabled") config["Analytics:Enabled"] = "yes";
        if (kind == "query") context.Request.QueryString = new("?token=SYNTHETIC_PRIVATE");
        if (kind == "post") context.Request.Method = "POST";
        if (kind == "head") context.Request.Method = "HEAD";
        if (kind == "error") context.Response.StatusCode = 400;
        if (kind == "redirect") context.Response.StatusCode = 302;
        Assert.Null(PublicAnalytics.MeasurementId(context, config));
        Assert.Equal(PublicAnalytics.DefaultPolicy, PublicAnalytics.ContentSecurityPolicy(context, config));
    }

    [Fact]
    public async Task Real_Razor_layout_has_only_an_invisible_tag_on_the_clean_successful_homepage_without_private_backends()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions {
            ApplicationName = typeof(QuillSign.Pages.IndexModel).Assembly.FullName,
            EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders(); builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> {
            ["Analytics:Enabled"] = "true", ["Analytics:MeasurementId"] = SyntheticId,
            ["ConnectionStrings:Database"] = "", ["Email:Enabled"] = "false", ["Work:Enabled"] = "false" });
        builder.Services.AddRazorPages(); builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
        builder.Services.AddQuillSignDatabase(builder.Configuration);
        builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
        builder.Services.AddQuillSignWork(builder.Configuration, builder.Environment, registerHandlers: false);
        builder.Services.AddQuillSignSender(builder.Configuration, builder.Environment);
        builder.Services.AddPdfVerificationBrowser(builder.Configuration);
        builder.Services.AddScoped<Func<UploadedPdfVerification>>(_ => () => throw new InvalidOperationException("Private backend must not resolve."));
        await using var app = builder.Build();
        app.Use(async (context, next) => {
            context.Response.OnStarting(() => {
                context.Response.Headers["Content-Security-Policy"] = PublicAnalytics.ContentSecurityPolicy(context, app.Configuration);
                return Task.CompletedTask;
            }); await next();
        });
        app.UseRouting(); app.UseRateLimiter(); app.UseAuthentication(); app.UseAuthorization(); app.MapRazorPages();
        await app.StartAsync(); using var client = app.GetTestClient();
        using var home = await client.GetAsync("/"); var html = await home.Content.ReadAsStringAsync();
        Assert.True(home.IsSuccessStatusCode); Assert.True(home.Headers.CacheControl?.NoStore);
        Assert.Contains("data-measurement-id=\"" + SyntheticId + "\"", html);
        Assert.DoesNotContain("Allow analytics", html); Assert.DoesNotContain("Decline analytics", html);
        Assert.DoesNotContain("Analytics settings", html); Assert.DoesNotContain("Optional analytics", html);
        Assert.DoesNotContain("analytics-status", html); Assert.DoesNotContain("analytics-choice", html);
        Assert.Contains("<script id=\"analytics\"", html); Assert.Contains("/analytics.js", html);
        Assert.DoesNotContain("<script src=\"https://", html);
        var csp = Assert.Single(home.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("https://www.googletagmanager.com", csp); Assert.Contains("connect-src 'self'", csp);
        Assert.DoesNotContain("unsafe-inline", csp); Assert.DoesNotContain("doubleclick", csp); Assert.DoesNotContain("https://*", csp);
        foreach (var path in new[] { "/?token=SYNTHETIC_PRIVATE", "/verify", "/missing" }) {
            using var response = await client.GetAsync(path); var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("analytics.js", body); Assert.DoesNotContain(SyntheticId, body);
            Assert.DoesNotContain("SYNTHETIC_PRIVATE", body);
            Assert.Equal(PublicAnalytics.DefaultPolicy, Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
        }
        builder.Configuration["Analytics:Enabled"] = "false";
        using var disabled = await client.GetAsync("/");
        Assert.DoesNotContain("analytics.js", await disabled.Content.ReadAsStringAsync());
        Assert.Equal(PublicAnalytics.DefaultPolicy, Assert.Single(disabled.Headers.GetValues("Content-Security-Policy")));
    }

    private static DefaultHttpContext Home() { var context = new DefaultHttpContext(); context.Request.Method = "GET"; context.Request.Path = "/"; return context; }
    private static IConfigurationRoot Config(string? id = SyntheticId) => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
        ["Analytics:Enabled"] = "true", ["Analytics:MeasurementId"] = id }).Build();
}

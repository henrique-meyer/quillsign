using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Email;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailTemplateDesignTests : IAsyncLifetime
{
    private WebApplication app = null!;
    private static readonly Uri Link = new("https://example.invalid/demo/access#token=synthetic-private-code");
    private static readonly DateTimeOffset At = new(2026, 10, 22, 12, 0, 0, TimeSpan.Zero);
    private const string Untrusted = "<script>alert(\"synthetic\")</script>&";

    public async Task InitializeAsync() => app = await Host();

    private static async Task<WebApplication> Host(bool configured = true)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(EmailOptions).Assembly.FullName,
            EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory
        });
        builder.Logging.ClearProviders();
        builder.WebHost.UseTestServer();
        builder.Services.AddRazorPages();
        if (configured) builder.Services.AddSingleton(new EmailOptions { BaseUrl = "https://example.invalid/demo/" });
        builder.Services.AddScoped<RazorEmailViews>();
        var app = builder.Build();
        await app.StartAsync();
        return app;
    }

    public Task DisposeAsync() => app.DisposeAsync().AsTask();

    private async Task<string> Render<T>(string template, T model)
    {
        using var scope = app.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<RazorEmailViews>()
            .RenderAsync("/Views/Email/" + template, model);
    }

    private Task<string> Html(string template) => template switch
    {
        "SenderMagicLink" => Render(template + ".html.cshtml", new SenderMagicLinkModel(Link)),
        "SignerInvite" => Render(template + ".html.cshtml", new SignerInviteModel(Untrusted, Untrusted,
            Untrusted, Untrusted, Untrusted + "\r\nSecond line", Link, At, Untrusted, Untrusted)),
        "Completion" => Render(template + ".html.cshtml", new CompletionEmailModel(Untrusted, At, At.AddDays(7), Link, At.AddHours(1), false, true)),
        "Lookup" => Render(template + ".html.cshtml", new LookupEmailModel(Link, new("https://example.invalid/demo/find/access"), new string('a', 1800), At)),
        "EnvelopeDeclined" => Render(template + ".html.cshtml", new DeclinePayload(Untrusted, Untrusted, "signer@example.invalid", Untrusted)),
        "Void" => Render(template + ".html.cshtml", new VoidEmailModel(Untrusted, At, Untrusted, true)),
        _ => throw new ArgumentException("Unknown test template.")
    };

    [Theory]
    [InlineData("SenderMagicLink", true)]
    [InlineData("SignerInvite", true)]
    [InlineData("Completion", true)]
    [InlineData("Lookup", true)]
    [InlineData("EnvelopeDeclined", false)]
    [InlineData("Void", false)]
    public async Task Every_transaction_uses_the_shared_card_and_preserves_encoded_content_and_private_links(string template, bool action)
    {
        var html = await Html(template);
        Assert.Single(Regex.Matches(html, "<!doctype html>", RegexOptions.IgnoreCase));
        Assert.Single(Regex.Matches(html, "<h1[ >]"));
        Assert.Contains("Sent with QuillSign", html);
        Assert.Contains("max-width:600px", html);
        Assert.Contains("<!--[if mso]>", html);
        Assert.DoesNotContain("<script>", html);
        if (template is not ("SenderMagicLink" or "Lookup")) Assert.Contains(HtmlEncoder.Default.Encode(Untrusted), html);
        var image = Assert.Single(Regex.Matches(html, "<img[^>]+>"));
        Assert.Contains("src=\"https://example.invalid/demo/logo.png\"", image.Value);
        Assert.DoesNotContain("token", image.Value);
        var links = Regex.Matches(html, "href=\"([^\"]+)\"").Select(x => System.Net.WebUtility.HtmlDecode(x.Groups[1].Value)).ToArray();
        Assert.Equal(action ? template == "Lookup" ? 1 : 2 : 0, links.Count(x => x == Link.AbsoluteUri));
        Assert.All(links, url => Assert.StartsWith("https://example.invalid/demo/", url));
        Assert.DoesNotContain("data:", html);
        Assert.DoesNotContain("javascript:", html);
        Assert.DoesNotContain("<form", html);
    }

    [Fact]
    public async Task Completion_warning_retention_and_demo_facts_remain_conditional()
    {
        var attached = await Html("Completion");
        Assert.Contains("Attached:", attached);
        Assert.Contains("Server retention ends", attached);
        Assert.Contains("Demo instance", attached);
        Assert.DoesNotContain("Attachment-size warning", attached);
        var linkOnly = await Render("Completion.html.cshtml", new CompletionEmailModel("Synthetic", At, null, Link, At.AddHours(1), true, false));
        Assert.Contains("Attachment-size warning", linkOnly);
        Assert.DoesNotContain("Attached:", linkOnly);
        Assert.DoesNotContain("Server retention ends", linkOnly);
        Assert.DoesNotContain("Demo instance", linkOnly);
        Assert.Contains("Saved copies do not depend on this link.", linkOnly);
    }

    [Fact]
    public async Task Lookup_keeps_exact_manual_code_and_plain_text_does_not_inherit_html()
    {
        var html = await Html("Lookup");
        Assert.Contains(new string('a', 1800), html);
        Assert.Contains("word-break:break-all", html);
        var text = await Render("SenderMagicLink.text.cshtml", new SenderMagicLinkModel(Link));
        Assert.Contains(Link.AbsoluteUri, text);
        Assert.Contains("15 minutes", text);
        Assert.DoesNotContain("<html", text);
        Assert.DoesNotContain("Sent with", text);
    }

    [Theory]
    [InlineData("")]
    [InlineData("https://user@example.invalid/")]
    [InlineData("https://example.invalid/?token=private")]
    [InlineData("javascript:alert(1)")]
    public async Task Unconfigured_or_unsafe_brand_origin_keeps_readable_wordmark_without_image(string origin)
    {
        app.Services.GetRequiredService<EmailOptions>().BaseUrl = origin;
        var html = await Html("SenderMagicLink");
        Assert.DoesNotContain("<img", html);
        Assert.Contains("QuillSign", html);
        Assert.Contains(Link.AbsoluteUri, html);
    }

    [Fact]
    public async Task Standalone_worker_renderer_without_registered_email_options_keeps_the_wordmark_and_verification_link()
    {
        await using var standalone = await Host(configured: false);
        using var scope = standalone.Services.CreateScope();
        var email = await new VerificationEmailTemplate(new EmailOptions { BaseUrl = "https://example.invalid/demo/" },
            scope.ServiceProvider.GetRequiredService<RazorEmailViews>()).RenderAsync("recipient@example.invalid", new string('a', 43));
        Assert.DoesNotContain("<img", email.Html);
        Assert.Contains("QuillSign", email.Html);
        Assert.Contains("href=\"https://example.invalid/demo/sender/verify?token=" + new string('a', 43) + "\"", email.Html);
        Assert.Contains("https://example.invalid/demo/sender/verify?token=" + new string('a', 43), email.Text);
    }
}

using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class SignerReviewBrowserIsolationTests
{
    [Fact]
    public async Task Public_home_never_resolves_checkpoint_services_or_requires_a_database()
    {
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName=typeof(SignerReviewBrowser).Assembly.FullName,
            EnvironmentName="Development",ContentRootPath=AppContext.BaseDirectory });
        builder.Logging.ClearProviders(); builder.WebHost.UseTestServer(); builder.Services.AddRazorPages();
        builder.Services.AddSingleton(TimeProvider.System); builder.Services.AddSingleton(new EmailOptions()); builder.Services.AddSingleton(new WorkOptions());
        builder.Services.AddQuillSignSender(builder.Configuration,builder.Environment); builder.Services.AddScoped<SignerReviewProtection>(); builder.Services.AddSignerReviewBrowser();
        builder.Services.AddScoped<QuillSign.Data.QuillSignDbContext>(_=>throw new InvalidOperationException("A public page must never resolve a database context."));
        builder.Services.AddScoped<SignerCheckpointReads>(_=>throw new InvalidOperationException("A public page must never resolve checkpoint database services."));
        await using var app=builder.Build(); app.UseRouting(); app.UseRateLimiter(); app.UseAuthentication(); app.UseAuthorization(); app.MapRazorPages();
        await app.StartAsync(); using var client=app.GetTestClient(); using var response=await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK,response.StatusCode); Assert.Contains("QuillSign",await response.Content.ReadAsStringAsync());
    }
}

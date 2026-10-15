using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Email;

namespace QuillSign.Tests;

public sealed class EmailConfigurationTests
{
    private static ServiceProvider Configure(Dictionary<string, string?> settings, string environment)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddQuillSignEmail(new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), new TestEnvironment(environment));
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task Unconfigured_bootstrap_can_resolve_disabled_sender_without_database_or_credentials()
    {
        using var provider = Configure([], "Production");
        using var scope = provider.CreateScope();
        await Assert.ThrowsAsync<EmailDisabledException>(() => scope.ServiceProvider.GetRequiredService<IEmailSender>()
            .SendAsync(new("recipient@example.invalid", "Synthetic", "Synthetic", "Synthetic")));
    }

    [Theory]
    [InlineData("Production", "http://localhost/", "mailpit", "true")]
    [InlineData("Production", "https://example.invalid/", "mailpit", "false")]
    [InlineData("Development", "https://example.invalid/", "smtp.example.invalid", "false")]
    [InlineData("Development", "https://example.invalid/?token=bad", "mailpit", "false")]
    [InlineData("Development", "https://user@example.invalid/", "mailpit", "false")]
    public void Invalid_endpoint_or_transport_configuration_is_rejected(string environment, string url, string smtpHost, string tls)
    {
        Assert.Throws<InvalidOperationException>(() => Configure(new()
        {
            ["Email:Enabled"] = "true", ["Email:Provider"] = "Smtp", ["Email:FromEmail"] = "sender@example.invalid",
            ["Email:BaseUrl"] = url, ["Email:Smtp:Host"] = smtpHost, ["Email:Smtp:UseStartTls"] = tls
        }, environment));
    }

    [Theory]
    [InlineData("local-only")]
    [InlineData("sender@example.invalid\r\nBcc: other@example.invalid")]
    [InlineData("one@example.invalid, two@example.invalid")]
    public void Invalid_or_multiple_mailboxes_are_rejected(string address) => Assert.Throws<ArgumentException>(() => EmailAddress.Normalize(address));

    private sealed class TestEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "QuillSign.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}

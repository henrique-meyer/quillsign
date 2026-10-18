using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class SandboxConversionConfigurationTests
{
    [Theory]
    [InlineData(false, "Http")]
    [InlineData(true, "Http")]
    [InlineData(false, "Sandbox")]
    public void Ordinary_configuration_does_not_resolve_managed_identity_or_sandbox_storage(bool enabled, string transport)
    {
        var services = new ServiceCollection();
        services.AddSandboxDocumentConversion(new ConfigurationBuilder().Build(), new() { Enabled = enabled, Transport = transport }, new());
        using var provider = services.BuildServiceProvider();
        Assert.Null(provider.GetService<ISandboxDocxTransport>());
        Assert.Null(provider.GetService<ISandboxConversionLedger>());
    }

    [Fact]
    public async Task Explicit_sandbox_configuration_registers_scoped_transport_with_no_request_logging()
    {
        var services = new ServiceCollection(); var logs = new Logs(); services.AddLogging(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        services.AddSandboxDocumentConversion(new ConfigurationBuilder().Build(),
            new() { Enabled = true, Transport = "Sandbox", Sandbox = SandboxDocxTransportTests.Configuration() }, new());
        Assert.Equal(ServiceLifetime.Scoped, services.Single(s => s.ServiceType == typeof(ISandboxDocxTransport)).Lifetime);
        services.AddHttpClient("QuillSignSandboxConversion").ConfigurePrimaryHttpMessageHandler(() => new SyntheticHttp());
        using var provider = services.BuildServiceProvider();
        using var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("QuillSignSandboxConversion");
        Assert.Equal(Timeout.InfiniteTimeSpan, client.Timeout);
        using var response = await client.GetAsync("https://private.example.invalid/synthetic-private-path");
        Assert.Empty(logs.Messages);
    }

    private sealed class SyntheticHttp : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)); }
    private sealed class Logs : ILoggerProvider, ILogger
    {
        public readonly List<string> Messages = [];
        public ILogger CreateLogger(string categoryName) => this;
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }
}

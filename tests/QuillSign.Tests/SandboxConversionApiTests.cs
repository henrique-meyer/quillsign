using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Azure.Core;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class SandboxConversionApiTests
{
    [Fact]
    public async Task Uses_only_fixed_region_scope_and_audience_and_does_not_disclose_error_bodies_or_retry()
    {
        var credential = new Credential(); var handler = new Handler(_ => new(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("private provider body") });
        using var client = new HttpClient(handler); var options = SandboxDocxTransportTests.Configuration(); var api = new SandboxConversionApi(client, credential, options);
        var error = await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => api.JsonAsync(HttpMethod.Get, "sandboxes", null, default));
        Assert.DoesNotContain("private", error.Message); Assert.Equal(1, handler.Calls);
        Assert.Equal("management.eastus.azuredevcompute.io", handler.Request!.RequestUri!.Host);
        Assert.Contains(options.SubscriptionId, handler.Request.RequestUri.AbsolutePath); Assert.DoesNotContain("private", handler.Request.RequestUri.AbsoluteUri);
        Assert.Equal("Bearer", handler.Request.Headers.Authorization!.Scheme); Assert.Equal("synthetic-access-token", handler.Request.Headers.Authorization.Parameter);
        Assert.Equal(new[] { "https://dynamicsessions.io/.default" }, credential.Scopes); Assert.Equal(HttpVersion.Version11, handler.Request.Version);
    }

    [Theory]
    [InlineData("../private")]
    [InlineData("https://private.example.invalid/")]
    [InlineData("/private")]
    [InlineData("sandboxes?private")]
    [InlineData("sandboxes#private")]
    [InlineData("sandboxes\\private")]
    public async Task Arbitrary_route_syntax_is_rejected_before_credentials_or_HTTP(string path)
    {
        var credential = new Credential(); var handler = new Handler(_ => new(HttpStatusCode.OK)); using var http = new HttpClient(handler);
        var api = new SandboxConversionApi(http, credential, SandboxDocxTransportTests.Configuration());
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => api.JsonAsync(HttpMethod.Get, path, null, default));
        Assert.Equal(0, handler.Calls); Assert.Null(credential.Scopes);
    }

    [Theory]
    [InlineData("redirect")]
    [InlineData("media")]
    [InlineData("encoding")]
    [InlineData("length")]
    [InlineData("truncated")]
    [InlineData("header")]
    [InlineData("oversize")]
    public async Task Downloads_fail_closed_on_unsupported_provider_responses(string mode)
    {
        var handler = new Handler(_ =>
        {
            var response = new HttpResponseMessage(mode == "redirect" ? HttpStatusCode.TemporaryRedirect : HttpStatusCode.OK);
            response.Headers.Location = new("https://private.example.invalid/");
            response.Content = new ByteArrayContent(mode == "header" ? "private"u8.ToArray() : mode == "oversize" ? new byte[2000] : PdfFixtures.Create());
            response.Content.Headers.ContentType = new(mode == "media" ? "text/html" : "application/octet-stream");
            if (mode == "encoding") response.Content.Headers.ContentEncoding.Add("gzip");
            if (mode == "length") response.Content.Headers.ContentLength = 0;
            if (mode == "truncated") response.Content.Headers.ContentLength = response.Content.Headers.ContentLength + 1;
            return response;
        });
        using var http = new HttpClient(handler); var api = new SandboxConversionApi(http, new Credential(), SandboxDocxTransportTests.Configuration());
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => api.DownloadAsync(Guid.NewGuid().ToString("D"), mode == "oversize" ? 1024 : 10485760, default));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task File_gateway_octet_stream_is_bounded_and_never_uses_caller_paths()
    {
        var bytes = PdfFixtures.Create(); var handler = new Handler(_ =>
        { var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }; response.Content.Headers.ContentType = new("application/octet-stream"); return response; });
        using var http = new HttpClient(handler); var api = new SandboxConversionApi(http, new Credential(), SandboxDocxTransportTests.Configuration());
        Assert.Equal(bytes, await api.DownloadAsync(Guid.NewGuid().ToString("D"), 10485760, default));
        Assert.Contains("path=%2Ftmp%2Fquillsign-output.pdf", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task Malformed_and_oversize_metadata_are_private_failures()
    {
        foreach (var body in new[] { "private invalid json", new string('x', 1048577) })
        {
            var handler = new Handler(_ => new(HttpStatusCode.OK) { Content = new StringContent(body) }); using var http = new HttpClient(handler);
            var api = new SandboxConversionApi(http, new Credential(), SandboxDocxTransportTests.Configuration());
            var error = await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => api.JsonAsync(HttpMethod.Get, "sandboxes", null, default));
            Assert.DoesNotContain("private", error.Message); Assert.Equal(1, handler.Calls);
        }
    }

    [Theory]
    [InlineData("region")]
    [InlineData("subscription")]
    [InlineData("group")]
    [InlineData("resource-group")]
    [InlineData("identity")]
    [InlineData("daily")]
    [InlineData("monthly")]
    public void Configuration_cannot_introduce_arbitrary_hosts_paths_or_unbounded_attempts(string field)
    {
        var options = SandboxDocxTransportTests.Configuration();
        switch (field)
        {
            case "region": options.Region = "private.example.invalid"; break;
            case "subscription": options.SubscriptionId = "private"; break;
            case "group": options.GroupName = "../private"; break;
            case "resource-group": options.ResourceGroup = "../private"; break;
            case "identity": options.ManagedIdentityClientId = "private"; break;
            case "daily": options.MaximumDailyAttempts = 0; break;
            case "monthly": options.MaximumMonthlyAttempts = 1001; break;
        }
        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    private sealed class Credential : TokenCredential
    {
        public string[]? Scopes;
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new NotSupportedException();
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        { Scopes = requestContext.Scopes; return ValueTask.FromResult(new AccessToken("synthetic-access-token", DateTimeOffset.UtcNow.AddMinutes(5))); }
    }
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        public int Calls; public HttpRequestMessage? Request;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Calls++; Request = request; return Task.FromResult(response(request)); }
    }
}

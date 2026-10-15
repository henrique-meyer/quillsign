using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using QuillSign.Email;

namespace QuillSign.Tests;

public sealed class SnsProtocolTests
{
    [Theory]
    [InlineData("Notification", "1")]
    [InlineData("Notification", "2")]
    [InlineData("SubscriptionConfirmation", "1")]
    [InlineData("SubscriptionConfirmation", "2")]
    [InlineData("UnsubscribeConfirmation", "2")]
    public async Task Authenticates_canonical_fields_and_old_retries(string type, string version)
    {
        using var fixture = new SnsFixtures();
        var input = fixture.Message("Synthetic é message\nline two", type, version);
        if (type == "Notification") input["Subject"] = "Synthetic subject";
        var validator = new SnsMessageValidator(fixture.Options, fixture);
        var result = await validator.ValidateAsync(fixture.Sign(input), default);
        Assert.Equal(type, result.Type);
        Assert.Equal(input["Message"], result.Message);
        Assert.Equal(type == "Notification", result.ConfirmationUrl is null);
        Assert.Equal(1, fixture.Fetches);
    }

    [Theory]
    [InlineData("SigningCertURL", "http://sns.us-east-1.amazonaws.com/SimpleNotificationService-synthetic.pem")]
    [InlineData("SigningCertURL", "https://sns.us-east-1.amazonaws.com.evil.invalid/SimpleNotificationService-synthetic.pem")]
    [InlineData("SigningCertURL", "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-synthetic.pem")]
    [InlineData("SigningCertURL", "https://sns.us-east-1.amazonaws.com:444/SimpleNotificationService-synthetic.pem")]
    [InlineData("SigningCertURL", "https://user@sns.us-east-1.amazonaws.com/SimpleNotificationService-synthetic.pem")]
    [InlineData("SigningCertURL", "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-synthetic.pem?x=1")]
    [InlineData("SigningCertURL", "https://sns.us-east-1.amazonaws.com/%53impleNotificationService-synthetic.pem")]
    [InlineData("SigningCertURL", "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-synthetic.pem#fragment")]
    [InlineData("TopicArn", "arn:aws:sns:us-east-1:000000000000:another-topic")]
    [InlineData("SignatureVersion", "3")]
    [InlineData("SubscribeURL", "https://example.invalid/confirm")]
    [InlineData("SubscribeURL", "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=wrong&Token=synthetic-confirmation-token")]
    public async Task Rejects_untrusted_sources_before_any_outbound_request(string field, string value)
    {
        using var fixture = new SnsFixtures();
        var input = fixture.Message("synthetic", "SubscriptionConfirmation");
        input[field] = value;
        await Assert.ThrowsAsync<InvalidSnsMessageException>(() => new SnsMessageValidator(fixture.Options, fixture).ValidateAsync(fixture.Sign(input), default));
        Assert.Equal(0, fixture.Fetches);
    }

    [Fact]
    public async Task Tampering_any_signed_field_is_rejected()
    {
        using var fixture = new SnsFixtures();
        var original = fixture.Message("Synthetic payload", "SubscriptionConfirmation");
        fixture.Sign(original);
        original["Message"] = "Tampered payload";
        await Assert.ThrowsAsync<InvalidSnsMessageException>(() => new SnsMessageValidator(fixture.Options, fixture)
            .ValidateAsync(JsonSerializer.SerializeToUtf8Bytes(original), default));
    }

    [Theory]
    [InlineData("{\"Type\":\"Notification\",\"type\":\"SubscriptionConfirmation\"}")]
    [InlineData("[]")]
    [InlineData("{broken")]
    public async Task Ambiguous_and_malformed_json_is_rejected_without_fetch(string body)
    {
        using var fixture = new SnsFixtures();
        await Assert.ThrowsAsync<InvalidSnsMessageException>(() => new SnsMessageValidator(fixture.Options, fixture).ValidateAsync(Encoding.UTF8.GetBytes(body), default));
        Assert.Equal(0, fixture.Fetches);
    }

    [Theory]
    [InlineData(HttpStatusCode.Redirect, false)]
    [InlineData(HttpStatusCode.NotFound, false)]
    [InlineData(HttpStatusCode.ServiceUnavailable, true)]
    [InlineData(HttpStatusCode.TooManyRequests, true)]
    public async Task Certificate_source_rejects_redirects_and_distinguishes_retryable_failures(HttpStatusCode status, bool retryable)
    {
        using var handler = new StaticHandler(() => new HttpResponseMessage(status));
        using var client = new HttpClient(handler);
        using var source = new SnsCertificateSource(new ClientFactory(client), new RejectTrust());
        if (retryable) await Assert.ThrowsAsync<FeedbackUnavailableException>(() => source.GetAsync(new(SnsFixtures.CertificateUrl), default));
        else await Assert.ThrowsAsync<InvalidSnsMessageException>(() => source.GetAsync(new(SnsFixtures.CertificateUrl), default));
    }

    [Fact]
    public async Task Trusted_certificates_are_cached_and_untrusted_certificates_are_rejected()
    {
        using var fixture = new SnsFixtures();
        using var handler = new StaticHandler(() => new(HttpStatusCode.OK) { Content = new StringContent(fixture.Certificate.ExportCertificatePem()) });
        using var client = new HttpClient(handler);
        using var rejected = new SnsCertificateSource(new ClientFactory(client), new SnsCertificateTrust());
        await Assert.ThrowsAsync<InvalidSnsMessageException>(() => rejected.GetAsync(new(SnsFixtures.CertificateUrl), default));
        using var source = new SnsCertificateSource(new ClientFactory(client), new FixtureTrust(fixture.Certificate));
        Assert.Equal(fixture.Certificate.RawData, await source.GetAsync(new(SnsFixtures.CertificateUrl), default));
        Assert.Equal(fixture.Certificate.RawData, await source.GetAsync(new(SnsFixtures.CertificateUrl), default));
        Assert.Equal(2, handler.Requests); // One rejected fetch, one cached trusted fetch.
    }

    [Fact]
    public async Task Oversized_certificate_body_is_rejected()
    {
        using var handler = new StaticHandler(() => new(HttpStatusCode.OK) { Content = new StringContent(new string('a', 65537)) });
        using var client = new HttpClient(handler);
        using var source = new SnsCertificateSource(new ClientFactory(client), new RejectTrust());
        await Assert.ThrowsAsync<InvalidSnsMessageException>(() => source.GetAsync(new(SnsFixtures.CertificateUrl), default));
    }

    private sealed class RejectTrust : ISnsCertificateTrust { public bool IsTrusted(X509Certificate2 certificate) => false; }
    private sealed class FixtureTrust(X509Certificate2 root) : ISnsCertificateTrust
    {
        public bool IsTrusted(X509Certificate2 certificate)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(certificate);
        }
    }
    internal sealed class ClientFactory(HttpClient client) : IHttpClientFactory { public HttpClient CreateClient(string name) => client; }
    internal sealed class StaticHandler(Func<HttpResponseMessage> response) : HttpMessageHandler
    {
        public int Requests { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Requests++; return Task.FromResult(response()); }
    }
}

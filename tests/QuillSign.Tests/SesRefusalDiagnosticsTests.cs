using System.Net;
using Amazon;
using Amazon.Runtime;
using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;
using QuillSign.Email;
using QuillSign.Email.Pilot;

namespace QuillSign.Tests;

public sealed class SesRefusalDiagnosticsTests
{
    internal const string PrivateDetail = "private@example.invalid token=private-token arn:aws:private-resource";

    [Theory]
    [InlineData("MessageRejected", 400, "Email address is not verified. ", "identity-unverified", false)]
    [InlineData("MessageRejectedException", 400, "Invalid content: ", "message-rejected", false)]
    [InlineData("AccessDeniedException", 400, "", "authorization", false)]
    [InlineData("unrecognized", 403, "", "authorization", false)]
    [InlineData("unrecognized", 401, "", "authorization", false)]
    [InlineData("SendingPausedException", 400, "Account paused. ", "account-paused", false)]
    [InlineData("SendingPausedException", 400, "Sending paused for configuration set. ", "configuration-paused", false)]
    [InlineData("ConfigurationSetSendingPaused", 400, "", "configuration-paused", false)]
    [InlineData("ConfigurationSetDoesNotExistException", 400, "", "configuration-missing", false)]
    [InlineData("NotFoundException", 404, "", "resource-missing", false)]
    [InlineData("MailFromDomainNotVerifiedException", 400, "", "mail-from-unverified", false)]
    [InlineData("BadRequestException", 400, "", "invalid-request", false)]
    [InlineData("unrecognized", 429, "", "throttled", true)]
    [InlineData("unrecognized", 400, "Email address is not verified. ", "other", false)]
    [InlineData(PrivateDetail, 418, "", "other", false)]
    public async Task Refusals_preserve_only_bounded_category_and_status_without_raw_SDK_data(
        string code, int status, string prefix, string category, bool retryable)
    {
        var sdk = new AmazonSimpleEmailServiceV2Exception(prefix + PrivateDetail) {
            ErrorCode = code, StatusCode = (HttpStatusCode)status, RequestId = PrivateDetail
        };
        using var client = new RefusingSes(sdk);
        var message = await Prepare();
        var error = await Assert.ThrowsAsync<EmailNotSubmittedException>(() =>
            new SesPreparedEmailTransport(client, Settings).SendAsync(message, default));
        Assert.Equal($"provider-rejected-{status}-{category}", error.FailureCode);
        Assert.Equal(retryable, error.Retryable);
        Assert.Equal("The provider did not accept this email.", error.Message);
        Assert.Null(error.InnerException); Assert.Empty(error.Data);
        Assert.DoesNotContain(PrivateDetail, error.FailureCode);
        Assert.Matches("^[a-z0-9-]{1,80}$", error.FailureCode);
        Assert.Equal(1, client.Calls);
        Assert.Equal(message.Sha256, client.Sha256);
    }

    [Fact]
    public async Task Typed_throttling_without_an_error_code_retains_existing_retry_classification()
    {
        foreach (var sdk in new AmazonSimpleEmailServiceV2Exception[] {
            new TooManyRequestsException(PrivateDetail) { StatusCode = HttpStatusCode.BadRequest },
            new LimitExceededException(PrivateDetail) { StatusCode = HttpStatusCode.BadRequest }
        }) {
            using var client = new RefusingSes(sdk);
            var prepared = await Prepare();
            var error = await Assert.ThrowsAsync<EmailNotSubmittedException>(() =>
                new SesPreparedEmailTransport(client, Settings).SendAsync(prepared, default));
            Assert.True(error.Retryable); Assert.Equal("provider-rejected-400-throttled", error.FailureCode);
            Assert.Equal(1, client.Calls);
        }
    }

    [Theory]
    [InlineData(500)] [InlineData(503)]
    public async Task Server_failures_remain_ambiguous_and_are_not_reclassified_as_known_unsent(int status)
    {
        var sdk = new AmazonSimpleEmailServiceV2Exception(PrivateDetail) { StatusCode = (HttpStatusCode)status };
        using var client = new RefusingSes(sdk);
        var prepared = await Prepare();
        var error = await Record.ExceptionAsync(() => new SesPreparedEmailTransport(client, Settings).SendAsync(prepared, default));
        Assert.Same(sdk, error); Assert.Equal(1, client.Calls);
    }

    [Fact]
    public void Ordinary_provider_refusals_keep_the_generic_contract()
    {
        Assert.Equal("provider-rejected", new EmailNotSubmittedException(false).FailureCode);
        Assert.Equal("provider-rejected", new EmailNotSubmittedException(true).FailureCode);
    }

    internal static readonly EmailPilotSesSettings Settings = new("sender@example.invalid", "Synthetic", "us-east-1", "synthetic");
    private static Task<PreparedRawMime> Prepare() => PreparedRawMime.PrepareAsync(
        new("recipient@example.invalid", "Synthetic NO AGREEMENT", "Synthetic", "<p>Synthetic</p>"), Settings.FromEmail, Settings.FromName);

    internal sealed class RefusingSes(Exception failure) : AmazonSimpleEmailServiceV2Client(new AnonymousAWSCredentials(),
        new AmazonSimpleEmailServiceV2Config { RegionEndpoint = RegionEndpoint.USEast1, MaxErrorRetry = 0, AllowAutoRedirect = false })
    {
        internal int Calls;
        internal byte[]? Sha256;
        public override async Task<SendEmailResponse> SendEmailAsync(SendEmailRequest request, CancellationToken cancellationToken = default)
        {
            Calls++; using var bytes = new MemoryStream();
            await request.Content.Raw.Data.CopyToAsync(bytes, cancellationToken);
            Sha256 = System.Security.Cryptography.SHA256.HashData(bytes.ToArray());
            throw failure;
        }
    }
}

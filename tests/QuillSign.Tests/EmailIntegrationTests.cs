using System.Net;
using System.Data.Common;
using System.Text;
using System.Text.Json;
using Amazon;
using Amazon.Runtime;
using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Tests;

public sealed class EmailIntegrationTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private static string Recipient() => "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid";

    private static async Task<WebApplication> Host(EmailOptions options, ISnsCertificateSource certificates,
        Func<QuillSignDbContext> database, IHttpClientFactory? clients = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(EmailOptions).Assembly.FullName,
            EnvironmentName = "Development", ContentRootPath = AppContext.BaseDirectory
        });
        builder.Logging.ClearProviders();
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Email:Enabled"] = options.Enabled.ToString(), ["Email:Provider"] = options.Provider,
            ["Email:FromEmail"] = options.FromEmail, ["Email:FromName"] = options.FromName,
            ["Email:BaseUrl"] = options.BaseUrl, ["Email:Ses:Region"] = options.Ses.Region,
            ["Email:Ses:ConfigurationSet"] = options.Ses.ConfigurationSet, ["Email:Sns:Enabled"] = options.Sns.Enabled.ToString(),
            ["Email:Sns:TopicArn"] = options.Sns.TopicArn, ["Email:Sns:AutoConfirmSubscriptions"] = options.Sns.AutoConfirmSubscriptions.ToString()
        });
        builder.Services.AddRazorPages();
        builder.Services.AddSingleton(certificates);
        if (clients is not null) builder.Services.AddSingleton(clients);
        builder.Services.AddScoped(_ => database());
        builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
        var app = builder.Build();
        app.MapSesFeedback();
        await app.StartAsync();
        return app;
    }

    private static async Task<HttpResponseMessage> Post(WebApplication app, byte[] body)
        => await app.GetTestClient().PostAsync("/webhooks/ses", new ByteArrayContent(body));

    [Fact]
    public async Task Disabled_sender_and_invalid_feedback_do_not_resolve_database_or_provider()
    {
        using var sns = new SnsFixtures();
        await using var app = await Host(sns.Options, sns, () => throw new InvalidOperationException("Database must not be resolved."));
        using var scope = app.Services.CreateScope();
        var sender = scope.ServiceProvider.GetRequiredService<IEmailSender>();
        await Assert.ThrowsAsync<EmailDisabledException>(() => sender.SendAsync(new("recipient@example.invalid", "Synthetic", "Text", "<p>HTML</p>")));
        using var invalid = await Post(app, Encoding.UTF8.GetBytes("{}"));
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        var confirmation = sns.Sign(sns.Message("Synthetic confirmation", "SubscriptionConfirmation"));
        using var valid = await Post(app, confirmation);
        Assert.Equal(HttpStatusCode.Accepted, valid.StatusCode);
        Assert.False(sns.Options.Sns.AutoConfirmSubscriptions);
    }

    [Fact]
    public async Task Disabled_feedback_returns_not_found_and_oversized_message_is_rejected()
    {
        using var sns = new SnsFixtures();
        sns.Options.Sns.Enabled = false;
        await using (var app = await Host(sns.Options, sns, fixture.Open))
        {
            using var response = await Post(app, sns.Sign(sns.Message("Synthetic")));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal(0, sns.Fetches);
        }
        sns.Options.Sns.Enabled = true;
        await using var enabled = await Host(sns.Options, sns, fixture.Open);
        using var oversized = await Post(enabled, new byte[512 * 1024 + 1]);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);
        Assert.Equal(0, sns.Fetches);
    }

    [Fact]
    public async Task Razor_templates_render_multipart_message_and_local_mailpit_captures_it()
    {
        using var sns = new SnsFixtures();
        sns.Options.BaseUrl = "https://example.invalid/demo/";
        await using var app = await Host(sns.Options, sns, fixture.Open);
        using var scope = app.Services.CreateScope();
        var token = new string('a', 43);
        var recipient = Recipient();
        var message = await scope.ServiceProvider.GetRequiredService<VerificationEmailTemplate>().RenderAsync(recipient, token);
        var link = "https://example.invalid/demo/sender/verify?token=" + token;
        Assert.Contains(link, message.Text);
        Assert.Contains("href=\"" + link + "\"", message.Html);
        Assert.Contains("15 minutes", message.Text);
        await Assert.ThrowsAsync<ArgumentException>(() => scope.ServiceProvider.GetRequiredService<VerificationEmailTemplate>().RenderAsync(recipient, "bad token"));
        var smtpPort = int.Parse(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_SMTP_PORT") ?? throw new InvalidOperationException("Use the local test helper."));
        var inboxPort = int.Parse(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT") ?? throw new InvalidOperationException("Use the local test helper."));
        var options = new EmailOptions
        {
            Enabled = true, Provider = "Smtp", FromEmail = "noreply@example.invalid",
            Smtp = new() { Host = "127.0.0.1", Port = smtpPort, UseStartTls = false }
        };
        await using var db = fixture.Open();
        var delivery = await new EmailSender(options, () => db, () => new SmtpEmailTransport(options)).SendAsync(message);
        Assert.Equal("Smtp", delivery.Provider);
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{inboxPort}") };
        string? captured = null;
        for (var attempt = 0; attempt < 20 && captured is null; attempt++)
        {
            using var list = JsonDocument.Parse(await http.GetStringAsync("/api/v1/messages"));
            foreach (var item in list.RootElement.GetProperty("messages").EnumerateArray())
                if (item.GetProperty("To").EnumerateArray().Any(to => to.GetProperty("Address").GetString() == recipient))
                    captured = item.GetProperty("ID").GetString();
            if (captured is null) await Task.Delay(100);
        }
        Assert.NotNull(captured);
        using var detail = JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/" + captured));
        Assert.Contains(link, detail.RootElement.GetProperty("Text").GetString());
        Assert.Contains(link, detail.RootElement.GetProperty("HTML").GetString());
    }

    [Fact]
    public async Task Ses_adapter_sends_configured_content_and_suppression_blocks_provider_creation()
    {
        using var sns = new SnsFixtures();
        var options = sns.Options;
        options.Enabled = true;
        using var client = new FakeSes();
        await using var db = fixture.Open();
        var constructions = 0;
        var sender = new EmailSender(options, () => db, () => { constructions++; return new SesEmailTransport(client, options); });
        var recipient = Recipient();
        var envelope = Guid.NewGuid();
        var message = new OutgoingEmail(recipient.ToUpperInvariant(), "Synthetic subject", "Synthetic text", "<p>Synthetic HTML</p>", envelope);
        var sent = await sender.SendAsync(message);
        Assert.Equal(new EmailDelivery("Ses", "synthetic-provider-id"), sent);
        var request = Assert.IsType<SendEmailRequest>(client.Request);
        Assert.Equal(recipient, Assert.Single(request.Destination.ToAddresses));
        Assert.Contains(options.FromEmail, request.FromEmailAddress);
        Assert.Equal(options.Ses.ConfigurationSet, request.ConfigurationSetName);
        Assert.Equal(message.Text, request.Content.Simple.Body.Text.Data);
        Assert.Equal(message.Html, request.Content.Simple.Body.Html.Data);
        Assert.Equal("UTF-8", request.Content.Simple.Subject.Charset);
        Assert.Equal(envelope.ToString("N"), Assert.Single(request.Content.Simple.Headers).Value);
        db.Suppressions.Add(new() { Email = recipient, Reason = SuppressionReason.Complaint });
        await db.SaveChangesAsync();
        await Assert.ThrowsAsync<RecipientSuppressedException>(() => sender.SendAsync(message));
        Assert.Equal(1, constructions);
        await Assert.ThrowsAsync<ArgumentException>(() => sender.SendAsync(message with { Subject = "bad\r\nsubject" }));
    }

    [Fact]
    public async Task Concurrent_and_reordered_feedback_is_idempotent_and_keeps_complaints_terminal()
    {
        using var sns = new SnsFixtures();
        var recipient = Recipient();
        var id = Guid.NewGuid().ToString("N");
        await using (var seed = fixture.Open())
        {
            seed.EmailOutbox.Add(new() { To = recipient, Template = "synthetic", Status = EmailStatus.Sent, Provider = "Ses", ProviderMessageId = id });
            await seed.SaveChangesAsync();
        }
        await using var app = await Host(sns.Options, sns, fixture.Open);
        var bounce = sns.Sign(sns.Message(sns.Feedback(recipient, id)));
        var responses = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Post(app, bounce)));
        foreach (var response in responses) { using (response) Assert.Equal(HttpStatusCode.Accepted, response.StatusCode); }
        byte[] suppressionVersion, outboxVersion;
        DateTimeOffset created;
        await using (var inspect = fixture.Open())
        {
            var suppression = await inspect.Suppressions.SingleAsync(x => x.Email == recipient);
            Assert.Equal(SuppressionReason.Bounce, suppression.Reason);
            suppressionVersion = suppression.RowVersion;
            created = suppression.CreatedAt;
            var row = await inspect.EmailOutbox.SingleAsync(x => x.ProviderMessageId == id);
            Assert.Equal(EmailStatus.Bounced, row.Status);
            outboxVersion = row.RowVersion;
        }
        using (var duplicate = await Post(app, bounce)) Assert.Equal(HttpStatusCode.Accepted, duplicate.StatusCode);
        await using (var inspect = fixture.Open())
        {
            Assert.Equal(suppressionVersion, (await inspect.Suppressions.SingleAsync(x => x.Email == recipient)).RowVersion);
            Assert.Equal(outboxVersion, (await inspect.EmailOutbox.SingleAsync(x => x.ProviderMessageId == id)).RowVersion);
        }
        foreach (var type in new[] { "Complaint", "Bounce", "Delivery", "Reject", "Send", "Complaint" })
        {
            using var response = await Post(app, sns.Sign(sns.Message(sns.Feedback(recipient, id, type))));
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        }
        await using var final = fixture.Open();
        var finalSuppression = await final.Suppressions.SingleAsync(x => x.Email == recipient);
        Assert.Equal(SuppressionReason.Complaint, finalSuppression.Reason);
        Assert.Equal(created, finalSuppression.CreatedAt);
        Assert.Equal(EmailStatus.Complained, (await final.EmailOutbox.SingleAsync(x => x.ProviderMessageId == id)).Status);
    }

    [Theory]
    [InlineData("Transient")]
    [InlineData("Undetermined")]
    public async Task Temporary_bounces_do_not_permanently_suppress(string bounceType)
    {
        using var sns = new SnsFixtures();
        var recipient = Recipient();
        await using var app = await Host(sns.Options, sns, fixture.Open);
        using var response = await Post(app, sns.Sign(sns.Message(sns.Feedback(recipient, "synthetic", bounceType: bounceType))));
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        await using var db = fixture.Open();
        Assert.False(await db.Suppressions.AnyAsync(x => x.Email == recipient));
    }

    [Fact]
    public async Task Feedback_keeps_existing_opt_outs_and_does_not_change_other_provider_or_recipient()
    {
        using var sns = new SnsFixtures();
        var recipient = Recipient();
        var other = Recipient();
        var id = Guid.NewGuid().ToString("N");
        await using var db = fixture.Open();
        db.Suppressions.Add(new() { Email = recipient, Reason = SuppressionReason.BlockedSender });
        db.EmailOutbox.AddRange(
            new EmailOutbox { To = recipient, Template = "synthetic", Status = EmailStatus.Sent, Provider = "Smtp", ProviderMessageId = id },
            new EmailOutbox { To = other, Template = "synthetic", Status = EmailStatus.Sent, Provider = "Ses", ProviderMessageId = id });
        await db.SaveChangesAsync();
        var before = (await db.Suppressions.SingleAsync(x => x.Email == recipient)).RowVersion.ToArray();
        await using var app = await Host(sns.Options, sns, fixture.Open);
        using var response = await Post(app, sns.Sign(sns.Message(sns.Feedback(recipient, id, "Complaint"))));
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        db.ChangeTracker.Clear();
        var suppression = await db.Suppressions.SingleAsync(x => x.Email == recipient);
        Assert.Equal(SuppressionReason.BlockedSender, suppression.Reason);
        Assert.Equal(before, suppression.RowVersion);
        Assert.All(await db.EmailOutbox.Where(x => x.ProviderMessageId == id).ToListAsync(), x => Assert.Equal(EmailStatus.Sent, x.Status));
    }

    [Fact]
    public async Task A_failure_after_suppression_write_rolls_back_the_entire_feedback_transaction()
    {
        using var sns = new SnsFixtures();
        var recipient = Recipient();
        await using var source = fixture.Open();
        await using var failing = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(source.Database.GetDbConnection().ConnectionString).AddInterceptors(new FailOutboxUpdate()).Options);
        var feedback = Assert.IsType<SesFeedback>(SesFeedback.Parse(sns.Feedback(recipient, "synthetic"), sns.Options));
        await Assert.ThrowsAsync<IOException>(() => new SesFeedbackProcessor(failing, TimeProvider.System).ApplyAsync(feedback, default));
        Assert.False(await source.Suppressions.AnyAsync(x => x.Email == recipient));
    }

    [Theory]
    [InlineData("SubscriptionConfirmation", HttpStatusCode.OK, HttpStatusCode.Accepted, 1)]
    [InlineData("SubscriptionConfirmation", HttpStatusCode.ServiceUnavailable, HttpStatusCode.ServiceUnavailable, 1)]
    [InlineData("UnsubscribeConfirmation", HttpStatusCode.OK, HttpStatusCode.Accepted, 0)]
    public async Task Explicit_confirmation_uses_only_verified_destination_and_never_resubscribes(string type, HttpStatusCode outbound, HttpStatusCode expected, int calls)
    {
        using var sns = new SnsFixtures();
        sns.Options.Sns.AutoConfirmSubscriptions = true;
        using var handler = new SnsProtocolTests.StaticHandler(() => new(outbound));
        using var client = new HttpClient(handler);
        await using var app = await Host(sns.Options, sns, () => throw new InvalidOperationException("Confirmation needs no SQL."), new SnsProtocolTests.ClientFactory(client));
        using var response = await Post(app, sns.Sign(sns.Message("Synthetic", type)));
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(calls, handler.Requests);
    }

    [Fact]
    public async Task Signed_feedback_for_other_sender_configuration_or_recipient_is_rejected()
    {
        using var sns = new SnsFixtures();
        var recipient = Recipient();
        await using var app = await Host(sns.Options, sns, () => throw new InvalidOperationException("No writes allowed."));
        var original = sns.Feedback(recipient, "synthetic");
        foreach (var wrong in new[]
        {
            original.Replace(sns.Options.FromEmail, "different@example.invalid"),
            original.Replace(sns.Options.Ses.ConfigurationSet, "other-config"),
            original.Replace("\"emailAddress\":\"" + recipient, "\"emailAddress\":\"different@example.invalid")
        })
        {
            using var response = await Post(app, sns.Sign(sns.Message(wrong)));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task Database_and_certificate_outages_return_retryable_status_with_no_private_body()
    {
        using var sns = new SnsFixtures();
        QuillSignDbContext Unavailable() => new(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer("Server=127.0.0.1,1;Database=unavailable;User Id=synthetic;Password=synthetic;Connect Timeout=1;Encrypt=true;TrustServerCertificate=true").Options);
        await using var app = await Host(sns.Options, sns, Unavailable);
        var input = sns.Sign(sns.Message(sns.Feedback(Recipient(), "synthetic")));
        using var dbFailure = await Post(app, input);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, dbFailure.StatusCode);
        Assert.Equal("", await dbFailure.Content.ReadAsStringAsync());
        sns.Failure = new FeedbackUnavailableException();
        using var certificateFailure = await Post(app, input);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, certificateFailure.StatusCode);
    }

    private sealed class FakeSes() : AmazonSimpleEmailServiceV2Client(new AnonymousAWSCredentials(), RegionEndpoint.USEast1)
    {
        public SendEmailRequest? Request { get; private set; }
        public override Task<SendEmailResponse> SendEmailAsync(SendEmailRequest request, CancellationToken cancellationToken = default)
        { Request = request; return Task.FromResult(new SendEmailResponse { MessageId = "synthetic-provider-id" }); }
    }

    private sealed class FailOutboxUpdate : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal)) throw new IOException("Synthetic connection loss.");
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }
    }
}

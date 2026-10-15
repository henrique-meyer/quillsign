using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;
using MailKit.Security;
using MimeKit;
using MimeKit.Utils;

namespace QuillSign.Email;

public sealed class SesEmailTransport(IAmazonSimpleEmailServiceV2 client, EmailOptions options) : IEmailTransport
{
    public async Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken)
    {
        var simple = new Amazon.SimpleEmailV2.Model.Message
        {
            Subject = new Content { Data = message.Subject, Charset = "UTF-8" },
            Body = new Body
            {
                Text = new Content { Data = message.Text, Charset = "UTF-8" },
                Html = new Content { Data = message.Html, Charset = "UTF-8" }
            }
        };
        if (message.EnvelopeId is { } envelope)
            simple.Headers = [new MessageHeader { Name = "X-QuillSign-Envelope", Value = envelope.ToString("N") }];
        var response = await client.SendEmailAsync(new SendEmailRequest
        {
            FromEmailAddress = new MailboxAddress(options.FromName, EmailAddress.Normalize(options.FromEmail)).ToString(),
            Destination = new Destination { ToAddresses = [message.To] },
            ConfigurationSetName = options.Ses.ConfigurationSet,
            Content = new EmailContent { Simple = simple }
        }, cancellationToken);
        if (string.IsNullOrWhiteSpace(response.MessageId)) throw new InvalidOperationException("SES returned no delivery identifier.");
        return new EmailDelivery("Ses", response.MessageId);
    }
}

public sealed class SmtpEmailTransport(EmailOptions options) : IEmailTransport
{
    public async Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken)
    {
        var mime = new MimeMessage { Subject = message.Subject, MessageId = MimeUtils.GenerateMessageId("quillsign.invalid") };
        mime.From.Add(new MailboxAddress(options.FromName, EmailAddress.Normalize(options.FromEmail)));
        mime.To.Add(new MailboxAddress("", message.To));
        if (message.EnvelopeId is { } envelope) mime.Headers.Add("X-QuillSign-Envelope", envelope.ToString("N"));
        mime.Body = new BodyBuilder { TextBody = message.Text, HtmlBody = message.Html }.ToMessageBody();
        using var smtp = new MailKit.Net.Smtp.SmtpClient { Timeout = 15000 };
        await smtp.ConnectAsync(options.Smtp.Host, options.Smtp.Port,
            options.Smtp.UseStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.None, cancellationToken);
        if (!string.IsNullOrWhiteSpace(options.Smtp.Username))
            await smtp.AuthenticateAsync(options.Smtp.Username, options.Smtp.Password, cancellationToken);
        await smtp.SendAsync(mime, cancellationToken);
        // Once DATA was accepted, a failed QUIT must not turn success into a retry.
        // Disposal closes this per-send connection without another network operation.
        return new EmailDelivery("Smtp", mime.MessageId);
    }
}

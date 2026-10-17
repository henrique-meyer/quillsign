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
        message=PdfEmailAttachments.Snapshot(message,options.Attachments,cancellationToken);
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
        var streams=new List<MemoryStream>();
        if(message.Attachments is {Count:>0}) {
            simple.Attachments=[];
            foreach(var file in message.Attachments) {
                var bytes=file.OpenRead();streams.Add(bytes);
                simple.Attachments.Add(new Attachment {FileName=file.FileName,ContentType=PdfEmailAttachment.ContentType,
                    ContentDisposition=AttachmentContentDisposition.ATTACHMENT,ContentTransferEncoding=AttachmentContentTransferEncoding.BASE64,RawContent=bytes});
            }
        }
        SendEmailResponse response;
        try { response = await client.SendEmailAsync(new SendEmailRequest
        {
            FromEmailAddress = new MailboxAddress(options.FromName, EmailAddress.Normalize(options.FromEmail)).ToString(),
            Destination = new Destination { ToAddresses = [message.To] },
            ConfigurationSetName = options.Ses.ConfigurationSet,
            Content = new EmailContent { Simple = simple }
        }, cancellationToken); }
        catch (AmazonSimpleEmailServiceV2Exception e) when ((int)e.StatusCode is >= 400 and < 500)
        { throw new EmailNotSubmittedException((int)e.StatusCode == 429 || e is TooManyRequestsException or LimitExceededException); }
        finally {foreach(var stream in streams)stream.Dispose();}
        if (string.IsNullOrWhiteSpace(response.MessageId)) throw new InvalidOperationException("SES returned no delivery identifier.");
        return new EmailDelivery("Ses", response.MessageId);
    }
}

public sealed class SmtpEmailTransport(EmailOptions options) : IEmailTransport
{
    public async Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken)
    {
        message=PdfEmailAttachments.Snapshot(message,options.Attachments,cancellationToken);
        using var mime = new MimeMessage { Subject = message.Subject, MessageId = MimeUtils.GenerateMessageId("quillsign.invalid") };
        mime.From.Add(new MailboxAddress(options.FromName, EmailAddress.Normalize(options.FromEmail)));
        mime.To.Add(new MailboxAddress("", message.To));
        if (message.EnvelopeId is { } envelope) mime.Headers.Add("X-QuillSign-Envelope", envelope.ToString("N"));
        var body=new BodyBuilder {TextBody=message.Text,HtmlBody=message.Html};
        foreach(var file in message.Attachments!) {
            var part=(MimePart)body.Attachments.Add(file.FileName,file.CopyBytes(),ContentType.Parse(PdfEmailAttachment.ContentType));
            part.ContentDisposition=new ContentDisposition(ContentDisposition.Attachment) {FileName=file.FileName};
            part.ContentTransferEncoding=ContentEncoding.Base64;
        }
        mime.Body=body.ToMessageBody();
        using var smtp = new MailKit.Net.Smtp.SmtpClient { Timeout = 15000 };
        try
        {
            await smtp.ConnectAsync(options.Smtp.Host, options.Smtp.Port,
            options.Smtp.UseStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.None, cancellationToken);
            if (!string.IsNullOrWhiteSpace(options.Smtp.Username))
                await smtp.AuthenticateAsync(options.Smtp.Username, options.Smtp.Password, cancellationToken);
        }
        catch (Exception e) when (e is IOException or System.Net.Sockets.SocketException or OperationCanceledException or MailKit.Security.AuthenticationException or MailKit.Net.Smtp.SmtpCommandException or MailKit.Net.Smtp.SmtpProtocolException)
        { throw new EmailNotSubmittedException(true); }
        try { await smtp.SendAsync(mime, cancellationToken); }
        catch (MailKit.Net.Smtp.SmtpCommandException e)
        { throw new EmailNotSubmittedException((int)e.StatusCode < 500); }
        // Once DATA was accepted, a failed QUIT must not turn success into a retry.
        // Disposal closes this per-send connection without another network operation.
        return new EmailDelivery("Smtp", mime.MessageId);
    }
}

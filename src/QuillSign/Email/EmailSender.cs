using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Email;

public sealed record OutgoingEmail(string To, string Subject, string Text, string Html, Guid? EnvelopeId = null,
    IReadOnlyList<PdfEmailAttachment>? Attachments = null);
public sealed record EmailDelivery(string Provider, string MessageId);

public interface IEmailSender
{
    Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken = default);
}

public interface IEmailTransport
{
    Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken);
}

public sealed class EmailDisabledException() : InvalidOperationException("Email delivery is disabled.");
public sealed class RecipientSuppressedException() : InvalidOperationException("Delivery is suppressed for this recipient.");
public sealed class EmailNotSubmittedException(bool retryable) : Exception("The provider did not accept this email.")
{
    public bool Retryable { get; } = retryable;
}

public sealed class EmailSender(EmailOptions options, Func<QuillSignDbContext> database, Func<IEmailTransport> transport) : IEmailSender
{
    public async Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken = default)
    {
        if (!options.Enabled) throw new EmailDisabledException();
        message=PdfEmailAttachments.Snapshot(message,options.Attachments,cancellationToken);
        var recipient = message.To;
        if (await database().Suppressions.AnyAsync(x => x.Email == recipient, cancellationToken))
            throw new RecipientSuppressedException();
        // Provider construction is deferred: disabled or suppressed sends never obtain
        // AWS credentials or open an SMTP connection. Durable retries belong to QUILS-14.
        IEmailTransport provider;
        try { provider = transport(); }
        catch (Exception e) when (e is not OperationCanceledException) { throw new EmailNotSubmittedException(true); }
        return await provider.SendAsync(message with { To = recipient }, cancellationToken);
    }
}

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
    public string FailureCode { get; } = "provider-rejected";

    // Only bounded categories can enter durable operational evidence. Never
    // retain the SDK exception, its message, request ID or arbitrary error code.
    internal EmailNotSubmittedException(bool retryable, int status, ProviderRefusalReason reason) : this(retryable)
    {
        if (status is < 400 or > 499) throw new ArgumentOutOfRangeException(nameof(status));
        var category = reason switch {
            ProviderRefusalReason.UnverifiedIdentity => "identity-unverified",
            ProviderRefusalReason.Authorization => "authorization",
            ProviderRefusalReason.AccountPaused => "account-paused",
            ProviderRefusalReason.ConfigurationPaused => "configuration-paused",
            ProviderRefusalReason.ConfigurationMissing => "configuration-missing",
            ProviderRefusalReason.ResourceMissing => "resource-missing",
            ProviderRefusalReason.MailFromUnverified => "mail-from-unverified",
            ProviderRefusalReason.Throttled => "throttled",
            ProviderRefusalReason.MessageRejected => "message-rejected",
            ProviderRefusalReason.InvalidRequest => "invalid-request",
            _ => "other"
        };
        FailureCode = FormattableString.Invariant($"provider-rejected-{status}-{category}");
    }
}

internal enum ProviderRefusalReason
{
    Other, UnverifiedIdentity, Authorization, AccountPaused, ConfigurationPaused,
    ConfigurationMissing, ResourceMissing, MailFromUnverified, Throttled, MessageRejected, InvalidRequest
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

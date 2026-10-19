using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed class EmailPilotTransportRefusedException() : InvalidOperationException("This pilot submission has no current unused authority.");

// Immutable configuration passed to the lazy provider factory, never credentials.
public sealed record EmailPilotSesSettings(string FromEmail, string FromName, string Region, string ConfigurationSet);

public interface IPreparedEmailTransport
{
    Task<EmailDelivery> SendAsync(PreparedRawMime message, CancellationToken cancellationToken);
}

// Deliberately not IEmailSender and not registered by startup. The caller must
// first commit its normal typed submission intent, then supply that owned lease.
public sealed class EmailPilotSender(EmailPilotOptions options, EmailOptions email, WorkOptions work,
    Func<EmailPilotWorkAuthority> authority, Func<EmailPilotLedger> ledger, Func<QuillSignDbContext> database,
    Func<EmailPilotSesSettings, IPreparedEmailTransport> transport, TimeProvider time)
{
    public async Task<EmailDelivery> SendAsync(WorkLease lease, OutgoingEmail message, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var settings = Settings();
        if (settings is null || lease is null || lease.Kind != WorkKind.Email) throw new EmailPilotTransportRefusedException();
        var verifier = authority();
        var scope = await verifier.ReadAsync(lease, ct);
        if (scope is null || message is null || message.EnvelopeId != scope.EnvelopeId ||
            scope.MailRole(message.To) is not (EmailPilotRole.Sender or EmailPilotRole.FirstSigner or EmailPilotRole.SecondSigner or EmailPilotRole.Recipient))
            throw new EmailPilotTransportRefusedException();
        var role = scope.MailRole(message.To);
        await DemandUnsuppressed(message.To, ct);
        // Serialize exactly once. Later accounting and SES consume this same
        // artifact; retrying this method cannot reopen the consumed attempt.
        var prepared = await PreparedRawMime.PrepareAsync(message, settings.FromEmail, settings.FromName, ct);
        if (prepared.Recipient != message.To || prepared.EnvelopeId != scope.EnvelopeId || prepared.ByteCount is < 1 or > EmailPilotLimits.MessageBytes)
            throw new EmailPilotTransportRefusedException();
        await DemandCurrent(verifier, scope, settings, ct);
        var request = new EmailPilotReservation(
            Identity("reservation", lease, null), scope.EnvelopeId, Identity("operation", lease, role),
            EmailPilotAttemptKind.Application, role, prepared.ByteCount, Convert.ToHexStringLower(prepared.Sha256));
        // This uses an isolated committed ledger transaction. Any exception,
        // including a lost commit acknowledgement, exits before the factory.
        // The same deterministic ID also fences changed bytes or role on replay.
        var outcome = await ledger().ReserveAsync(request, prepared.Recipient, ct);
        if (outcome != EmailPilotReservationOutcome.Reserved) throw new EmailPilotTransportRefusedException();
        await DemandUnsuppressed(prepared.Recipient, ct);
        await DemandCurrent(verifier, scope, settings, ct);
        ct.ThrowIfCancellationRequested();
        // Cancellation remains bounded by the original run/lease, even while a
        // client is resolving credentials or the one provider call is in flight.
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var remaining = scope.Until - time.GetUtcNow();
        if (remaining <= TimeSpan.Zero) throw new EmailPilotTransportRefusedException();
        bounded.CancelAfter(remaining);
        var provider = transport(settings);
        await DemandUnsuppressed(prepared.Recipient, bounded.Token);
        await DemandCurrent(verifier, scope, settings, bounded.Token);
        bounded.Token.ThrowIfCancellationRequested();
        // No catch/refund/retry: both definite and ambiguous failures consumed
        // this exact attempt. Durable disposition belongs to the typed handler.
        return await provider.SendAsync(prepared, bounded.Token);
    }

    private async Task DemandUnsuppressed(string recipient, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (await database().Suppressions.AsNoTracking().AnyAsync(x => x.Email == recipient, ct)) throw new RecipientSuppressedException();
    }

    private async Task DemandCurrent(EmailPilotWorkAuthority verifier, EmailPilotWorkScope scope, EmailPilotSesSettings settings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (Settings() != settings || scope.Until <= time.GetUtcNow() || !await verifier.StillCurrentAsync(scope, ct) ||
            Settings() != settings || scope.Until <= time.GetUtcNow()) throw new EmailPilotTransportRefusedException();
    }

    private EmailPilotSesSettings? Settings()
    {
        if (!options.Enabled || email.Enabled || !work.Enabled || email.Provider != "Ses" ||
            email.FromName is null || email.Ses is null ||
            email.Ses.Region is not { Length: >= 5 and <= 40 } region || !region.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-') ||
            email.Ses.ConfigurationSet is not { Length: >= 1 and <= 64 } set || !set.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-')) return null;
        try { if (email.FromEmail != EmailAddress.Normalize(email.FromEmail)) return null; }
        catch (ArgumentException) { return null; }
        return new(email.FromEmail, email.FromName, region, set);
    }

    private static Guid Identity(string purpose, WorkLease lease, EmailPilotRole? role)
    {
        var bytes = SHA256.HashData(Encoding.ASCII.GetBytes($"quillsign-pilot-email-v1:{purpose}:{lease.Id:N}:{lease.Attempt}:{role?.ToString() ?? "one-attempt"}"));
        return new Guid(bytes.AsSpan(0, 16));
    }
}

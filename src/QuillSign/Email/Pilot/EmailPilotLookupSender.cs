using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

// Separate typed path: lookup transport/work/outbox retain null EnvelopeId.
// Only authenticated immutable mapping supplies the accounting subject.
public sealed class EmailPilotLookupSender(EmailPilotOptions options, EmailOptions email, WorkOptions work,
    Func<EmailPilotLookupAccess> access, Func<EmailPilotLedger> ledger, Func<QuillSignDbContext> database,
    Func<EmailPilotSesSettings, IPreparedEmailTransport> transport, TimeProvider time)
{
    public async Task<EmailDelivery> SendAsync(WorkLease lease, OutgoingEmail message, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested(); var settings = Settings();
        if (settings is null || message is null || message.EnvelopeId is not null) throw new EmailPilotTransportRefusedException();
        var verifier = access(); var scope = await verifier.ReadWorkAsync(lease, true, ct);
        if (scope is null || message.To != scope.Manifest.Mailboxes.Sender) throw new EmailPilotTransportRefusedException();
        await Unsuppressed(message.To, ct);
        var prepared = await PreparedRawMime.PrepareAsync(message, settings.FromEmail, settings.FromName, ct);
        if (prepared.EnvelopeId is not null || prepared.Recipient != scope.Manifest.Mailboxes.Sender) throw new EmailPilotTransportRefusedException();
        await Current(verifier, scope, settings, ct);
        var reservation = new EmailPilotReservation(Identity("reservation", lease), scope.Request.SubjectEnvelopeId,
            Identity("operation", lease), EmailPilotAttemptKind.Application, EmailPilotRole.Sender,
            prepared.ByteCount, Convert.ToHexStringLower(prepared.Sha256));
        // A prior consumed/conflicting receipt is not evidence that a prior
        // invocation never called. Preserve original intent on every refusal.
        if (await ledger().ReserveAsync(reservation, prepared.Recipient, ct) != EmailPilotReservationOutcome.Reserved)
            throw new EmailPilotTransportRefusedException();
        await Unsuppressed(prepared.Recipient, ct); await Current(verifier, scope, settings, ct);
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var remaining = scope.Until - time.GetUtcNow(); if (remaining <= TimeSpan.Zero) throw new EmailPilotTransportRefusedException();
        bounded.CancelAfter(remaining); bounded.Token.ThrowIfCancellationRequested();
        var provider = transport(settings);
        await Unsuppressed(prepared.Recipient, bounded.Token); await Current(verifier, scope, settings, bounded.Token);
        bounded.Token.ThrowIfCancellationRequested();
        return await provider.SendAsync(prepared, bounded.Token);
    }
    private async Task Unsuppressed(string recipient, CancellationToken ct)
    { if (await database().Suppressions.AsNoTracking().AnyAsync(x => x.Email == recipient, ct)) throw new RecipientSuppressedException(); }
    private async Task Current(EmailPilotLookupAccess verifier, EmailPilotLookupWorkScope scope, EmailPilotSesSettings settings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (Settings() != settings || scope.Until <= time.GetUtcNow() || !await verifier.StillCurrentAsync(scope, ct) ||
            Settings() != settings || scope.Until <= time.GetUtcNow()) throw new EmailPilotTransportRefusedException();
    }
    private EmailPilotSesSettings? Settings()
    {
        if (!options.Enabled || email.Enabled || !work.Enabled || email.Provider != "Ses" || email.FromName is null || email.Ses is null ||
            email.Ses.Region is not { Length: >= 5 and <= 40 } region || !region.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-') ||
            email.Ses.ConfigurationSet is not { Length: >= 1 and <= 64 } set || !set.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-')) return null;
        try { if (EmailAddress.Normalize(email.FromEmail) != email.FromEmail) return null; } catch (ArgumentException) { return null; }
        return new(email.FromEmail, email.FromName, region, set);
    }
    private static Guid Identity(string purpose, WorkLease lease) => new(SHA256.HashData(Encoding.ASCII.GetBytes(
        EmailPilotLookupRules.Version + ":" + purpose + ":" + lease.Id.ToString("N") + ":" + lease.Attempt)).AsSpan(0, 16));
}

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Sender;

public static class InvitationResendStatement
{
    public const string Version = "sender-resend-v1";
    public const string Text = "Send a replacement invitation to the current signer. Older unused invitation links will stop working.";
    public static string Sha256 => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Text)));
}
public sealed record InvitationResendReview(Guid SignerId, string Name, string Email, string Version, Guid DocumentId, string DocumentSha256, string DisclosureSha256);
public sealed record InvitationResendPreview(string Title, InvitationResendReview Review, InvitationResendOutcome? Blocked);
public enum InvitationResendOutcome { Queued, AlreadyRequested, Unavailable, InvalidContext, InvalidConfirmation, Conflict, Closed, Busy, Capped, Suppressed }

// Trusted callers supply the protected authentication ticket's original expiry.
// The browser caller also supplies its protected review deadline and enforces
// CSRF/rate limits; form values are not authority.
public sealed class InvitationResends(QuillSignDbContext db, InvitationResendOptions options, EmailOptions email, WorkOptions work,
    InvitationResendProtection protection, SignerInvitationProtection invitations, SignerAccess access, AuditWriter audit,
    Func<IWorkSignals> signals, TimeProvider time)
{
    private readonly InvitationResendRules rules = new(db, options, protection, time);
    private bool Enabled => options.Enabled && email.Enabled && work.Enabled;
    public async Task<InvitationResendReview?> ReviewAsync(ClaimsPrincipal sender, string publicId, DateTimeOffset ticketExpiresAt, CancellationToken ct = default)
        => (await ReadAsync(sender, publicId, ticketExpiresAt, false, ct))?.Review;
    public Task<InvitationResendPreview?> PreviewAsync(ClaimsPrincipal sender, string publicId, DateTimeOffset ticketExpiresAt, CancellationToken ct = default)
        => ReadAsync(sender, publicId, ticketExpiresAt, true, ct);
    private async Task<InvitationResendPreview?> ReadAsync(ClaimsPrincipal sender, string publicId, DateTimeOffset ticketExpiresAt, bool availability, CancellationToken ct)
    {
        options.Validate(); if (!Enabled) return null;
        var identity = SendDraftWorkflow.Identity(sender, publicId); if (identity is null || ticketExpiresAt <= time.GetUtcNow()) return null;
        Clean(); await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var scope = await ScopeAsync(identity.Value.Id, identity.Value.Email, publicId, ct); if (scope is null) return null;
        InvitationResendOutcome? blocked = null;
        if (availability) {
            await InvitationResendRules.VerifyIndexAsync(db, scope.Value.Envelope.Id, ct);
            if (scope.Value.Deadline < InvitationResendProtection.DayEnd(time.GetUtcNow())) blocked = InvitationResendOutcome.Unavailable;
            else if (await db.Suppressions.AnyAsync(x => x.Email == scope.Value.Context.Identity.Email, ct)) blocked = InvitationResendOutcome.Suppressed;
            else if (await PreviousAsync(scope.Value.Context, ct) is null) blocked = InvitationResendOutcome.Busy;
        }
        if (ticketExpiresAt <= time.GetUtcNow() || scope.Value.Envelope.ExpiresAt <= time.GetUtcNow()) return null;
        DocumentRetentionAccess.Check(scope.Value.Deadline, time);
        await tx.CommitAsync(ct); DocumentRetentionAccess.Check(scope.Value.Deadline, time);
        return Enabled && ticketExpiresAt > time.GetUtcNow() ? new(scope.Value.Envelope.Title!, Review(scope.Value), blocked) : null;
    }
    public async Task<InvitationResendOutcome> RequestAsync(ClaimsPrincipal sender, string publicId, DateTimeOffset ticketExpiresAt,
        Guid requestId, InvitationResendReview reviewed, bool confirmed, string? statementVersion, string? ip, string? userAgent, CancellationToken ct = default,
        DateTimeOffset? reviewExpiresAt = null)
    {
        options.Validate(); if (!Enabled) return InvitationResendOutcome.Unavailable;
        var identity = SendDraftWorkflow.Identity(sender, publicId);
        if (identity is null || ticketExpiresAt <= time.GetUtcNow()) return InvitationResendOutcome.InvalidContext;
        if (!confirmed || statementVersion != InvitationResendStatement.Version) return InvitationResendOutcome.InvalidConfirmation;
        if (requestId == Guid.Empty || reviewed is null || !InvitationResendProtection.RowVersion(reviewed.Version)) return InvitationResendOutcome.Conflict;
        if (reviewExpiresAt <= time.GetUtcNow() || reviewExpiresAt > ticketExpiresAt) return InvitationResendOutcome.Conflict;
        var ipHash = InvitationResendProtection.IpHash(ip); Clean();
        try { return await CoreAsync(identity.Value.Id, identity.Value.Email, publicId, ticketExpiresAt.ToUniversalTime(), requestId, reviewed, ipHash, ip, userAgent, reviewExpiresAt?.ToUniversalTime(), ct); }
        finally { db.ChangeTracker.Clear(); }
    }
    private async Task<InvitationResendOutcome> CoreAsync(Guid envelopeId, string senderEmail, string publicId, DateTimeOffset until,
        Guid id, InvitationResendReview reviewed, string ipHash, string? ip, string? ua, DateTimeOffset? reviewExpiresAt, CancellationToken ct)
    {
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        InvitationResendOutcome outcome;
        await using (var tx = await db.Database.BeginTransactionAsync(ct)) {
            var scope = await ScopeAsync(envelopeId, senderEmail, publicId, ct); if (scope is null) return InvitationResendOutcome.Closed;
            await InvitationResendRules.VerifyIndexAsync(db, envelopeId, ct);
            if (Review(scope.Value) != reviewed) return InvitationResendOutcome.Conflict;
            await InvitationResendRules.LockAsync(db, ct);
            var existing = await rules.FindAsync(id, envelopeId, ct);
            if (existing is not null) {
                var p = existing.Mail.Request;
                if (p.SignerId != reviewed.SignerId || p.SenderEmail != senderEmail || p.IpHash != ipHash || p.SenderTicketExpiresAt != until ||
                    p.DocumentId != reviewed.DocumentId || p.DocumentSha256 != reviewed.DocumentSha256 || p.DisclosureSha256 != reviewed.DisclosureSha256 || p.ReviewedVersion != reviewed.Version)
                    return InvitationResendOutcome.Conflict;
                outcome = InvitationResendOutcome.AlreadyRequested;
            } else {
                if (await db.WorkItems.AnyAsync(x => x.Id == id, ct) || await db.EmailOutbox.AnyAsync(x => x.Id == id, ct)) return InvitationResendOutcome.Conflict;
                if (await db.Suppressions.AnyAsync(x => x.Email == reviewed.Email, ct)) return InvitationResendOutcome.Suppressed;
                var previous = await PreviousAsync(scope.Value.Context, ct); if (previous is null) return InvitationResendOutcome.Busy;
                var now = time.GetUtcNow(); var counterUntil = InvitationResendProtection.DayEnd(now);
                // Purge must not erase a daily cap reservation before that day ends.
                if (scope.Value.Deadline < counterUntil) return InvitationResendOutcome.Unavailable;
                var deadline = counterUntil;
                if (scope.Value.Envelope.ExpiresAt is { } expires && expires < deadline) deadline = expires;
                if (scope.Value.Deadline is { } retention && retention < deadline) deadline = retention;
                if (deadline <= now) return InvitationResendOutcome.Closed;
                var request = new ResendRequest("resend-request-v1", id, envelopeId, reviewed.SignerId, previous.Value, reviewed.Email, senderEmail, ipHash,
                    reviewed.Version, reviewed.DocumentId, reviewed.DocumentSha256, reviewed.DisclosureSha256, now, until, deadline, counterUntil);
                if (!await rules.WithinCapsAsync(request, false, ct)) return InvitationResendOutcome.Capped;
                db.EmailOutbox.Add(new() { Id = id, EnvelopeId = envelopeId, To = reviewed.Email, Template = InvitationResendProtection.Template,
                    AvailableAt = now, PayloadJson = protection.Protect(new(request)) });
                db.WorkItems.Add(new() { Id = id, EnvelopeId = envelopeId, Kind = WorkKind.Email, AvailableAt = now, PayloadJson = JsonSerializer.Serialize(new { emailId = id }) });
                await db.SaveChangesAsync(ct);
                await db.AuthTokens.Where(x => x.EnvelopeId == envelopeId && x.PartyId == reviewed.SignerId && x.PartyType == PartyType.Signer &&
                    x.Purpose == TokenPurpose.SignerAccess && x.UsedAt == null && x.ExpiresAt > now).ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, now), ct);
                await audit.AppendAsync(envelopeId, InvitationResendProtection.Event, senderEmail, ip, ua, ct, InvitationResendProtection.Evidence(request));
                await signals().PutHintAsync(id, now, ct); outcome = InvitationResendOutcome.Queued;
            }
            if (!Enabled) return InvitationResendOutcome.Unavailable;
            if (until <= time.GetUtcNow()) return InvitationResendOutcome.InvalidContext;
            DocumentRetentionAccess.Check(scope.Value.Deadline, time);
            if (scope.Value.Envelope.ExpiresAt <= time.GetUtcNow()) return InvitationResendOutcome.Closed;
            var saved = await rules.FindAsync(id, envelopeId, ct) ?? throw InvitationResendRules.Invalid();
            if (saved.Mail.Request.Deadline <= time.GetUtcNow()) return InvitationResendOutcome.Closed;
            if (reviewExpiresAt <= time.GetUtcNow()) return InvitationResendOutcome.Conflict;
            await tx.CommitAsync(ct);
        }
        try { await signals().PublishAsync(id, TimeSpan.Zero, ct); }
        catch (Exception e) when (e is Azure.RequestFailedException or IOException or OperationCanceledException or HttpRequestException) { /* The committed hint recovers. */ }
        return outcome;
    }
    private async Task<Guid?> PreviousAsync(SignerReadContext context, CancellationToken ct)
    {
        var latest = await rules.LatestAsync(context.Identity.EnvelopeId, context.Identity.SignerId, ct);
        if (latest is not null) {
            if (latest.Mail.Request.DocumentId != context.Identity.DocumentId || latest.Mail.Request.DocumentSha256 != context.Identity.DocumentHash ||
                latest.Mail.Request.DisclosureSha256 != context.Identity.DisclosureHash || latest.Mail.Request.Email != context.Identity.Email) throw InvitationResendRules.Invalid();
            return await rules.SettledAsync(latest.Row, latest.Work, context.Identity.SignerId, context.Identity.DocumentHash, context.Identity.DisclosureHash, latest.Mail.Issued?.Id, ct) ? latest.Row.Id : null;
        }
        var rows = await db.EmailOutbox.AsNoTracking().Where(x => x.EnvelopeId == context.Identity.EnvelopeId && x.To == context.Identity.Email && x.Template == "signer-invitation").Take(2).ToArrayAsync(ct);
        if (rows.Length != 1) return null;
        var row = rows[0]; var p = invitations.Read(row.PayloadJson);
        if (p.SignerId != context.Identity.SignerId || p.DocumentId != context.Identity.DocumentId || p.DocumentSha256 != context.Identity.DocumentHash ||
            p.DisclosureSha256 != context.Identity.DisclosureHash || row.AttachmentsJson != "[]") throw InvitationResendRules.Invalid();
        var item = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == row.Id, ct);
        return item is not null && await rules.SettledAsync(row, item, p.SignerId, context.Identity.DocumentHash, context.Identity.DisclosureHash, p.LastTokenId, ct) ? row.Id : null;
    }
    private async Task<(Envelope Envelope, SignerReadContext Context, DateTimeOffset? Deadline)?> ScopeAsync(Guid id, string email, string publicId, CancellationToken ct)
    {
        var envelope = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (envelope is null || envelope.SenderEmail != email || envelope.PublicId != publicId || envelope.SenderVerifiedAt is null ||
            envelope.Status != EnvelopeStatus.Sent || envelope.ExpiresAt <= time.GetUtcNow()) return null;
        var deadline = await SenderPreparationRetention.ReadAsync(db, envelope, time, ct);
        _ = await SenderSentStatus.ReadSentAsync(db, envelope, null, ct);
        var current = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == id && x.Status != SignerStatus.Signed).OrderBy(x => x.Order).FirstOrDefaultAsync(ct);
        if (current is null) return null;
        var context = await access.GetEligibleLockedAsync(id, current.Id, ct);
        return context is null ? null : (envelope, context, deadline);
    }
    private static InvitationResendReview Review((Envelope Envelope, SignerReadContext Context, DateTimeOffset? Deadline) scope) => new(scope.Context.Identity.SignerId,
        scope.Context.SignerName, scope.Context.Identity.Email, Convert.ToBase64String(scope.Envelope.RowVersion), scope.Context.Identity.DocumentId,
        scope.Context.Identity.DocumentHash, scope.Context.Identity.DisclosureHash);
    private void Clean() { if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Invitation resend requires a clean standalone unit of work."); }
}

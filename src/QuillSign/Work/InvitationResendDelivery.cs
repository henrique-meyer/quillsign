using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;

namespace QuillSign.Work;

public sealed class InvitationResendDelivery(QuillSignDbContext db, InvitationResendOptions options, InvitationResendProtection protection,
    SignerAccess access, SignerInvitationFactory tokens, SignerInvitationTemplate template, IEmailSender sender,
    EmailOptions email, WorkOptions work, AuditWriter audit, TimeProvider time)
{
    private readonly InvitationResendRules rules = new(db, options, protection, time);
    private bool Enabled => options.Enabled && email.Enabled && work.Enabled;

    public async Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken ct)
    {
        options.Validate(); if (!Enabled) return new(WorkOutcome.Retry, "delivery-disabled");
        ResendRequest p; ResendToken issued; OutgoingEmail outgoing; DateTimeOffset intentAt; string intentPayload;
        var committing = false;
        try {
            var located = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == lease.Id, ct) ?? throw Invalid();
            p = protection.Read(located).Request;
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var parent = await ParentAsync(p.EnvelopeId, ct);
            await InvitationResendRules.LockAsync(db, ct);
            var current = await OwnedAsync(lease, p, null, ct);
            var context = await PolicyAsync(parent, p, ct);
            var expires = parent.ExpiresAt;
            var retention = await DocumentRetentionAccess.ReadAsync(db, parent, ct);
            if (retention is { } end && (expires is null || end < expires)) expires = end;
            var invitation = tokens.Create(p.EnvelopeId, p.SignerId, p.Email, expires, p.DocumentId, context.DocumentSha256, context.Disclosure.Sha256);
            outgoing = await template.RenderAsync(context, parent.Message, invitation.RawToken, invitation.Record.ExpiresAt, ct);
            _ = await PolicyAsync(parent, p, ct); // Slow rendering cannot cross a policy/authority boundary.
            if (lease.Until <= time.GetUtcNow() || invitation.Record.ExpiresAt <= time.GetUtcNow()) throw Invalid();
            issued = new(invitation.Record.Id, Convert.ToHexStringLower(invitation.Record.TokenSha256), invitation.Record.ExpiresAt);
            intentAt = time.GetUtcNow(); intentPayload = protection.Protect(new(p, issued));
            var changed = await db.EmailOutbox.Where(x => x.Id == p.Id && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt, intentAt).SetProperty(x => x.Attempts, lease.Attempt)
                    .SetProperty(x => x.PayloadJson, intentPayload), ct);
            if (changed != 1) throw Invalid();
            db.AuthTokens.Add(invitation.Record); await db.SaveChangesAsync(ct);
            if (!Enabled || p.Deadline <= time.GetUtcNow() || lease.Until <= time.GetUtcNow() || issued.ExpiresAt <= time.GetUtcNow()) throw Invalid();
            committing = true; await tx.CommitAsync(ct);
        }
        catch (CryptographicException) when (!committing) { return new(WorkOutcome.Retry, "resend-payload-unavailable"); }
        catch (InvalidDataException) when (!committing) { return new(WorkOutcome.Failed, "resend-scope-unavailable"); }
        // An unknown commit acknowledgement propagates with no provider call.
        if (!Enabled || p.Deadline <= time.GetUtcNow() || lease.Until <= time.GetUtcNow() || issued.ExpiresAt <= time.GetUtcNow()) {
            await ClearAsync(lease, p, issued, intentAt, intentPayload, ct);
            return new(Enabled ? WorkOutcome.Failed : WorkOutcome.Retry, Enabled ? "resend-expired" : "delivery-disabled");
        }
        EmailDelivery delivery;
        try { delivery = await sender.SendAsync(outgoing, ct); }
        catch (EmailNotSubmittedException e) {
            await ClearAsync(lease, p, issued, intentAt, intentPayload, ct);
            return new(e.Retryable ? WorkOutcome.Retry : WorkOutcome.Failed, "provider-rejected");
        }
        catch (Exception e) when (e is RecipientSuppressedException or EmailDisabledException) {
            await ClearAsync(lease, p, issued, intentAt, intentPayload, ct);
            return new(WorkOutcome.Failed, e is RecipientSuppressedException ? "recipient-suppressed" : "delivery-disabled");
        }
        // Unknown provider/receipt outcomes retain the exact protected intent.
        // WorkStore settles ambiguous submissions without replaying transport.
        await ReceiptAsync(lease, p, issued, intentAt, intentPayload, delivery, ct);
        return new(WorkOutcome.Completed);
    }
    private async Task<SignerReadContext> PolicyAsync(Envelope parent, ResendRequest p, CancellationToken ct)
    {
        if (!Enabled || p.RequestedAt > time.GetUtcNow() || p.Deadline <= time.GetUtcNow() || parent.Status != EnvelopeStatus.Sent ||
            parent.SenderEmail != p.SenderEmail || Convert.ToBase64String(parent.RowVersion) != p.ReviewedVersion || parent.ExpiresAt <= time.GetUtcNow()) throw Invalid();
        _ = await SenderSentStatus.ReadSentAsync(db, parent, null, ct);
        var retention = await DocumentRetentionAccess.ReadAsync(db, parent, ct);
        if (retention < p.CounterUntil || retention <= time.GetUtcNow()) throw Invalid();
        var context = await access.GetEligibleLockedAsync(p.EnvelopeId, p.SignerId, ct) ?? throw Invalid();
        if (context.Identity.Email != p.Email || context.Identity.DocumentId != p.DocumentId || context.Identity.DocumentHash != p.DocumentSha256 ||
            context.Identity.DisclosureHash != p.DisclosureSha256 || await db.Suppressions.AnyAsync(x => x.Email == p.Email, ct)) throw Invalid();
        var latest = await rules.LatestAsync(p.EnvelopeId, p.SignerId, ct) ?? throw Invalid();
        if (latest.Mail.Request != p || !await rules.WithinCapsAsync(p, true, ct)) throw Invalid();
        return context;
    }
    private async Task<Envelope> ParentAsync(Guid id, CancellationToken ct) => await db.Envelopes
        .FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct) ?? throw Invalid();

    private async Task<ResendSaved> OwnedAsync(WorkLease lease, ResendRequest p, DateTimeOffset? intent, CancellationToken ct)
    {
        var owned = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (lease.Kind != WorkKind.Email || lease.Id != p.Id || owned is null || owned.Kind != WorkKind.Email || owned.EnvelopeId != p.EnvelopeId ||
            owned.Status != WorkStatus.Leased || owned.LeaseOwner != lease.Owner || owned.LeaseExpiresAt != lease.Until || owned.Attempts != lease.Attempt ||
            owned.PayloadJson != JsonSerializer.Serialize(new { emailId = p.Id }) || lease.Until <= time.GetUtcNow())
            throw new InvalidOperationException("Invitation resend lease is no longer owned.");
        var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct) ?? throw Invalid();
        var mail = protection.Read(row);
        if (mail.Request != p || row.Status != EmailStatus.Queued || row.SubmissionStartedAt != intent || row.Attempts > lease.Attempt ||
            intent is null && mail.Issued is not null || intent is not null && (mail.Issued is null || row.Attempts != lease.Attempt)) throw Invalid();
        return new(row, owned, mail);
    }
    private async Task ClearAsync(WorkLease lease, ResendRequest p, ResendToken issued, DateTimeOffset intentAt, string intentPayload, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        _ = await ParentAsync(p.EnvelopeId, ct); await InvitationResendRules.LockAsync(db, ct);
        var current = await OwnedAsync(lease, p, intentAt, ct);
        if (current.Row.PayloadJson != intentPayload || current.Mail.Issued != issued) throw Invalid();
        var token = await db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={issued.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (token is null || token.EnvelopeId != p.EnvelopeId || token.PartyType != PartyType.Signer || token.PartyId != p.SignerId || token.Email != p.Email ||
            token.Purpose != TokenPurpose.SignerAccess || token.UsedAt is not null || token.DocumentId != p.DocumentId || token.ExpiresAt != issued.ExpiresAt ||
            token.DocumentSha256 is null || Convert.ToHexStringLower(token.DocumentSha256) != p.DocumentSha256 || token.DisclosureSha256 is null ||
            Convert.ToHexStringLower(token.DisclosureSha256) != p.DisclosureSha256 || Convert.ToHexStringLower(token.TokenSha256) != issued.Sha256) throw Invalid();
        await db.AuthTokens.Where(x => x.Id == issued.Id && x.ExpiresAt > time.GetUtcNow()).ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, time.GetUtcNow()), ct);
        await db.EmailOutbox.Where(x => x.Id == p.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt, (DateTimeOffset?)null)
            .SetProperty(x => x.PayloadJson, protection.Protect(new(p))), ct);
        await tx.CommitAsync(ct);
    }
    private async Task ReceiptAsync(WorkLease lease, ResendRequest p, ResendToken issued, DateTimeOffset intentAt, string intentPayload, EmailDelivery delivered, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(delivered.Provider) || string.IsNullOrWhiteSpace(delivered.MessageId)) throw Invalid();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        _ = await ParentAsync(p.EnvelopeId, ct); // Never recreate rows after purge.
        var owned = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (owned is null || owned.Kind != WorkKind.Email || owned.EnvelopeId != p.EnvelopeId || owned.Attempts != lease.Attempt || row is null ||
            row.EnvelopeId != p.EnvelopeId || row.Template != InvitationResendProtection.Template || row.To != p.Email || row.PayloadJson != intentPayload ||
            row.SubmissionStartedAt != intentAt || row.Attempts != lease.Attempt) throw Invalid();
        await db.EmailOutbox.Where(x => x.Id == p.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Provider, delivered.Provider)
            .SetProperty(x => x.ProviderMessageId, delivered.MessageId).SetProperty(x => x.Status, x => x.Status == EmailStatus.Queued ? EmailStatus.Sent : x.Status), ct);
        await db.Signers.Where(x => x.Id == p.SignerId && x.EnvelopeId == p.EnvelopeId && x.Email == p.Email && x.Status == SignerStatus.Pending)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, SignerStatus.Notified), ct);
        await audit.AppendAsync(p.EnvelopeId, "invitation_resend_submitted", null, null, null, ct, JsonSerializer.Serialize(new {
            emailId = p.Id, tokenId = issued.Id, documentSha256 = p.DocumentSha256, disclosureSha256 = p.DisclosureSha256,
            signerId = p.SignerId, recipient = p.Email, provider = delivered.Provider, providerMessageId = delivered.MessageId,
            meaning = "provider_accepted_not_proof_of_delivery" }), PartyType.System);
        await tx.CommitAsync(ct);
    }
    private static InvalidDataException Invalid() => InvitationResendProtection.Invalid();
}

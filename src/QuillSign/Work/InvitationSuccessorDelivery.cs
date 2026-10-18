using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Signing;

namespace QuillSign.Work;

public sealed class InvitationSuccessorDelivery(QuillSignDbContext db, InvitationSuccessorProtection protection,
    InvitationSuccessorJobs jobs, InvitationLineage lineage, SignerAccess access, SignerInvitationFactory tokens,
    SignerInvitationTemplate template, IEmailSender sender, EmailOptions email, WorkOptions work, AuditWriter audit, TimeProvider time)
{
    public async Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken ct)
    {
        if (!email.Enabled || !work.Enabled) return new(WorkOutcome.Retry, "delivery-disabled");
        InvitationSuccessorScope p; InvitationSuccessorToken issued; DateTimeOffset intent; string intentPayload; OutgoingEmail outgoing;
        var committing = false;
        try
        {
            var located = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == lease.Id, ct) ?? throw Invalid();
            p = protection.Read(located).Scope;
            var policy = jobs.Policy(p.Reason);
            if (policy is null || !policy.Enabled) return new(WorkOutcome.Retry, "successor-delivery-disabled");
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var parent = await ParentAsync(p.EnvelopeId, ct);
            await OwnedAsync(lease, p, null, null, ct);
            var context = await PolicyAsync(parent, p, ct);
            var expires = parent.ExpiresAt;
            var retention = await DocumentRetentionAccess.ReadAsync(db, parent, ct);
            if (retention is { } end && (expires is null || end < expires)) expires = end;
            var invitation = tokens.Create(p.EnvelopeId, p.SignerId, p.Recipient, expires, p.DocumentId,
                context.DocumentSha256, context.Disclosure.Sha256, p.Contact.Number == 0 ? null : p.Contact.RevisionId);
            outgoing = await template.RenderAsync(context, parent.Message, invitation.RawToken, invitation.Record.ExpiresAt, ct, p.Reason);
            _ = await PolicyAsync(parent, p, ct);
            await OwnedAsync(lease, p, null, null, ct);
            if (lease.Until <= time.GetUtcNow() || invitation.Record.ExpiresAt <= time.GetUtcNow()) throw Invalid();
            intent = time.GetUtcNow(); issued = new(invitation.Record.Id, Convert.ToHexStringLower(invitation.Record.TokenSha256), invitation.Record.ExpiresAt);
            intentPayload = protection.Protect(new(p, issued));
            var changed = await db.EmailOutbox.Where(x => x.Id == p.Id && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt, intent).SetProperty(x => x.Attempts, lease.Attempt)
                    .SetProperty(x => x.PayloadJson, intentPayload), ct);
            if (changed != 1) throw Invalid();
            // Same-contact replacement preserves used tokens and redeemed
            // sessions. Contact correction separately retires old authority.
            await db.AuthTokens.Where(x => x.EnvelopeId == p.EnvelopeId && x.PartyId == p.SignerId && x.PartyType == PartyType.Signer &&
                x.Purpose == TokenPurpose.SignerAccess && x.UsedAt == null && x.ExpiresAt > intent)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, intent), ct);
            db.AuthTokens.Add(invitation.Record); await db.SaveChangesAsync(ct);
            if (!Enabled(p) || p.Deadline <= time.GetUtcNow() || lease.Until <= time.GetUtcNow() || issued.ExpiresAt <= time.GetUtcNow()) throw Invalid();
            committing = true; await tx.CommitAsync(ct);
        }
        catch (CryptographicException) when (!committing) { return new(WorkOutcome.Retry, "successor-payload-unavailable"); }
        catch (InvalidDataException) when (!committing) { return new(WorkOutcome.Failed, "successor-scope-unavailable"); }
        // Unknown commit acknowledgement makes no provider call and retains any
        // committed intent. WorkStore never submits that intent a second time.
        if (!Enabled(p) || p.Deadline <= time.GetUtcNow() || lease.Until <= time.GetUtcNow() || issued.ExpiresAt <= time.GetUtcNow())
        {
            await ClearAsync(lease, p, issued, intent, intentPayload, ct);
            return new(Enabled(p) ? WorkOutcome.Failed : WorkOutcome.Retry, Enabled(p) ? "successor-expired" : "delivery-disabled");
        }
        EmailDelivery delivered;
        try { delivered = await sender.SendAsync(outgoing, ct); }
        catch (EmailNotSubmittedException e)
        {
            await ClearAsync(lease, p, issued, intent, intentPayload, ct);
            return new(e.Retryable ? WorkOutcome.Retry : WorkOutcome.Failed, "provider-rejected");
        }
        catch (Exception e) when (e is RecipientSuppressedException or EmailDisabledException)
        {
            await ClearAsync(lease, p, issued, intent, intentPayload, ct);
            return new(WorkOutcome.Failed, e is RecipientSuppressedException ? "recipient-suppressed" : "delivery-disabled");
        }
        await ReceiptAsync(lease, p, issued, intent, intentPayload, delivered, ct);
        return new(WorkOutcome.Completed);
    }

    private bool Enabled(InvitationSuccessorScope p) => email.Enabled && work.Enabled && jobs.Policy(p.Reason)?.Enabled == true;
    private async Task<SignerReadContext> PolicyAsync(Envelope parent, InvitationSuccessorScope p, CancellationToken ct)
    {
        if (!Enabled(p) || parent.Status != EnvelopeStatus.Sent || parent.SenderEmail != p.SenderEmail || p.AdmittedAt > time.GetUtcNow() ||
            p.Deadline <= time.GetUtcNow() || parent.ExpiresAt <= time.GetUtcNow()) throw Invalid();
        var contacts = await new SignerContactState(db, time).ReadHistoryLockedAsync(parent, ct);
        var current = contacts.Current.SingleOrDefault(x => x.Id == p.SignerId);
        if (current is null || current.Epoch != p.Contact || current.Email != p.Recipient) throw Invalid();
        var history = await lineage.ReadLockedAsync(parent, p.SignerId, contacts, ct);
        if (history is null || history.Latest.Id != p.Id || history.Latest.Recipient != p.Recipient) throw Invalid();
        var context = await access.GetEligibleLockedAsync(p.EnvelopeId, p.SignerId, ct) ?? throw Invalid();
        if (context.Identity.Email != p.Recipient || context.Identity.DocumentId != p.DocumentId || context.Identity.DocumentHash != p.DocumentSha256 ||
            context.Identity.DisclosureHash != p.DisclosureSha256 || await db.Suppressions.AnyAsync(x => x.Email == p.Recipient, ct) ||
            !await jobs.Policy(p.Reason)!.ValidateLockedAsync(parent, p, ct)) throw Invalid();
        var retention = await DocumentRetentionAccess.ReadAsync(db, parent, ct);
        if (retention < new DateTimeOffset(p.AdmittedAt.UtcDateTime.Date, TimeSpan.Zero).AddDays(1)) throw Invalid();
        DocumentRetentionAccess.Check(retention, time);
        return context;
    }
    private async Task<Envelope> ParentAsync(Guid id, CancellationToken ct) => await db.Envelopes
        .FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct) ?? throw Invalid();
    private async Task OwnedAsync(WorkLease lease, InvitationSuccessorScope p, DateTimeOffset? intent, string? payload, CancellationToken ct)
    {
        var item = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (lease.Kind != WorkKind.Email || lease.Id != p.Id || item is null || row is null || item.EnvelopeId != p.EnvelopeId || item.Kind != WorkKind.Email ||
            item.Status != WorkStatus.Leased || item.LeaseOwner != lease.Owner || item.LeaseExpiresAt != lease.Until || item.Attempts != lease.Attempt ||
            item.PayloadJson != JsonSerializer.Serialize(new { emailId = p.Id }) || lease.Until <= time.GetUtcNow() || row.Status != EmailStatus.Queued ||
            row.SubmissionStartedAt != intent || row.Attempts > lease.Attempt || payload is not null && row.PayloadJson != payload) throw Invalid();
        var saved = protection.Read(row);
        if (saved.Scope != p || intent is null && saved.Issued is not null || intent is not null && (saved.Issued is null || row.Attempts != lease.Attempt)) throw Invalid();
    }
    private async Task ClearAsync(WorkLease lease, InvitationSuccessorScope p, InvitationSuccessorToken issued, DateTimeOffset intent, string payload, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct); _ = await ParentAsync(p.EnvelopeId, ct);
        await OwnedAsync(lease, p, intent, payload, ct);
        var token = await db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={issued.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (token is null || token.EnvelopeId != p.EnvelopeId || token.PartyId != p.SignerId || token.PartyType != PartyType.Signer || token.Email != p.Recipient ||
            token.Purpose != TokenPurpose.SignerAccess || token.DocumentId != p.DocumentId || token.ExpiresAt != issued.ExpiresAt ||
            token.SignerContactRevisionId != (p.Contact.Number == 0 ? (Guid?)null : p.Contact.RevisionId) || token.DocumentSha256 is not { Length: 32 } ||
            Convert.ToHexStringLower(token.DocumentSha256) != p.DocumentSha256 || token.DisclosureSha256 is not { Length: 32 } ||
            Convert.ToHexStringLower(token.DisclosureSha256) != p.DisclosureSha256 || Convert.ToHexStringLower(token.TokenSha256) != issued.Sha256) throw Invalid();
        await db.AuthTokens.Where(x => x.Id == token.Id && x.UsedAt == null && x.ExpiresAt > time.GetUtcNow()).ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, time.GetUtcNow()), ct);
        await db.EmailOutbox.Where(x => x.Id == p.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt, (DateTimeOffset?)null)
            .SetProperty(x => x.PayloadJson, protection.Protect(new(p))), ct);
        await tx.CommitAsync(ct);
    }
    private async Task ReceiptAsync(WorkLease lease, InvitationSuccessorScope p, InvitationSuccessorToken issued, DateTimeOffset intent,
        string payload, EmailDelivery delivered, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(delivered.Provider) || string.IsNullOrWhiteSpace(delivered.MessageId)) throw Invalid();
        await using var tx = await db.Database.BeginTransactionAsync(ct); _ = await ParentAsync(p.EnvelopeId, ct);
        var item = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={p.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={p.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (item is null || row is null || item.Kind != WorkKind.Email || item.EnvelopeId != p.EnvelopeId || item.Attempts != lease.Attempt ||
            row.PayloadJson != payload || row.SubmissionStartedAt != intent || row.Attempts != lease.Attempt || protection.Read(row).Scope != p) throw Invalid();
        await db.EmailOutbox.Where(x => x.Id == p.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Provider, delivered.Provider)
            .SetProperty(x => x.ProviderMessageId, delivered.MessageId).SetProperty(x => x.Status, x => x.Status == EmailStatus.Queued ? EmailStatus.Sent : x.Status), ct);
        await db.Signers.Where(x => x.Id == p.SignerId && x.EnvelopeId == p.EnvelopeId && x.Email == p.Recipient && x.Status == SignerStatus.Pending)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, SignerStatus.Notified), ct);
        await audit.AppendAsync(p.EnvelopeId, InvitationSuccessorProtection.ReceiptEvent, null, null, null, ct, JsonSerializer.Serialize(new {
            emailId = p.Id, tokenId = issued.Id, documentSha256 = p.DocumentSha256, disclosureSha256 = p.DisclosureSha256,
            signerId = p.SignerId, recipient = p.Recipient, contact = p.Contact, provider = delivered.Provider,
            providerMessageId = delivered.MessageId, meaning = "provider_accepted_not_proof_of_delivery" }), PartyType.System);
        await tx.CommitAsync(ct);
    }
    private static InvalidDataException Invalid() => InvitationSuccessorProtection.Invalid();
}

using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Work;

public sealed class LookupLinkDelivery(QuillSignDbContext db, LookupDeliveryOptions limits, LookupDeliveryProtection protection,
    DocumentLookupProtection links, Func<DocumentLookup> lookup, Func<LookupEmailTemplate> template, IEmailSender sender,
    EmailOptions emailOptions, WorkOptions workOptions, TimeProvider time, LookupContactRetention retention)
{
    private bool Enabled => emailOptions.Enabled && workOptions.Enabled;
    public async Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken ct)
    {
        if (!Enabled) return new(WorkOutcome.Retry, "delivery-disabled");
        limits.Validate(); LookupMailPayload request; DocumentLookupLink link; LookupIssuedToken binding; OutgoingEmail outgoing; LookupContactRetentionSnapshot policy;
        try {
            await using (var tx = await db.Database.BeginTransactionAsync(ct)) {
                await LookupDeliveryRules.LockAsync(db, ct);
                var owned = await OwnedAsync(lease, null, ct); request = owned.Payload;
                policy = await retention.ReadAsync(owned.Row, ct);
                if (await PolicyAsync(request, policy, ct) is { } stopped) return stopped;
                await tx.CommitAsync(ct);
            }
            // Issuance owns a separate transaction. No transport leaves this worker
            // unless the later exact submission intent commits and remains valid.
            link = await lookup().IssueAsync(request.Email, ct);
            var issued = links.Link(link.Transport) ?? throw Invalid();
            binding = new(issued.TokenId, issued.TokenRevision, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(issued.RawToken))), issued.ExpiresAt);
            outgoing = await template().RenderAsync(request.Email, link, ct);
        }
        catch (CryptographicException) { return new(WorkOutcome.Retry, "lookup-payload-unavailable"); }
        catch (Exception e) when (e is InvalidDataException or ArgumentException) { return new(WorkOutcome.Failed, "lookup-scope-unavailable"); }

        DateTimeOffset intentAt; string intentPayload;
        try {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await LookupDeliveryRules.LockAsync(db, ct);
            var current = await OwnedAsync(lease, null, ct);
            if (current.Payload != request) throw Invalid();
            policy = await retention.ReadAsync(current.Row, ct);
            if (await PolicyAsync(request, policy, ct) is { } stopped) return stopped;
            await TokenAsync(binding, ct);
            intentAt = time.GetUtcNow(); if (lease.Until <= intentAt || binding.ExpiresAt <= intentAt) throw Invalid();
            intentPayload = protection.Protect(request with { Issued = binding });
            var changed = await db.EmailOutbox.Where(x => x.Id == lease.Id && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt, intentAt).SetProperty(x => x.Attempts, lease.Attempt)
                    .SetProperty(x => x.PayloadJson, intentPayload), ct);
            if (changed != 1) throw Invalid();
            if (lease.Until <= time.GetUtcNow() || Deadline(request, policy) <= time.GetUtcNow() || binding.ExpiresAt <= time.GetUtcNow()) throw Invalid();
            await tx.CommitAsync(ct);
        }
        catch (CryptographicException) { return new(WorkOutcome.Retry, "lookup-payload-unavailable"); }
        catch (InvalidDataException) { return new(WorkOutcome.Failed, "lookup-scope-unavailable"); }
        // Unknown SQL commit acknowledgements propagate: no provider call, no
        // assumption that a persisted intent can be replayed safely.
        if (!Enabled || Deadline(request, policy) <= time.GetUtcNow() || binding.ExpiresAt <= time.GetUtcNow() || lease.Until <= time.GetUtcNow()) {
            await ClearAsync(lease, intentAt, intentPayload, ct);
            return new(Enabled ? WorkOutcome.Failed : WorkOutcome.Retry, Enabled ? "lookup-expired" : "delivery-disabled");
        }
        try {
            var delivered = await sender.SendAsync(outgoing, ct);
            await RecordReceiptAsync(lease, request, intentAt, intentPayload, delivered, ct);
            return new(WorkOutcome.Completed);
        }
        catch (EmailNotSubmittedException e) {
            await ClearAsync(lease, intentAt, intentPayload, ct);
            return new(e.Retryable ? WorkOutcome.Retry : WorkOutcome.Failed, "provider-rejected");
        }
        catch (Exception e) when (e is RecipientSuppressedException or EmailDisabledException) {
            await ClearAsync(lease, intentAt, intentPayload, ct);
            return new(WorkOutcome.Failed, e is RecipientSuppressedException ? "recipient-suppressed" : "delivery-disabled");
        }
        // An arbitrary provider/receipt error might follow acceptance. Preserve
        // intent for WorkStore's existing ambiguous recovery, without another send.
    }

    private DateTimeOffset Deadline(LookupMailPayload p, LookupContactRetentionSnapshot policy) => LookupContactRetention.DispatchDeadline(p, limits, policy);
    private async Task<WorkResult?> PolicyAsync(LookupMailPayload p, LookupContactRetentionSnapshot policy, CancellationToken ct)
    {
        limits.Validate();
        if (!Enabled) return new(WorkOutcome.Retry, "delivery-disabled");
        if (p.RequestedAt > time.GetUtcNow() || Deadline(p, policy) <= time.GetUtcNow()) return new(WorkOutcome.Failed, "lookup-request-expired");
        if (await db.Suppressions.AnyAsync(x => x.Email == p.Email, ct)) return new(WorkOutcome.Failed, "recipient-suppressed");
        if (!await LookupDeliveryRules.WithinCapsAsync(db, limits, protection, p.Email, p.IpHash, time.GetUtcNow(), true, ct)) return new(WorkOutcome.Retry, "lookup-daily-limit");
        return null;
    }
    private async Task<(EmailOutbox Row, LookupMailPayload Payload)> OwnedAsync(WorkLease lease, DateTimeOffset? intent, CancellationToken ct)
    {
        var work = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (lease.Kind != WorkKind.Email || work is null || work.Kind != WorkKind.Email || work.EnvelopeId is not null || work.Status != WorkStatus.Leased ||
            work.LeaseOwner != lease.Owner || work.Attempts != lease.Attempt || work.LeaseExpiresAt != lease.Until || lease.Until <= time.GetUtcNow())
            throw new InvalidOperationException("Lookup work lease is no longer owned.");
        var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (row is null || row.Status != EmailStatus.Queued || row.SubmissionStartedAt != intent) throw Invalid();
        var p = protection.Read(row);
        if (intent is null && p.Issued is not null || intent is not null && (p.Issued is null || row.Attempts != lease.Attempt)) throw Invalid();
        return (row, p);
    }
    private async Task TokenAsync(LookupIssuedToken issued, CancellationToken ct)
    {
        var token = await db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={issued.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (token is null || token.Purpose != TokenPurpose.Lookup || token.EnvelopeId is not null || token.PartyType != PartyType.System || token.PartyId is not null ||
            token.Email != "" || token.UsedAt is not null || token.ExpiresAt != issued.ExpiresAt || Convert.ToBase64String(token.RowVersion) != issued.Revision ||
            !CryptographicOperations.FixedTimeEquals(token.TokenSha256, Convert.FromHexString(issued.Sha256))) throw Invalid();
    }
    private async Task ClearAsync(WorkLease lease, DateTimeOffset intentAt, string intentPayload, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await LookupDeliveryRules.LockAsync(db, ct);
        var current = await OwnedAsync(lease, intentAt, ct);
        if (current.Row.PayloadJson != intentPayload) throw Invalid();
        var issued = current.Payload.Issued ?? throw Invalid(); await TokenAsync(issued, ct);
        await db.AuthTokens.Where(x => x.Id == issued.Id && x.UsedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, time.GetUtcNow()), ct);
        var cleared = protection.Protect(current.Payload with { Issued = null });
        await db.EmailOutbox.Where(x => x.Id == lease.Id && x.SubmissionStartedAt == intentAt && x.PayloadJson == intentPayload)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt, (DateTimeOffset?)null)
                .SetProperty(x => x.PayloadJson, cleared), ct);
        await tx.CommitAsync(ct);
    }
    private async Task RecordReceiptAsync(WorkLease lease, LookupMailPayload request, DateTimeOffset intentAt, string intentPayload, EmailDelivery delivered, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var work = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (work is null || work.Kind != WorkKind.Email || work.EnvelopeId is not null || work.Attempts != lease.Attempt) throw Invalid();
        var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        // CLR comparison is ordinal, including whitespace. SQL's default collation
        // cannot establish exact protected-intent equality. Feedback remains valid.
        if (row is null || row.EnvelopeId is not null || row.Template != LookupDeliveryProtection.Template || row.To != request.Email ||
            row.PayloadJson != intentPayload || row.SubmissionStartedAt != intentAt || row.Attempts != lease.Attempt) throw Invalid();
        await db.EmailOutbox.Where(x => x.Id == lease.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Provider, delivered.Provider)
            .SetProperty(x => x.ProviderMessageId, delivered.MessageId).SetProperty(x => x.Status, x => x.Status == EmailStatus.Queued ? EmailStatus.Sent : x.Status), ct);
        await tx.CommitAsync(ct);
    }
    private static InvalidDataException Invalid() => new("Lookup delivery scope is unavailable.");
}

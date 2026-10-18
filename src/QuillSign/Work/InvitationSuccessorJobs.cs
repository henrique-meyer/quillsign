using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Signing;

namespace QuillSign.Work;

public interface IInvitationSuccessorPolicy
{
    InvitationSuccessorReason Reason { get; }
    bool Enabled { get; }
    // The caller owns the envelope transaction. Implementations verify the
    // reason's persisted authority/cap reservation; they never commit or send.
    Task<bool> ValidateLockedAsync(Envelope envelope, InvitationSuccessorScope scope, CancellationToken ct);
}
public enum InvitationPredecessorRetirement { Settled, Retired, Busy, Conflict }

public sealed class InvitationSuccessorJobs(QuillSignDbContext db, SignerAccess access, InvitationLineage lineage,
    InvitationSuccessorProtection protection, IEnumerable<IInvitationSuccessorPolicy> policies,
    WorkOptions work, EmailOptions email, Func<IWorkSignals> signals, AuditWriter audit, TimeProvider time)
{
    public static Guid CorrectionWorkId(Guid revisionId)
    {
        if (revisionId == Guid.Empty) throw new ArgumentException("Supply an immutable correction revision.");
        return new(SHA256.HashData(Encoding.ASCII.GetBytes("contact-correction-invitation-v1:" + revisionId.ToString("N"))).AsSpan(0, 16));
    }

    public async Task<InvitationPredecessorRetirement> RetirePredecessorLockedAsync(Envelope envelope, Guid signerId,
        Guid expectedPredecessorId, CancellationToken ct = default)
    {
        RequireTransaction();
        var parent = await ParentAsync(envelope, ct);
        if (await access.GetEligibleLockedAsync(parent.Id, signerId, ct) is null) return InvitationPredecessorRetirement.Conflict;
        var contacts = await new SignerContactState(db, time).ReadHistoryLockedAsync(parent, ct);
        var history = await lineage.ReadLockedAsync(parent, signerId, contacts, ct);
        var party = contacts.Current.SingleOrDefault(x => x.Id == signerId);
        if (history is null || history.Latest.Id != expectedPredecessorId || party is null || history.Latest.Contact != party.Epoch ||
            history.Latest.Recipient != party.Email) return InvitationPredecessorRetirement.Conflict;
        var previous = history.Latest;
        if (await lineage.SettledLockedAsync(previous, ct)) return InvitationPredecessorRetirement.Settled;
        var item = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={previous.Id}").AsNoTracking().SingleAsync(ct);
        var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={previous.Id}").AsNoTracking().SingleAsync(ct);
        // Started or ambiguous submission is never converted into a definite
        // rejection. It may already have escaped to the earlier mailbox.
        if (row.Status != EmailStatus.Queued || row.SubmissionStartedAt is not null || row.Provider is not null || row.ProviderMessageId is not null ||
            row.LastError == "submission-ambiguous" || item.LastError == "submission-ambiguous" ||
            item.Kind != WorkKind.Email || item.EnvelopeId != parent.Id || row.EnvelopeId != parent.Id ||
            item.Status is not (WorkStatus.Queued or WorkStatus.Leased) || row.PayloadJson != previous.Outbox.PayloadJson ||
            item.Status == WorkStatus.Leased && (item.LeaseOwner is null || item.LeaseExpiresAt is null)) return InvitationPredecessorRetirement.Busy;
        var mailChanged = await db.EmailOutbox.Where(x => x.Id == row.Id && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, EmailStatus.Failed).SetProperty(x => x.LastError, "contact-corrected-before-submission"), ct);
        var workChanged = await db.WorkItems.Where(x => x.Id == item.Id && x.Status == item.Status && x.Attempts == item.Attempts)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, WorkStatus.Failed)
            .SetProperty(x => x.LastError, "contact-corrected-before-submission").SetProperty(x => x.LeaseOwner, (Guid?)null)
            .SetProperty(x => x.LeaseExpiresAt, (DateTimeOffset?)null), ct);
        if (mailChanged != 1 || workChanged != 1) throw Invalid();
        await audit.AppendAsync(parent.Id, "invitation_retired_before_submission", null, null, null, ct,
            JsonSerializer.Serialize(new { invitationId = previous.Id, signerId, contact = previous.Contact, meaning = "never_submitted_not_recalled" }), PartyType.System);
        return InvitationPredecessorRetirement.Retired;
    }

    public async Task<Guid> PrepareCorrectionAsync(Envelope envelope, Guid revisionId, CancellationToken ct = default)
    {
        RequireTransaction();
        if (!work.Enabled || !email.Enabled) throw new EmailDisabledException();
        var parent = await ParentAsync(envelope, ct);
        var contacts = await new SignerContactState(db, time).ReadHistoryLockedAsync(parent, ct);
        var revision = contacts.Revision(revisionId) ?? throw Invalid();
        var party = contacts.Current.SingleOrDefault(x => x.Id == revision.SignerId) ?? throw Invalid();
        if (party.Epoch != new SignerContactEpoch(revision.Id, revision.Number)) throw Invalid();
        var id = CorrectionWorkId(revision.Id);
        var history = await lineage.ReadLockedAsync(parent, party.Id, contacts, ct) ?? throw Invalid();
        if (history.Latest.Id == id)
        {
            var existing = protection.Read(history.Latest.Outbox).Scope;
            if (existing.Reason != InvitationSuccessorReason.ContactCorrection || existing.AuthorizationSha256 != SignerContactHistory.Digest(revision)) throw Invalid();
            return id; // Exact saved admission, with no new work or hint.
        }
        if (await db.WorkItems.AnyAsync(x => x.Id == id, ct) || await db.EmailOutbox.AnyAsync(x => x.Id == id, ct)) throw Invalid();
        var context = await access.GetEligibleLockedAsync(parent.Id, party.Id, ct) ?? throw Invalid();
        var predecessor = history.Latest;
        if (predecessor.Contact.RevisionId != revision.PreviousRevisionId || predecessor.Contact.Number != revision.Number - 1 ||
            predecessor.Recipient != revision.OldEmail || !await lineage.SettledLockedAsync(predecessor, ct) ||
            context.Identity.Email != revision.NewEmail || context.Identity.DocumentId != revision.DocumentId ||
            context.Identity.DocumentHash != revision.DocumentSha256 || context.Identity.DisclosureHash != revision.DisclosureSha256) throw Invalid();
        if (await db.Suppressions.AnyAsync(x => x.Email == party.Email, ct)) throw new RecipientSuppressedException();
        var counterUntil = DayEnd(revision.ChangedAt);
        var retention = await DocumentRetentionAccess.ReadAsync(db, parent, ct);
        if (retention < counterUntil || retention <= time.GetUtcNow()) throw Invalid();
        var deadline = parent.ExpiresAt is { } expires && expires < counterUntil ? expires : counterUntil;
        if (retention is { } end && end < deadline) deadline = end;
        var p = new InvitationSuccessorScope(InvitationSuccessorProtection.Version, id, parent.Id, party.Id, predecessor.Id,
            party.Epoch, InvitationSuccessorReason.ContactCorrection, party.Email, parent.SenderEmail, revision.DocumentId,
            revision.DocumentSha256, revision.DisclosureSha256, SignerContactHistory.Digest(revision), revision.ChangedAt, deadline.ToUniversalTime());
        var policy = Policy(p.Reason);
        if (policy is null || !policy.Enabled) throw new EmailDisabledException();
        if (!await policy.ValidateLockedAsync(parent, p, ct)) throw Invalid();
        db.EmailOutbox.Add(new() { Id = id, EnvelopeId = parent.Id, To = p.Recipient, Template = InvitationSuccessorProtection.Template,
            AvailableAt = p.AdmittedAt, PayloadJson = protection.Protect(new(p)) });
        db.WorkItems.Add(new() { Id = id, EnvelopeId = parent.Id, Kind = WorkKind.Email, AvailableAt = p.AdmittedAt,
            PayloadJson = JsonSerializer.Serialize(new { emailId = id }) });
        await db.SaveChangesAsync(ct);
        await audit.AppendAsync(parent.Id, InvitationSuccessorProtection.Event, parent.SenderEmail, null, null, ct,
            InvitationSuccessorProtection.Canonical(p), PartyType.Sender);
        if (!work.Enabled || !email.Enabled || !policy.Enabled || p.Deadline <= time.GetUtcNow() ||
            !await policy.ValidateLockedAsync(parent, p, ct)) throw Invalid();
        DocumentRetentionAccess.Check(retention, time);
        await signals().PutHintAsync(id, p.AdmittedAt, ct);
        return id;
    }

    public async Task PublishAsync(Guid id, CancellationToken ct = default)
    {
        if (db.Database.CurrentTransaction is not null) throw new InvalidOperationException("Commit before publishing invitation work.");
        try { await signals().PublishAsync(id, TimeSpan.Zero, ct); }
        catch (Exception e) when (e is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { /* Durable hint recovers. */ }
    }
    internal IInvitationSuccessorPolicy? Policy(InvitationSuccessorReason reason)
    {
        var matches = policies.Where(x => x.Reason == reason).Take(2).ToArray();
        if (matches.Length > 1) throw Invalid();
        return matches.SingleOrDefault();
    }
    private async Task<Envelope> ParentAsync(Envelope expected, CancellationToken ct)
    {
        var e = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={expected.Id}")
            .AsNoTracking().SingleOrDefaultAsync(ct) ?? throw Invalid();
        if (!e.RowVersion.AsSpan().SequenceEqual(expected.RowVersion) || e.Status != EnvelopeStatus.Sent || e.ExpiresAt <= time.GetUtcNow()) throw Invalid();
        return e;
    }
    private void RequireTransaction() { if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Successor preparation requires its parent's transaction."); }
    private static DateTimeOffset DayEnd(DateTimeOffset at) => new DateTimeOffset(at.UtcDateTime.Date, TimeSpan.Zero).AddDays(1);
    private static InvalidDataException Invalid() => InvitationSuccessorProtection.Invalid();
}

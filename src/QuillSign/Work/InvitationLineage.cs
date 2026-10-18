using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Work;

public sealed record VerifiedInvitationEntry(Guid Id, Guid SignerId, Guid? PreviousId, SignerContactEpoch Contact,
    string Recipient, Guid DocumentId, string DocumentSha256, string DisclosureSha256,
    DateTimeOffset AdmittedAt, InvitationSuccessorReason? Reason, EmailOutbox Outbox, WorkItem Work, Guid? TokenId, DateTimeOffset? Deadline=null);
public sealed class VerifiedInvitationLineage
{
    public ImmutableArray<VerifiedInvitationEntry> Entries { get; }
    public VerifiedInvitationEntry Latest => Entries[^1];
    internal VerifiedInvitationLineage(IEnumerable<VerifiedInvitationEntry> entries) => Entries = entries.ToImmutableArray();
}

// Trusted internal reader. The caller obtains contacts from SignerContactState
// under this same envelope transaction. This class never admits or sends mail.
public sealed class InvitationLineage(QuillSignDbContext db, SignerInvitationProtection originals,
    InvitationResendProtection resends, InvitationSuccessorProtection successors, TimeProvider time)
{
    internal static async Task<bool> RequiresVerifiedHistoryAsync(QuillSignDbContext db, Guid envelopeId, CancellationToken ct)
        => await db.AuditEvents.AnyAsync(x => x.EnvelopeId == envelopeId &&
            (x.Event == InvitationSuccessorProtection.Event || x.Event == SignerContactHistory.Event), ct) ||
            await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == envelopeId && x.Template == InvitationSuccessorProtection.Template, ct);

    public async Task<VerifiedInvitationLineage?> ReadLockedAsync(Envelope envelope, Guid signerId,
        VerifiedSignerContacts contacts, CancellationToken ct = default)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Invitation history requires its envelope transaction.");
        var locked = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={envelope.Id}")
            .AsNoTracking().SingleOrDefaultAsync(ct);
        if (locked is null || !locked.RowVersion.AsSpan().SequenceEqual(envelope.RowVersion) || locked.SentAt is null ||
            contacts.Current.All(x => x.Id != signerId)) throw Invalid();
        var rules = new InvitationResendRules(db, new(), resends, time);
        // Bounded sizes are read before protected payloads. The contact verifier
        // already bounds and verifies the full envelope audit chain.
        var auditsQuery = db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id &&
            (x.Event == InvitationResendProtection.Event || x.Event == InvitationSuccessorProtection.Event));
        var sizes = await auditsQuery.OrderBy(x => x.Sequence).Select(x => EF.Functions.DataLength(x.DataJson)).Take(513).ToArrayAsync(ct);
        if (sizes.Length > 512 || sizes.Any(x => x > 24000)) throw Invalid();
        var audits = await auditsQuery.OrderBy(x => x.Sequence).Take(513).ToArrayAsync(ct);
        if (audits.Length != sizes.Length) throw Invalid();
        var count = await db.EmailOutbox.CountAsync(x => x.EnvelopeId == envelope.Id &&
            (x.Template == InvitationResendProtection.Template || x.Template == InvitationSuccessorProtection.Template), ct);
        if (count != audits.Length) throw Invalid();
        var rootsQuery = db.EmailOutbox.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id && x.Template == "signer-invitation");
        var rootSizes = await rootsQuery.Select(x => EF.Functions.DataLength(x.PayloadJson)).Take(101).ToArrayAsync(ct);
        if (rootSizes.Length > 100 || rootSizes.Any(x => x > 24000)) throw Invalid();
        var roots = await rootsQuery.Take(101).ToArrayAsync(ct);
        if (roots.Length != rootSizes.Length) throw Invalid();
        var chains = new Dictionary<Guid, List<VerifiedInvitationEntry>>();
        var ids = new HashSet<Guid>();
        var sent = await QuillSign.Sender.SenderSentStatus.ReadSentAsync(db, envelope, null, ct);
        if (await new SignerCheckpointState(db, time).CurrentAsync(envelope, ct) is null) throw Invalid();
        foreach (var row in roots)
        {
            var p = originals.Read(row.PayloadJson);
            var party = contacts.Resolve(p.SignerId, p.Contact);
            if (party is null || row.To != party.Email || row.AttachmentsJson != "[]" || row.AvailableAt < envelope.SentAt ||
                row.AvailableAt > time.GetUtcNow() || row.AvailableAt.Offset != TimeSpan.Zero || !Enum.IsDefined(row.Status) ||
                p.DocumentId == Guid.Empty || !SignerReminderPolicy.Hash(p.DocumentSha256) || !SignerReminderPolicy.Hash(p.DisclosureSha256) ||
                envelope.ErsdSha256 is not { Length: 32 } || p.DisclosureSha256 != Convert.ToHexStringLower(envelope.ErsdSha256) ||
                !ids.Add(row.Id) || chains.ContainsKey(p.SignerId)) throw Invalid();
            if (party.Order == 1)
            {
                if (row.Id != sent.InvitationWorkId || p.DocumentId.ToString("N") != envelope.SentPdfBlob || p.DocumentSha256 != sent.DocumentHash) throw Invalid();
            }
            else
            {
                var previous = contacts.Current.SingleOrDefault(x => x.Order == party.Order - 1) ?? throw Invalid();
                var f = await db.SignerFinishAcceptances.AsNoTracking().SingleOrDefaultAsync(x => x.EnvelopeId == envelope.Id && x.SignerId == previous.Id, ct);
                if (f?.ProcessedAt is null || f.NextInvitationId != row.Id || f.PdfObjectId != p.DocumentId ||
                    f.PdfSha256 is not { Length: 32 } || Convert.ToHexStringLower(f.PdfSha256) != p.DocumentSha256 || row.AvailableAt < f.ProcessedAt) throw Invalid();
            }
            var work = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == row.Id, ct) ?? throw Invalid();
            if (work.EnvelopeId != envelope.Id || work.Kind != WorkKind.Email || work.PayloadJson != "{}" || !Enum.IsDefined(work.Status)) throw Invalid();
            chains.Add(p.SignerId, [new(row.Id, p.SignerId, null, p.Contact, row.To, p.DocumentId, p.DocumentSha256!,
                p.DisclosureSha256!, row.AvailableAt, null, row, work, p.LastTokenId,envelope.ExpiresAt)]);
        }
        foreach (var audit in audits)
        {
            VerifiedInvitationEntry entry;
            if (audit.Event == InvitationResendProtection.Event)
            {
                var saved = await rules.FromAuditAsync(audit, ct); var p = saved.Mail.Request;
                entry = new(p.Id, p.SignerId, p.PreviousId, SignerContactEpoch.Legacy, p.Email, p.DocumentId, p.DocumentSha256,
                    p.DisclosureSha256, p.RequestedAt, InvitationSuccessorReason.ManualResend, saved.Row, saved.Work, saved.Mail.Issued?.Id,p.Deadline);
            }
            else
            {
                var p = InvitationSuccessorProtection.ReadEvidence(audit);
                var size = await db.EmailOutbox.Where(x => x.Id == p.Id).Select(x => EF.Functions.DataLength(x.PayloadJson)).SingleOrDefaultAsync(ct);
                if (size is < 1 or > 24000) throw Invalid();
                var row = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == p.Id, ct); var mail = successors.Read(row);
                var work = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == p.Id, ct) ?? throw Invalid();
                if (mail.Scope != p || work.EnvelopeId != envelope.Id || work.Kind != WorkKind.Email || !Enum.IsDefined(work.Status) ||
                    work.PayloadJson != JsonSerializer.Serialize(new { emailId = p.Id })) throw Invalid();
                entry = new(p.Id, p.SignerId, p.PreviousId, p.Contact, p.Recipient, p.DocumentId, p.DocumentSha256, p.DisclosureSha256,
                    p.AdmittedAt, p.Reason, row, work, mail.Issued?.Id,p.Deadline);
                if (p.Reason == InvitationSuccessorReason.ContactCorrection)
                {
                    var revision = contacts.Revision(p.Contact.RevisionId) ?? throw Invalid();
                    if (revision.SignerId != p.SignerId || revision.Number != p.Contact.Number || revision.ChangedAt > p.AdmittedAt ||
                        revision.NewEmail != p.Recipient || revision.DocumentId != p.DocumentId || revision.DocumentSha256 != p.DocumentSha256 ||
                        revision.DisclosureSha256 != p.DisclosureSha256 || p.SenderEmail != envelope.SenderEmail ||
                        p.AuthorizationSha256 != SignerContactHistory.Digest(revision)) throw Invalid();
                }
            }
            var historical = contacts.Resolve(entry.SignerId, entry.Contact);
            if (historical is null || historical.Email != entry.Recipient || !ids.Add(entry.Id) || !chains.TryGetValue(entry.SignerId, out var chain)) throw Invalid();
            var previous = chain[^1];
            if (entry.PreviousId != previous.Id || entry.AdmittedAt < previous.AdmittedAt || entry.DocumentId != previous.DocumentId ||
                entry.DocumentSha256 != previous.DocumentSha256 || entry.DisclosureSha256 != previous.DisclosureSha256) throw Invalid();
            if (entry.Reason == InvitationSuccessorReason.ContactCorrection)
            {
                var revision = contacts.Revision(entry.Contact.RevisionId) ?? throw Invalid();
                if (entry.Contact.Number != previous.Contact.Number + 1 || revision.PreviousRevisionId != previous.Contact.RevisionId || revision.OldEmail != previous.Recipient) throw Invalid();
            }
            else if (entry.Contact != previous.Contact) throw Invalid();
            if (!await SettledLockedAsync(previous, ct)) throw Invalid();
            chain.Add(entry);
        }
        return chains.TryGetValue(signerId, out var found) ? new(found) : null;
    }

    public Task<bool> SettledLockedAsync(VerifiedInvitationEntry entry, CancellationToken ct = default)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Invitation settlement requires its envelope transaction.");
        var rules = new InvitationResendRules(db, new(), resends, time);
        return rules.SettledAsync(entry.Outbox, entry.Work, entry.SignerId, entry.DocumentSha256, entry.DisclosureSha256, entry.TokenId, ct);
    }
    private static InvalidDataException Invalid() => InvitationSuccessorProtection.Invalid();
}

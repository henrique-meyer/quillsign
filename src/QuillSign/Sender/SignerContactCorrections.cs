using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Sender;

// The trusted browser wrapper owns CSRF and the protected review/ticket. Every
// mutation below independently rechecks its authority under the envelope lock.
public sealed class SignerContactCorrections(QuillSignDbContext db, SignerContactCorrectionOptions options,
    EmailOptions email, WorkOptions work, SignerAccess access, InvitationLineage lineage,
    InvitationSuccessorJobs jobs, AuditWriter audit, TimeProvider time)
{
    private bool Enabled => options.Enabled && email.Enabled && work.Enabled;
    private readonly SignerContactCorrectionPolicy policy = new(db, options, email, work, time);
    private readonly SignerContactState contacts = new(db, time);
    private sealed record Scope(Envelope Envelope, Signer Signer, SignerReadContext Context,
        VerifiedSignerContacts Contacts, VerifiedInvitationLineage Invitations, DateTimeOffset? Retention);

    public async Task<SignerContactCorrectionPreview?> PreviewAsync(ClaimsPrincipal sender, string publicId,
        DateTimeOffset ticketExpiresAt, string? newEmail, CancellationToken ct = default)
    {
        options.Validate(); if (!Enabled) return null;
        var identity = SendDraftWorkflow.Identity(sender, publicId);
        if (identity is null || ticketExpiresAt <= time.GetUtcNow()) return null;
        var address = string.IsNullOrEmpty(newEmail) ? "" : EmailAddress.Normalize(newEmail);
        Clean(); await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var envelope = await EnvelopeAsync(identity.Value.Id, identity.Value.Email, publicId, ct);
        var scope = envelope is null ? null : await ScopeAsync(envelope, ct); if (scope is null) return null;
        SignerContactCorrectionOutcome? blocked = null;
        if (scope.Retention < InvitationResendProtection.DayEnd(time.GetUtcNow())) blocked = SignerContactCorrectionOutcome.Unavailable;
        else if (address.Length != 0 && (address == scope.Signer.Email || await DuplicateAsync(scope, address, ct))) blocked = SignerContactCorrectionOutcome.DuplicateAddress;
        else if (address.Length != 0 && await db.Suppressions.AnyAsync(x => x.Email == address, ct)) blocked = SignerContactCorrectionOutcome.Suppressed;
        else if (!await CanRetireAsync(scope.Invitations.Latest, ct)) blocked = SignerContactCorrectionOutcome.Busy;
        if (ticketExpiresAt <= time.GetUtcNow() || envelope!.ExpiresAt <= time.GetUtcNow()) return null;
        DocumentRetentionAccess.Check(scope.Retention, time);
        await tx.CommitAsync(ct);
        return Enabled && ticketExpiresAt > time.GetUtcNow() ? new(envelope.Title!, Review(scope, address), blocked) : null;
    }

    public async Task<SignerContactCorrectionOutcome> RequestAsync(ClaimsPrincipal sender, string publicId, DateTimeOffset ticketExpiresAt,
        Guid requestId, SignerContactCorrectionReview reviewed, bool confirmed, string? statementVersion, string? ip, string? userAgent,
        CancellationToken ct = default, DateTimeOffset? reviewExpiresAt = null)
    {
        options.Validate(); if (!Enabled) return SignerContactCorrectionOutcome.Unavailable;
        var identity = SendDraftWorkflow.Identity(sender, publicId);
        if (identity is null || ticketExpiresAt <= time.GetUtcNow()) return SignerContactCorrectionOutcome.InvalidContext;
        if (!confirmed || statementVersion != SignerContactCorrectionStatement.Version) return SignerContactCorrectionOutcome.InvalidConfirmation;
        if (requestId == Guid.Empty || reviewed is null || !InvitationResendProtection.RowVersion(reviewed.Version) ||
            !InvitationResendProtection.RowVersion(reviewed.SignerVersion) || reviewExpiresAt <= time.GetUtcNow() ||
            reviewExpiresAt > ticketExpiresAt || reviewExpiresAt > InvitationResendProtection.DayEnd(time.GetUtcNow())) return SignerContactCorrectionOutcome.Conflict;
        try { if (EmailAddress.Normalize(reviewed.NewEmail) != reviewed.NewEmail) return SignerContactCorrectionOutcome.Conflict; }
        catch (ArgumentException) { return SignerContactCorrectionOutcome.Conflict; }
        var ipHash = InvitationResendProtection.IpHash(ip); Clean();
        try { return await CoreAsync(identity.Value.Id, identity.Value.Email, publicId, ticketExpiresAt.ToUniversalTime(), requestId,
            reviewed, ipHash, ip, userAgent, reviewExpiresAt?.ToUniversalTime(), ct); }
        finally { db.ChangeTracker.Clear(); }
    }

    private async Task<SignerContactCorrectionOutcome> CoreAsync(Guid envelopeId, string sender, string publicId, DateTimeOffset until,
        Guid id, SignerContactCorrectionReview reviewed, string ipHash, string? ip, string? ua, DateTimeOffset? reviewUntil, CancellationToken ct)
    {
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        Guid queued;
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            var envelope = await EnvelopeAsync(envelopeId, sender, publicId, ct); if (envelope is null) return SignerContactCorrectionOutcome.Closed;
            // Lock before inserting any envelope-local reservation: another
            // envelope's cap scan must never wait on our uncommitted evidence.
            await SignerContactCorrectionPolicy.LockAsync(db, ct);
            var existing = await SignerContactCorrectionPolicy.FindAsync(db, envelopeId, id, ct);
            if (existing is not null)
            {
                if (existing.Review != reviewed || existing.SenderEmail != sender || existing.IpHash != ipHash ||
                    existing.SenderTicketExpiresAt != until || existing.ReviewExpiresAt != reviewUntil) return SignerContactCorrectionOutcome.Conflict;
                var verified = await contacts.ReadHistoryLockedAsync(envelope, ct);
                var savedRevision = verified.Revision(id);
                var history = await lineage.ReadLockedAsync(envelope, reviewed.SignerId, verified, ct);
                if (savedRevision is null || SignerContactHistory.Digest(savedRevision) != existing.RevisionSha256 || history is null ||
                    history.Entries.Count(x => x.Id == InvitationSuccessorJobs.CorrectionWorkId(id)) != 1) throw SignerContactCorrectionPolicy.Invalid();
                // Exact saved commands are recognized before current row versions
                // or current signing status, which the first command changed.
                return SignerContactCorrectionOutcome.AlreadyRequested;
            }
            if (await db.SignerContactRevisions.AnyAsync(x => x.Id == id, ct) || await db.WorkItems.AnyAsync(x => x.Id == InvitationSuccessorJobs.CorrectionWorkId(id), ct) ||
                await db.EmailOutbox.AnyAsync(x => x.Id == InvitationSuccessorJobs.CorrectionWorkId(id), ct)) return SignerContactCorrectionOutcome.Conflict;
            var scope = await ScopeAsync(envelope, ct); if (scope is null) return SignerContactCorrectionOutcome.Closed;
            if (Review(scope, reviewed.NewEmail) != reviewed) return SignerContactCorrectionOutcome.Conflict;
            if (reviewed.NewEmail == reviewed.OldEmail || await DuplicateAsync(scope, reviewed.NewEmail, ct)) return SignerContactCorrectionOutcome.DuplicateAddress;
            if (await db.Suppressions.AnyAsync(x => x.Email == reviewed.NewEmail, ct)) return SignerContactCorrectionOutcome.Suppressed;
            var now = time.GetUtcNow().ToUniversalTime(); var dayEnd = InvitationResendProtection.DayEnd(now);
            if (scope.Retention < dayEnd) return SignerContactCorrectionOutcome.Unavailable;
            if (scope.Contacts.Current.Sum(x => x.Epoch.Number) >= SignerContactHistory.MaximumCorrections) return SignerContactCorrectionOutcome.Capped;
            var fields = await db.Fields.Where(x => x.EnvelopeId == envelopeId && x.SignerId == scope.Signer.Id).OrderBy(x => x.Id).Take(201).ToArrayAsync(ct);
            if (fields.Length > 200) throw SignerContactCorrectionPolicy.Invalid();
            var retired = SignerContactState.RetirementJson(scope.Signer, fields);
            var previous = reviewed.ContactRevisionId == Guid.Empty ? null : scope.Contacts.Revision(reviewed.ContactRevisionId) ?? throw SignerContactCorrectionPolicy.Invalid();
            var revision = new SignerContactRevision(SignerContactHistory.Version, id, envelopeId, reviewed.SignerId, reviewed.ContactRevisionId,
                reviewed.ContactRevisionNumber + 1, reviewed.OldEmail, reviewed.NewEmail, now, until, reviewed.Version, reviewed.SignerVersion,
                reviewed.DocumentId, reviewed.DocumentSha256, reviewed.DisclosureSha256, SignerContactState.RetirementDigest(retired),
                previous is null ? null : SignerContactHistory.Digest(previous), SignerContactCorrectionStatement.Version, SignerContactCorrectionStatement.Sha256);
            var reservation = new ContactCorrectionAdmission("contact-correction-admission-v1", id, envelopeId, sender, ipHash, reviewed, now,
                until, reviewUntil, dayEnd, scope.Invitations.Latest.Id, SignerContactHistory.Digest(revision));
            if (!await policy.WithinCapsAsync(reservation, false, ct)) return SignerContactCorrectionOutcome.Capped;
            var retirement = await jobs.RetirePredecessorLockedAsync(envelope, reviewed.SignerId, scope.Invitations.Latest.Id, ct);
            if (retirement == InvitationPredecessorRetirement.Busy) return SignerContactCorrectionOutcome.Busy;
            if (retirement == InvitationPredecessorRetirement.Conflict) return SignerContactCorrectionOutcome.Conflict;
            // Predecessor retirement may append an audit event. Sample the final
            // correction timestamp afterwards so audit chronology stays ordered.
            now = time.GetUtcNow().ToUniversalTime();
            revision = revision with { ChangedAt = now };
            reservation = reservation with { AdmittedAt = now, RevisionSha256 = SignerContactHistory.Digest(revision) };
            if (InvitationResendProtection.DayEnd(now) != dayEnd || now >= until || reviewUntil <= now) return SignerContactCorrectionOutcome.Conflict;
            db.SignerContactRevisions.Add(new() { Id = id, EnvelopeId = envelopeId, SignerId = reviewed.SignerId, Number = revision.Number,
                PreviousRevisionId = previous?.Id, ChangedAt = now, EvidenceJson = SignerContactHistory.Canonical(revision), RetirementJson = retired });
            Reset(scope.Signer, reviewed.NewEmail);
            foreach (var field in fields) { field.Value = null; field.FilledAt = null; field.FilledBy = null; field.SignatureAdoptionId = null; field.ImageSha256 = null; }
            await db.SaveChangesAsync(ct);
            await db.AuthTokens.Where(x => x.EnvelopeId == envelopeId && x.PartyType == PartyType.Signer && x.PartyId == reviewed.SignerId &&
                x.Purpose == TokenPurpose.SignerAccess && x.UsedAt == null && x.ExpiresAt > now).ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, now), ct);
            await db.SignerReviewCandidates.Where(x => x.EnvelopeId == envelopeId && x.SignerId == reviewed.SignerId && x.UsedAt == null && x.SupersededAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SupersededAt, now), ct);
            // A status no-op invalidates earlier sender reviews without changing
            // the immutable document, disclosure, predecessors or signing order.
            await db.Envelopes.Where(x => x.Id == envelopeId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, EnvelopeStatus.Sent), ct);
            await audit.AppendAtAsync(envelopeId, SignerContactHistory.Event, sender, ip, ua, ct, SignerContactHistory.Canonical(revision), now);
            await audit.AppendAtAsync(envelopeId, SignerContactCorrectionPolicy.Event, sender, ip, ua, ct, SignerContactCorrectionPolicy.Canonical(reservation), now);
            var updated = await EnvelopeAsync(envelopeId, sender, publicId, ct) ?? throw SignerContactCorrectionPolicy.Invalid();
            queued = await jobs.PrepareCorrectionAsync(updated, id, ct);
            if (!Enabled) return SignerContactCorrectionOutcome.Unavailable;
            if (until <= time.GetUtcNow()) return SignerContactCorrectionOutcome.InvalidContext;
            if (reviewUntil <= time.GetUtcNow() || dayEnd <= time.GetUtcNow()) return SignerContactCorrectionOutcome.Conflict;
            DocumentRetentionAccess.Check(scope.Retention, time);
            if (updated.ExpiresAt <= time.GetUtcNow()) return SignerContactCorrectionOutcome.Closed;
            await tx.CommitAsync(ct);
        }
        await jobs.PublishAsync(queued, ct);
        return SignerContactCorrectionOutcome.Queued;
    }

    private Task<Envelope?> EnvelopeAsync(Guid id, string sender, string publicId, CancellationToken ct) => db.Envelopes
        .FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking()
        .SingleOrDefaultAsync(x => x.SenderEmail == sender && x.PublicId == publicId && x.SenderVerifiedAt != null &&
            x.Status == EnvelopeStatus.Sent && (x.ExpiresAt == null || x.ExpiresAt > time.GetUtcNow()), ct);
    private async Task<Scope?> ScopeAsync(Envelope envelope, CancellationToken ct)
    {
        var retention = await SenderPreparationRetention.ReadAsync(db, envelope, time, ct);
        var signer = await db.Signers.Where(x => x.EnvelopeId == envelope.Id && x.Status != SignerStatus.Signed).OrderBy(x => x.Order).FirstOrDefaultAsync(ct);
        if (signer is null || signer.Status == SignerStatus.Declined || await db.SignerFinishAcceptances.AnyAsync(x => x.EnvelopeId == envelope.Id && x.SignerId == signer.Id, ct)) return null;
        var context = await access.GetEligibleLockedAsync(envelope.Id, signer.Id, ct); if (context is null) return null;
        var verified = await contacts.ReadHistoryLockedAsync(envelope, ct);
        var history = await lineage.ReadLockedAsync(envelope, signer.Id, verified, ct); if (history is null) return null;
        var party = verified.Current.Single(x => x.Id == signer.Id);
        if (history.Latest.Contact != party.Epoch || history.Latest.Recipient != signer.Email || history.Latest.DocumentId != context.Identity.DocumentId ||
            history.Latest.DocumentSha256 != context.Identity.DocumentHash || history.Latest.DisclosureSha256 != context.Identity.DisclosureHash) throw SignerContactCorrectionPolicy.Invalid();
        return new(envelope, signer, context, verified, history, retention);
    }
    private static SignerContactCorrectionReview Review(Scope scope, string address)
    {
        var party = scope.Contacts.Current.Single(x => x.Id == scope.Signer.Id);
        return new(scope.Signer.Id, scope.Signer.FullName, scope.Signer.Email, address, Convert.ToBase64String(scope.Envelope.RowVersion),
            Convert.ToBase64String(scope.Signer.RowVersion), party.Epoch.RevisionId, party.Epoch.Number, scope.Context.Identity.DocumentId,
            scope.Context.Identity.DocumentHash, scope.Context.Identity.DisclosureHash);
    }
    private async Task<bool> DuplicateAsync(Scope scope, string address, CancellationToken ct) =>
        scope.Contacts.Current.Any(x => x.Id != scope.Signer.Id && x.Email == address) || await db.Recipients.AnyAsync(x => x.EnvelopeId == scope.Envelope.Id && x.Email == address, ct);
    private async Task<bool> CanRetireAsync(VerifiedInvitationEntry previous, CancellationToken ct)
    {
        if (await lineage.SettledLockedAsync(previous, ct)) return true;
        var row = previous.Outbox; var item = previous.Work;
        return row.Status == EmailStatus.Queued && row.SubmissionStartedAt is null && row.Provider is null && row.ProviderMessageId is null &&
            row.LastError != "submission-ambiguous" && item.LastError != "submission-ambiguous" && item.Status is WorkStatus.Queued or WorkStatus.Leased;
    }
    private static void Reset(Signer signer, string address)
    {
        signer.Email = address; signer.Status = SignerStatus.Pending;
        signer.ConsentAt = null; signer.ConsentIp = null; signer.ConsentUa = null;
        signer.SignatureImageBlob = null; signer.InitialsImageBlob = null; signer.SignatureMethod = null; signer.SignatureAdoptionId = null;
        signer.SignatureImageSha256 = null; signer.InitialsImageSha256 = null; signer.SignatureAdoptedAt = null; signer.SignatureTypedName = null;
        signer.SignatureTypedInitials = null; signer.SignatureNormalizationVersion = null; signer.SignatureAdoptionVersion = null;
    }
    private void Clean()
    {
        if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Signer contact correction requires a clean standalone unit of work.");
        db.ChangeTracker.Clear();
    }
}

using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Completion;

// Explicit internal operation for a future CSRF-protected browser POST. It creates
// only an existing exact-party final reader; no raw link is returned or delivered.
public sealed class LookupPacketAccess(QuillSignDbContext db, DocumentLookup lookup, CompletionAccess completion,
    CompletionAccessState state, AuditWriter audit, TimeProvider time)
{
    public async Task<CompletionReaderSession?> OpenAsync(ClaimsPrincipal principal, string? receipt, string publicId, CancellationToken ct = default)
    {
        if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())
            throw new InvalidOperationException("Lookup packet handoff requires a clean standalone unit of work.");
        try
        {
            var result = await OpenCore(principal, receipt, publicId, ct);
            if (result is null) db.ChangeTracker.Clear();
            return result;
        }
        catch { db.ChangeTracker.Clear(); throw; }
    }

    private async Task<CompletionReaderSession?> OpenCore(ClaimsPrincipal principal, string? receipt, string publicId, CancellationToken ct)
    {
        if (!Guid.TryParseExact(publicId, "N", out var parsed) || parsed == Guid.Empty || parsed.ToString("N") != publicId) return null;
        var identity = await lookup.AuthenticateAsync(principal, receipt, ct); if (identity is null) return null;
        var restriction = await lookup.RestrictionAsync(identity, ct); if (!restriction.Allowed) return null;
        var now = time.GetUtcNow();
        var query = db.Envelopes.AsNoTracking().Where(x => x.PublicId == publicId && x.Status == EnvelopeStatus.Completed &&
            x.CompletedAt <= identity.RedeemedAt && (x.PurgeAfter == null || x.PurgeAfter > now) && (x.SenderEmail == identity.Email ||
            db.Signers.Any(s => s.EnvelopeId == x.Id && s.Email == identity.Email) || db.Recipients.Any(r => r.EnvelopeId == x.Id && r.Email == identity.Email)));
        if (restriction.IsPilot) query = query.Where(x => x.Id == restriction.Request!.SubjectEnvelopeId);
        else if (lookup.RequiresCohortExclusion) query = query.Where(x => !db.EmailPilotEnrollments.Any(p => p.SubjectEnvelopeId == x.Id));
        var id = await query.Select(x => (Guid?)x.Id).SingleOrDefaultAsync(ct);
        if (id is null) return null;
        var prepared = await completion.PrepareAsync(id.Value, ct); if (prepared is null) return null;
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        // All envelope work uses the parent lock first; the lookup row then fences
        // revocation and concurrent handoffs without acquiring another envelope.
        await state.RecheckLockedAsync(prepared.Saved, ct);
        var current = await lookup.AuthenticateLockedAsync(principal, receipt, ct);
        if (current != identity || prepared.Saved.PublicId != publicId || prepared.Saved.CompletedAt > identity.RedeemedAt) return null;
        var member = await Member(prepared.Saved, identity.Email, ct); if (member is null) return null;
        var link = await completion.PrepareLockedAsync(prepared, member.Type, member.Id, ct); if (link is null) return null;
        var reader = await completion.RedeemLockedAsync(prepared, link, identity.ExpiresAt, ct); if (reader is null) return null;
        await audit.AppendAsync(id.Value, "completion_lookup_opened", member.Email, null, null, ct,
            JsonSerializer.Serialize(new
            {
                version = "lookup-packet-access-v1", authentication = "single_use_verified_mailbox_lookup",
                lookupTokenId = identity.TokenId, lookupTokenRevision = identity.TokenRevision, lookupSessionId = identity.SessionId,
                lookupExpiresAt = identity.ExpiresAt, readerTokenId = reader.Session.Identity.TokenId,
                readerSessionId = reader.Session.Identity.SessionId, readerExpiresAt = reader.Session.Identity.ExpiresAt,
                publicationId = prepared.Saved.Id, party = member.Type.ToString(), partyId = member.Id,
                authority = "readonly_published_final_pair", observation = "session_prepared_not_document_receipt"
            }), member.Type, member.Id);
        await state.RecheckLockedAsync(prepared.Saved, ct);
        if (await lookup.AuthenticateLockedAsync(principal, receipt, ct) != identity) throw Invalid();
        var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == id.Value, ct);
        if (await SenderPreparationRetention.ReadAsync(db, envelope, time, ct) != reader.Deadline) throw Invalid();
        DocumentRetentionAccess.Check(reader.Deadline, time);
        if (prepared.Until <= time.GetUtcNow() || reader.Session.Identity.ExpiresAt <= time.GetUtcNow()) throw Invalid();
        // Unknown acknowledgement exposes no session. An explicit live lookup retry
        // may create a fresh reader; it never replays this consumed temporary link.
        await tx.CommitAsync(ct);
        DocumentRetentionAccess.Check(reader.Deadline, time);
        if (await completion.AuthenticateAsync(CompletionAccessProtection.Principal(reader.Session.Identity), publicId, reader.Session.Receipt, ct) is null) return null;
        if (await lookup.AuthenticateAsync(principal, receipt, ct) != identity || reader.Session.Identity.ExpiresAt <= time.GetUtcNow()) return null;
        return reader.Session;
    }

    private async Task<CompletionAccessParty?> Member(DownloadPublication saved, string email, CancellationToken ct)
    {
        var sender = await state.PartyLockedAsync(saved, PartyType.Sender, null, ct);
        if (sender?.Email == email) return sender;
        var signer = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == saved.EnvelopeId && x.Email == email)
            .OrderBy(x => x.Order).Select(x => (Guid?)x.Id).FirstOrDefaultAsync(ct);
        if (signer is not null && await state.PartyLockedAsync(saved, PartyType.Signer, signer, ct) is { } s && s.Email == email) return s;
        var recipient = await db.Recipients.AsNoTracking().Where(x => x.EnvelopeId == saved.EnvelopeId && x.Email == email).Select(x => (Guid?)x.Id).SingleOrDefaultAsync(ct);
        var member = recipient is null ? null : await state.PartyLockedAsync(saved, PartyType.Recipient, recipient, ct);
        return member?.Email == email ? member : null;
    }
    private static InvalidDataException Invalid() => new("Lookup packet handoff could not be verified.");
}

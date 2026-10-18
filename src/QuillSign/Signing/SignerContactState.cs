using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Signing;

public sealed class VerifiedSignerContacts
{
    private readonly IReadOnlyList<SignerContactParty> generations;
    private readonly IReadOnlyList<SignerContactRevision> revisions;
    public IReadOnlyList<SignerContactParty> Current { get; }
    internal VerifiedSignerContacts(IReadOnlyList<SignerContactParty> current, IReadOnlyList<SignerContactParty> generations, IReadOnlyList<SignerContactRevision> revisions)
    { Current = Array.AsReadOnly(current.ToArray()); this.generations = Array.AsReadOnly(generations.ToArray()); this.revisions = Array.AsReadOnly(revisions.ToArray()); }
    public SignerContactParty? Resolve(Guid signerId, SignerContactEpoch epoch) => generations.SingleOrDefault(x => x.Id == signerId && x.Epoch == epoch);
    public SignerContactRevision? Revision(Guid revisionId) => revisions.SingleOrDefault(x => x.Id == revisionId);
}

public sealed record RetiredSignerEntries(Signer Signer, IReadOnlyList<DocumentField> Fields);

// Source-only prerequisites. These services are deliberately not registered and
// cannot admit corrections. All state/session checks require the envelope lock.
public sealed class SignerContactState(QuillSignDbContext db, TimeProvider time)
{
    private const int MaximumRetirementBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, MaxDepth = 8 };

    public async Task<IReadOnlyList<SignerContactParty>> ReadLockedAsync(Envelope envelope, CancellationToken ct = default)
        => (await ReadHistoryLockedAsync(envelope, ct)).Current;

    public async Task<VerifiedSignerContacts> ReadHistoryLockedAsync(Envelope envelope, CancellationToken ct = default)
    {
        RequireTransaction();
        var saved = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={envelope.Id}")
            .AsNoTracking().SingleOrDefaultAsync(ct);
        if (saved is null || saved.PublicId != envelope.PublicId || saved.SenderEmail != envelope.SenderEmail || saved.Status == EnvelopeStatus.Draft || saved.SentAt is null || saved.SenderVerifiedAt is null ||
            !saved.RowVersion.AsSpan().SequenceEqual(envelope.RowVersion)) throw Invalid();
        // Verify the complete immutable prefix that establishes the latest contact.
        // Later download/notification events cannot change that contact authority,
        // and published completion readers support an arbitrarily long operational tail.
        var boundary = await db.AuditEvents.Where(x => x.EnvelopeId == saved.Id && (x.Event == SignerContactHistory.Event || x.Event == "sent"))
            .MaxAsync(x => (long?)x.Sequence, ct) ?? throw Invalid();
        var sizes = await db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == saved.Id && x.Sequence <= boundary).OrderBy(x => x.Sequence)
            .Select(x => new { x.Id, Bytes = EF.Functions.DataLength(x.DataJson) }).Take(513).ToArrayAsync(ct);
        if (sizes.Length is < 1 or > 512 || sizes.Any(x => x.Bytes is null or > 2 * 1024 * 1024) || sizes.Sum(x => (long)x.Bytes.GetValueOrDefault()) > 16 * 1024 * 1024) throw Invalid();
        var events = await db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == saved.Id && x.Sequence <= boundary).OrderBy(x => x.Sequence).Take(513).ToArrayAsync(ct);
        if (events.Length != sizes.Length) throw Invalid();
        byte[]? previous = null;
        foreach (var entry in events)
        {
            if (entry.Sequence < 1 || entry.Sequence > events.Length || entry != events[entry.Sequence - 1] || entry.At > time.GetUtcNow() ||
                entry.Hash is not { Length: 32 } || (previous is null ? entry.PrevHash is not null : !Same(previous, entry.PrevHash)) || !AuditMatches(entry)) throw Invalid();
            previous = entry.Hash;
        }
        var sent = events.Where(x => x.Event == "sent").ToArray();
        if (sent.Length != 1 || sent[0].ActorType != PartyType.Sender || sent[0].ActorEmail != saved.SenderEmail || sent[0].At < saved.SentAt) throw Invalid();
        var roster = events.LastOrDefault(x => x.Sequence < sent[0].Sequence && x.Event is "signer_added" or "signer_updated" or "signer_removed" or "signers_reordered");
        if (roster is null || roster.ActorType != PartyType.Sender || roster.ActorEmail != saved.SenderEmail) throw Invalid();
        SignerContactParty[] original;
        try
        {
            using var json = JsonDocument.Parse(roster.DataJson);
            original = json.RootElement.GetProperty("signers").EnumerateArray().Select(x => new SignerContactParty(x.GetProperty("Id").GetGuid(),
                x.GetProperty("Order").GetInt32(), x.GetProperty("FullName").GetString()!, x.GetProperty("Email").GetString()!,
                x.GetProperty("Role").GetString(), SignerContactEpoch.Legacy)).Take(101).ToArray();
        }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or FormatException) { throw Invalid(); }
        var changes = events.Where(x => x.Event == SignerContactHistory.Event).ToArray();
        var recordSizes = await db.SignerContactRevisions.AsNoTracking().Where(x => x.EnvelopeId == saved.Id)
            .Select(x => new { Bytes = EF.Functions.DataLength(x.RetirementJson), Evidence = EF.Functions.DataLength(x.EvidenceJson) }).Take(101).ToArrayAsync(ct);
        if (recordSizes.Length != changes.Length || recordSizes.Length > 100 || recordSizes.Any(x => x.Bytes is null || x.Bytes > MaximumRetirementBytes * 2 || x.Evidence is null or > 16384) ||
            recordSizes.Sum(x => (long)x.Bytes.GetValueOrDefault()) > 16 * 1024 * 1024) throw Invalid();
        var records = await db.SignerContactRevisions.AsNoTracking().Where(x => x.EnvelopeId == saved.Id).Take(101).ToArrayAsync(ct);
        var signers = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == saved.Id).OrderBy(x => x.Order).Take(101).ToArrayAsync(ct);
        var fields = records.Length == 0 ? [] : await db.Fields.AsNoTracking().Where(x => x.EnvelopeId == saved.Id).OrderBy(x => x.Id).Take(201).ToArrayAsync(ct);
        if (records.Length != changes.Length || signers.Length is < 1 or > 100 || fields.Length > 200) throw Invalid();
        var revisions = new List<SignerContactRevision>();
        foreach (var entry in changes)
        {
            SignerContactRevision revision;
            try { revision = JsonSerializer.Deserialize<SignerContactRevision>(entry.DataJson, Json) ?? throw Invalid(); }
            catch (JsonException) { throw Invalid(); }
            var record = records.SingleOrDefault(x => x.Id == revision.Id) ?? throw Invalid();
            if (record.SignerId != revision.SignerId || record.Number != revision.Number || record.ChangedAt != revision.ChangedAt ||
                record.PreviousRevisionId != (revision.PreviousRevisionId == Guid.Empty ? null : revision.PreviousRevisionId) ||
                record.EvidenceJson != entry.DataJson || record.EvidenceJson != SignerContactHistory.Canonical(revision) ||
                await db.SignerFinishAcceptances.AnyAsync(x => x.EnvelopeId == saved.Id && x.SignerId == revision.SignerId && x.FinishedAt < revision.ChangedAt, ct) ||
                events.Any(x => x.Event == "signer_finish_accepted" && x.ActorType == PartyType.Signer && x.ActorId == revision.SignerId && x.Sequence < entry.Sequence)) throw Invalid();
            VerifyRetirement(record.RetirementJson, revision, original, fields);
            revisions.Add(revision);
        }
        var current = signers.Select(x =>
        {
            var last = revisions.LastOrDefault(r => r.SignerId == x.Id);
            return new SignerContactParty(x.Id, x.Order, x.FullName, x.Email, x.Role, last is null ? SignerContactEpoch.Legacy : new(last.Id, last.Number));
        }).ToArray();
        var verified = SignerContactHistory.Verify(new(saved.Id, saved.SenderEmail, sent[0].Sequence, saved.SentAt.Value, time.GetUtcNow()), original, changes, current);
        var generations = original.ToList();
        foreach (var r in revisions)
        {
            var first = original.Single(x => x.Id == r.SignerId);
            generations.Add(first with { Email = r.NewEmail, Epoch = new(r.Id, r.Number) });
        }
        return new(verified, generations, revisions);
    }

    public async Task<bool> SessionMatchesLockedAsync(Envelope envelope, VerifiedSigner identity, CancellationToken ct = default)
    {
        var current = (await ReadLockedAsync(envelope, ct)).SingleOrDefault(x => x.Id == identity.SignerId);
        if (current is null || identity.SessionId == Guid.Empty || identity.EnvelopeId != envelope.Id || identity.PublicId != envelope.PublicId || identity.Email != current.Email || identity.SessionExpiresAt.Offset != TimeSpan.Zero || identity.SessionExpiresAt <= time.GetUtcNow()) return false;
        var session = await db.SignerContactSessions.AsNoTracking().SingleOrDefaultAsync(x => x.SessionId == identity.SessionId, ct);
        if (current.Epoch == SignerContactEpoch.Legacy) return session is null;
        return session is not null && session.EnvelopeId == envelope.Id && session.SignerId == identity.SignerId && session.RevisionId == current.Epoch.RevisionId &&
            session.ExpiresAt == identity.SessionExpiresAt && session.CreatedAt <= time.GetUtcNow() && session.ExpiresAt > time.GetUtcNow() && Same(session.SessionSha256, SessionHash(identity));
    }

    // Contact binding only; caller still verifies the exact stored token hash,
    // single-use/expiry, current document/disclosure and ordinary redemption scope.
    public async Task<bool> TokenMatchesLockedAsync(Envelope envelope, AuthToken token, CancellationToken ct = default)
    {
        var current = (await ReadLockedAsync(envelope, ct)).SingleOrDefault(x => x.Id == token.PartyId);
        return current is not null && TokenMatches(envelope, current, token);
    }

    // Called only within the successful single-use token redemption transaction.
    // Registering a row alone does not issue a cookie or confer public authority.
    public async Task BindRedeemedSessionLockedAsync(Envelope envelope, VerifiedSigner identity, Guid redeemedTokenId, CancellationToken ct = default)
    {
        var current = (await ReadLockedAsync(envelope, ct)).SingleOrDefault(x => x.Id == identity.SignerId) ?? throw Invalid();
        if (identity.SessionId == Guid.Empty || identity.EnvelopeId != envelope.Id || identity.PublicId != envelope.PublicId || identity.Email != current.Email || identity.SessionExpiresAt <= time.GetUtcNow()) throw Invalid();
        var token = await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x => x.Id == redeemedTokenId, ct);
        if (token?.UsedAt is null || !TokenMatches(envelope, current, token) || token.UsedAt > time.GetUtcNow() || token.EnvelopeId != envelope.Id || token.PartyId != identity.SignerId || token.PartyType != PartyType.Signer ||
            token.Purpose != TokenPurpose.SignerAccess || token.Email != identity.Email || token.DocumentId != identity.DocumentId ||
            token.DocumentSha256 is not { Length: 32 } || Convert.ToHexStringLower(token.DocumentSha256) != identity.DocumentHash ||
            token.DisclosureSha256 is not { Length: 32 } || Convert.ToHexStringLower(token.DisclosureSha256) != identity.DisclosureHash) throw Invalid();
        if (current.Epoch == SignerContactEpoch.Legacy) return;
        var revision = await db.SignerContactRevisions.AsNoTracking().SingleAsync(x => x.Id == current.Epoch.RevisionId, ct);
        if (token.UsedAt < revision.ChangedAt) throw Invalid();
        if (await db.SignerContactSessions.AnyAsync(x => x.SessionId == identity.SessionId, ct)) throw Invalid();
        db.SignerContactSessions.Add(new() { SessionId = identity.SessionId, EnvelopeId = envelope.Id, SignerId = identity.SignerId, RevisionId = current.Epoch.RevisionId,
            SessionSha256 = SessionHash(identity), CreatedAt = time.GetUtcNow(), ExpiresAt = identity.SessionExpiresAt });
        await db.SaveChangesAsync(ct);
    }

    public static string RetirementJson(Signer signer, IReadOnlyList<DocumentField> fields)
    {
        var text = JsonSerializer.Serialize(new RetiredSignerEntries(signer, fields.OrderBy(x => x.Id).ToArray()));
        if (Encoding.UTF8.GetByteCount(text) > MaximumRetirementBytes) throw Invalid();
        return text;
    }
    public static string RetirementDigest(string json)
    {
        if (json is null || json.Length > MaximumRetirementBytes || Encoding.UTF8.GetByteCount(json) > MaximumRetirementBytes) throw Invalid();
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    }
    private static void VerifyRetirement(string json, SignerContactRevision revision, SignerContactParty[] original, DocumentField[] fields)
    {
        if (RetirementDigest(json) != revision.RetirementSha256) throw Invalid();
        RetiredSignerEntries snapshot;
        try { snapshot = JsonSerializer.Deserialize<RetiredSignerEntries>(json, new JsonSerializerOptions { MaxDepth = 8 }) ?? throw Invalid(); }
        catch (JsonException) { throw Invalid(); }
        var signer = snapshot.Signer; var party = original.SingleOrDefault(x => x.Id == revision.SignerId);
        if (signer is null || snapshot.Fields is null || party is null || signer.Id != party.Id || signer.EnvelopeId != revision.EnvelopeId || signer.Order != party.Order ||
            signer.FullName != party.Name || signer.Role != party.Role || signer.Email != revision.OldEmail || signer.Status is not (SignerStatus.Pending or SignerStatus.Notified or SignerStatus.Viewed) ||
            signer.SignedAt is not null || signer.ConsentAt > revision.ChangedAt || signer.SignatureAdoptedAt > revision.ChangedAt || snapshot.Fields.Count is < 1 or > 200 ||
            snapshot.Fields.Any(x => x is null || x.SignerId != signer.Id || x.EnvelopeId != signer.EnvelopeId || x.FilledAt > revision.ChangedAt) ||
            snapshot.Fields.Select(x => x.Id).Distinct().Count() != snapshot.Fields.Count || RetirementJson(signer, snapshot.Fields) != json) throw Invalid();
        if (signer.RowVersion is not { Length: 8 } || Convert.ToBase64String(signer.RowVersion) != revision.ReviewedSignerVersion) throw Invalid();
        var definitions = fields.Where(x => x.SignerId == signer.Id).OrderBy(x => x.Id).Select(Definition).ToArray();
        if (!snapshot.Fields.OrderBy(x => x.Id).Select(Definition).SequenceEqual(definitions)) throw Invalid();
    }
    private static string Definition(DocumentField f) => JsonSerializer.Serialize(new { f.Id, f.EnvelopeId, f.SignerId, f.Type, f.Page, f.X, f.Y, f.Width, f.Height, f.Required, f.Label, f.Source, f.AiConfidence });
    private static byte[] SessionHash(VerifiedSigner identity) => SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity));
    private static bool TokenMatches(Envelope envelope, SignerContactParty current, AuthToken token) => token.EnvelopeId == envelope.Id && token.PartyId == current.Id &&
        token.PartyType == PartyType.Signer && token.Purpose == TokenPurpose.SignerAccess && token.Email == current.Email &&
        token.SignerContactRevisionId == (current.Epoch == SignerContactEpoch.Legacy ? null : current.Epoch.RevisionId);
    private static bool AuditMatches(AuditEvent entry)
    { try { return Same(entry.Hash, AuditHash.Compute(entry)); } catch (JsonException) { return false; } }
    private static bool Same(byte[]? a, byte[]? b) => a is { Length: 32 } && b is { Length: 32 } && CryptographicOperations.FixedTimeEquals(a, b);
    private void RequireTransaction() { if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Signer contact verification requires the envelope transaction."); }
    private static InvalidDataException Invalid() => new("Signer contact history could not be verified.");
}

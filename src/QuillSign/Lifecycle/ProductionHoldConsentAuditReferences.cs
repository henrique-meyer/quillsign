using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Legal;
using QuillSign.Signing;

namespace QuillSign.Lifecycle;

// Saved link/consent history only. Expired evidence never becomes a new receipt,
// session or participant capability; missing legacy session rows are not invented.
internal static class ProductionHoldConsentAuditReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { MaxDepth = 4, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private sealed record Link(Guid signerId, Guid tokenId, Guid documentId, string documentSha256, string disclosureSha256, string authentication);
    private sealed record LegacyLink(Guid signerId, Guid tokenId, string documentSha256, string disclosureSha256, string authentication);
    private sealed record Consent(string disclosureVersion, string disclosureSha256, string documentSha256, Guid accessReceiptId,
        string accessMethod, bool agreement, bool canRetain, string serverEvidence, string clientEvidence);
    private sealed class Epoch(Guid signer, Guid revision, string email, long sequence, DateTimeOffset started)
    {
        internal Guid Signer = signer, Revision = revision;
        internal string Email = email;
        internal long StartSequence = sequence, EndSequence = long.MaxValue;
        internal DateTimeOffset Started = started, Ended, ActualConsent;
        internal bool Linked, Consented;
        internal AuditEvent? Consent;
        internal List<DateTimeOffset> Actions = [];
    }
    private static bool Action(string name) => name is "signature_adopted" or "field_filled" or "field_cleared" or "signer_review_prepared" or "signer_finish_accepted" or "signer_completed";

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects)
    {
        try { Verify(sql, objects); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException or NullReferenceException)
        { throw new InvalidDataException("Historical signer link and consent evidence could not be verified.", error); }
    }
    private static void Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        T[] Table<T>(string name, int maximum)
        { var rows = tables[name]; if (rows.GetArrayLength() > maximum) throw Invalid(); return rows.Deserialize<T[]>(Rows) ?? throw Invalid(); }
        var audits = Table<AuditEvent>("AuditEvents", 4096);
        var signers = Table<Signer>("Signers", 100); var tokens = Table<AuthToken>("AuthTokens", 4096);
        var previews = Table<SignaturePreview>("SignaturePreviews", 4000); var records = Table<SignerContactRevisionRecord>("SignerContactRevisions", 100);
        if (!audits.Any(x => x.Event is "link_opened" or "consent_given" || Action(x.Event)) && records.Length == 0 && previews.Length == 0 &&
            signers.All(x => x.ConsentAt is null && x.ConsentIp is null && x.ConsentUa is null) && !tokens.Any(x => x.Purpose == TokenPurpose.SignerAccess && x.UsedAt is not null)) return;
        var id = sql.GetProperty("RecordId").GetGuid(); var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var e = Table<Envelope>("Envelopes", 1).Single(); var sent = audits.Single(x => x.Event == "sent");
        if (id == Guid.Empty || e.Id != id || e.SentAt is null || captured.Offset != TimeSpan.Zero || captured < e.SentAt ||
            !ElectronicRecordDisclosure.Verify(new(e.ErsdVersion!, e.PublicId, e.Title!, e.SenderEmail, e.ErsdText!, e.ErsdSha256!))) throw Invalid();
        var finishes = Table<SignerFinishAcceptance>("SignerFinishAcceptances", 100);
        var sessions = Table<SignerContactSession>("SignerContactSessions", 4000);
        var retirements = new Dictionary<Guid, (SignerContactRevision Revision, Signer Signer)>();
        foreach (var row in records)
        {
            var revision = Canonical<SignerContactRevision>(row.EvidenceJson, new(JsonSerializerDefaults.Web) { MaxDepth = 4, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow });
            var saved = ProductionHoldObjectReferences.ReadRetired(JsonSerializer.SerializeToElement(row)).Signer;
            if (row.EnvelopeId != id || revision.EnvelopeId != id || row.Id != revision.Id || row.SignerId != revision.SignerId ||
                row.EvidenceJson != SignerContactHistory.Canonical(revision) || SignerContactState.RetirementDigest(row.RetirementJson) != revision.RetirementSha256 ||
                saved.Id != revision.SignerId || saved.EnvelopeId != id || saved.Email != revision.OldEmail) throw Invalid();
            retirements.Add(row.Id, (revision, saved));
        }
        var epochs = new List<Epoch>(); var active = new Dictionary<Guid, Epoch>();
        foreach (var signer in signers)
        {
            var original = retirements.Values.Where(x => x.Revision.SignerId == signer.Id).OrderBy(x => x.Revision.Number).FirstOrDefault();
            if (signer.EnvelopeId != id || signer.Id == Guid.Empty) throw Invalid();
            var epoch = new Epoch(signer.Id, Guid.Empty, original.Revision is null ? signer.Email : original.Revision.OldEmail, sent.Sequence, e.SentAt.Value);
            epochs.Add(epoch); active.Add(signer.Id, epoch);
        }
        var usedTokens = new HashSet<Guid>(); var receipts = new HashSet<Guid>(); var corrections = new HashSet<Guid>();
        foreach (var audit in audits.Where(x => x.Event is "link_opened" or "consent_given" or SignerContactHistory.Event || Action(x.Event)).OrderBy(x => x.Sequence))
        {
            if (audit.EnvelopeId != id || audit.Sequence <= sent.Sequence || audit.At.Offset != TimeSpan.Zero || audit.At < e.SentAt || audit.At > captured ||
                !Bounded(audit.DataJson, 64 * 1024) || !Same(audit.Hash, AuditHash.Compute(audit))) throw Invalid();
            if (audit.Event == SignerContactHistory.Event)
            {
                var (revision, saved) = retirements.Values.Single(x => SignerContactHistory.Canonical(x.Revision) == audit.DataJson);
                var prior = active[revision.SignerId];
                if (!corrections.Add(revision.Id) || audit.ActorType != PartyType.Sender || audit.ActorId is not null || audit.ActorEmail != e.SenderEmail ||
                    audit.At != revision.ChangedAt || prior.Email != revision.OldEmail) throw Invalid();
                Close(prior, saved, audit.Sequence, audit.At);
                var next = new Epoch(prior.Signer, revision.Id, revision.NewEmail, audit.Sequence, audit.At); active[prior.Signer] = next; epochs.Add(next); continue;
            }
            if (audit.ActorType != PartyType.Signer || audit.ActorId is not Guid signerId || !active.TryGetValue(signerId, out var epoch) || audit.ActorEmail != epoch.Email) throw Invalid();
            var signer = signers.Single(x => x.Id == signerId);
            var (source, sourceHash) = ProductionHoldAdoptionAuditReferences.Source(e, signer, signers, finishes, audit.At);
            var documentHash = Hex(sourceHash); var disclosureHash = Hex(e.ErsdSha256!);
            if (!objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == $"{id:N}/{source:N}" && x.Sha256 == documentHash)) throw Invalid();
            if (audit.Event == "link_opened")
            {
                using var shape = JsonDocument.Parse(audit.DataJson); var modern = shape.RootElement.TryGetProperty("documentId", out _);
                var link = modern ? Canonical<Link>(audit.DataJson) : FromLegacy(Canonical<LegacyLink>(audit.DataJson), source);
                var token = tokens.Single(x => x.Id == link.tokenId);
                if (!usedTokens.Add(token.Id) || link.signerId != signerId || link.documentId != source || link.documentSha256 != documentHash ||
                    link.disclosureSha256 != disclosureHash || link.authentication != "single_use_email_link" || token.EnvelopeId != id || token.PartyId != signerId ||
                    token.PartyType != PartyType.Signer || token.Purpose != TokenPurpose.SignerAccess || token.Email != epoch.Email || token.TokenSha256 is not { Length: 32 } ||
                    token.UsedAt is not { } consumed || consumed.Offset != TimeSpan.Zero || consumed < epoch.Started || consumed > audit.At ||
                    token.ExpiresAt.Offset != TimeSpan.Zero || consumed >= token.ExpiresAt || token.SignerContactRevisionId != (epoch.Revision == Guid.Empty ? null : epoch.Revision)) throw Invalid();
                var scoped = token.DocumentId is not null || token.DocumentSha256 is not null || token.DisclosureSha256 is not null;
                if (modern || scoped)
                { if (token.DocumentId != source || !Same(token.DocumentSha256, sourceHash) || !Same(token.DisclosureSha256, e.ErsdSha256)) throw Invalid(); }
                else if (epoch.Revision != Guid.Empty) throw Invalid();
                if (!modern && epoch.Revision != Guid.Empty) throw Invalid();
                epoch.Linked = true; continue;
            }
            if (audit.Event == "consent_given")
            {
                var consent = Canonical<Consent>(audit.DataJson);
                if (!epoch.Linked || epoch.Consent is not null || consent.disclosureVersion != e.ErsdVersion || consent.disclosureSha256 != disclosureHash ||
                    consent.documentSha256 != documentHash || consent.accessReceiptId == Guid.Empty || !receipts.Add(consent.accessReceiptId) ||
                    consent.accessMethod is not ("preview" or "download") || !consent.agreement || !consent.canRetain ||
                    consent.serverEvidence != "hash_verified_pdf_prepared" || consent.clientEvidence != "signer_reported_access_and_retention") throw Invalid();
                epoch.Consent = audit; continue;
            }
            if (epoch.Consent is null) throw Invalid();
            epoch.Actions.Add(audit.At);
        }
        if (corrections.Count != records.Length || tokens.Any(x => x.Purpose == TokenPurpose.SignerAccess && x.UsedAt is not null && !usedTokens.Contains(x.Id))) throw Invalid();
        foreach (var signer in signers) { if (active[signer.Id].Email != signer.Email) throw Invalid(); Close(active[signer.Id], signer, long.MaxValue, captured); }
        var sessionIds = new HashSet<Guid>();
        foreach (var session in sessions)
            if (session.EnvelopeId != id || session.SessionId == Guid.Empty || !sessionIds.Add(session.SessionId) || session.SessionSha256 is not { Length: 32 } ||
                session.CreatedAt.Offset != TimeSpan.Zero || session.ExpiresAt.Offset != TimeSpan.Zero || session.CreatedAt > captured || session.ExpiresAt <= session.CreatedAt ||
                !epochs.Any(x => x.Signer == session.SignerId && x.Revision != Guid.Empty && x.Revision == session.RevisionId && session.CreatedAt >= x.Started && session.CreatedAt <= x.Ended)) throw Invalid();
        foreach (var preview in previews)
        {
            var candidates = epochs.Where(x => x.Signer == preview.SignerId && x.Consented && preview.EnvelopeId == id && preview.CreatedAt >= x.ActualConsent && preview.CreatedAt <= x.Ended);
            if (preview.UsedAt is not null)
            {
                var adoption = audits.Single(x => x.Event == "signature_adopted" && AdoptionId(x.DataJson) == preview.Id);
                candidates = candidates.Where(x => adoption.Sequence > x.StartSequence && adoption.Sequence < x.EndSequence && preview.UsedAt >= x.ActualConsent);
            }
            if (!candidates.Any(x => x.Revision == Guid.Empty || sessions.Any(s => s.SignerId == x.Signer && s.RevisionId == x.Revision &&
                Same(s.SessionSha256, preview.SessionSha256) && s.CreatedAt <= preview.CreatedAt && s.ExpiresAt > (preview.UsedAt ?? preview.CreatedAt)))) throw Invalid();
        }
        void Close(Epoch epoch, Signer saved, long endSequence, DateTimeOffset ended)
        {
            epoch.EndSequence = endSequence; epoch.Ended = ended;
            if (epoch.Consent is not { } consent)
            { if (saved.ConsentAt is not null || saved.ConsentIp is not null || saved.ConsentUa is not null) throw Invalid(); return; }
            var lower = audits.Single(x => x.Sequence == consent.Sequence - 1).At;
            if (saved.ConsentAt is not { } accepted || accepted.Offset != TimeSpan.Zero || accepted < lower || accepted > consent.At || accepted > ended ||
                saved.ConsentIp != consent.Ip || saved.ConsentUa != consent.UserAgent || epoch.Actions.Any(x => x < accepted || x > ended)) throw Invalid();
            epoch.Consented = true; epoch.ActualConsent = accepted;
        }
    }
    private static Link FromLegacy(LegacyLink value, Guid savedSource) => new(value.signerId, value.tokenId, savedSource, value.documentSha256, value.disclosureSha256, value.authentication);
    private static Guid AdoptionId(string raw) { if (!Bounded(raw, 8192)) throw Invalid(); using var json = JsonDocument.Parse(raw); return json.RootElement.GetProperty("adoptionId").GetGuid(); }
    private static T Canonical<T>(string raw, JsonSerializerOptions? options = null)
    { if (!Bounded(raw, 8192)) throw Invalid(); var value = JsonSerializer.Deserialize<T>(raw, options ?? Strict) ?? throw Invalid(); return JsonSerializer.Serialize(value, options) == raw ? value : throw Invalid(); }
    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    private static bool Same(byte[]? left, byte[]? right) => left is { Length: 32 } && right is { Length: 32 } && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool Bounded(string? raw, int maximum) => raw is not null && raw.Length <= maximum && Encoding.UTF8.GetByteCount(raw) <= maximum;
    private static InvalidDataException Invalid() => new("Historical signer link and consent evidence could not be verified.");
}

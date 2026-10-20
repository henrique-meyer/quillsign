using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Signing;

namespace QuillSign.Lifecycle;

// Saved adoption history, never a live preview/access reader. Consent, field
// changes and the complete acceptance graph retain their separate checks.
internal static class ProductionHoldAdoptionAuditReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { MaxDepth = 4, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private sealed record Evidence(Guid adoptionId, Guid? replacedAdoptionId, string statementVersion, string statement, string statementSha256,
        bool acknowledged, string method, string? reportedTypedName, string? reportedTypedInitials, string normalizationVersion,
        Guid signatureObjectId, Guid initialsObjectId, string signatureSha256, string initialsSha256, string documentSha256,
        string disclosureSha256, string serverEvidence, string identityEvidence);

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects)
    {
        try { Verify(sql, objects); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException or NullReferenceException)
        { throw Invalid(); }
    }
    private static void Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        T[] Table<T>(string name, int limit)
        { var rows = tables[name]; if (rows.GetArrayLength() > limit) throw Invalid(); return rows.Deserialize<T[]>(Rows) ?? throw Invalid(); }
        var audits = Table<AuditEvent>("AuditEvents", 4096);
        var previews = Table<SignaturePreview>("SignaturePreviews", 4000);
        var signers = Table<Signer>("Signers", 100);
        if (!audits.Any(x => x.Event == "signature_adopted") && !previews.Any(x => x.UsedAt is not null) && signers.All(x => Matches(null, x))) return;
        var id = sql.GetProperty("RecordId").GetGuid(); var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var envelope = Table<Envelope>("Envelopes", 1).Single();
        var sent = audits.Single(x => x.Event == "sent");
        if (id == Guid.Empty || envelope.Id != id || envelope.SentAt is null || envelope.ErsdSha256 is not { Length: 32 } ||
            captured.Offset != TimeSpan.Zero || captured < envelope.SentAt || signers.Any(x => x.EnvelopeId != id || x.Id == Guid.Empty) ||
            signers.Select(x => x.Id).Distinct().Count() != signers.Length || previews.Select(x => x.Id).Distinct().Count() != previews.Length ||
            previews.GroupBy(x => x.SignerId).Any(x => x.Count() > SignatureAdoption.MaximumPreviewsPerSigner)) throw Invalid();
        var records = Table<SignerContactRevisionRecord>("SignerContactRevisions", 100);
        var finishes = Table<SignerFinishAcceptance>("SignerFinishAcceptances", 100);
        var states = signers.ToDictionary(x => x.Id, _ => (SignaturePreview?)null);
        var addresses = signers.ToDictionary(x => x.Id, x => x.Email);
        var retirements = new Dictionary<Guid, (SignerContactRevision Revision, RetiredSignerEntries Snapshot)>();
        foreach (var row in records)
        {
            if (!Bounded(row.EvidenceJson, 8192) || !Bounded(row.RetirementJson, 4 * 1024 * 1024)) throw Invalid();
            var revision = JsonSerializer.Deserialize<SignerContactRevision>(row.EvidenceJson, new JsonSerializerOptions(JsonSerializerDefaults.Web) { MaxDepth = 4 }) ?? throw Invalid();
            // The object-reference and preparation codecs authenticate the complete
            // bounded retirement/epoch history before this narrower projection.
            if (SignerContactHistory.Canonical(revision) != row.EvidenceJson || row.Id != revision.Id || row.EnvelopeId != id || revision.EnvelopeId != id ||
                row.SignerId != revision.SignerId || row.Number != revision.Number || row.ChangedAt != revision.ChangedAt ||
                row.PreviousRevisionId != (revision.PreviousRevisionId == Guid.Empty ? null : revision.PreviousRevisionId) ||
                SignerContactState.RetirementDigest(row.RetirementJson) != revision.RetirementSha256 || !states.ContainsKey(row.SignerId)) throw Invalid();
            var snapshot = ProductionHoldObjectReferences.ReadRetired(JsonSerializer.SerializeToElement(row));
            if (JsonSerializer.Serialize(snapshot) != row.RetirementJson || snapshot.Signer.Id != row.SignerId || snapshot.Signer.EnvelopeId != id ||
                snapshot.Signer.Email != revision.OldEmail || Convert.ToBase64String(snapshot.Signer.RowVersion) != revision.ReviewedSignerVersion ||
                !retirements.TryAdd(row.Id, (revision, snapshot))) throw Invalid();
        }
        foreach (var group in retirements.Values.GroupBy(x => x.Revision.SignerId))
            addresses[group.Key] = group.OrderBy(x => x.Revision.Number).First().Revision.OldEmail;
        var used = new HashSet<Guid>(); var corrected = new HashSet<Guid>();
        foreach (var audit in audits.Where(x => x.Event is "signature_adopted" or SignerContactHistory.Event).OrderBy(x => x.Sequence))
        {
            if (audit.EnvelopeId != id || audit.Sequence <= sent.Sequence || audit.At.Offset != TimeSpan.Zero || audit.At < envelope.SentAt || audit.At > captured ||
                !Bounded(audit.DataJson, 8192) || !Same(audit.Hash, AuditHash.Compute(audit))) throw Invalid();
            if (audit.Event == SignerContactHistory.Event)
            {
                var pair = retirements.Values.Single(x => SignerContactHistory.Canonical(x.Revision) == audit.DataJson);
                var revision = pair.Revision; var saved = pair.Snapshot.Signer;
                if (!corrected.Add(revision.Id) || audit.ActorType != PartyType.Sender || audit.ActorId is not null || audit.ActorEmail != envelope.SenderEmail ||
                    audit.At != revision.ChangedAt || addresses[revision.SignerId] != revision.OldEmail || !Matches(states[revision.SignerId], saved)) throw Invalid();
                states[revision.SignerId] = null; addresses[revision.SignerId] = revision.NewEmail; continue;
            }
            var evidence = JsonSerializer.Deserialize<Evidence>(audit.DataJson, Strict) ?? throw Invalid();
            if (JsonSerializer.Serialize(evidence) != audit.DataJson || audit.ActorType != PartyType.Signer || audit.ActorId is not Guid signerId ||
                !states.ContainsKey(signerId) || audit.ActorEmail != addresses[signerId] || EmailAddress.Normalize(audit.ActorEmail) != audit.ActorEmail) throw Invalid();
            var p = previews.Single(x => x.Id == evidence.adoptionId); var signer = signers.Single(x => x.Id == signerId);
            if (!used.Add(p.Id) || p.Id == Guid.Empty || p.EnvelopeId != id || p.SignerId != signerId || p.UsedAt is not { } adopted ||
                p.CreatedAt.Offset != TimeSpan.Zero || p.ExpiresAt.Offset != TimeSpan.Zero || adopted.Offset != TimeSpan.Zero ||
                p.CreatedAt < envelope.SentAt || adopted < p.CreatedAt || adopted >= p.ExpiresAt || p.ExpiresAt > p.CreatedAt.AddMinutes(SignatureAdoption.PreviewMinutes) || audit.At < adopted ||
                p.SessionSha256 is not { Length: 32 } || p.BaselineSignerVersion is not { Length: 8 } || !Enum.IsDefined(p.Method) ||
                p.NormalizationVersion != SignaturePng.Version || p.AdoptionVersion != SignatureAdoptionStatement.Version ||
                p.SignatureObjectId == Guid.Empty || p.InitialsObjectId == Guid.Empty || p.SignatureObjectId == p.InitialsObjectId ||
                p.SignatureWidth is < 1 or > SignaturePng.MaximumWidth || p.InitialsWidth is < 1 or > SignaturePng.MaximumWidth ||
                p.SignatureHeight is < 1 or > SignaturePng.MaximumHeight || p.InitialsHeight is < 1 or > SignaturePng.MaximumHeight ||
                (p.Method == SignatureMethod.Typed ? !Descriptor(p.TypedName, 200) || !Descriptor(p.TypedInitials, 20) : p.TypedName is not null || p.TypedInitials is not null) ||
                evidence.replacedAdoptionId != states[signerId]?.Id || !Same(p.DisclosureSha256, envelope.ErsdSha256) ||
                !SignatureAdoption.MatchesAdoptionEvidence(audit.DataJson, p, Hex(p.DocumentSha256), Hex(envelope.ErsdSha256)) ||
                evidence.serverEvidence != "previewed_assets_bound_to_explicit_adoption_request" || evidence.identityEvidence != "email_link_session_with_prior_consent") throw Invalid();
            Guid source; byte[] hash;
            if (signer.Order == 1)
            { source = Guid.ParseExact(envelope.SentPdfBlob!, "N"); hash = envelope.SentPdfSha256!; }
            else
            {
                var previous = signers.Single(x => x.Order == signer.Order - 1);
                var finish = finishes.Single(x => x.SignerId == previous.Id && x.ProcessedAt is not null);
                if (previous.Status != SignerStatus.Signed || previous.SignedAt != finish.FinishedAt || finish.EnvelopeId != id || finish.ProcessedAt > p.CreatedAt ||
                    finish.FinishedAt > finish.ProcessedAt || !Same(finish.DisclosureSha256, envelope.ErsdSha256)) throw Invalid();
                source = finish.PdfObjectId; hash = finish.PdfSha256;
            }
            if (p.DocumentId != source || !Same(p.DocumentSha256, hash)) throw Invalid();
            Match(p.DocumentId, p.DocumentSha256); Match(p.SignatureObjectId, p.SignatureSha256, true); Match(p.InitialsObjectId, p.InitialsSha256, true);
            states[signerId] = p;
        }
        if (corrected.Count != records.Length || previews.Any(x => x.UsedAt is not null && !used.Contains(x.Id))) throw Invalid();
        foreach (var signer in signers)
            if (addresses[signer.Id] != signer.Email || !Matches(states[signer.Id], signer)) throw Invalid();

        void Match(Guid objectId, byte[] hash, bool mark = false)
        {
            if (objectId == Guid.Empty || hash is not { Length: 32 } || !objects.Any(x => x.Address.Area == "normalized" &&
                x.Address.Name == $"{id:N}/{objectId:N}" && x.Sha256 == Hex(hash) && (!mark || x.Address.Length is > 0 and <= SignaturePng.MaximumBytes))) throw Invalid();
        }
    }
    private static bool Matches(SignaturePreview? p, Signer signer) => p is not null ? SignatureAdoption.MatchesRevision(p, signer) :
        signer.SignatureAdoptionId is null && signer.SignatureAdoptedAt is null && signer.SignatureImageBlob is null && signer.InitialsImageBlob is null &&
        signer.SignatureImageSha256 is null && signer.InitialsImageSha256 is null && signer.SignatureMethod is null && signer.SignatureTypedName is null &&
        signer.SignatureTypedInitials is null && signer.SignatureNormalizationVersion is null && signer.SignatureAdoptionVersion is null;
    private static bool Descriptor(string? value, int maximum)
    {
        if (value is not { Length: > 0 } || value.Length > maximum || value.Trim() != value) return false;
        _ = new UTF8Encoding(false, true).GetByteCount(value);
        return value.IsNormalized(NormalizationForm.FormC) && !value.EnumerateRunes().Any(r => Rune.GetUnicodeCategory(r) is
            System.Globalization.UnicodeCategory.Control or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.Surrogate);
    }
    private static bool Same(byte[]? left, byte[]? right) => left is { Length: 32 } && right is { Length: 32 } && CryptographicOperations.FixedTimeEquals(left, right);
    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    private static bool Bounded(string? raw, int limit) => raw is not null && raw.Length <= limit && Encoding.UTF8.GetByteCount(raw) <= limit;
    private static InvalidDataException Invalid() => new("Historical signature adoption evidence could not be verified.");
}

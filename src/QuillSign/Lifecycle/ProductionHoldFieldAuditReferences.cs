using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;

namespace QuillSign.Lifecycle;

// Historical editable-field transitions. Verified preparation/adoption projections
// are evidence, not capabilities. Full consent/review/Finish semantics remain separate.
internal static class ProductionHoldFieldAuditReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { MaxDepth = 4, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private sealed record Evidence(Guid fieldId, string type, string? previousValue, string? value, Guid? previousAdoptionId,
        Guid? adoptionId, string? previousImageSha256, string? imageSha256, string? valueSha256, string documentSha256, string disclosureSha256, string input);
    private sealed record State(string? Value, Guid? Adoption, string? ImageHash, DateTimeOffset? Lower, DateTimeOffset? Upper);
    private static readonly State Empty = new(null, null, null, null, null);

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IReadOnlyList<FieldInput> definitions, IReadOnlyList<HoldAdoptedMark> adoptions)
    {
        try { Verify(sql, objects, definitions, adoptions); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException or NullReferenceException)
        { throw Invalid(error); }
    }
    private static void Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IReadOnlyList<FieldInput> definitions, IReadOnlyList<HoldAdoptedMark> adoptions)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        T[] Table<T>(string name, int maximum)
        { var value = tables[name]; if (value.GetArrayLength() > maximum) throw Invalid(); return value.Deserialize<T[]>(Rows) ?? throw Invalid(); }
        var audits = Table<AuditEvent>("AuditEvents", 4096);
        if (definitions.Count > 200) throw Invalid();
        var assigned = definitions.Where(x => x.SignerId is not null).ToDictionary(x => x.Id);
        if (assigned.Count == 0 && !audits.Any(x => x.Event is "field_filled" or "field_cleared")) return;
        var id = sql.GetProperty("RecordId").GetGuid(); var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var e = Table<Envelope>("Envelopes", 1).Single();
        if (e.Status == EnvelopeStatus.Draft && !audits.Any(x => x.Event is "field_filled" or "field_cleared")) return;
        var sent = audits.Single(x => x.Event == "sent");
        if (id == Guid.Empty || e.Id != id || e.SentAt is null || e.ErsdSha256 is not { Length: 32 } || captured.Offset != TimeSpan.Zero || captured < e.SentAt) throw Invalid();
        var signers = Table<Signer>("Signers", 100); var current = Table<DocumentField>("Fields", 200);
        var finishes = Table<SignerFinishAcceptance>("SignerFinishAcceptances", 100);
        var contacts = Table<SignerContactRevisionRecord>("SignerContactRevisions", 100);
        var states = assigned.ToDictionary(x => x.Key, _ => Empty);
        var addresses = signers.ToDictionary(x => x.Id, x => x.Email);
        var resetAfter = signers.ToDictionary(x => x.Id, _ => sent.Sequence);
        var retired = new Dictionary<Guid, (SignerContactRevision Revision, RetiredSignerEntries Snapshot)>();
        foreach (var row in contacts)
        {
            if (!Bounded(row.EvidenceJson, 8192)) throw Invalid();
            var revision = JsonSerializer.Deserialize<SignerContactRevision>(row.EvidenceJson, new JsonSerializerOptions(JsonSerializerDefaults.Web) { MaxDepth = 4 }) ?? throw Invalid();
            if (row.EnvelopeId != id || revision.Id != row.Id || revision.SignerId != row.SignerId || SignerContactHistory.Canonical(revision) != row.EvidenceJson ||
                SignerContactState.RetirementDigest(row.RetirementJson) != revision.RetirementSha256) throw Invalid();
            retired.Add(row.Id, (revision, ProductionHoldObjectReferences.ReadRetired(JsonSerializer.SerializeToElement(row))));
        }
        foreach (var group in retired.Values.GroupBy(x => x.Revision.SignerId)) addresses[group.Key] = group.OrderBy(x => x.Revision.Number).First().Revision.OldEmail;
        var corrections = new HashSet<Guid>();
        foreach (var audit in audits.Where(x => x.Event is "field_filled" or "field_cleared" or SignerContactHistory.Event).OrderBy(x => x.Sequence))
        {
            if (audit.EnvelopeId != id || audit.Sequence <= sent.Sequence || audit.At.Offset != TimeSpan.Zero || audit.At < e.SentAt || audit.At > captured ||
                !Bounded(audit.DataJson, 64 * 1024) || !Same(audit.Hash, AuditHash.Compute(audit))) throw Invalid();
            if (audit.Event == SignerContactHistory.Event)
            {
                var (revision, snapshot) = retired.Values.Single(x => SignerContactHistory.Canonical(x.Revision) == audit.DataJson);
                if (!corrections.Add(revision.Id) || audit.ActorType != PartyType.Sender || audit.ActorId is not null || audit.ActorEmail != e.SenderEmail ||
                    revision.ChangedAt != audit.At || addresses[revision.SignerId] != revision.OldEmail || finishes.Any(x => x.SignerId == revision.SignerId)) throw Invalid();
                MatchFields(snapshot.Fields, revision.SignerId, audit.At);
                foreach (var field in assigned.Values.Where(x => x.SignerId == revision.SignerId)) states[field.Id] = Empty;
                addresses[revision.SignerId] = revision.NewEmail; resetAfter[revision.SignerId] = audit.Sequence; continue;
            }
            var data = JsonSerializer.Deserialize<Evidence>(audit.DataJson, Strict) ?? throw Invalid();
            if (JsonSerializer.Serialize(data) != audit.DataJson || !assigned.TryGetValue(data.fieldId, out var definition) ||
                audit.ActorType != PartyType.Signer || audit.ActorId != definition.SignerId || data.type != definition.Type || data.type == nameof(FieldType.DateSigned)) throw Invalid();
            var signer = signers.Single(x => x.Id == definition.SignerId && x.EnvelopeId == id);
            var kind = Enum.Parse<FieldType>(definition.Type); var mark = kind is FieldType.Signature or FieldType.Initials;
            var (source, hash) = ProductionHoldAdoptionAuditReferences.Source(e, signer, signers, finishes, audit.At);
            if (audit.ActorEmail != addresses[signer.Id] || data.documentSha256 != Hex(hash) || data.disclosureSha256 != Hex(e.ErsdSha256) ||
                data.input != (kind == FieldType.FullName ? "server_signer_record" : "explicit_owned_field_request") ||
                !objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == $"{id:N}/{source:N}" && x.Sha256 == Hex(hash))) throw Invalid();
            var previous = states[data.fieldId];
            if (data.previousValue != previous.Value || data.previousAdoptionId != previous.Adoption || data.previousImageSha256 != previous.ImageHash ||
                data.valueSha256 != (data.value is null ? null : Hex(SHA256.HashData(Encoding.UTF8.GetBytes(data.value))))) throw Invalid();
            if (mark && previous.Value is not null) Mark(previous.Adoption, previous.Value, previous.ImageHash, signer.Id, kind, audit.Sequence);
            var finish = finishes.SingleOrDefault(x => x.SignerId == signer.Id);
            if (finish is not null && (finish.FinishedAt < audit.At || audits.Any(x => x.Event == "signer_finish_accepted" && x.ActorId == signer.Id && x.Sequence < audit.Sequence))) throw Invalid();
            if (audit.Event == "field_cleared")
            {
                if (data.value is not null || data.adoptionId is not null || data.imageSha256 is not null || previous == Empty) throw Invalid();
                states[data.fieldId] = Empty; continue;
            }
            if (data.value is null) throw Invalid();
            if (mark)
            {
                var latest = adoptions.Where(x => x.SignerId == signer.Id && x.Sequence > resetAfter[signer.Id] && x.Sequence < audit.Sequence).OrderBy(x => x.Sequence).LastOrDefault() ?? throw Invalid();
                if (latest.Id != data.adoptionId) throw Invalid();
                Mark(data.adoptionId, data.value, data.imageSha256, signer.Id, kind, audit.Sequence);
            }
            else if (data.adoptionId is not null || data.imageSha256 is not null || SignerFields.Canonical(data.value) != data.value ||
                kind == FieldType.FullName && data.value != SignerFields.Canonical(signer.FullName) || kind == FieldType.Checkbox && data.value is not ("true" or "false") ||
                kind == FieldType.Date && !DateOnly.TryParseExact(data.value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _)) throw Invalid();
            if (previous.Value == data.value && previous.Adoption == data.adoptionId && previous.ImageHash == data.imageSha256 && previous.Upper is not null) throw Invalid();
            var lower = audits.Single(x => x.Sequence == audit.Sequence - 1).At;
            states[data.fieldId] = new(data.value, data.adoptionId, data.imageSha256, lower, audit.At);
        }
        if (corrections.Count != contacts.Length) throw Invalid();
        foreach (var signer in signers)
        {
            if (addresses[signer.Id] != signer.Email) throw Invalid();
            MatchFields(current.Where(x => x.SignerId == signer.Id).ToArray(), signer.Id, captured);
        }
        foreach (var finish in finishes)
        {
            if (finish.EnvelopeId != id || finish.FinishedAt.Offset != TimeSpan.Zero || finish.FinishedAt < e.SentAt || finish.FinishedAt > captured ||
                !Bounded(finish.FieldsJson, 16 * 1024 * 1024) || !Same(finish.FieldsSha256, SHA256.HashData(Encoding.UTF8.GetBytes(finish.FieldsJson)))) throw Invalid();
            var fields = ProductionHoldObjectReferences.ReadFinishFields(JsonSerializer.SerializeToElement(finish));
            MatchFields(fields, finish.SignerId, finish.FinishedAt);
            // This binds the saved field snapshot to its exact producer evidence;
            // it deliberately does not stand in for complete review/Finish verification.
            var evidence = audits.Single(x => x.Event == "signer_finish_accepted" && x.ActorId == finish.SignerId);
            if (evidence.DataJson != SignerFinish.EvidenceJson(finish) || evidence.EnvelopeId != id || evidence.ActorType != PartyType.Signer || evidence.Sequence <= sent.Sequence ||
                evidence.At.Offset != TimeSpan.Zero || evidence.At < finish.FinishedAt || evidence.At > captured ||
                evidence.ActorEmail != addresses[finish.SignerId] || evidence.Ip != finish.Ip || evidence.UserAgent != finish.UserAgent || !Same(evidence.Hash, AuditHash.Compute(evidence))) throw Invalid();
        }
        void Mark(Guid? adoption, string value, string? imageHash, Guid signer, FieldType kind, long sequence)
        {
            var p = adoptions.Single(x => x.Id == adoption && x.SignerId == signer && x.Sequence < sequence);
            var objectId = kind == FieldType.Signature ? p.SignatureObjectId : p.InitialsObjectId;
            var hash = kind == FieldType.Signature ? p.SignatureSha256 : p.InitialsSha256;
            if (value != objectId.ToString("N") || imageHash != hash || !objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == $"{id:N}/{objectId:N}" && x.Sha256 == hash)) throw Invalid();
        }
        void MatchFields(IReadOnlyList<DocumentField> saved, Guid signer, DateTimeOffset at)
        {
            var expected = assigned.Values.Where(x => x.SignerId == signer).ToArray();
            if (saved.Count != expected.Length || saved.Select(x => x.Id).Distinct().Count() != saved.Count) throw Invalid();
            foreach (var field in saved)
            {
                var definition = expected.Single(x => x.Id == field.Id);
                if (field.EnvelopeId != id || field.SignerId != signer || definition != new FieldInput(field.Id, field.SignerId, field.Type.ToString(), field.Page, field.X, field.Y,
                    field.Width, field.Height, field.Required, field.Label, definition.Value)) throw Invalid();
                if (field.Type == FieldType.DateSigned)
                {
                    // This is only the server-owned Date Signed transition, not
                    // an invented editable-field event or full Finish validation.
                    var finish = finishes.SingleOrDefault(x => x.SignerId == signer);
                    if (field.SignatureAdoptionId is not null || field.ImageSha256 is not null ||
                        (finish is null || at < finish.FinishedAt ? field.Value is not null || field.FilledAt is not null || field.FilledBy is not null :
                            finish.ProspectiveDate != DateOnly.FromDateTime(finish.FinishedAt.UtcDateTime) ||
                            field.Value != finish.ProspectiveDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) || field.FilledAt != finish.FinishedAt || field.FilledBy != PartyType.Signer)) throw Invalid();
                    continue;
                }
                var state = states[field.Id];
                if (field.Value != state.Value || field.SignatureAdoptionId != state.Adoption || (field.ImageSha256 is null ? null : Hex(field.ImageSha256)) != state.ImageHash ||
                    (state.Upper is null ? field.FilledAt is not null || field.FilledBy is not null : field.FilledBy != PartyType.Signer || field.FilledAt is not { } filled ||
                        filled.Offset != TimeSpan.Zero || filled < state.Lower || filled > state.Upper || filled > at)) throw Invalid();
            }
        }
    }
    private static bool Same(byte[]? left, byte[]? right) => left is { Length: 32 } && right is { Length: 32 } && CryptographicOperations.FixedTimeEquals(left, right);
    private static string Hex(byte[] value) => Convert.ToHexStringLower(value);
    private static bool Bounded(string? raw, int maximum) => raw is not null && raw.Length <= maximum && Encoding.UTF8.GetByteCount(raw) <= maximum;
    private static InvalidDataException Invalid(Exception? cause = null) => new("Historical signer field evidence could not be verified.", cause);
}

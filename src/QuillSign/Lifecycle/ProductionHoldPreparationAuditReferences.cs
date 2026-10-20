using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Signing;

namespace QuillSign.Lifecycle;

// Historical preparation only. Later assigned-field changes, Send/disclosure
// and acceptance graphs still need their own codecs; this grants no authority.
internal static class ProductionHoldPreparationAuditReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { MaxDepth = 8, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private sealed record SignerEvidence(Guid? signerId, SignerListItem[] signers);
    private sealed record RecipientEvidence(Guid recipientId, RecipientItem[] recipients);
    private sealed record FieldEvidence(string documentId, FieldInput[] fields);
    private sealed record Details(string title, string? message);
    private static bool Selected(string name) => name is "signer_added" or "signer_updated" or "signer_removed" or "signers_reordered" or
        "recipient_added" or "recipient_updated" or "recipient_removed" or "envelope_details_updated" or "fields_saved";

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldUploadedDocument> documents)
        => _ = ReadVerified(sql, documents);
    internal static FieldInput[] ReadVerified(JsonElement sql, IReadOnlyList<HoldUploadedDocument> documents)
    {
        try { return Verify(sql, documents); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException)
        { throw Invalid(); }
    }
    private static FieldInput[] Verify(JsonElement sql, IReadOnlyList<HoldUploadedDocument> documents)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        var auditRows = tables["AuditEvents"];
        if (!auditRows.EnumerateArray().Any(x => Selected(x.GetProperty("Event").GetString()!))) return [];
        if (auditRows.GetArrayLength() > 4096) throw Invalid();
        var id = sql.GetProperty("RecordId").GetGuid();
        var e = tables["Envelopes"].EnumerateArray().Single().Deserialize<Envelope>(Rows) ?? throw Invalid();
        if (id == Guid.Empty || e.Id != id || e.SenderVerifiedAt is null || EmailAddress.Normalize(e.SenderEmail) != e.SenderEmail) throw Invalid();
        var audits = auditRows.Deserialize<AuditEvent[]>(Rows) ?? throw Invalid();
        var sent = audits.Where(x => x.Event == "sent").SingleOrDefault();
        SignerListItem[] signers = []; RecipientItem[] recipients = []; FieldInput[] fields = [];
        var signerIds = new HashSet<Guid>(); var recipientIds = new HashSet<Guid>(); Guid fieldDocument = Guid.Empty;
        Details? details = null; long detailsSequence = 0;
        foreach (var audit in audits.Where(x => Selected(x.Event)).OrderBy(x => x.Sequence))
        {
            if (audit.EnvelopeId != id || audit.ActorType != PartyType.Sender || audit.ActorId is not null || audit.ActorEmail != e.SenderEmail ||
                audit.Sequence < 1 || audit.At.Offset != TimeSpan.Zero || audit.At < e.SenderVerifiedAt ||
                sent is not null && audit.Sequence >= sent.Sequence || audit.Hash is not { Length: 32 } || !Bounded(audit.DataJson) ||
                !CryptographicOperations.FixedTimeEquals(audit.Hash, AuditHash.Compute(audit))) throw Invalid();
            var document = documents.LastOrDefault(x => x.Sequence < audit.Sequence) ?? throw Invalid();
            if (document.PreviewSequence is not { } preview || preview >= audit.Sequence) throw Invalid();
            if (fieldDocument != document.ObjectId) { fields = []; fieldDocument = document.ObjectId; }
            if (audit.Event.StartsWith("signer", StringComparison.Ordinal))
            {
                ArrayBound(audit.DataJson, "signers", 100); var next = Canonical<SignerEvidence>(audit.DataJson);
                if (next.signerId is not { } selected || selected == Guid.Empty || next.signers is null ||
                    next.signers.Where((x, n) => x is null || x.Id == Guid.Empty || x.Order != n + 1 || !Name(x.FullName) || !Address(x.Email) || !Optional(x.Role, 512)).Any() ||
                    next.signers.Select(x => x.Id).Distinct().Count() != next.signers.Length || next.signers.Select(x => x.Email).Distinct().Count() != next.signers.Length) throw Invalid();
                var old = signers.SingleOrDefault(x => x.Id == selected); var changed = next.signers.SingleOrDefault(x => x.Id == selected);
                SignerListItem[] expected;
                switch (audit.Event)
                {
                    case "signer_added":
                        if (old is not null || changed is null || !signerIds.Add(selected)) throw Invalid();
                        expected = [.. signers, changed with { Order = signers.Length + 1 }]; break;
                    case "signer_updated":
                        if (old is null || changed is null || old.Email != changed.Email && fields.Any(x => x.SignerId == selected)) throw Invalid();
                        expected = signers.Select(x => x.Id == selected ? changed with { Order = x.Order } : x).ToArray(); break;
                    case "signer_removed":
                        if (old is null || changed is not null || fields.Any(x => x.SignerId == selected)) throw Invalid();
                        expected = signers.Where(x => x.Id != selected).Select((x, n) => x with { Order = n + 1 }).ToArray(); break;
                    default:
                        if (old is null || changed is null || Math.Abs(old.Order - changed.Order) != 1) throw Invalid();
                        expected = signers.ToArray(); (expected[old.Order - 1], expected[changed.Order - 1]) = (expected[changed.Order - 1], expected[old.Order - 1]);
                        expected = expected.Select((x, n) => x with { Order = n + 1 }).ToArray(); break;
                }
                if (!expected.SequenceEqual(next.signers)) throw Invalid(); signers = next.signers;
            }
            else if (audit.Event.StartsWith("recipient_", StringComparison.Ordinal))
            {
                ArrayBound(audit.DataJson, "recipients", 100); var next = Canonical<RecipientEvidence>(audit.DataJson);
                if (next.recipientId == Guid.Empty || next.recipients is null || next.recipients.Any(x => x is null || x.Id == Guid.Empty || !Name(x.Name) || !Address(x.Email)) ||
                    next.recipients.Select(x => x.Id).Distinct().Count() != next.recipients.Length || next.recipients.Select(x => x.Email).Distinct().Count() != next.recipients.Length) throw Invalid();
                var old = recipients.SingleOrDefault(x => x.Id == next.recipientId); var changed = next.recipients.SingleOrDefault(x => x.Id == next.recipientId);
                if (audit.Event == "recipient_added" ? old is not null || changed is null || !recipientIds.Add(next.recipientId)
                    : old is null || (audit.Event == "recipient_removed" ? changed is not null : changed is null)) throw Invalid();
                var expected = recipients.Where(x => x.Id != next.recipientId).Concat(changed is null ? [] : [changed]);
                // Preserve the actual historical sequence; culture-sensitive name
                // ordering is not guessed when authenticating an old snapshot.
                if (!SetEqual(expected, next.recipients, x => x.Id)) throw Invalid(); recipients = next.recipients;
            }
            else if (audit.Event == "fields_saved")
            {
                ArrayBound(audit.DataJson, "fields", 200); var next = Canonical<FieldEvidence>(audit.DataJson);
                if (next.documentId != document.ObjectId.ToString("N") || next.fields is null || next.fields.Select(x => x?.Id).Distinct().Count() != next.fields.Length) throw Invalid();
                foreach (var field in next.fields)
                {
                    if (field is null || field.Id == Guid.Empty || !Enum.TryParse<FieldType>(field.Type, out var kind) || !Enum.IsDefined(kind) || kind.ToString() != field.Type ||
                        field.Page < 1 || field.Page > document.Pages || !FieldGeometry.InBounds(field.X, field.Y, field.Width, field.Height) ||
                        field.X != FieldGeometry.Round(field.X) || field.Y != FieldGeometry.Round(field.Y) || field.Width != FieldGeometry.Round(field.Width) || field.Height != FieldGeometry.Round(field.Height) ||
                        !Optional(field.Label, 512) || !Value(field.Value) ||
                        (field.SignerId is { } owner ? !signers.Any(x => x.Id == owner) || field.Value is not null : kind is not (FieldType.Text or FieldType.Checkbox or FieldType.Date)) ||
                        field.Value is not null && (kind == FieldType.Checkbox && field.Value is not ("true" or "false") ||
                            kind == FieldType.Date && !DateOnly.TryParseExact(field.Value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))) throw Invalid();
                }
                fields = next.fields;
            }
            else
            {
                details = Canonical<Details>(audit.DataJson); detailsSequence = audit.Sequence;
                if (!Name(details.title) || !Value(details.message) || details.message is not null && (details.message.Length == 0 || details.message.Trim() != details.message)) throw Invalid();
            }
        }
        if (details is not null && (e.Message != details.message || e.Status == EnvelopeStatus.Draft && detailsSequence > documents[^1].Sequence && e.Title != details.title)) throw Invalid();
        var currentSigners = Entities<Signer>("Signers", 100).OrderBy(x => x.Order).ToArray();
        if (currentSigners.Any(x => x.EnvelopeId != id)) throw Invalid();
        var records = Entities<SignerContactRevisionRecord>("SignerContactRevisions", 100);
        var changes = audits.Where(x => x.Event == SignerContactHistory.Event).OrderBy(x => x.Sequence).ToArray();
        if (records.Length != changes.Length) throw Invalid();
        if (records.Length == 0)
        {
            if (!signers.SequenceEqual(currentSigners.Select(x => new SignerListItem(x.Id, x.Order, x.FullName, x.Email, x.Role)))) throw Invalid();
        }
        else
        {
            if (sent is null || e.SentAt is null) throw Invalid();
            var revisions = new List<SignerContactRevision>();
            foreach (var change in changes)
            {
                if (!Bounded(change.DataJson, 8192)) throw Invalid();
                var revision = JsonSerializer.Deserialize<SignerContactRevision>(change.DataJson, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, MaxDepth = 4 }) ?? throw Invalid();
                var record = records.Single(x => x.Id == revision.Id);
                if (SignerContactHistory.Canonical(revision) != change.DataJson || record.EvidenceJson != change.DataJson || record.EnvelopeId != id || record.SignerId != revision.SignerId ||
                    record.Number != revision.Number || record.ChangedAt != revision.ChangedAt || record.PreviousRevisionId != (revision.PreviousRevisionId == Guid.Empty ? null : revision.PreviousRevisionId)) throw Invalid();
                revisions.Add(revision);
            }
            _ = SignerContactHistory.Verify(new(id, e.SenderEmail, sent.Sequence, e.SentAt.Value, sql.GetProperty("CapturedAt").GetDateTimeOffset()),
                signers.Select(x => new SignerContactParty(x.Id, x.Order, x.FullName, x.Email, x.Role, SignerContactEpoch.Legacy)).ToArray(), changes,
                currentSigners.Select(x => { var last = revisions.LastOrDefault(r => r.SignerId == x.Id); return new SignerContactParty(x.Id, x.Order, x.FullName, x.Email, x.Role,
                    last is null ? SignerContactEpoch.Legacy : new(last.Id, last.Number)); }).ToArray());
        }
        var currentRecipients = Entities<Recipient>("Recipients", 100);
        if (currentRecipients.Any(x => x.EnvelopeId != id) || !SetEqual(recipients, currentRecipients.Select(x => new RecipientItem(x.Id, x.Name!, x.Email)), x => x.Id)) throw Invalid();
        if (fieldDocument != documents[^1].ObjectId) fields = [];
        var currentFields = Entities<DocumentField>("Fields", 200);
        if (currentFields.Length != fields.Length) throw Invalid();
        foreach (var current in currentFields)
        {
            var field = fields.Single(x => x.Id == current.Id);
            if (current.EnvelopeId != id || current.DateFormat != (current.Type is FieldType.Date or FieldType.DateSigned ? "yyyy-MM-dd" : null) ||
                field != new FieldInput(current.Id, current.SignerId, current.Type.ToString(), current.Page, current.X, current.Y, current.Width, current.Height, current.Required, current.Label,
                    current.SignerId is null || e.Status == EnvelopeStatus.Draft ? current.Value : field.Value)) throw Invalid();
        }
        return fields;
        T[] Entities<T>(string name, int maximum) { if (tables[name].GetArrayLength() > maximum) throw Invalid(); return tables[name].Deserialize<T[]>(Rows) ?? throw Invalid(); }
    }
    private static bool SetEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual, Func<T, Guid> key) => expected.OrderBy(key).SequenceEqual(actual.OrderBy(key));
    private static bool Name(string? text) => text is { Length: > 0 and <= 512 } && text.Trim() == text && !text.Any(char.IsControl);
    private static bool Optional(string? text, int maximum) => text is null || text.Length is > 0 && text.Length <= maximum && text.Trim() == text && !text.Any(char.IsControl);
    private static bool Value(string? text) => text is null || text.Length <= 4000 && !text.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t'));
    private static bool Address(string? text) => text is not null && EmailAddress.Normalize(text) == text;
    private static bool Bounded(string? raw, int maximum = 6 * 1024 * 1024) => raw is not null && raw.Length <= maximum && Encoding.UTF8.GetByteCount(raw) <= maximum;
    private static T Canonical<T>(string raw) { var value = JsonSerializer.Deserialize<T>(raw, Strict) ?? throw Invalid(); if (JsonSerializer.Serialize(value) != raw) throw Invalid(); return value; }
    private static void ArrayBound(string raw, string property, int maximum)
    {
        var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(raw), new() { MaxDepth = 8 });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) throw Invalid(); var found = false;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName) throw Invalid(); var name = reader.GetString(); if (!reader.Read()) throw Invalid();
            if (name != property) { reader.Skip(); continue; }
            if (found || reader.TokenType != JsonTokenType.StartArray) throw Invalid(); found = true; var count = 0;
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray) { if (reader.TokenType != JsonTokenType.StartObject || ++count > maximum) throw Invalid(); reader.Skip(); }
        }
        if (!found) throw Invalid();
    }
    private static InvalidDataException Invalid() => new("Historical sender preparation evidence could not be verified.");
}

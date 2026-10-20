using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using QuillSign.Data;
using QuillSign.Completion;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// Explicit named SQL reference coverage. Historical references inside opaque audit,
// recipe or outbox payloads still need coverage before complete preservation can
// be claimed. The census also retains extant unreferenced/replaced prefix objects.
internal static class ProductionHoldObjectReferences
{
    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects)
    {
        var id = sql.GetProperty("RecordId").GetGuid(); var prefix = $"{id:N}/";
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        JsonElement[] Rows(string table) => tables.TryGetValue(table, out var rows) ? rows.EnumerateArray().ToArray() : throw Invalid();
        void Required(string area, string path, JsonElement row, string objectKey, string hashKey, string? lengthKey = null, bool optional = false)
        {
            var key = row.GetProperty(objectKey); var digest = row.GetProperty(hashKey);
            if (optional && key.ValueKind == JsonValueKind.Null && digest.ValueKind == JsonValueKind.Null) return;
            var value = key.GetString();
            if (!Guid.TryParseExact(value, "N", out var objectId) && !Guid.TryParseExact(value, "D", out objectId) || objectId == Guid.Empty) throw Invalid();
            Match(area, prefix + path + objectId.ToString("N"), digest.GetBytesFromBase64(),
                lengthKey is null ? null : row.GetProperty(lengthKey).GetInt64());
        }
        void Match(string area, string name, byte[] hash, long? length = null, string? version = null, string? etag = null)
        {
            if (hash.Length != 32 || length is <= 0 || !objects.Any(x => x.Address.Area == area && x.Address.Name == name &&
                x.Sha256 == Convert.ToHexStringLower(hash) && (length is null || x.Address.Length == length) &&
                (version is null || x.Address.VersionId == version) && (etag is null || x.Address.ETag == etag))) throw Invalid();
        }
        void EnvelopeReferences(JsonElement envelope)
        {
            Required("originals", "", envelope, "OriginalBlob", "OriginalSha256", optional: true);
            Required("normalized", "", envelope, "PdfBlob", "PdfSha256", optional: true);
            Required("normalized", "", envelope, "SentPdfBlob", "SentPdfSha256", optional: true);
            Required("final", "executed/", envelope, "FinalBlob", "FinalSha256", optional: true);
            Required("final", "certificate/", envelope, "CertificateBlob", "CertificateSha256", optional: true);
        }
        void SignerReferences(JsonElement signer)
        {
            Required("normalized", "", signer, "SignatureImageBlob", "SignatureImageSha256", optional: true);
            Required("normalized", "", signer, "InitialsImageBlob", "InitialsImageSha256", optional: true);
        }
        void HistoricalFields(IReadOnlyList<DocumentField>? fields, Guid signer)
        {
            if (signer == Guid.Empty || fields is null || fields.Count is < 1 or > 200 || fields.Any(x => x is null || x.Id == Guid.Empty ||
                x.EnvelopeId != id || x.SignerId != signer || !Enum.IsDefined(x.Type)) || fields.Select(x => x.Id).Distinct().Count() != fields.Count) throw Invalid();
            foreach (var field in fields.Where(x => x.Type is FieldType.Signature or FieldType.Initials))
                Required("normalized", "", JsonSerializer.SerializeToElement(field), "Value", "ImageSha256", optional: true);
        }
        EnvelopeReferences(Rows("Envelopes").Single());
        foreach (var row in Rows("Signers"))
            SignerReferences(row);
        foreach (var row in Rows("SignerContactRevisions"))
        {
            var snapshot = ReadRetired(row);
            var raw = row.GetProperty("EvidenceJson").GetString();
            if (raw is null || raw.Length > 8192 || Encoding.UTF8.GetByteCount(raw) > 8192) throw Invalid();
            SignerContactRevision revision;
            try { revision = JsonSerializer.Deserialize<SignerContactRevision>(raw, new JsonSerializerOptions(JsonSerializerDefaults.Web) { MaxDepth = 4 }) ?? throw Invalid(); }
            catch (JsonException error) { throw new InvalidDataException("Historical contact evidence could not be decoded.", error); }
            if (SignerContactHistory.Canonical(revision) != raw || revision.EnvelopeId != id || revision.Id != row.GetProperty("Id").GetGuid() ||
                revision.SignerId != row.GetProperty("SignerId").GetGuid() || revision.Number != row.GetProperty("Number").GetInt32() ||
                revision.ChangedAt != row.GetProperty("ChangedAt").GetDateTimeOffset() ||
                revision.RetirementSha256 != SignerContactState.RetirementDigest(row.GetProperty("RetirementJson").GetString()!) ||
                snapshot.Signer is null || snapshot.Signer.EnvelopeId != id || snapshot.Signer.Id != revision.SignerId || snapshot.Signer.Email != revision.OldEmail) throw Invalid();
            Match("normalized", prefix + revision.DocumentId.ToString("N"), Convert.FromHexString(revision.DocumentSha256));
            SignerReferences(JsonSerializer.SerializeToElement(snapshot.Signer)); HistoricalFields(snapshot.Fields, snapshot.Signer.Id);
        }
        foreach (var row in Rows("SignerFinishAcceptances"))
        {
            var fields = Typed<DocumentField[]>(row, "FieldsJson", 16 * 1024 * 1024);
            var raw = row.GetProperty("FieldsJson").GetString() ?? throw Invalid();
            if (!CryptographicOperations.FixedTimeEquals(row.GetProperty("FieldsSha256").GetBytesFromBase64(), SHA256.HashData(Encoding.UTF8.GetBytes(raw)))) throw Invalid();
            HistoricalFields(fields, row.GetProperty("SignerId").GetGuid());
        }
        foreach (var row in Rows("CompletionPublicationIntents"))
        {
            var before = Typed<Envelope>(row, "BeforeEnvelopeJson", 512 * 1024);
            var intent = row.Deserialize<CompletionPublicationIntent>() ?? throw Invalid();
            if (before.Id != id || intent.EnvelopeId != id || !CryptographicOperations.FixedTimeEquals(intent.RecipeSha256, CompletionPublication.Recipe(intent))) throw Invalid();
            EnvelopeReferences(JsonSerializer.SerializeToElement(before));
        }
        foreach (var row in Rows("SignaturePreviews"))
        {
            Required("normalized", "", row, "DocumentId", "DocumentSha256");
            Required("normalized", "", row, "SignatureObjectId", "SignatureSha256");
            Required("normalized", "", row, "InitialsObjectId", "InitialsSha256");
        }
        foreach (var row in Rows("SignerReviewCandidates").Concat(Rows("SignerFinishAcceptances")))
        {
            Required("normalized", "", row, "SourceObjectId", "SourceSha256");
            Required("normalized", "", row, "PdfObjectId", "PdfSha256", "PdfLength");
        }
        foreach (var row in Rows("CompletionCandidates"))
        {
            Required("normalized", "", row, "SourceObjectId", "SourceSha256");
            Required("normalized", "completion-candidates/", row, "PdfObjectId", "PdfSha256", "PdfLength");
        }
        foreach (var row in Rows("CompletionSealOutputs"))
        {
            var kind = row.GetProperty("Kind").GetString();
            if (kind is not ("Executed" or "Certificate")) throw Invalid();
            Required("normalized", kind == "Executed" ? "completion-candidates/" : "completion-seals/certificate-source/",
                row, "SourceObjectId", "SourceSha256", "SourceLength");
            Required("normalized", kind == "Executed" ? "completion-seals/executed/" : "completion-seals/certificate/",
                row, "PdfObjectId", "PdfSha256", "PdfLength");
        }
        foreach (var row in Rows("Fields"))
            if (row.GetProperty("Type").GetString() is "Signature" or "Initials")
                Required("normalized", "", row, "Value", "ImageSha256", optional: true);
        foreach (var row in Rows("AuthTokens"))
            Required("normalized", "", row, "DocumentId", "DocumentSha256", optional: true);
        foreach (var row in Rows("CompletionPublicationResults"))
        {
            using var documents = JsonDocument.Parse(row.GetProperty("FinalDocumentsJson").GetString()!);
            foreach (var (name, kind) in new[] { ("Executed", FinalDocumentKind.Executed), ("Certificate", FinalDocumentKind.Certificate) })
            {
                var stored = documents.RootElement.GetProperty(name).Deserialize<FinalStoredDocument>() ?? throw Invalid();
                if (stored.Document.EnvelopeId != id || stored.Document.Kind != kind || stored.Document.ObjectId == Guid.Empty ||
                    string.IsNullOrEmpty(stored.VersionId) || string.IsNullOrEmpty(stored.ETag)) throw Invalid();
                Match("final", prefix + kind.ToString().ToLowerInvariant() + "/" + stored.Document.ObjectId.ToString("N"), stored.Sha256,
                    stored.Length, stored.VersionId, stored.ETag);
            }
        }
    }
    internal static RetiredSignerEntries ReadRetired(JsonElement row) => Typed<RetiredSignerEntries>(row, "RetirementJson", 4 * 1024 * 1024);
    internal static DocumentField[] ReadFinishFields(JsonElement row) => Typed<DocumentField[]>(row, "FieldsJson", 16 * 1024 * 1024);
    private static T Typed<T>(JsonElement row, string property, int maximum)
    {
        var raw = row.GetProperty(property).GetString();
        if (raw is null || raw.Length > maximum || Encoding.UTF8.GetByteCount(raw) > maximum) throw Invalid();
        try
        {
            // Bound entity arrays before constructing fields. A small JSON array
            // of millions of empty objects must not allocate millions of entities.
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(raw), new JsonReaderOptions { MaxDepth = 16 });
            if (!reader.Read()) throw Invalid();
            if (typeof(T) == typeof(DocumentField[])) FieldArray(ref reader);
            else if (typeof(T) == typeof(RetiredSignerEntries))
            {
                if (reader.TokenType != JsonTokenType.StartObject) throw Invalid(); var seen = false;
                while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
                {
                    if (reader.TokenType != JsonTokenType.PropertyName) throw Invalid(); var name = reader.GetString();
                    if (!reader.Read()) throw Invalid();
                    if (name == "Fields") { if (seen) throw Invalid(); seen = true; FieldArray(ref reader); }
                    else reader.Skip();
                }
                if (!seen) throw Invalid();
            }
            var value = JsonSerializer.Deserialize<T>(raw, new JsonSerializerOptions { MaxDepth = 16 }) ?? throw Invalid();
            // Old serialized entity evidence is preserved byte for byte. Unknown
            // columns, omitted properties or alternate interpretation need review.
            if (JsonSerializer.Serialize(value) != raw) throw Invalid(); return value;
        }
        catch (JsonException error) { throw new InvalidDataException("Historical hold object references could not be decoded.", error); }
    }
    private static void FieldArray(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.StartArray) throw Invalid(); var count = 0;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        { if (reader.TokenType != JsonTokenType.StartObject || ++count > 200) throw Invalid(); reader.Skip(); }
        if (reader.TokenType != JsonTokenType.EndArray || count == 0) throw Invalid();
    }
    private static InvalidDataException Invalid() => new("A named SQL evidence reference has no verified exact object bytes.");
}

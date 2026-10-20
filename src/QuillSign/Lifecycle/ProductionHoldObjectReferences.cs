using System.Text.Json;
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
        JsonElement[] Rows(string table) => tables[table].EnumerateArray().ToArray();
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
        var envelope = Rows("Envelopes").Single();
        Required("originals", "", envelope, "OriginalBlob", "OriginalSha256", optional: true);
        Required("normalized", "", envelope, "PdfBlob", "PdfSha256", optional: true);
        Required("normalized", "", envelope, "SentPdfBlob", "SentPdfSha256", optional: true);
        Required("final", "executed/", envelope, "FinalBlob", "FinalSha256", optional: true);
        Required("final", "certificate/", envelope, "CertificateBlob", "CertificateSha256", optional: true);
        foreach (var row in Rows("Signers"))
        {
            Required("normalized", "", row, "SignatureImageBlob", "SignatureImageSha256", optional: true);
            Required("normalized", "", row, "InitialsImageBlob", "InitialsImageSha256", optional: true);
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
    private static InvalidDataException Invalid() => new("A named SQL evidence reference has no verified exact object bytes.");
}

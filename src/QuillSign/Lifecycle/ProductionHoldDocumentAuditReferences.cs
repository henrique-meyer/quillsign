using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

// Private evidence projection, never an HTTP input or storage capability.
internal sealed record HoldUploadedDocument(long Sequence, Guid ObjectId, string Sha256, int Pages, long? PreviewSequence);

// Explicit historical document schemas. Upload v0/v1 record digests, not the
// newly allocated object IDs. Subsequent replacement/preview/current anchors
// supply only the IDs actually present in those schemas; never invent one.
internal static class ProductionHoldDocumentAuditReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { MaxDepth = 8, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private sealed record UploadV0(string filename, string originalSha256, string pdfSha256, int pageCount, string? previousDocument);
    private sealed record UploadV1(string filename, string originalSha256, string pdfSha256, int pageCount, string? previousDocument, string? retentionSha256);
    private sealed record Converted(string filename, string originalSha256, string pdfSha256, int pageCount, string? previousDocument, string? retentionSha256, JsonElement conversion);
    private sealed record Preview(string document, string pdfSha256);
    private sealed record Conversion(string version, string originalFilename, string originalMime, long originalBytes, long pdfBytes);
    private sealed record ImageConversion(string version, string originalFilename, string originalMime, long originalBytes, long pdfBytes, int width, int height);
    private sealed record OfficeConversion(string version, string originalFilename, string originalMime, long originalBytes, long pdfBytes, long conversionInputBytes, string conversionInputSha256);
    private sealed record Upload(AuditEvent Event, UploadV0 Data, string? Retention, JsonElement? Conversion);

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects)
        => _ = ReadVerified(sql, objects);
    internal static IReadOnlyList<HoldUploadedDocument> ReadVerified(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects)
    {
        try { return Verify(sql, objects); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException or DocumentRejectedException)
        { throw Invalid(); }
    }
    private static IReadOnlyList<HoldUploadedDocument> Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects)
    {
        var id = sql.GetProperty("RecordId").GetGuid();
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        var selected = tables["AuditEvents"].EnumerateArray().Where(x => x.GetProperty("Event").GetString() is
            "document_uploaded" or "document_replaced" or "preview_confirmed").ToArray();
        if (selected.Length == 0) return [];
        if (id == Guid.Empty || selected.Length > 4096) throw Invalid();
        var e = tables["Envelopes"].EnumerateArray().Single().Deserialize<Envelope>(Rows) ?? throw Invalid();
        if (e.Id != id || e.CreatedAt.Offset != TimeSpan.Zero || e.SenderVerifiedAt is null || e.SenderVerifiedAt.Value.Offset != TimeSpan.Zero ||
            QuillSign.Email.EmailAddress.Normalize(e.SenderEmail) != e.SenderEmail) throw Invalid();
        var audits = new List<AuditEvent>();
        foreach (var row in selected)
        {
            var raw = row.GetProperty("DataJson").GetString();
            if (raw is null || raw.Length > 8192 || Encoding.UTF8.GetByteCount(raw) > 8192) throw Invalid();
            var audit = row.Deserialize<AuditEvent>(Rows) ?? throw Invalid();
            if (audit.EnvelopeId != id || audit.Sequence < 1 || audit.ActorType != PartyType.Sender || audit.ActorId is not null || audit.ActorEmail != e.SenderEmail ||
                audit.At.Offset != TimeSpan.Zero || audit.At < e.CreatedAt || audit.At < e.SenderVerifiedAt || audit.Hash is not { Length: 32 } ||
                !CryptographicOperations.FixedTimeEquals(audit.Hash, AuditHash.Compute(audit))) throw Invalid();
            audits.Add(audit);
        }
        audits.Sort((a, b) => a.Sequence.CompareTo(b.Sequence));
        if (audits.Select(x => x.Sequence).Distinct().Count() != audits.Count) throw Invalid();
        var uploads = audits.Where(x => x.Event != "preview_confirmed").Select(ReadUpload).ToArray();
        if (uploads.Length == 0 || uploads[0].Event.Event != "document_uploaded" || uploads[0].Data.previousDocument is not null ||
            uploads.Skip(1).Any(x => x.Event.Event != "document_replaced")) throw Invalid();
        var documents = uploads.Skip(1).Select(x => Id(x.Data.previousDocument)).Append(Id(e.PdfBlob)).ToArray();
        if (documents.Distinct().Count() != documents.Length) throw Invalid();
        var snapshots = tables["DocumentRetentionSnapshots"].Deserialize<DocumentRetentionSnapshot[]>(Rows) ?? throw Invalid();
        if (snapshots.Length > 1) throw Invalid();
        var retention = snapshots.SingleOrDefault(); string? retentionHash = null;
        if (retention is not null)
        {
            if (!e.IsDemo || retention.EnvelopeId != id || retention.PolicyVersion != UploadRetention.Version || retention.Days is < 1 or > 36500 ||
                retention.StartedAt.Offset != TimeSpan.Zero || retention.DeleteAfter.Offset != TimeSpan.Zero ||
                retention.StartedAt > DateTimeOffset.MaxValue.AddDays(-retention.Days) || retention.DeleteAfter != retention.StartedAt.AddDays(retention.Days) ||
                retention.OriginalObjectId == Guid.Empty || retention.PdfObjectId != documents[0] || retention.OriginalSha256 is not { Length: 32 } || retention.PdfSha256 is not { Length: 32 } ||
                uploads[0].Data.originalSha256 != Convert.ToHexStringLower(retention.OriginalSha256) || uploads[0].Data.pdfSha256 != Convert.ToHexStringLower(retention.PdfSha256) ||
                uploads[0].Event.At < retention.StartedAt || uploads[0].Event.At >= retention.DeleteAfter) throw Invalid();
            retentionHash = UploadRetention.Digest(retention);
            Exact("originals", retention.OriginalObjectId, uploads[0].Data.originalSha256);
        }
        for (var n = 0; n < uploads.Length; n++)
        {
            var upload = uploads[n]; var data = upload.Data;
            if (data.filename is null || data.filename != DocumentWorkflow.Filename(data.filename) || data.pageCount is < 1 or > 200 ||
                !Digest(data.originalSha256) || !Digest(data.pdfSha256) || upload.Retention != retentionHash) throw Invalid();
            // This UUID comes from the next saved replacement or current upload,
            // not from a digest lookup or a later signing checkpoint.
            Exact("normalized", documents[n], data.pdfSha256);
            if (!objects.Any(x => Owned(x, "originals") && x.Sha256 == data.originalSha256)) throw Invalid();
            var mime = "application/pdf";
            if (upload.Conversion is { } conversion) mime = VerifyConversion(conversion, data, documents[n]);
            if (n == uploads.Length - 1 && (e.OriginalSha256 is not { Length: 32 } || e.PdfSha256 is not { Length: 32 } ||
                Convert.ToHexStringLower(e.OriginalSha256) != data.originalSha256 || Convert.ToHexStringLower(e.PdfSha256) != data.pdfSha256 ||
                e.PageCount != data.pageCount || e.OriginalMime != mime)) throw Invalid();
        }
        Exact("originals", Id(e.OriginalBlob), uploads[^1].Data.originalSha256);
        var previews = new Dictionary<Guid, long>();
        foreach (var preview in audits.Where(x => x.Event == "preview_confirmed"))
        {
            var prior = uploads.Select((u, n) => (u, n)).LastOrDefault(x => x.u.Event.Sequence < preview.Sequence);
            if (prior.u is null) throw Invalid();
            var data = Canonical<Preview>(preview.DataJson); var document = Id(data.document);
            if (document != documents[prior.n] || data.pdfSha256 != prior.u.Data.pdfSha256 || !previews.TryAdd(document, preview.Sequence)) throw Invalid();
            Exact("normalized", document, data.pdfSha256);
        }
        var currentPreview = audits.LastOrDefault(x => x.Event == "preview_confirmed" && x.Sequence > uploads[^1].Event.Sequence);
        if (e.PreviewConfirmedAt is { } confirmed
            ? confirmed.Offset != TimeSpan.Zero || confirmed < uploads[^1].Event.At || currentPreview is null || currentPreview.At < confirmed
            : currentPreview is not null) throw Invalid();
        return uploads.Select((u, n) => new HoldUploadedDocument(u.Event.Sequence, documents[n], u.Data.pdfSha256, u.Data.pageCount,
            previews.TryGetValue(documents[n], out var sequence) ? sequence : null)).ToArray();

        bool Owned(HoldObjectEvidence x, string area) => x.Address.Area == area && x.Address.Name.StartsWith($"{id:N}/", StringComparison.Ordinal) &&
            Guid.TryParseExact(x.Address.Name[(id.ToString("N").Length + 1)..], "N", out var file) && file != Guid.Empty;
        void Exact(string area, Guid objectId, string hash, long? length = null)
        {
            if (!Digest(hash) || !objects.Any(x => Owned(x, area) && x.Address.Name == $"{id:N}/{objectId:N}" && x.Sha256 == hash &&
                (length is null || x.Address.Length == length))) throw Invalid();
        }
        string VerifyConversion(JsonElement raw, UploadV0 upload, Guid pdf)
        {
            var version = raw.GetProperty("version").GetString(); Conversion core;
            if (version is "docx-gotenberg-v1" or "text-docx-gotenberg-v1") core = Canonical<Conversion>(raw.GetRawText());
            else if (version == "image-stb-v1")
            {
                var image = Canonical<ImageConversion>(raw.GetRawText());
                if (image.width is < 1 or > 12000 || image.height is < 1 or > 12000 || (long)image.width * image.height > ImageHeaderValidation.MaximumPixels || upload.pageCount != 1) throw Invalid();
                core = new(image.version, image.originalFilename, image.originalMime, image.originalBytes, image.pdfBytes);
            }
            else
            {
                var office = Canonical<OfficeConversion>(raw.GetRawText());
                if (office.conversionInputBytes is < 1 or > 64 * 1024 * 1024 || !Digest(office.conversionInputSha256)) throw Invalid();
                core = new(office.version, office.originalFilename, office.originalMime, office.originalBytes, office.pdfBytes);
            }
            if (core.originalFilename is null) throw Invalid();
            var extension = version switch
            {
                "docx-gotenberg-v1" when core.originalMime == DocxDocumentWorkflow.Mime => ".docx",
                "text-docx-gotenberg-v1" when core.originalMime == TextDocumentWorkflow.Mime => ".txt",
                "image-stb-v1" when core.originalMime == "image/png" => ".png",
                "image-stb-v1" when core.originalMime == "image/jpeg" && core.originalFilename.EndsWith(".jpeg", StringComparison.Ordinal) => ".jpeg",
                "image-stb-v1" when core.originalMime == "image/jpeg" => ".jpg",
                _ => OfficeExtension(version, core.originalMime)
            };
            if (core.originalFilename != upload.filename[..^4] + extension || core.originalBytes is < 1 or > 64 * 1024 * 1024 || core.pdfBytes is < 1 or > 64 * 1024 * 1024 ||
                !objects.Any(x => Owned(x, "originals") && x.Sha256 == upload.originalSha256 && x.Address.Length == core.originalBytes)) throw Invalid();
            Exact("normalized", pdf, upload.pdfSha256, core.pdfBytes); return core.originalMime;
        }
    }

    private static string OfficeExtension(string? version, string mime)
    {
        // Freeze the historical version registry independently of future intake
        // pipelines. Adding a converter must not silently authorize its schema.
        var kind = version switch
        {
            "static-pptx-gotenberg-v1" => OfficeSourceKind.Pptx,
            "values-xlsx-print-gotenberg-v1" => OfficeSourceKind.Xlsx,
            "static-odt-gotenberg-v1" => OfficeSourceKind.Odt,
            "literal-rtf-docx-gotenberg-v1" => OfficeSourceKind.Rtf,
            _ => throw Invalid()
        };
        var family = OfficeDocumentWorkflow.Family(kind);
        return family.Mime == mime ? family.Extension : throw Invalid();
    }
    private static Upload ReadUpload(AuditEvent audit)
    {
        using var document = JsonDocument.Parse(audit.DataJson, new() { MaxDepth = 8 }); var root = document.RootElement;
        if (root.TryGetProperty("conversion", out _))
        {
            var v = Canonical<Converted>(audit.DataJson);
            return new(audit, new(v.filename, v.originalSha256, v.pdfSha256, v.pageCount, v.previousDocument), v.retentionSha256, v.conversion.Clone());
        }
        if (root.TryGetProperty("retentionSha256", out _))
        {
            var v = Canonical<UploadV1>(audit.DataJson);
            return new(audit, new(v.filename, v.originalSha256, v.pdfSha256, v.pageCount, v.previousDocument), v.retentionSha256, null);
        }
        return new(audit, Canonical<UploadV0>(audit.DataJson), null, null);
    }
    private static T Canonical<T>(string raw)
    {
        var value = JsonSerializer.Deserialize<T>(raw, Strict) ?? throw Invalid();
        if (JsonSerializer.Serialize(value) != raw) throw Invalid(); return value;
    }
    private static Guid Id(string? value) => Guid.TryParseExact(value, "N", out var id) && id != Guid.Empty ? id : throw Invalid();
    private static bool Digest(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    private static InvalidDataException Invalid() => new("Historical document audit references could not be verified.");
}

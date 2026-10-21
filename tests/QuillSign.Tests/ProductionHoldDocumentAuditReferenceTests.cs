using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionHoldDocumentAuditReferenceTests
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Historical_replacement_binds_original_digest_and_exact_prior_preview_even_when_title_changes(bool legacy)
    {
        var f = new Frame(legacy); using var sql = f.Sql(); f.Demand(sql);
        Assert.NotEqual(f.FirstPdf, Guid.Parse(f.Envelope.PdfBlob!)); Assert.NotEqual("first.pdf", f.Envelope.Title);
        f.Objects.RemoveAt(0); using var missing = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(missing));
    }

    [Theory]
    [InlineData("actor")][InlineData("actor-role")][InlineData("actor-id")][InlineData("owner")][InlineData("pre-verification")]
    [InlineData("first-event")][InlineData("second-event")][InlineData("first-previous")][InlineData("previous-id")][InlineData("duplicate-id")]
    [InlineData("preview-id")][InlineData("preview-hash")][InlineData("preview-before-upload")][InlineData("duplicate-preview")]
    [InlineData("missing-preview")][InlineData("current-unconfirmed")][InlineData("confirmation-time")]
    [InlineData("original-missing")][InlineData("original-hash")][InlineData("original-area")][InlineData("original-owner")]
    [InlineData("prior-missing")][InlineData("prior-hash")][InlineData("prior-area")][InlineData("prior-owner")]
    [InlineData("current-pdf-hash")][InlineData("current-original-hash")][InlineData("current-original-id")][InlineData("current-pages")][InlineData("current-mime")]
    [InlineData("unknown")][InlineData("retention")][InlineData("filename")][InlineData("page-limit")][InlineData("digest-case")]
    public void Rehashed_changes_missing_history_and_wrong_scopes_fail_without_newer_copy_fallback(string fault)
    {
        var f = new Frame(false);
        switch (fault)
        {
            case "actor": f.Audits[0].ActorEmail = "other@example.invalid"; break;
            case "actor-role": f.Audits[0].ActorType = PartyType.Signer; break;
            case "actor-id": f.Audits[0].ActorId = Guid.NewGuid(); break;
            case "owner": f.Audits[0].EnvelopeId = Guid.NewGuid(); break;
            case "pre-verification": f.Audits[0].At = f.Envelope.SenderVerifiedAt!.Value.AddSeconds(-1); break;
            case "first-event": f.Audits[0].Event = "document_replaced"; break;
            case "second-event": f.Audits[2].Event = "document_uploaded"; break;
            case "first-previous": f.Edit(0, x => x["previousDocument"] = f.FirstPdf.ToString("N")); break;
            case "previous-id": f.Edit(2, x => x["previousDocument"] = Guid.NewGuid().ToString("N")); break;
            case "duplicate-id": f.Edit(2, x => x["previousDocument"] = f.Envelope.PdfBlob); break;
            case "preview-id": f.Edit(1, x => x["document"] = f.Envelope.PdfBlob); break;
            case "preview-hash": f.Edit(1, x => x["pdfSha256"] = new string('0', 64)); break;
            case "preview-before-upload": f.Audits[1].Sequence = 0; break;
            case "duplicate-preview": f.Audits.Add(new() { EnvelopeId = f.Envelope.Id, Sequence = 5, ActorEmail = f.Envelope.SenderEmail, Event = "preview_confirmed", At = f.Audits[3].At, DataJson = f.Audits[3].DataJson }); break;
            case "missing-preview": f.Audits.RemoveAt(3); break;
            case "current-unconfirmed": f.Envelope.PreviewConfirmedAt = null; break;
            case "confirmation-time": f.Envelope.PreviewConfirmedAt = f.Audits[^1].At.AddSeconds(1); break;
            case "original-missing": f.Objects.RemoveAt(0); break;
            case "original-hash": f.Objects[0] = f.Objects[0] with { Sha256 = new string('0', 64) }; break;
            case "original-area": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Area = "normalized" } }; break;
            case "original-owner": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Name = $"{Guid.NewGuid():N}/{Guid.NewGuid():N}" } }; break;
            case "prior-missing": f.Objects.RemoveAt(1); break;
            case "prior-hash": f.Objects[1] = f.Objects[1] with { Sha256 = new string('0', 64) }; break;
            case "prior-area": f.Objects[1] = f.Objects[1] with { Address = f.Objects[1].Address with { Area = "originals" } }; break;
            case "prior-owner": f.Objects[1] = f.Objects[1] with { Address = f.Objects[1].Address with { Name = $"{Guid.NewGuid():N}/{f.FirstPdf:N}" } }; break;
            case "current-pdf-hash": f.Envelope.PdfSha256 = new byte[32]; break;
            case "current-original-hash": f.Envelope.OriginalSha256 = new byte[32]; break;
            case "current-original-id": f.Envelope.OriginalBlob = Guid.NewGuid().ToString("N"); break;
            case "current-pages": f.Envelope.PageCount = 2; break;
            case "current-mime": f.Envelope.OriginalMime = "other/type"; break;
            case "unknown": f.Edit(0, x => x["hiddenObject"] = Guid.NewGuid().ToString("N")); break;
            case "retention": f.Edit(0, x => x["retentionSha256"] = new string('a', 64)); break;
            case "filename": f.Edit(0, x => x["filename"] = "bad.docx"); break;
            case "page-limit": f.Edit(0, x => x["pageCount"] = 201); break;
            case "digest-case": f.Edit(0, x => x["originalSha256"] = f.OriginalHash.ToUpperInvariant()); break;
        }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Theory]
    [InlineData("docx-gotenberg-v1")][InlineData("text-docx-gotenberg-v1")]
    [InlineData("image-stb-v1")][InlineData("image-stb-jpeg-v1")][InlineData("image-stb-jpg-v1")]
    [InlineData("static-pptx-gotenberg-v1")][InlineData("values-xlsx-print-gotenberg-v1")]
    [InlineData("static-odt-gotenberg-v1")][InlineData("literal-rtf-docx-gotenberg-v1")]
    public void Every_current_conversion_schema_binds_saved_lengths_MIME_and_historical_sources(string pipeline)
    {
        var f = new Frame(false); f.ConvertLast(pipeline); using var sql = f.Sql(); f.Demand(sql);
        Assert.Equal(4, f.Objects.Count); // intermediate conversion input is not a retained object
    }

    [Theory]
    [InlineData("future-version")][InlineData("unknown")][InlineData("missing")][InlineData("mime")][InlineData("filename")]
    [InlineData("original-length")][InlineData("pdf-length")][InlineData("zero-length")][InlineData("over-limit")]
    [InlineData("image-width")][InlineData("image-pixels")][InlineData("image-pages")]
    [InlineData("input-length")][InlineData("input-hash")][InlineData("explicit-null")]
    public void Unknown_or_changed_conversion_provenance_cannot_hide_uncovered_references(string fault)
    {
        var f = new Frame(false);
        f.ConvertLast(fault.StartsWith("image-", StringComparison.Ordinal) ? "image-stb-v1" : "static-pptx-gotenberg-v1");
        f.Edit(2, x =>
        {
            var c = x["conversion"]!;
            switch (fault)
            {
                case "future-version": c["version"] = "future-converter-v9"; break;
                case "unknown": c["anotherObject"] = Guid.NewGuid().ToString("N"); break;
                case "missing": c.AsObject().Remove("originalBytes"); break;
                case "mime": c["originalMime"] = "wrong/type"; break;
                case "filename": c["originalFilename"] = "other.pptx"; break;
                case "original-length": c["originalBytes"] = 101; break;
                case "pdf-length": c["pdfBytes"] = 201; break;
                case "zero-length": c["pdfBytes"] = 0; break;
                case "over-limit": c["pdfBytes"] = 64 * 1024 * 1024 + 1; break;
                case "image-width": c["width"] = 0; break;
                case "image-pixels": c["width"] = 12000; c["height"] = 12000; break;
                case "image-pages": x["pageCount"] = 2; f.Envelope.PageCount = 2; break;
                case "input-length": c["conversionInputBytes"] = 0; break;
                case "input-hash": c["conversionInputSha256"] = "bad"; break;
                case "explicit-null": x["conversion"] = null; break;
            }
        });
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Fact]
    public void Frozen_demo_retention_digest_stays_distinct_from_production_policy()
    {
        var f = new Frame(false); f.DemoRetention(); using var sql = f.Sql(); f.Demand(sql);
        f.Envelope.IsDemo = false; using var production = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(production));
    }

    private sealed class Frame
    {
        internal readonly Guid FirstPdf = Guid.NewGuid();
        internal readonly string OriginalHash = Convert.ToHexStringLower(SHA256.HashData("First original - NO AGREEMENT"u8));
        private readonly string firstHash = Convert.ToHexStringLower(SHA256.HashData("First PDF - NO AGREEMENT"u8));
        internal Envelope Envelope = new() { SenderEmail = "sender@example.invalid", Title = "Later title", CreatedAt = DateTimeOffset.Parse("2025-01-01T00:00:00Z"), SenderVerifiedAt = DateTimeOffset.Parse("2025-01-01T00:01:00Z"), OriginalMime = "application/pdf", PageCount = 1 };
        internal List<AuditEvent> Audits = [];
        internal List<HoldObjectEvidence> Objects = [];
        private DocumentRetentionSnapshot[] retention = [];
        internal Frame(bool legacy)
        {
            var original = Guid.NewGuid(); var current = Guid.NewGuid(); Envelope.OriginalBlob = original.ToString("N"); Envelope.PdfBlob = current.ToString("N");
            Envelope.OriginalSha256 = SHA256.HashData("Current original - NO AGREEMENT"u8); Envelope.PdfSha256 = SHA256.HashData("Current PDF - NO AGREEMENT"u8);
            var first = Guid.NewGuid();
            Objects = [Evidence("originals", first, OriginalHash, 100), Evidence("normalized", FirstPdf, firstHash, 200),
                Evidence("originals", original, Convert.ToHexStringLower(Envelope.OriginalSha256), 100), Evidence("normalized", current, Convert.ToHexStringLower(Envelope.PdfSha256), 200)];
            string Upload(string filename, string originalHash, string pdfHash, string? prior, bool old) => old
                ? JsonSerializer.Serialize(new { filename, originalSha256 = originalHash, pdfSha256 = pdfHash, pageCount = 1, previousDocument = prior })
                : JsonSerializer.Serialize(new { filename, originalSha256 = originalHash, pdfSha256 = pdfHash, pageCount = 1, previousDocument = prior, retentionSha256 = (string?)null });
            Add("document_uploaded", Upload("first.pdf", OriginalHash, firstHash, null, legacy));
            Add("preview_confirmed", JsonSerializer.Serialize(new { document = FirstPdf.ToString("N"), pdfSha256 = firstHash }));
            Add("document_replaced", Upload("second.pdf", Objects[2].Sha256, Objects[3].Sha256, FirstPdf.ToString("N"), false));
            Add("preview_confirmed", JsonSerializer.Serialize(new { document = current.ToString("N"), pdfSha256 = Objects[3].Sha256 }));
            Envelope.PreviewConfirmedAt = Audits[3].At;
            Rehash();
        }
        private void Add(string name, string data) => Audits.Add(new() { Id = 100 + Audits.Count, EnvelopeId = Envelope.Id, Sequence = Audits.Count + 1,
            ActorEmail = Envelope.SenderEmail, Event = name, At = Envelope.SenderVerifiedAt!.Value.AddMinutes(Audits.Count + 1), DataJson = data });
        private HoldObjectEvidence Evidence(string area, Guid file, string hash, long length) => new(new(area, $"{Envelope.Id:N}/{file:N}", "historical-version", "", "\"etag\"", length), hash);
        internal void Edit(int n, Action<JsonObject> action) { var data = JsonNode.Parse(Audits[n].DataJson)!.AsObject(); action(data); Audits[n].DataJson = data.ToJsonString(); }
        internal void Rehash() { byte[]? previous = null; foreach (var audit in Audits) { audit.PrevHash = previous; audit.Hash = AuditHash.Compute(audit); previous = audit.Hash; } }
        internal void ConvertLast(string pipeline)
        {
            var originalVersion = pipeline.StartsWith("image-stb-", StringComparison.Ordinal) ? "image-stb-v1" : pipeline;
            var family = pipeline switch { "docx-gotenberg-v1" => (".docx", DocxDocumentWorkflow.Mime), "text-docx-gotenberg-v1" => (".txt", TextDocumentWorkflow.Mime),
                "image-stb-v1" => (".png", "image/png"), "image-stb-jpeg-v1" => (".jpeg", "image/jpeg"), "image-stb-jpg-v1" => (".jpg", "image/jpeg"),
                _ => Enum.GetValues<OfficeSourceKind>().Select(OfficeDocumentWorkflow.Family).Where(x => x.Pipeline == pipeline).Select(x => (x.Extension, x.Mime)).Single() };
            Envelope.OriginalMime = family.Item2;
            var conversion = JsonSerializer.SerializeToNode(new { version = originalVersion, originalFilename = "second" + family.Item1, originalMime = family.Item2, originalBytes = 100, pdfBytes = 200 })!;
            if (originalVersion == "image-stb-v1") { conversion["width"] = 20; conversion["height"] = 30; }
            else if (pipeline is not ("docx-gotenberg-v1" or "text-docx-gotenberg-v1")) { conversion["conversionInputBytes"] = 300; conversion["conversionInputSha256"] = firstHash; }
            Edit(2, x => x["conversion"] = conversion); Rehash();
        }
        internal void DemoRetention()
        {
            Envelope.IsDemo = true;
            var original = Guid.ParseExact(Objects[0].Address.Name.Split('/')[1], "N");
            retention = [new() { EnvelopeId = Envelope.Id, PolicyVersion = UploadRetention.Version, Days = 7, StartedAt = Envelope.SenderVerifiedAt!.Value,
                DeleteAfter = Envelope.SenderVerifiedAt.Value.AddDays(7), OriginalObjectId = original, PdfObjectId = FirstPdf, OriginalSha256 = Convert.FromHexString(OriginalHash), PdfSha256 = Convert.FromHexString(firstHash) }];
            var digest = UploadRetention.Digest(retention[0]); Edit(0, x => x["retentionSha256"] = digest); Edit(2, x => x["retentionSha256"] = digest); Rehash();
        }
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "AuditEvents", Rows = Audits }, new { Table = "DocumentRetentionSnapshots", Rows = retention } } },
            new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        internal void Demand(JsonDocument sql) => ProductionHoldDocumentAuditReferences.Demand(sql.RootElement, Objects);
    }
}

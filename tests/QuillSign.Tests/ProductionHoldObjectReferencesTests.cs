using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionHoldObjectReferencesTests
{
    [Fact]
    public void Named_sources_replaced_marks_review_Finish_candidate_seal_and_exact_final_versions_all_require_actual_bytes()
    {
        using var model = new Model(); ProductionHoldObjectReferences.Demand(model.Document.RootElement, model.Objects);
        // Every distinct required name has coverage; retaining only final PDFs is
        // never sufficient, even if those are the only currently public objects.
        foreach (var item in model.Objects)
            Assert.Throws<InvalidDataException>(() => ProductionHoldObjectReferences.Demand(model.Document.RootElement, model.Objects.Where(x => x != item).ToArray()));
    }
    [Theory]
    [InlineData("version")][InlineData("etag")][InlineData("length")][InlineData("hash")]
    public void Final_receipt_requires_exact_stored_version_ETag_length_and_hash(string fault)
    {
        using var model = new Model(); var original = model.Objects.First(x => x.Address.Area == "final");
        var changed = fault switch
        {
            "version" => original with { Address = original.Address with { VersionId = "wrong-version" } },
            "etag" => original with { Address = original.Address with { ETag = "\"wrong\"" } },
            "length" => original with { Address = original.Address with { Length = 41 } },
            _ => original with { Sha256 = new string('0', 64) }
        };
        Assert.Throws<InvalidDataException>(() => ProductionHoldObjectReferences.Demand(model.Document.RootElement, model.Objects.Select(x => x == original ? changed : x).ToArray()));
    }
    [Fact]
    public void An_old_version_with_the_required_bytes_can_be_preserved_when_a_named_write_once_root_has_changed()
    {
        using var model = new Model(); var original = model.Objects.First(x => x.Address.Area == "originals");
        var newer = original with { Address = original.Address with { VersionId = "later-version", ETag = "\"later\"" }, Sha256 = new string('0', 64) };
        ProductionHoldObjectReferences.Demand(model.Document.RootElement, model.Objects.Append(newer).ToArray());
    }
    private sealed class Model : IDisposable
    {
        internal readonly List<HoldObjectEvidence> Objects = []; internal readonly JsonDocument Document;
        internal Model()
        {
            var id = Guid.NewGuid(); var hash = SHA256.HashData("Synthetic bytes - NO AGREEMENT"u8); const long length = 40;
            Guid Add(string area, string path = "")
            {
                var key = Guid.NewGuid(); Objects.Add(new(new(area, $"{id:N}/{path}{key:N}", "synthetic-version", "", "\"synthetic-etag\"", length), Convert.ToHexStringLower(hash))); return key;
            }
            var original = Add("originals"); var normalized = Add("normalized"); var sent = Add("normalized");
            var signature = Add("normalized"); var initials = Add("normalized"); var replaced = Add("normalized"); var review = Add("normalized");
            var candidate = Add("normalized", "completion-candidates/"); var executed = Add("normalized", "completion-seals/executed/");
            var certificateSource = Add("normalized", "completion-seals/certificate-source/"); var certificate = Add("normalized", "completion-seals/certificate/");
            var finalExecuted = Add("final", "executed/"); var finalCertificate = Add("final", "certificate/");
            FinalStoredDocument Stored(Guid key, FinalDocumentKind kind) => new(new(id, kind, key), length, hash, "synthetic-version", "\"synthetic-etag\"", FinalProtection.LegalHold, null, DateTimeOffset.UnixEpoch);
            var tables = new Dictionary<string, object[]>
            {
                ["Envelopes"] = [new Envelope { Id = id, OriginalBlob = original.ToString("N"), OriginalSha256 = hash, PdfBlob = normalized.ToString("N"), PdfSha256 = hash,
                    SentPdfBlob = sent.ToString("N"), SentPdfSha256 = hash, FinalBlob = finalExecuted.ToString("N"), FinalSha256 = hash, CertificateBlob = finalCertificate.ToString("N"), CertificateSha256 = hash }],
                ["Signers"] = [new Signer { EnvelopeId = id, SignatureImageBlob = signature.ToString("N"), SignatureImageSha256 = hash, InitialsImageBlob = initials.ToString("N"), InitialsImageSha256 = hash }],
                ["SignaturePreviews"] = [new SignaturePreview { EnvelopeId = id, DocumentId = sent, DocumentSha256 = hash, SignatureObjectId = replaced, SignatureSha256 = hash, InitialsObjectId = initials, InitialsSha256 = hash }],
                ["SignerReviewCandidates"] = [new SignerReviewCandidate { EnvelopeId = id, SourceObjectId = sent, SourceSha256 = hash, PdfObjectId = review, PdfSha256 = hash, PdfLength = length }],
                ["SignerFinishAcceptances"] = [new SignerFinishAcceptance { EnvelopeId = id, SourceObjectId = sent, SourceSha256 = hash, PdfObjectId = review, PdfSha256 = hash, PdfLength = length }],
                ["CompletionCandidates"] = [new CompletionCandidate { EnvelopeId = id, SourceObjectId = review, SourceSha256 = hash, PdfObjectId = candidate, PdfSha256 = hash, PdfLength = length }],
                ["CompletionSealOutputs"] = [new CompletionSealOutput { EnvelopeId = id, Kind = CompletionSealKind.Executed, SourceObjectId = candidate, SourceSha256 = hash, SourceLength = length,
                    PdfObjectId = executed, PdfSha256 = hash, PdfLength = length }, new CompletionSealOutput { EnvelopeId = id, Kind = CompletionSealKind.Certificate, SourceObjectId = certificateSource,
                        SourceSha256 = hash, SourceLength = length, PdfObjectId = certificate, PdfSha256 = hash, PdfLength = length }],
                ["Fields"] = [new DocumentField { EnvelopeId = id, Type = FieldType.Signature, Value = replaced.ToString("N"), ImageSha256 = hash }],
                ["AuthTokens"] = [new AuthToken { EnvelopeId = id, DocumentId = normalized, DocumentSha256 = hash }],
                ["CompletionPublicationResults"] = [new CompletionPublicationResult { EnvelopeId = id, FinalDocumentsJson = JsonSerializer.Serialize(new {
                    Executed = Stored(finalExecuted, FinalDocumentKind.Executed), Certificate = Stored(finalCertificate, FinalDocumentKind.Certificate) }) }]
            };
            var options = new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } };
            Document = JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = id, Tables = tables.Select(x => new { Table = x.Key, Rows = x.Value }) }, options));
        }
        public void Dispose() => Document.Dispose();
    }
}

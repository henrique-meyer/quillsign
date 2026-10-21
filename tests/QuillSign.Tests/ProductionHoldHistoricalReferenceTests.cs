using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Completion;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldHistoricalReferenceTests
{
    private static readonly byte[] Bytes = "Synthetic historical evidence - NO AGREEMENT"u8.ToArray();
    private static readonly byte[] Hash = SHA256.HashData(Bytes);

    [Fact]
    public void Replaced_retired_marks_Finish_entries_and_prepublication_sources_require_their_own_exact_objects()
    {
        using var frame = new Frame(); ProductionHoldObjectReferences.Demand(frame.Sql.RootElement, frame.Objects);
        // None of these references exists in the current signer/field/envelope rows.
        Assert.Equal(8, frame.Objects.Count);
    }

    [Theory]
    [InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)][InlineData(5)][InlineData(6)][InlineData(7)]
    public void Every_missing_historical_component_fails_even_when_current_rows_are_empty(int missing)
    {
        using var frame = new Frame(); frame.Objects.RemoveAt(missing);
        Assert.Throws<InvalidDataException>(() => ProductionHoldObjectReferences.Demand(frame.Sql.RootElement, frame.Objects));
    }

    [Theory]
    [InlineData("retired-owner")][InlineData("retired-party")][InlineData("retired-field-owner")][InlineData("finish-owner")]
    [InlineData("finish-party")][InlineData("finish-hash")][InlineData("before-owner")][InlineData("unknown-property")]
    [InlineData("malformed")][InlineData("null-fields")][InlineData("field-type")][InlineData("too-many-fields")]
    [InlineData("retired-hash")][InlineData("revision-owner")][InlineData("revision-document-missing")][InlineData("before-recipe")]
    public void Foreign_partial_ambiguous_and_corrupt_nested_evidence_is_rejected(string fault)
    {
        using var frame = new Frame(fault);
        Assert.Throws<InvalidDataException>(() => ProductionHoldObjectReferences.Demand(frame.Sql.RootElement, frame.Objects));
    }

    [Fact]
    public void An_object_at_the_right_address_with_different_bytes_does_not_satisfy_a_historical_reference()
    {
        using var frame = new Frame(); frame.Objects[0] = frame.Objects[0] with { Sha256 = new string('0', 64) };
        Assert.Throws<InvalidDataException>(() => ProductionHoldObjectReferences.Demand(frame.Sql.RootElement, frame.Objects));
    }

    private sealed class Frame : IDisposable
    {
        internal readonly List<HoldObjectEvidence> Objects = [];
        internal readonly JsonDocument Sql;
        internal Frame(string? fault = null)
        {
            var id = Guid.NewGuid(); var signerId = Guid.NewGuid(); var ids = Enumerable.Range(0, 8).Select(_ => Guid.NewGuid()).ToArray();
            for (var i = 0; i < ids.Length; i++)
            {
                var area = i == 4 ? "originals" : i >= 6 ? "final" : "normalized";
                var path = i == 6 ? "executed/" : i == 7 ? "certificate/" : "";
                Objects.Add(new(new(area, $"{id:N}/{path}{ids[i]:N}", "synthetic-version", "", "\"synthetic-etag\"", Bytes.Length), Convert.ToHexStringLower(Hash)));
            }
            DocumentField Field(Guid image) => new() { EnvelopeId = id, SignerId = signerId, Type = FieldType.Signature,
                Value = image.ToString("N"), ImageSha256 = Hash, SignatureAdoptionId = Guid.NewGuid() };
            var oldSigner = new Signer { EnvelopeId = id, Id = signerId, SignatureImageBlob = ids[0].ToString("N"), SignatureImageSha256 = Hash,
                InitialsImageBlob = ids[1].ToString("N"), InitialsImageSha256 = Hash, Email = "old-synthetic@example.invalid" };
            var oldFields = new[] { Field(ids[2]) }; var finishFields = new[] { Field(ids[3]) };
            var before = new Envelope { Id = id, OriginalBlob = ids[4].ToString("N"), OriginalSha256 = Hash, PdfBlob = ids[5].ToString("N"), PdfSha256 = Hash,
                FinalBlob = ids[6].ToString("N"), FinalSha256 = Hash, CertificateBlob = ids[7].ToString("N"), CertificateSha256 = Hash };
            if (fault == "retired-owner") oldSigner.EnvelopeId = Guid.NewGuid();
            if (fault == "retired-party") oldSigner.Id = Guid.NewGuid();
            if (fault == "retired-field-owner") oldFields[0].EnvelopeId = Guid.NewGuid();
            if (fault == "finish-owner") finishFields[0].EnvelopeId = Guid.NewGuid();
            if (fault == "finish-party") finishFields[0].SignerId = Guid.NewGuid();
            if (fault == "before-owner") before.Id = Guid.NewGuid();
            if (fault == "field-type") oldFields[0].Type = (FieldType)999;
            if (fault == "too-many-fields") oldFields = Enumerable.Range(0, 201).Select(_ => Field(ids[2])).ToArray();
            var retired = JsonSerializer.Serialize(new RetiredSignerEntries(oldSigner, fault == "null-fields" ? null! : oldFields));
            if (fault == "unknown-property") retired = retired[..^1] + ",\"UnknownObjectId\":\"" + Guid.NewGuid() + "\"}";
            if (fault == "malformed") retired = "{";
            var entries = JsonSerializer.Serialize(finishFields);
            var finish = new SignerFinishAcceptance { EnvelopeId = id, SignerId = signerId, SourceObjectId = ids[3], SourceSha256 = Hash,
                PdfObjectId = ids[3], PdfSha256 = Hash, PdfLength = Bytes.Length, FieldsJson = entries,
                FieldsSha256 = fault == "finish-hash" ? new byte[32] : SHA256.HashData(Encoding.UTF8.GetBytes(entries)) };
            var at = new DateTimeOffset(2030, 1, 1, 12, 0, 0, TimeSpan.Zero); var revisionId = Guid.NewGuid();
            var revision = new SignerContactRevision(SignerContactHistory.Version, revisionId, fault == "revision-owner" ? Guid.NewGuid() : id, signerId, Guid.Empty, 1,
                "old-synthetic@example.invalid", "new-synthetic@example.invalid", at, at.AddMinutes(5), Convert.ToBase64String(new byte[8]), Convert.ToBase64String(new byte[8]),
                fault == "revision-document-missing" ? Guid.NewGuid() : ids[3], Convert.ToHexStringLower(Hash), new string('0', 64),
                fault == "retired-hash" ? new string('0', 64) : SignerContactState.RetirementDigest(retired), null, SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
            var intent = new CompletionPublicationIntent { EnvelopeId = id, BeforeEnvelopeJson = JsonSerializer.Serialize(before) };
            intent.RecipeSha256 = fault == "before-recipe" ? new byte[32] : CompletionPublication.Recipe(intent);
            var tables = new Dictionary<string, object[]> {
                ["Envelopes"] = [new Envelope { Id = id }], ["Signers"] = [], ["SignaturePreviews"] = [],
                ["SignerReviewCandidates"] = [], ["SignerFinishAcceptances"] = [finish], ["CompletionCandidates"] = [],
                ["CompletionSealOutputs"] = [], ["Fields"] = [], ["AuthTokens"] = [], ["CompletionPublicationResults"] = [],
                ["SignerContactRevisions"] = [new SignerContactRevisionRecord { Id = revisionId, EnvelopeId = id, SignerId = signerId, Number = 1,
                    ChangedAt = at, EvidenceJson = SignerContactHistory.Canonical(revision), RetirementJson = retired }],
                ["CompletionPublicationIntents"] = [intent]
            };
            Sql = JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = id, Tables = tables.Select(x => new { Table = x.Key, Rows = x.Value }) },
                new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        }
        public void Dispose() => Sql.Dispose();
    }
}

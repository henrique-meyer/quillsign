using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionReviewInputCodecTests
{
    internal static readonly DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
    internal sealed record Example(IDataProtectionProvider Keys, ProductionSignerReviewWrite Write, HoldWitnessReviewPlan Plan, byte[] Cipher);
    internal static Example Create(int count = 0, string? value = null)
    {
        var keys = new EphemeralDataProtectionProvider(); var record = Guid.NewGuid(); var signer = Guid.NewGuid(); var source = Guid.NewGuid(); var adoption = Guid.NewGuid();
        var identity = new VerifiedSigner(record, "synthetic-review", signer, "signer@example.invalid", source, new('a', 64), new('b', 64), Now.AddHours(1)) { SessionId = Guid.NewGuid() };
        var signature = SignaturePng.Normalize(SignatureAdoptionTests.Mark()); var initials = SignaturePng.Normalize(SignatureAdoptionTests.Mark(60));
        var marks = new SignerPdfMarks(adoption, Guid.NewGuid(), Guid.NewGuid(), signature.Bytes, initials.Bytes, signature.Sha256, initials.Sha256, SignaturePng.Version);
        var fields = Enumerable.Range(0, count).Select(_ => new DocumentField { EnvelopeId = record, SignerId = signer, Type = FieldType.Text, Page = 1,
            X = .1m, Y = .1m, Width = .5m, Height = .1m, Value = value ?? "original value", FilledAt = Now.AddSeconds(-1), FilledBy = PartyType.Signer,
            Label = new string('\u6f22', 512), Placeholder = new string('\u6f22', 512), DateFormat = new string('\u6f22', 512), RowVersion = [1,2,3,4,5,6,7,8] }).ToArray();
        var pages = new[] { new PageGeometry(612, 792, 0, 1, [0,0,612,792], [0,0,612,792]) };
        // Exact anonymous producer property names/order, including complete saved fields.
        var snapshot = JsonSerializer.Serialize(new { version = "signer-review-v1", identity.EnvelopeId, identity.SignerId, identity.DocumentId, identity.DocumentHash, identity.DisclosureHash,
            RowVersion = new byte[8], PageCount = (int?)1, PageSizesJson = JsonSerializer.Serialize(pages), FullName = "Synthetic signer", ConsentAt = (DateTimeOffset?)Now.AddMinutes(-1),
            signerVersion = new byte[8], adoptionId = adoption, SignatureSha256 = signature.Sha256, InitialsSha256 = initials.Sha256, NormalizationVersion = SignaturePng.Version, fields });
        var request = new SignerPdfRequest(record, signer, "Synthetic signer", Now, adoption, fields.Select(f => new SignerPdfField(f.Id, f.EnvelopeId, f.SignerId,
            f.RowVersion, f.Type, f.Page, f.X, f.Y, f.Width, f.Height, f.Required, f.Value, f.FilledAt, f.FilledBy)).ToArray(), marks);
        var metadata = new ReviewRenderInputV1(record, signer, request.FullName, Now, adoption, request.Fields.ToArray(),
            new(adoption, marks.SignatureObjectId, marks.InitialsObjectId, signature.Sha256, initials.Sha256, SignaturePng.Version));
        var pdf = Encoding.ASCII.GetBytes("synthetic metadata-only PDF fixture");
        var row = new SignerReviewCandidate { EnvelopeId = record, SignerId = signer, SourceObjectId = source, AdoptionId = adoption, PdfObjectId = Guid.NewGuid(), PdfLength = pdf.Length,
            SourceSha256 = Convert.FromHexString(identity.DocumentHash), DisclosureSha256 = Convert.FromHexString(identity.DisclosureHash), SessionSha256 = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity)),
            SnapshotSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(snapshot)), PdfSha256 = SHA256.HashData(pdf), RecipeSha256 = Convert.FromHexString(ProductionReviewInputCodec.Binding(metadata, 1, Convert.FromHexString(identity.DocumentHash))),
            RendererVersion = SignerPdfRenderer.Version, SnapshotVersion = "signer-review-v1", PreparedAt = Now, ExpiresAt = Now.AddMinutes(10), ProspectiveDate = DateOnly.FromDateTime(Now.UtcDateTime) };
        var rendered = new RenderedSignerPdf(pdf, row.PdfSha256, row.SourceSha256, row.RecipeSha256, record, signer, adoption, Now, SignerPdfRenderer.Version);
        var write = ProductionSignerReviewWrite.Own(keys, Guid.NewGuid(), Guid.NewGuid(), row, identity, identity.SessionExpiresAt, snapshot, request, pages, rendered, 7, 3, new byte[32]);
        var plan = write.Plan(null, null, new('c', 64), []); using var stream = write.Open(DocumentBlobKind.ReviewInput); using var bytes = new MemoryStream(); stream.CopyTo(bytes);
        return new(keys, write, plan, bytes.ToArray());
    }
    [Fact]
    public void Maximum_two_hundred_Unicode_values_and_all_metadata_roundtrip_without_expanding_the_journal_header()
    {
        var test = Create(200, new string('\u00e9', 4000)); var verified = ProductionReviewInputCodec.OpenVerified(test.Keys, test.Plan, test.Cipher);
        Assert.Equal(200, verified.Snapshot.fields.Length); Assert.All(verified.Snapshot.fields, f => { Assert.Equal(4000, f.Value!.Length); Assert.Equal(512, f.Label!.Length); });
        Assert.True(ProductionRecordReviewWriteContract.PlanBytes(test.Plan).Length < 49152); Assert.True(test.Cipher.Length < ProductionReviewInputCodec.MaximumCipherBytes);
        var copy = verified.Snapshot; copy.RowVersion[0] = 99; copy.fields[0].FilledAt = Now;
        Assert.Equal(0, verified.Snapshot.RowVersion[0]); Assert.Equal(Now.AddSeconds(-1), verified.Snapshot.fields[0].FilledAt);
    }
    [Theory]
    [InlineData("owner")][InlineData("operation")][InlineData("candidate")][InlineData("cipher")][InlineData("plain-hash")][InlineData("snapshot")][InlineData("version")][InlineData("key")]
    public void Wrong_binding_or_protection_never_returns_a_verified_fact(string change)
    {
        var t = Create(); var p = t.Plan; var cipher = t.Cipher.ToArray(); var keys = t.Keys;
        switch (change)
        {
            case "owner": p = p with { Identity = p.Identity with { EnvelopeId = Guid.NewGuid() } }; break;
            case "operation": p = p with { OperationId = Guid.NewGuid() }; break;
            case "candidate": var row = ProductionRecordReviewWriteContract.ReadRow(p.CandidateRowJson); row.Id = Guid.NewGuid(); p = p with { CandidateRowJson = ProductionRecordReviewWriteContract.Row(row) }; break;
            case "cipher": cipher[^1] ^= 1; p = p with { Input = p.Input with { Sha256 = ProductionReviewInputCodec.Hash(cipher) } }; break;
            case "plain-hash": p = p with { InputPlainSha256 = new('d', 64) }; break;
            case "snapshot": p = p with { SnapshotSha256 = new('d', 64) }; break;
            case "version": p = p with { InputVersion = "future" }; break;
            case "key": keys = new EphemeralDataProtectionProvider(); break;
        }
        Assert.Throws<InvalidDataException>(() => ProductionReviewInputCodec.OpenVerified(keys, p, cipher));
    }
    [Theory]
    [InlineData("duplicate")][InlineData("future")][InlineData("scalar-array")][InlineData("geometry")][InlineData("too-many")]
    public void Closed_streaming_bounds_reject_unknown_duplicate_and_scalar_arrays_before_typed_allocation(string change)
    {
        var t = Create(); var body = ProductionReviewInputCodec.OpenVerified(t.Keys, t.Plan, t.Cipher).Body;
        var raw = JsonSerializer.Serialize(body);
        if (change == "duplicate") raw = raw.Replace("\"Version\":", "\"Version\":\"review-input-v1\",\"Version\":", StringComparison.Ordinal);
        if (change == "future") raw = raw.Insert(raw.Length - 1, ",\"future\":true");
        if (change == "scalar-array") raw = raw.Replace("\"MediaBox\":[0,0,612,792]", "\"MediaBox\":[" + string.Join(',', Enumerable.Repeat("1", 201)) + "]", StringComparison.Ordinal);
        if (change == "too-many") raw = raw.Replace("\"Fields\":[]", "\"Fields\":[" + string.Join(',', Enumerable.Repeat("{}", 201)) + "]", StringComparison.Ordinal);
        if (change == "geometry")
        {
            var snapshot = ProductionReviewInputCodec.Snapshot(body.OriginalSnapshotJson);
            var pageJson = "[{\"Width\":612,\"Height\":792,\"Rotation\":0,\"UserUnit\":1,\"MediaBox\":[" + string.Join(',', Enumerable.Repeat("1", 201)) + "],\"CropBox\":[0,0,612,792]}]";
            body = body with { OriginalSnapshotJson = JsonSerializer.Serialize(snapshot with { PageSizesJson = pageJson }) };
            var row = ProductionRecordReviewWriteContract.ReadRow(body.CandidateRowJson); row.SnapshotSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(body.OriginalSnapshotJson));
            body = body with { CandidateRowJson = ProductionRecordReviewWriteContract.Row(row) };
            Assert.Throws<InvalidDataException>(() => ProductionReviewInputCodec.Encode(body)); return;
        }
        Assert.Throws<InvalidDataException>(() => ProductionReviewInputCodec.Read(Encoding.UTF8.GetBytes(raw)));
    }
    [Fact]
    public void Sidecar_is_not_a_sender_signer_copied_capability_or_delete_target()
    {
        var t = Create(); var blob = t.Write.Input.Blob; var identity = t.Write.Identity;
        var sender = new ClaimsPrincipal(new ClaimsIdentity([new(EnvelopeStorageAuthorization.EnvelopeClaim, blob.EnvelopeId.ToString())], EnvelopeStorageAuthorization.SenderScheme));
        var signer = SignerAccessConfiguration.Principal(identity); var clock = new ProductionHoldWitnessJournalTests.Clock();
        var capability = ReviewInputCapability.Create(identity, blob, AssetOperation.Read, clock);
        EnvelopeStorageAuthorization.DemandRead(capability, blob);
        foreach (var principal in new[] { sender, signer, new ClaimsPrincipal(capability) })
        { Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(principal, blob)); Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.Demand(principal, blob)); }
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandDelete(capability, blob));
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(capability, blob with { Kind = DocumentBlobKind.Normalized }));
    }
    [Fact]
    public void Oversize_ciphertext_and_unknown_third_member_fail_before_any_unprotect_or_provider()
    {
        var t = Create(); Assert.Throws<InvalidDataException>(() => ProductionReviewInputCodec.OpenVerified(t.Keys, t.Plan, new byte[ProductionReviewInputCodec.MaximumCipherBytes + 1]));
        Assert.False(ProductionRecordReviewWriteContract.Member(t.Plan, t.Write.Input with { Blob = t.Write.Input.Blob with { ObjectId = Guid.NewGuid() } }));
        Assert.False(ProductionRecordReviewWriteContract.Item(t.Write.Identity.EnvelopeId, t.Write.Input with { Blob = t.Write.Input.Blob with { Kind = DocumentBlobKind.Signature } }));
    }
    [Fact]
    public void Retained_ciphertext_is_owned_before_invoking_the_key_provider_or_any_caller_can_reuse_its_buffer()
    {
        var test = Create(); var caller = test.Cipher.ToArray(); var provider = new MutatingKeys(test.Keys, () => caller[0] ^= 1);
        var result = ProductionReviewInputCodec.OpenVerified(provider, test.Plan, caller);
        Assert.Equal(test.Write.CandidateId, result.CandidateId); Assert.NotEqual(test.Cipher, caller);
    }
    private sealed class MutatingKeys(IDataProtectionProvider inner, Action mutate) : IDataProtectionProvider
    { public IDataProtector CreateProtector(string purpose) { mutate(); return inner.CreateProtector(purpose); } }
}

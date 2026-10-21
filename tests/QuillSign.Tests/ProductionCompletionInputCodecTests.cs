using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionCompletionInputCodecTests
{
    internal static readonly DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Lazy<byte[]> Certificate = new(() => {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Synthetic completion codec - NO AGREEMENT", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1)); return certificate.RawData;
    });
    internal static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    internal static HoldWitnessCompletionContext Context(CompletionSlot slot, CompletionSqlSelector[]? selectors = null)
        => new(slot, Guid.NewGuid(), 7, Hash("sql"), Hash("content"), Guid.NewGuid(), 1, Now.AddMinutes(10), Hash("payload"),
            ProductionCompletionProtocol.Effects(slot).Select(x => new CompletionEffectTarget(x, ProductionCompletionProtocol.Tsa(x) ? Guid.Empty : Guid.NewGuid())).ToImmutableArray(),
            (selectors ?? []).ToImmutableArray(), Hash("remainder"), Now);
    internal sealed record Example(IDataProtectionProvider Keys, ProductionCompletionInput Input, CompletionSealInputContext Context);
    internal static Example Seal(bool certificate = false)
    {
        var slot = certificate ? CompletionSlot.CertificateSeal : CompletionSlot.ExecutedSeal; var context = Context(slot);
        var rowId = Guid.NewGuid(); var cut = new CompletionInputAuditCut(9, Hash("audit"));
        var value = new CompletionSealInputContext(Guid.NewGuid(), Hash("candidate"), certificate ? context.Targets.Single(x => x.Effect == CompletionEffect.CertificateSource).TargetId : Guid.NewGuid(),
            100, Hash("source"), rowId, context.Targets.Single(x => x.Effect == (certificate ? CompletionEffect.CertificatePdf : CompletionEffect.ExecutedPdf)).TargetId,
            1, "Synthetic codec", Certificate.Value.ToArray(), Convert.ToHexStringLower(SHA256.HashData(Certificate.Value)), Now,
            certificate ? Hash("executed") : null, certificate ? Hash("executed-recipe") : null);
        context = context with { SqlRows = ProductionCompletionInputRows.Selectors(value, cut).ToImmutableArray() };
        var keys = new EphemeralDataProtectionProvider(); return new(keys, ProductionCompletionInput.OwnSealContext(keys, Guid.NewGuid(), context, value, Now, cut), value);
    }
    internal static byte[] Cipher(ProductionCompletionInput input) { using var stream = input.Open(); using var memory = new MemoryStream(); stream.CopyTo(memory); return memory.ToArray(); }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Both_exact_contexts_roundtrip_and_return_owned_public_certificate_and_factual_SQL_selectors(bool certificate)
    {
        var t = Seal(certificate); var verified = t.Input.Verified;
        var reopened = ProductionCompletionInputCodec.OpenVerified(t.Keys, verified.RecordId, verified.Context, verified.Kind, verified.Descriptor, Cipher(t.Input));
        Assert.Equal(verified.PlainSha256, reopened.PlainSha256); Assert.Equal(JsonSerializer.Serialize(t.Context), JsonSerializer.Serialize(reopened.Body.SealContext));
        var projection = VerifiedCompletionSlotContext.FromInput(reopened); Assert.Equal(verified.RecordId, projection.RecordId);
        var view = reopened.Body; view.SealContext!.CertificateDer[0] ^= 1;
        Assert.Equal(Certificate.Value, reopened.Body.SealContext!.CertificateDer);
        t.Context.CertificateDer[0] ^= 1; Assert.Equal(Certificate.Value, reopened.Body.SealContext.CertificateDer);
    }
    [Theory]
    [InlineData("record")][InlineData("operation")][InlineData("work")][InlineData("deadline")][InlineData("recorded")]
    [InlineData("target")][InlineData("kind")][InlineData("area")][InlineData("length")][InlineData("cipher")][InlineData("keys")]
    public void Purpose_owner_exact_context_and_cipher_binding_fail_closed(string fault)
    {
        var t = Seal(); var v = t.Input.Verified; var record = v.RecordId; var context = v.Context; var item = v.Descriptor; var kind = v.Kind; var cipher = Cipher(t.Input); var keys = t.Keys;
        switch (fault)
        {
            case "record": record = Guid.NewGuid(); item = item with { Blob = item.Blob with { EnvelopeId = record } }; break;
            case "operation": context = context with { OperationId = Guid.NewGuid() }; break;
            case "work": context = context with { WorkId = Guid.NewGuid() }; break;
            case "deadline": context = context with { Until = context.Until.AddSeconds(1) }; break;
            case "recorded": context = context with { RecordedAt = context.RecordedAt.AddSeconds(-1) }; break;
            case "target": item = item with { Blob = item.Blob with { ObjectId = Guid.NewGuid() } }; break;
            case "kind": kind = CompletionInputKind.ExecutedTimestampRequest; break;
            case "area": item = item with { Blob = item.Blob with { Kind = DocumentBlobKind.Normalized } }; break;
            case "length": item = item with { Length = item.Length + 1 }; break;
            case "cipher": cipher[^1] ^= 1; item = item with { Sha256 = ProductionCompletionInputCodec.Hash(cipher) }; break;
            case "keys": keys = new EphemeralDataProtectionProvider(); break;
        }
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.OpenVerified(keys, record, context, kind, item, cipher));
    }
    [Theory]
    [InlineData("future")][InlineData("duplicate")][InlineData("whitespace")][InlineData("unknown-kind")][InlineData("wrong-union")]
    [InlineData("certificate")][InlineData("source-length")][InlineData("short-source")][InlineData("source-output")][InlineData("future-clock")][InlineData("non-UTC")][InlineData("selectors")]
    public void Reprotected_shapes_and_original_context_faults_are_refused(string fault)
    {
        var t = Seal(); var body = t.Input.Verified.Body;
        if (fault is "future" or "duplicate" or "whitespace")
        {
            var raw = JsonSerializer.Serialize(body);
            raw = fault switch { "future" => raw.Insert(raw.Length - 1, ",\"Future\":true"), "duplicate" => raw.Replace("\"RecordId\":", "\"RecordId\":\"00000000-0000-0000-0000-000000000001\",\"RecordId\":"), _ => " " + raw };
            Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.Read(Encoding.UTF8.GetBytes(raw))); return;
        }
        body = fault switch {
            "unknown-kind" => body with { Kind = (CompletionInputKind)999 },
            "wrong-union" => body with { TimestampRequest = new([1], Hash("x"), Hash("y"), Now) },
            "certificate" => body with { SealContext = body.SealContext! with { CertificateDer = [1,2,3] } },
            "source-length" => body with { SealContext = body.SealContext! with { SourceLength = 0 } },
            "short-source" => body with { SealContext = body.SealContext! with { SourceLength = 15 } },
            "source-output" => body with { SealContext = body.SealContext! with { SourceObjectId = body.SealContext.OutputObjectId } },
            "future-clock" => body with { SealContext = body.SealContext! with { SigningAt = Now.AddSeconds(1) } },
            "non-UTC" => body with { RecordedAt = Now.ToOffset(TimeSpan.FromHours(1)) },
            "selectors" => body with { Context = body.Context with { SqlRows = [] } }, _ => body };
        if (fault == "selectors")
        {
            var cipher = ProductionCompletionInputCodec.Protector(t.Keys, body.RecordId, body.Context.OperationId, body.Kind, body.InputObjectId).Protect(ProductionCompletionInputCodec.Encode(body));
            var item = t.Input.Descriptor with { Length = cipher.Length, Sha256 = ProductionCompletionInputCodec.Hash(cipher) };
            var fact = ProductionCompletionInputCodec.OpenVerified(t.Keys, body.RecordId, body.Context, body.Kind, item, cipher);
            Assert.Throws<InvalidDataException>(() => VerifiedCompletionSlotContext.FromInput(fact));
        }
        else Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.Encode(body));
    }
    [Fact]
    public void Encoded_nonce_request_is_preserved_and_its_original_clock_never_becomes_a_new_deadline()
    {
        var t = Seal(); var encoded = Rfc3161TimestampRequest.CreateFromHash(SHA256.HashData([1,2,3]), HashAlgorithmName.SHA256, nonce: new byte[] {1,2,3,4}, requestSignerCertificates: true).Encode();
        var request = ProductionCompletionInput.OwnTimestampRequest(t.Keys, t.Input.Verified, encoded, Hash("authority"), Now);
        var original = encoded.ToArray(); encoded[0] ^= 1;
        Assert.Equal(original, request.Verified.Body.TimestampRequest!.Encoded); Assert.Equal(t.Input.Verified.PlainSha256, request.Verified.Body.TimestampRequest.ContextPlainSha256);
        Assert.Equal(t.Input.Verified.Context.Until, request.Verified.Context.Until);
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInput.OwnTimestampRequest(t.Keys, t.Input.Verified, original, Hash("authority"), Now.AddSeconds(1)));
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInput.OwnTimestampRequest(t.Keys, t.Input.Verified, [1,2,3], Hash("authority"), Now));
    }
    [Theory]
    [InlineData("duplicate")][InlineData("scalar-array")][InlineData("geometry")][InlineData("certificate")]
    public void Streaming_nested_arrays_and_encoded_payloads_are_bounded_before_typed_allocation(string fault)
    {
        var raw = fault switch {
            "duplicate" => "{\"a\":1,\"a\":2}",
            "scalar-array" => "{\"Events\":[" + string.Join(',', Enumerable.Repeat("1", 513)) + "]}",
            "geometry" => "{\"MediaBox\":[0,0,1,1,1]}",
            _ => "{\"CertificateDer\":\"" + new string('A', 4 * ((65536 + 2) / 3) + 1) + "\"}" };
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.DemandJson(Encoding.UTF8.GetBytes(raw)));
    }
    [Fact]
    public void Eleven_body_and_aggregate_limits_are_not_per_attempt_refundable_or_extensible()
    {
        ProductionCompletionInputCodec.DemandAggregate([ProductionCompletionInputCodec.MaximumCipherBytes, 1]);
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.DemandAggregate(Enumerable.Repeat(1L, 12)));
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.DemandAggregate([0]));
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.DemandAggregate([ProductionCompletionInputCodec.MaximumCipherBytes + 1L]));
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.DemandAggregate(Enumerable.Repeat((long)ProductionCompletionInputCodec.MaximumCipherBytes, 4)));
    }
    [Fact]
    public void Ordinary_sender_copied_principal_and_delete_paths_cannot_use_internal_input()
    {
        var t = Seal(); var blob = t.Input.Descriptor.Blob; var clock = new Clock();
        var capability = CompletionInputCapability.Create(t.Input, AssetOperation.Read, clock); EnvelopeStorageAuthorization.DemandRead(capability, blob);
        var sender = new ClaimsPrincipal(new ClaimsIdentity([new(EnvelopeStorageAuthorization.EnvelopeClaim, blob.EnvelopeId.ToString())], EnvelopeStorageAuthorization.SenderScheme));
        foreach (var principal in new[] { sender, new ClaimsPrincipal(capability), new ClaimsPrincipal() })
        { Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(principal, blob)); Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.Demand(principal, blob)); }
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandDelete(capability, blob));
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(capability, blob with { Kind = DocumentBlobKind.ReviewInput }));
        clock.At = t.Input.Verified.Context.Until; Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(capability, blob));
    }
    [Fact]
    public void Cipher_is_owned_before_a_key_provider_callback_can_reuse_the_callers_buffer()
    {
        var t = Seal(); var original = Cipher(t.Input); var caller = original.ToArray(); var v = t.Input.Verified;
        var keys = new MutatingKeys(t.Keys, () => caller[0] ^= 1);
        var read = ProductionCompletionInputCodec.OpenVerified(keys, v.RecordId, v.Context, v.Kind, v.Descriptor, caller);
        Assert.Equal(v.PlainSha256, read.PlainSha256); Assert.NotEqual(original, caller);
    }
    [Fact]
    public void Exact_historical_input_read_scope_closes_without_renewing_the_worker_deadline()
    {
        var f = Seal(); var descriptor = f.Input.Descriptor; var receipt = new ProductionRecordWriteReceipt(descriptor, "synthetic-v1", "\"synthetic-e1\"");
        var evidence = new HoldObjectEvidence(new("normalized", $"{descriptor.Blob.EnvelopeId:N}/completion-inputs/{descriptor.Blob.ObjectId:N}",
            receipt.VersionId, "", receipt.ETag, descriptor.Length), descriptor.Sha256);
        var current = ProductionHoldObjectTransportTests.Scope(descriptor.Blob.EnvelopeId);
        var scope = ProductionCompletionInputReadScope.FromHold(current, f.Input.Verified.Context, f.Input.Verified.Kind, descriptor, receipt, evidence);
        scope.Demand(); scope.Close(); scope.Close(); Assert.Throws<InvalidDataException>(() => scope.Demand());
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputReadScope.FromHold(current, f.Input.Verified.Context, f.Input.Verified.Kind,
            descriptor, receipt, evidence with { Address = evidence.Address with { VersionId = "newer-current" } }));
    }
    [Fact]
    public void Retained_raw_RFC_response_binds_original_nonce_and_verified_signed_token_without_a_network_authority()
    {
        var t = Seal();
        var encoded = Rfc3161TimestampRequest.CreateFromHash(SHA256.HashData(new byte[] {1,2,3}), HashAlgorithmName.SHA256,
            nonce: new byte[] {1,2,3,4}, requestSignerCertificates: true).Encode();
        var request = ProductionCompletionInput.OwnTimestampRequest(t.Keys, t.Input.Verified, encoded, Hash("authority"), Now);
        using var key = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=Synthetic offline timestamp - NO AGREEMENT", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.8") }, true));
        using var certificate = certificateRequest.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
        var bcCertificate = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certificate.RawData);
        var signer = new Org.BouncyCastle.Cms.SignerInfoGeneratorBuilder().Build(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA256WITHRSA",
            Org.BouncyCastle.Security.DotNetUtilities.GetRsaKeyPair(key).Private), bcCertificate);
        var tokens = new Org.BouncyCastle.Tsp.TimeStampTokenGenerator(signer,
            Org.BouncyCastle.Crypto.Operators.Asn1DigestFactory.Get(Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdSha256), new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.2.3.4.1"), true);
        tokens.SetCertificates(Org.BouncyCastle.Utilities.Collections.CollectionUtilities.CreateStore(new[] {bcCertificate}));
        var response = new Org.BouncyCastle.Tsp.TimeStampResponseGenerator(tokens, new[] {Org.BouncyCastle.Tsp.TspAlgorithms.Sha256})
            .Generate(new Org.BouncyCastle.Tsp.TimeStampRequest(encoded), Org.BouncyCastle.Math.BigInteger.One, Now.UtcDateTime).GetEncoded();
        Assert.True(Rfc3161TimestampRequest.TryDecode(encoded, out var original, out _));
        var returned = original.ProcessResponse(response, out _); var tokenBytes = returned.AsSignedCms().Encode();
        var fact = new QuillSign.Sealing.VerifiedTimestamp(tokenBytes, Now, Convert.ToHexStringLower(SHA256.HashData(certificate.RawData)), "1.2.3.4.1");
        var input = ProductionCompletionInput.OwnTimestampResponse(t.Keys, request.Verified, response, fact);
        Assert.Equal(response, input.Verified.Body.TimestampResponse!.EncodedResponse); Assert.Equal(tokenBytes, input.Verified.Body.TimestampResponse.VerifiedToken);
        response[0] ^= 1; tokenBytes[0] ^= 1;
        Assert.NotEqual(response, input.Verified.Body.TimestampResponse.EncodedResponse); Assert.NotEqual(tokenBytes, input.Verified.Body.TimestampResponse.VerifiedToken);
        var wrongEncoded = Rfc3161TimestampRequest.CreateFromHash(SHA256.HashData(new byte[] {1,2,3}), HashAlgorithmName.SHA256, nonce: new byte[] {9,9,9}, requestSignerCertificates: true).Encode();
        var wrongRequest = ProductionCompletionInput.OwnTimestampRequest(t.Keys, t.Input.Verified, wrongEncoded, Hash("authority"), Now);
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInput.OwnTimestampResponse(t.Keys, wrongRequest.Verified,
            input.Verified.Body.TimestampResponse.EncodedResponse, fact with { Encoded = input.Verified.Body.TimestampResponse.VerifiedToken }));
    }
    private sealed class MutatingKeys(IDataProtectionProvider inner, Action mutate) : IDataProtectionProvider
    { public IDataProtector CreateProtector(string purpose) { mutate(); return inner.CreateProtector(purpose); } }
    internal sealed class Clock : TimeProvider { internal DateTimeOffset At = Now; public override DateTimeOffset GetUtcNow() => At; }
}

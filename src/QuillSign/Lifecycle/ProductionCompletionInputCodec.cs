using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sealing;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal enum CompletionInputKind { CandidatePlan, ExecutedContext, ExecutedTimestampRequest, ExecutedTimestampResponse, ExecutedResult,
    CertificateContext, CertificateTimestampRequest, CertificateTimestampResponse, CertificateResult, PublicationIntentPlan, PublicationResultPlan }
internal sealed record CompletionInputAuditCut(long Sequence, string Sha256);
internal sealed record CompletionSealInputContext(Guid CandidateId, string CandidateRecipeSha256, Guid SourceObjectId,
    long SourceLength, string SourceSha256, Guid OutputRowId, Guid OutputObjectId, int Pages, string Provider,
    byte[] CertificateDer, string CertificateSha256, DateTimeOffset SigningAt, string? ExecutedSha256, string? ExecutedRecipeSha256);
internal sealed record CompletionTimestampInputRequest(byte[] Encoded, string ContextPlainSha256, string AuthoritySha256, DateTimeOffset StartedAt);
internal sealed record CompletionTimestampInputResponse(byte[] EncodedResponse, byte[] VerifiedToken, DateTimeOffset TimestampAt,
    string CertificateSha256, string Policy, string RequestPlainSha256);
internal sealed record CompletionSealMetadataInput(string Provider, string CertificateSha256, string CertificateDer,
    DateTimeOffset SealedAt, DateTimeOffset TimestampAt, string TimestampCertificateSha256, string TimestampPolicy);
internal sealed record CompletionPublicationInputPlan(CompletionPublicationIntent Intent, CompletionPublicationResult Result,
    Envelope Before, Envelope Completed, CompletionPublicationFiles Files, CompletionNotificationRosterMember[] Notifications);
internal sealed record CompletionInputV1(string Version, Guid RecordId, HoldWitnessCompletionContext Context,
    CompletionInputKind Kind, Guid InputObjectId, DateTimeOffset RecordedAt, CompletionInputAuditCut AuditCut,
    CompletionCandidate? Candidate = null, CompletionSealInputContext? SealContext = null,
    CompletionTimestampInputRequest? TimestampRequest = null, CompletionTimestampInputResponse? TimestampResponse = null,
    CompletionSealOutput? SealResult = null, CompletionPublicationIntent? Intent = null, CompletionPublicationInputPlan? Publication = null);

// Factual authenticated projection only. All views are reconstructed from owned
// bounded bytes; mutable arrays/entities cannot rewrite a verified body.
internal sealed class VerifiedCompletionInput
{
    private readonly byte[] plain;
    private readonly HoldWitnessCompletionContext context;
    internal CompletionInputV1 Body => ProductionCompletionInputCodec.Read(plain);
    internal Guid RecordId { get; }
    internal HoldWitnessCompletionContext Context => context;
    internal CompletionInputKind Kind { get; }
    internal string PlainSha256 { get; }
    internal ProductionRecordWriteDescriptor Descriptor { get; }
    private VerifiedCompletionInput(byte[] plain, ProductionRecordWriteDescriptor descriptor)
    {
        this.plain = plain.ToArray(); var body = Body;
        RecordId = body.RecordId; Kind = body.Kind; Descriptor = descriptor; context = body.Context;
        PlainSha256 = ProductionCompletionInputCodec.Hash(this.plain);
    }
    internal static VerifiedCompletionInput OpenVerified(IDataProtectionProvider keys, Guid recordId,
        HoldWitnessCompletionContext context, CompletionInputKind kind, ProductionRecordWriteDescriptor descriptor, byte[] cipher)
    {
        ProductionCompletionInputCodec.DemandDescriptor(recordId, context, kind, descriptor);
        if (cipher is not { Length: > 0 and <= ProductionCompletionInputCodec.MaximumCipherBytes }) throw ProductionCompletionInputCodec.Invalid();
        cipher = cipher.ToArray();
        if (cipher.LongLength != descriptor.Length || ProductionCompletionInputCodec.Hash(cipher) != descriptor.Sha256) throw ProductionCompletionInputCodec.Invalid();
        byte[] plain;
        try { plain = ProductionCompletionInputCodec.Protector(keys, recordId, context.OperationId, kind, descriptor.Blob.ObjectId).Unprotect(cipher); }
        catch (CryptographicException error) { throw new InvalidDataException("The exact completion input cannot be authenticated.", error); }
        var body = ProductionCompletionInputCodec.Read(plain); ProductionCompletionInputCodec.Validate(body);
        if (body.RecordId != recordId || body.InputObjectId != descriptor.Blob.ObjectId || body.Kind != kind ||
            ProductionCompletionInputCodec.ContextSha256(body.Context) != ProductionCompletionInputCodec.ContextSha256(context)) throw ProductionCompletionInputCodec.Invalid();
        return new(plain, descriptor);
    }
}

internal sealed class ProductionCompletionInput
{
    private readonly byte[] cipher;
    internal VerifiedCompletionInput Verified { get; }
    internal ProductionRecordWriteDescriptor Descriptor => Verified.Descriptor;
    internal DateTimeOffset RecordedAt => Verified.Body.RecordedAt;
    private ProductionCompletionInput(IDataProtectionProvider keys, CompletionInputV1 value)
    {
        var plain = ProductionCompletionInputCodec.Encode(value); var body = ProductionCompletionInputCodec.Read(plain);
        cipher = ProductionCompletionInputCodec.Protector(keys, body.RecordId, body.Context.OperationId, body.Kind, body.InputObjectId).Protect(plain);
        if (cipher.Length > ProductionCompletionInputCodec.MaximumCipherBytes) throw ProductionCompletionInputCodec.Invalid();
        var descriptor = new ProductionRecordWriteDescriptor(new(body.RecordId, DocumentBlobKind.CompletionInput, body.InputObjectId), cipher.LongLength, ProductionCompletionInputCodec.Hash(cipher));
        Verified = VerifiedCompletionInput.OpenVerified(keys, body.RecordId, body.Context, body.Kind, descriptor, cipher);
    }
    internal Stream Open() => new MemoryStream(cipher.ToArray(), false);
    internal static ProductionCompletionInput OwnCandidate(IDataProtectionProvider keys, Guid recordId, HoldWitnessCompletionContext context,
        CompletionCandidate row, PreparedCompletionPacket packet, DateTimeOffset recordedAt, CompletionInputAuditCut cut)
    {
        if (packet.Bytes is not { Length: > 0 and <= 64 * 1024 * 1024 } || packet.Bytes.LongLength != row.PdfLength ||
            ProductionCompletionInputCodec.Hash(packet.Bytes) != ProductionCompletionInputCodec.Hex(row.PdfSha256) ||
            packet.RendererVersion != row.RendererVersion || packet.DocumentPages != row.DocumentPages || packet.CertificatePages != row.CertificatePages ||
            !packet.SourceSha256.AsSpan().SequenceEqual(row.SourceSha256) || !packet.EvidenceSha256.AsSpan().SequenceEqual(row.EvidenceSha256)) throw ProductionCompletionInputCodec.Invalid();
        return new(keys, ProductionCompletionInputCodec.Frame(recordId, context, CompletionInputKind.CandidatePlan, recordedAt, cut) with { Candidate = row });
    }
    internal static ProductionCompletionInput OwnSealContext(IDataProtectionProvider keys, Guid recordId, HoldWitnessCompletionContext context,
        CompletionSealInputContext value, DateTimeOffset recordedAt, CompletionInputAuditCut cut)
    {
        var kind = context.Slot == CompletionSlot.ExecutedSeal ? CompletionInputKind.ExecutedContext :
            context.Slot == CompletionSlot.CertificateSeal ? CompletionInputKind.CertificateContext : throw ProductionCompletionInputCodec.Invalid();
        return new(keys, ProductionCompletionInputCodec.Frame(recordId, context, kind, recordedAt, cut) with { SealContext = value });
    }
    internal static ProductionCompletionInput OwnTimestampRequest(IDataProtectionProvider keys, VerifiedCompletionInput original,
        byte[] encoded, string authoritySha256, DateTimeOffset startedAt)
    {
        if (original.Kind is not (CompletionInputKind.ExecutedContext or CompletionInputKind.CertificateContext)) throw ProductionCompletionInputCodec.Invalid();
        var body = original.Body; var kind = original.Kind == CompletionInputKind.ExecutedContext ? CompletionInputKind.ExecutedTimestampRequest : CompletionInputKind.CertificateTimestampRequest;
        if (startedAt != body.SealContext!.SigningAt) throw ProductionCompletionInputCodec.Invalid();
        return new(keys, ProductionCompletionInputCodec.Frame(body.RecordId, body.Context, kind, body.Context.RecordedAt, body.AuditCut) with {
            TimestampRequest = new(encoded, original.PlainSha256, authoritySha256, startedAt) });
    }
    internal static ProductionCompletionInput OwnTimestampResponse(IDataProtectionProvider keys, VerifiedCompletionInput request,
        byte[] encodedResponse, VerifiedTimestamp token)
    {
        if (request.Kind is not (CompletionInputKind.ExecutedTimestampRequest or CompletionInputKind.CertificateTimestampRequest)) throw ProductionCompletionInputCodec.Invalid();
        if (encodedResponse is not { Length: > 0 and <= 128 * 1024 } || token?.Encoded is not { Length: > 0 and <= 128 * 1024 }) throw ProductionCompletionInputCodec.Invalid();
        var body = request.Body; encodedResponse = encodedResponse.ToArray(); token = token with { Encoded = token.Encoded.ToArray() };
        try
        {
            if (!Rfc3161TimestampRequest.TryDecode(body.TimestampRequest!.Encoded, out var actualRequest, out var read) ||
                read != body.TimestampRequest.Encoded.Length) throw ProductionCompletionInputCodec.Invalid();
            var returned = actualRequest.ProcessResponse(encodedResponse, out var consumed);
            if (consumed != encodedResponse.Length || !returned.AsSignedCms().Encode().AsSpan().SequenceEqual(token.Encoded)) throw ProductionCompletionInputCodec.Invalid();
        }
        catch (CryptographicException error) { throw new InvalidDataException("The actual completion timestamp response does not match its original request.", error); }
        var kind = request.Kind == CompletionInputKind.ExecutedTimestampRequest ? CompletionInputKind.ExecutedTimestampResponse : CompletionInputKind.CertificateTimestampResponse;
        return new(keys, ProductionCompletionInputCodec.Frame(body.RecordId, body.Context, kind, body.Context.RecordedAt, body.AuditCut) with {
            TimestampResponse = new(encodedResponse, token.Encoded, token.At, token.CertificateSha256, token.Policy, request.PlainSha256) });
    }
    internal static ProductionCompletionInput OwnSealResult(IDataProtectionProvider keys, VerifiedCompletionInput original,
        CompletionSealOutput row, SealedPdf pdf, DateTimeOffset recordedAt)
    {
        if (original.Kind is not (CompletionInputKind.ExecutedContext or CompletionInputKind.CertificateContext) ||
            pdf.Bytes is not { Length: > 0 and <= 64 * 1024 * 1024 } || pdf.Bytes.LongLength != row.PdfLength ||
            ProductionCompletionInputCodec.Hash(pdf.Bytes) != ProductionCompletionInputCodec.Hex(row.PdfSha256) ||
            !pdf.Sha256.AsSpan().SequenceEqual(row.PdfSha256) || !pdf.SourceSha256.AsSpan().SequenceEqual(row.SourceSha256) || pdf.PageCount != row.PageCount ||
            row.MetadataJson != CompletionSealOutputs.MetadataJson(pdf)) throw ProductionCompletionInputCodec.Invalid();
        var body = original.Body; var kind = original.Kind == CompletionInputKind.ExecutedContext ? CompletionInputKind.ExecutedResult : CompletionInputKind.CertificateResult;
        return new(keys, ProductionCompletionInputCodec.Frame(body.RecordId, body.Context, kind, recordedAt, body.AuditCut) with { SealContext = body.SealContext, SealResult = row });
    }
    internal static ProductionCompletionInput OwnIntent(IDataProtectionProvider keys, Guid recordId, HoldWitnessCompletionContext context,
        CompletionPublicationIntent row, DateTimeOffset recordedAt, CompletionInputAuditCut cut)
        => new(keys, ProductionCompletionInputCodec.Frame(recordId, context, CompletionInputKind.PublicationIntentPlan, recordedAt, cut) with { Intent = row });
    internal static ProductionCompletionInput OwnResult(IDataProtectionProvider keys, Guid recordId, HoldWitnessCompletionContext context,
        CompletionPublicationTransition transition, CompletionInputAuditCut cut)
    {
        if (transition.Before.Id != recordId || transition.Completed.Id != recordId || transition.Intent.EnvelopeId != recordId ||
            transition.Result.EnvelopeId != recordId || transition.Result.CompletedAt != transition.RecordedAt) throw ProductionCompletionInputCodec.Invalid();
        var expected = JsonSerializer.Deserialize<Envelope>(JsonSerializer.SerializeToUtf8Bytes(transition.Before)) ?? throw ProductionCompletionInputCodec.Invalid();
        CompletionPublication.Apply(expected, transition.Intent, transition.Pair, transition.RecordedAt);
        if (JsonSerializer.Serialize(expected) != JsonSerializer.Serialize(transition.Completed) ||
            transition.Candidate.Id != transition.Intent.CandidateId || transition.Pair.Executed.Id != transition.Intent.ExecutedOutputId ||
            transition.Pair.Certificate.Id != transition.Intent.CertificateOutputId ||
            !transition.Files.Executed.Sha256.AsSpan().SequenceEqual(transition.Pair.Executed.Pdf.Sha256) ||
            !transition.Files.Certificate.Sha256.AsSpan().SequenceEqual(transition.Pair.Certificate.Pdf.Sha256) ||
            transition.Files.Executed.Length != transition.Pair.Executed.Pdf.Bytes.LongLength ||
            transition.Files.Certificate.Length != transition.Pair.Certificate.Pdf.Bytes.LongLength) throw ProductionCompletionInputCodec.Invalid();
        var plan = new CompletionPublicationInputPlan(transition.Intent, transition.Result, transition.Before, transition.Completed,
            transition.Files, transition.Notifications.ToArray());
        return new(keys, ProductionCompletionInputCodec.Frame(recordId, context, CompletionInputKind.PublicationResultPlan, transition.RecordedAt, cut) with { Publication = plan });
    }
}

internal static partial class ProductionCompletionInputCodec
{
    internal const string Version = "completion-input-v1";
    internal const int MaximumPlainBytes = 16 * 1024 * 1024, MaximumCipherBytes = MaximumPlainBytes + 65536;
    internal const long MaximumAggregateCipherBytes = 64 * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    internal static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    internal static string ContextSha256(HoldWitnessCompletionContext value) => Hash(JsonSerializer.SerializeToUtf8Bytes(value));
    internal static InvalidDataException Invalid() => new("The exact protected completion input could not be verified.");
    internal static IDataProtector Protector(IDataProtectionProvider keys, Guid record, Guid operation, CompletionInputKind kind, Guid target)
        => keys.CreateProtector("QuillSign.ProductionCompletionInput.v1", record.ToString("N"), operation.ToString("N"), ((int)kind).ToString(System.Globalization.CultureInfo.InvariantCulture), target.ToString("N"));
    internal static CompletionEffect Effect(CompletionInputKind kind) => kind switch {
        CompletionInputKind.CandidatePlan => CompletionEffect.CandidateInput,
        CompletionInputKind.ExecutedContext => CompletionEffect.ExecutedContext,
        CompletionInputKind.ExecutedTimestampRequest => CompletionEffect.ExecutedRequest,
        CompletionInputKind.ExecutedTimestampResponse => CompletionEffect.ExecutedResponse,
        CompletionInputKind.ExecutedResult => CompletionEffect.ExecutedResult,
        CompletionInputKind.CertificateContext => CompletionEffect.CertificateContext,
        CompletionInputKind.CertificateTimestampRequest => CompletionEffect.CertificateRequest,
        CompletionInputKind.CertificateTimestampResponse => CompletionEffect.CertificateResponse,
        CompletionInputKind.CertificateResult => CompletionEffect.CertificateResult,
        CompletionInputKind.PublicationIntentPlan => CompletionEffect.PublicationIntentInput,
        CompletionInputKind.PublicationResultPlan => CompletionEffect.PublicationResultInput,
        _ => throw Invalid() };
    internal static void DemandDescriptor(Guid recordId, HoldWitnessCompletionContext context, CompletionInputKind kind, ProductionRecordWriteDescriptor item)
    {
        if (context is null || item is null) throw Invalid();
        ProductionCompletionProtocol.Context(context); var effect = Effect(kind);
        if (recordId == Guid.Empty || item.Blob.EnvelopeId != recordId || item.Blob.Kind != DocumentBlobKind.CompletionInput ||
            item.Length is < 1 or > MaximumCipherBytes || !ProductionCompletionProtocol.Hash(item.Sha256) ||
            !context.Targets.Contains(new(effect, item.Blob.ObjectId))) throw Invalid();
    }
    internal static CompletionInputV1 Frame(Guid recordId, HoldWitnessCompletionContext context, CompletionInputKind kind,
        DateTimeOffset recordedAt, CompletionInputAuditCut cut)
    {
        ProductionCompletionProtocol.Context(context);
        if (recordedAt != context.RecordedAt) throw Invalid();
        var targets = context.Targets.Where(x => x.Effect == Effect(kind)).ToArray();
        if (targets.Length != 1) throw Invalid();
        return new(Version, recordId, context, kind, targets[0].TargetId, recordedAt, cut);
    }
    internal static byte[] Encode(CompletionInputV1 body)
    {
        Validate(body); using var bytes = new MemoryStream();
        JsonSerializer.Serialize(new BoundedDocumentStream(bytes, MaximumPlainBytes), body, Json);
        return bytes.ToArray();
    }
    internal static VerifiedCompletionInput OpenVerified(IDataProtectionProvider keys, Guid recordId,
        HoldWitnessCompletionContext context, CompletionInputKind kind, ProductionRecordWriteDescriptor item, byte[] cipher)
        => VerifiedCompletionInput.OpenVerified(keys, recordId, context, kind, item, cipher);
    internal static void DemandAggregate(IEnumerable<long> lengths)
    {
        long total = 0; var count = 0;
        foreach (var length in lengths)
        {
            if (++count > 11 || length is < 1 or > MaximumCipherBytes || length > MaximumAggregateCipherBytes - total) throw Invalid();
            total += length;
        }
    }
}

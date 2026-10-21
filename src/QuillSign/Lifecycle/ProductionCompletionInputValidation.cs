using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

internal static partial class ProductionCompletionInputCodec
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly string[] CandidateColumns = ["Id", "EnvelopeId", "FinishId", "CopyVersion", "SourceObjectId", "SourceSha256", "PdfObjectId", "PdfLength", "PdfSha256",
        "DocumentPages", "CertificatePages", "GeometryJson", "EvidenceJson", "EvidenceSha256", "FrozenStateSha256", "AuditSequence", "AuditAnchor", "RecipeSha256", "RendererVersion", "SnapshotVersion", "PreparedAt", "RowVersion"];
    private static readonly string[] SealColumns = ["Id", "EnvelopeId", "CandidateId", "Kind", "SourceObjectId", "SourceLength", "SourceSha256", "PdfObjectId", "PdfLength", "PdfSha256",
        "PageCount", "EvidenceSha256", "CandidateRecipeSha256", "ExecutedSha256", "MetadataJson", "RecipeVersion", "RecipeSha256", "RowVersion"];
    internal static CompletionInputV1 Read(byte[] bytes)
    {
        if (bytes is not { Length: > 0 and <= MaximumPlainBytes }) throw Invalid(); GuardJson(bytes);
        try
        {
            var body = JsonSerializer.Deserialize<CompletionInputV1>(bytes, Json) ?? throw Invalid();
            if (!JsonSerializer.SerializeToUtf8Bytes(body, Json).AsSpan().SequenceEqual(bytes)) throw Invalid();
            return body;
        }
        catch (JsonException error) { throw new InvalidDataException("The completion input is not a closed canonical body.", error); }
    }
    internal static void Validate(CompletionInputV1 body)
    {
        try { ValidateCore(body); }
        catch (Exception error) when (error is JsonException or ArgumentException or InvalidOperationException or
            OverflowException or FormatException or NullReferenceException or KeyNotFoundException or DocumentRejectedException)
        { throw new InvalidDataException("The closed completion input facts could not be verified.", error); }
    }
    private static void ValidateCore(CompletionInputV1 body)
    {
        if (body is null || body.Context is null) throw Invalid();
        ProductionCompletionProtocol.Context(body.Context);
        if (body.Version != Version || body.RecordId == Guid.Empty || !Enum.IsDefined(body.Kind) || body.InputObjectId == Guid.Empty ||
            body.RecordedAt == default || body.RecordedAt.Offset != TimeSpan.Zero || body.RecordedAt != body.Context.RecordedAt || body.RecordedAt >= body.Context.Until ||
            body.AuditCut is null || body.AuditCut.Sequence < 1 || !ProductionCompletionProtocol.Hash(body.AuditCut.Sha256) ||
            !body.Context.Targets.Contains(new(Effect(body.Kind), body.InputObjectId))) throw Invalid();
        var candidate = body.Kind == CompletionInputKind.CandidatePlan;
        var context = body.Kind is CompletionInputKind.ExecutedContext or CompletionInputKind.CertificateContext;
        var request = body.Kind is CompletionInputKind.ExecutedTimestampRequest or CompletionInputKind.CertificateTimestampRequest;
        var response = body.Kind is CompletionInputKind.ExecutedTimestampResponse or CompletionInputKind.CertificateTimestampResponse;
        var seal = body.Kind is CompletionInputKind.ExecutedResult or CompletionInputKind.CertificateResult;
        var intent = body.Kind == CompletionInputKind.PublicationIntentPlan;
        var result = body.Kind == CompletionInputKind.PublicationResultPlan;
        if ((body.Candidate is not null) != candidate || (body.SealContext is not null) != (context || seal) ||
            (body.TimestampRequest is not null) != request || (body.TimestampResponse is not null) != response ||
            (body.SealResult is not null) != seal || (body.Intent is not null) != intent || (body.Publication is not null) != result) throw Invalid();
        if (candidate) Candidate(body, body.Candidate!);
        if (context || seal) SealContext(body, body.SealContext!);
        if (request)
        {
            var value = body.TimestampRequest!;
            if (value.Encoded is not { Length: > 0 and <= 65536 } || !ProductionCompletionProtocol.Hash(value.ContextPlainSha256) ||
                !ProductionCompletionProtocol.Hash(value.AuthoritySha256) || value.StartedAt == default || value.StartedAt.Offset != TimeSpan.Zero || value.StartedAt > body.RecordedAt ||
                !Rfc3161TimestampRequest.TryDecode(value.Encoded, out var decoded, out var consumed) || consumed != value.Encoded.Length ||
                !decoded.Encode().AsSpan().SequenceEqual(value.Encoded) || decoded.HashAlgorithmId.Value != "2.16.840.1.101.3.4.2.1" ||
                decoded.GetNonce() is not { } nonce || nonce.Length is < 1 or > 32) throw Invalid();
        }
        if (response)
        {
            var value = body.TimestampResponse!;
            if (value.EncodedResponse is not { Length: > 0 and <= 128 * 1024 } || value.VerifiedToken is not { Length: > 0 and <= 128 * 1024 } ||
                !ProductionCompletionProtocol.Hash(value.RequestPlainSha256) || !ProductionCompletionProtocol.Hash(value.CertificateSha256) ||
                value.Policy is not { Length: > 0 and <= 256 } || value.TimestampAt == default || value.TimestampAt.Offset != TimeSpan.Zero ||
                !Rfc3161TimestampToken.TryDecode(value.VerifiedToken, out var token, out var consumed) || consumed != value.VerifiedToken.Length ||
                token.TokenInfo.Timestamp != value.TimestampAt || token.TokenInfo.PolicyId.Value != value.Policy) throw Invalid();
            try
            {
                var cms = token.AsSignedCms(); cms.CheckSignature(true);
                if (cms.SignerInfos.Count != 1 || cms.SignerInfos[0].Certificate is not { } leaf || Hash(leaf.RawData) != value.CertificateSha256) throw Invalid();
            }
            catch (CryptographicException error) { throw new InvalidDataException("The retained completion timestamp signature cannot be verified.", error); }
        }
        if (seal) SealResult(body, body.SealResult!);
        if (intent) Intent(body, body.Intent!);
        // PublicationResultPlan has a separate closed producer-aware projection;
        // it is not valid until its typed transition factory supplies it.
        if (result) ValidatePublicationResult(body);
    }
    private static void Candidate(CompletionInputV1 body, CompletionCandidate row)
    {
        Shape<CompletionCandidate>(CandidateColumns);
        if (row.Id == Guid.Empty || row.EnvelopeId != body.RecordId || row.FinishId == Guid.Empty || row.CopyVersion is < 1 or > 20 ||
            row.SourceObjectId == Guid.Empty || row.PdfObjectId == row.SourceObjectId ||
            row.PdfObjectId != body.Context.Targets.Single(x => x.Effect == CompletionEffect.CandidatePdf).TargetId ||
            row.PdfLength is < 16 or > 64 * 1024 * 1024 || row.DocumentPages is < 1 or > 200 || row.CertificatePages is < 1 or > 64 || row.DocumentPages + row.CertificatePages > 200 ||
            !Hash32(row.SourceSha256) || !Hash32(row.PdfSha256) || !Hash32(row.EvidenceSha256) || !Hash32(row.FrozenStateSha256) ||
            !Hash32(row.AuditAnchor) || row.AuditSequence != body.AuditCut.Sequence || Hex(row.AuditAnchor) != body.AuditCut.Sha256 ||
            row.PreparedAt == default || row.PreparedAt.Offset != TimeSpan.Zero || row.PreparedAt > body.RecordedAt ||
            row.SnapshotVersion != CompletionCandidates.SnapshotVersion || row.RendererVersion != CompletionCertificateRenderer.Version ||
            row.RowVersion is not { Length: 0 } || !Hash32(row.RecipeSha256)) throw Invalid();
        var evidenceBytes = Nested(row.EvidenceJson); var geometryBytes = Nested(row.GeometryJson);
        if (Hash(evidenceBytes) != Hex(row.EvidenceSha256) || !CompletionCandidates.Recipe(row).AsSpan().SequenceEqual(row.RecipeSha256)) throw Invalid();
        var evidence = JsonSerializer.Deserialize<CompletionEvidence>(evidenceBytes, Json) ?? throw Invalid();
        var own = CompletionEvidenceValidation.Own(evidence, default);
        // Evidence deliberately uses the saved public UUID and original draft
        // document UUID, not the database owner/current checkpoint UUID. Their
        // exact SQL relationship is checked by the original-row binder.
        if (own.PreparedAt != row.PreparedAt ||
            own.Signers.Count != row.CopyVersion || !own.Document.CurrentSha256.AsSpan().SequenceEqual(row.SourceSha256) ||
            !CompletionEvidenceValidation.Digest(own).AsSpan().SequenceEqual(row.EvidenceSha256)) throw Invalid();
        var notifications = own.Signers.Select(x => x.Email).Concat(own.Recipients.Select(x => x.Email)).Prepend(own.Sender.Email)
            .Distinct(StringComparer.OrdinalIgnoreCase).Count();
        if (body.AuditCut.Sequence > 512 - 6 - notifications) throw Invalid();
        var pages = JsonSerializer.Deserialize<PageGeometry[]>(geometryBytes, Json) ?? throw Invalid();
        if (pages.Length != row.DocumentPages || pages.Any(x => x is null || x.MediaBox is not { Length: 4 } || x.CropBox is not { Length: 4 })) throw Invalid();
    }
    private static void SealContext(CompletionInputV1 body, CompletionSealInputContext value)
    {
        var certificate = body.Context.Slot == CompletionSlot.CertificateSeal;
        if (body.Context.Slot is not (CompletionSlot.ExecutedSeal or CompletionSlot.CertificateSeal) || value.CandidateId == Guid.Empty ||
            !ProductionCompletionProtocol.Hash(value.CandidateRecipeSha256) || value.SourceObjectId == Guid.Empty || value.SourceLength is < 16 or > 64 * 1024 * 1024 ||
            !ProductionCompletionProtocol.Hash(value.SourceSha256) || value.OutputRowId == Guid.Empty || value.Pages is < 1 or > 200 ||
            value.Provider is not { Length: > 0 and <= 128 } || value.CertificateDer is not { Length: > 0 and <= 65536 } ||
            Hash(value.CertificateDer) != value.CertificateSha256 || value.SigningAt == default || value.SigningAt.Offset != TimeSpan.Zero ||
            value.SigningAt > body.RecordedAt || value.OutputObjectId != body.Context.Targets.Single(x => x.Effect ==
                (certificate ? CompletionEffect.CertificatePdf : CompletionEffect.ExecutedPdf)).TargetId || value.OutputObjectId == value.SourceObjectId ||
            certificate != (value.ExecutedSha256 is not null) || certificate != (value.ExecutedRecipeSha256 is not null) ||
            certificate && (!ProductionCompletionProtocol.Hash(value.ExecutedSha256) || !ProductionCompletionProtocol.Hash(value.ExecutedRecipeSha256) ||
                value.SourceObjectId != body.Context.Targets.Single(x => x.Effect == CompletionEffect.CertificateSource).TargetId)) throw Invalid();
        try { using var leaf = X509CertificateLoader.LoadCertificate(value.CertificateDer); if (!leaf.RawData.AsSpan().SequenceEqual(value.CertificateDer)) throw Invalid(); }
        catch (CryptographicException error) { throw new InvalidDataException("The original completion certificate is not a bounded public certificate.", error); }
    }
    private static void SealResult(CompletionInputV1 body, CompletionSealOutput row)
    {
        Shape<CompletionSealOutput>(SealColumns); var value = body.SealContext!;
        var certificate = body.Context.Slot == CompletionSlot.CertificateSeal;
        if (row.Id != value.OutputRowId || row.EnvelopeId != body.RecordId || row.CandidateId != value.CandidateId ||
            row.Kind != (certificate ? CompletionSealKind.Certificate : CompletionSealKind.Executed) || row.SourceObjectId != value.SourceObjectId ||
            row.SourceLength != value.SourceLength || Hex(row.SourceSha256) != value.SourceSha256 || row.PdfObjectId != value.OutputObjectId ||
            row.PdfLength is < 16 or > 64 * 1024 * 1024 || row.RecipeVersion != CompletionSealOutputs.RecipeVersion || !Hash32(row.PdfSha256) || row.PageCount != value.Pages ||
            !Hash32(row.EvidenceSha256) || Hex(row.CandidateRecipeSha256) != value.CandidateRecipeSha256 ||
            (row.ExecutedSha256 is null ? null : Hex(row.ExecutedSha256)) != value.ExecutedSha256 ||
            row.RowVersion is not { Length: 0 } || !Hash32(row.RecipeSha256) ||
            !CompletionSealOutputs.Recipe(row).AsSpan().SequenceEqual(row.RecipeSha256)) throw Invalid();
        var metadata = JsonSerializer.Deserialize<CompletionSealMetadataInput>(Nested(row.MetadataJson), Json) ?? throw Invalid();
        if (JsonSerializer.Serialize(metadata, Json) != row.MetadataJson || metadata.Provider != value.Provider || metadata.CertificateSha256 != value.CertificateSha256 ||
            metadata.CertificateDer != Convert.ToBase64String(value.CertificateDer) || metadata.SealedAt != value.SigningAt ||
            metadata.TimestampAt == default || metadata.TimestampAt.Offset != TimeSpan.Zero || !ProductionCompletionProtocol.Hash(metadata.TimestampCertificateSha256) ||
            metadata.TimestampPolicy is not { Length: > 0 and <= 256 }) throw Invalid();
    }
    private static void Intent(CompletionInputV1 body, CompletionPublicationIntent row)
    {
        if (row.Id == Guid.Empty || row.EnvelopeId != body.RecordId || row.CandidateId == Guid.Empty || row.ExecutedOutputId == Guid.Empty || row.CertificateOutputId == Guid.Empty ||
            row.ExecutedObjectId == Guid.Empty || row.CertificateObjectId == Guid.Empty || row.ExecutedObjectId == row.CertificateObjectId ||
            row.PreparedAt == default || row.PreparedAt.Offset != TimeSpan.Zero || row.PreparedAt > body.RecordedAt || row.RetentionDays is < 0 or > 36500 ||
            row.DevelopmentWriteOnce || row.RowVersion is not { Length: 0 } || row.BeforeEnvelopeJson.Length > 262144 || row.StageBindingsJson.Length > 16384 || !Hash32(row.RecipeSha256) ||
            !CompletionPublication.Recipe(row).AsSpan().SequenceEqual(row.RecipeSha256)) throw Invalid();
        _ = Nested(row.BeforeEnvelopeJson); _ = Nested(row.StageBindingsJson); _ = DemandIntentFacts(row);
    }
    private static byte[] Nested(string raw)
    {
        if (raw is null || raw.Length > MaximumPlainBytes || Utf8.GetByteCount(raw) > MaximumPlainBytes) throw Invalid();
        var bytes = Utf8.GetBytes(raw); GuardJson(bytes); return bytes;
    }
    private static bool Hash32(byte[]? value) => value is { Length: 32 };
    private static void Shape<T>(string[] columns)
    {
        if (!typeof(T).GetProperties().Select(x => x.Name).Order(StringComparer.Ordinal).SequenceEqual(columns.Order(StringComparer.Ordinal))) throw Invalid();
    }
    private static void GuardJson(ReadOnlySpan<byte> bytes)
    {
        try
        {
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 48 });
            var objects = new Stack<HashSet<string>>(); var arrays = new Stack<(int Depth, int Count, int Maximum)>(); string? property = null;
            while (reader.Read())
            {
                if (arrays.Count > 0 && reader.CurrentDepth == arrays.Peek().Depth + 1 && reader.TokenType is not (JsonTokenType.EndArray or JsonTokenType.EndObject or JsonTokenType.PropertyName))
                { var a = arrays.Pop(); if (++a.Count > a.Maximum) throw Invalid(); arrays.Push(a); }
                if (reader.TokenType == JsonTokenType.StartObject) objects.Push(new(StringComparer.Ordinal));
                else if (reader.TokenType == JsonTokenType.EndObject) objects.Pop();
                else if (reader.TokenType == JsonTokenType.PropertyName) { property = reader.GetString(); if (!objects.Peek().Add(property!)) throw Invalid(); }
                else if (reader.TokenType == JsonTokenType.StartArray)
                {
                    var maximum = property switch { "MediaBox" or "CropBox" => 4, "Signers" => 20, "Recipients" => 50, "Events" => 512,
                        "Targets" => 11, "SqlRows" => 1024, "Notifications" => 201, _ => 200 };
                    arrays.Push((reader.CurrentDepth, 0, maximum)); property = null;
                }
                else if (reader.TokenType == JsonTokenType.EndArray) { var a = arrays.Pop(); if (a.Maximum == 4 && a.Count != 4) throw Invalid(); }
                else if (reader.TokenType == JsonTokenType.String)
                {
                    var maximum = property switch { "RowVersion" => 12, "Encoded" => 4 * ((65536 + 2) / 3),
                        "EncodedResponse" or "VerifiedToken" => 4 * ((128 * 1024 + 2) / 3), "CertificateDer" => 4 * ((65536 + 2) / 3),
                        "Png" => 4 * ((512 * 1024 + 2) / 3), _ => MaximumPlainBytes };
                    if (reader.ValueSpan.Length > maximum) throw Invalid(); property = null;
                }
            }
        }
        catch (JsonException error) { throw new InvalidDataException("The bounded completion input JSON is malformed.", error); }
    }
    internal static void DemandJson(ReadOnlySpan<byte> bytes) => GuardJson(bytes);
}

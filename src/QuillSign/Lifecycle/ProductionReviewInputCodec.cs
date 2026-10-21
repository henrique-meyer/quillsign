using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;

namespace QuillSign.Lifecycle;

internal sealed record ReviewMarkInputV1(Guid AdoptionId, Guid SignatureObjectId, Guid InitialsObjectId,
    byte[] SignatureSha256, byte[] InitialsSha256, string NormalizationVersion);
internal sealed record ReviewRenderInputV1(Guid EnvelopeId, Guid SignerId, string FullName, DateTimeOffset FinishAt,
    Guid? AdoptionId, SignerPdfField[] Fields, ReviewMarkInputV1? Marks);
internal sealed record ReviewInputV1(string Version, Guid RecordId, Guid OperationId, Guid CandidateId,
    string CandidateRowJson, VerifiedSigner Identity, DateTimeOffset AccessExpiresAt, string OriginalSnapshotJson,
    ReviewRenderInputV1 Render, PageGeometry[] Pages, long AuditId, int AuditSequence, string AuditSha256);
// Property names/order are the original Snapshot producer's names/order. Its
// numeric enum and byte-array representations remain part of the original hash.
internal sealed record ReviewSnapshotV1(string version, Guid EnvelopeId, Guid SignerId, Guid DocumentId,
    string DocumentHash, string DisclosureHash, byte[] RowVersion, int? PageCount, string? PageSizesJson,
    string FullName, DateTimeOffset? ConsentAt, byte[] signerVersion, Guid adoptionId,
    byte[] SignatureSha256, byte[] InitialsSha256, string NormalizationVersion, DocumentField[] fields);

// Only the codec constructs a verified fact. Callers receive owned views, never
// mutable arrays which could change an already authenticated semantic proof.
internal sealed class VerifiedReviewInput
{
    private readonly byte[] body;
    internal Guid RecordId { get; }
    internal Guid OperationId { get; }
    internal Guid CandidateId { get; }
    internal string PlanSha256 { get; }
    internal ReviewInputV1 Body => ProductionReviewInputCodec.Read(body);
    internal ReviewSnapshotV1 Snapshot => ProductionReviewInputCodec.Snapshot(Body.OriginalSnapshotJson);
    private VerifiedReviewInput(byte[] body, HoldWitnessReviewPlan plan)
    {
        this.body = body.ToArray(); var value = Body;
        RecordId = value.RecordId; OperationId = value.OperationId; CandidateId = value.CandidateId;
        PlanSha256 = ProductionRecordReviewWriteContract.PlanSha256(plan);
    }
    internal static VerifiedReviewInput Authenticate(byte[] body, HoldWitnessReviewPlan plan)
    {
        var value = ProductionReviewInputCodec.Read(body); ProductionReviewInputCodec.Validate(value);
        if (value.OperationId != plan.OperationId || value.CandidateRowJson != plan.CandidateRowJson || value.Identity != plan.Identity ||
            value.AccessExpiresAt != plan.AccessExpiresAt || value.AuditId != plan.AuditId || value.AuditSequence != plan.AuditSequence ||
            value.AuditSha256 != plan.AuditSha256 || ProductionReviewInputCodec.Hash(Encoding.UTF8.GetBytes(value.OriginalSnapshotJson)) != plan.SnapshotSha256 ||
            ProductionReviewInputCodec.Hash(body) != plan.InputPlainSha256) throw ProductionReviewInputCodec.Invalid();
        return new(body, plan);
    }
}

internal static class ProductionReviewInputCodec
{
    internal const string Version = "review-input-v1";
    internal const int MaximumPlainBytes = 16 * 1024 * 1024, MaximumCipherBytes = MaximumPlainBytes + 65536;
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly string[] FieldColumns = ["Id", "EnvelopeId", "SignerId", "Type", "Page", "X", "Y", "Width", "Height", "Required",
        "Label", "Placeholder", "DateFormat", "Source", "AiConfidence", "Value", "FilledAt", "FilledBy", "SignatureAdoptionId", "ImageSha256", "RowVersion"];
    internal static byte[] Encode(ReviewInputV1 value)
    {
        Validate(value); using var bytes = new MemoryStream();
        JsonSerializer.Serialize(new BoundedDocumentStream(bytes, MaximumPlainBytes), value, Json);
        return bytes.ToArray();
    }
    internal static byte[] Protect(IDataProtectionProvider keys, ReviewInputV1 body)
    {
        var plain = Encode(body); var cipher = Protector(keys, body.RecordId, body.OperationId, body.CandidateId).Protect(plain);
        if (cipher.Length > MaximumCipherBytes) throw Invalid(); return cipher;
    }
    internal static VerifiedReviewInput OpenVerified(IDataProtectionProvider keys, HoldWitnessReviewPlan plan, byte[] ciphertext)
    {
        ProductionRecordReviewWriteContract.Validate(plan);
        if (ciphertext is not { Length: > 0 and <= MaximumCipherBytes } || ciphertext.LongLength != plan.Input.Length || Hash(ciphertext) != plan.Input.Sha256) throw Invalid();
        var row = ProductionRecordReviewWriteContract.ReadRow(plan.CandidateRowJson);
        byte[] plain;
        try { plain = Protector(keys, row.EnvelopeId, plan.OperationId, row.Id).Unprotect(ciphertext.ToArray()); }
        catch (CryptographicException error) { throw new InvalidDataException("The retained review input cannot be authenticated.", error); }
        if (plain.Length is < 1 or > MaximumPlainBytes) throw Invalid();
        return VerifiedReviewInput.Authenticate(plain, plan);
    }
    private static IDataProtector Protector(IDataProtectionProvider keys, Guid record, Guid operation, Guid candidate)
        => keys.CreateProtector("QuillSign.ProductionReviewInput.v1", record.ToString("N"), operation.ToString("N"), candidate.ToString("N"));
    internal static ReviewInputV1 Read(byte[] bytes)
    {
        if (bytes.Length is < 1 or > MaximumPlainBytes) throw Invalid(); GuardJson(bytes);
        try
        {
            var value = JsonSerializer.Deserialize<ReviewInputV1>(bytes, Json) ?? throw Invalid();
            if (!JsonSerializer.SerializeToUtf8Bytes(value, Json).AsSpan().SequenceEqual(bytes)) throw Invalid();
            return value;
        }
        catch (JsonException error) { throw new InvalidDataException("The retained review input is not a closed canonical body.", error); }
    }
    internal static ReviewSnapshotV1 Snapshot(string raw)
    {
        if (raw is null || raw.Length > MaximumPlainBytes || Utf8.GetByteCount(raw) > MaximumPlainBytes) throw Invalid();
        var bytes = Utf8.GetBytes(raw); GuardJson(bytes);
        try
        {
            var value = JsonSerializer.Deserialize<ReviewSnapshotV1>(bytes, Json) ?? throw Invalid();
            if (JsonSerializer.Serialize(value, Json) != raw || value.fields is null || value.fields.Length > 200 ||
                !typeof(DocumentField).GetProperties().Select(x => x.Name).Order(StringComparer.Ordinal).SequenceEqual(FieldColumns.Order(StringComparer.Ordinal))) throw Invalid();
            return value;
        }
        catch (JsonException error) { throw new InvalidDataException("The original review snapshot is not canonical.", error); }
    }
    // Streaming limits precede typed array/entity allocation, including nested
    // snapshot JSON. Duplicate properties and future fields cannot disappear.
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
                else if (reader.TokenType == JsonTokenType.StartArray) { arrays.Push((reader.CurrentDepth, 0, property is "MediaBox" or "CropBox" ? 4 : 200)); property = null; }
                else if (reader.TokenType == JsonTokenType.EndArray) { var a = arrays.Pop(); if (a.Maximum == 4 && a.Count != 4) throw Invalid(); }
                if (reader.TokenType is JsonTokenType.String or JsonTokenType.PropertyName && reader.ValueSpan.Length > MaximumPlainBytes) throw Invalid();
            }
        }
        catch (JsonException error) { throw new InvalidDataException("The bounded review input JSON is malformed.", error); }
    }
    internal static void Validate(ReviewInputV1 body)
    {
        if (body.Version != Version || body.RecordId == Guid.Empty || body.OperationId == Guid.Empty || body.CandidateId == Guid.Empty ||
            body.Identity is null || body.Render is null || body.Render.Fields is null || body.Render.Fields.Length > 200 ||
            body.Pages is not { Length: >= 1 and <= 200 } || body.AuditId < 1 || body.AuditSequence < 1 || !IsHash(body.AuditSha256)) throw Invalid();
        var row = ProductionRecordReviewWriteContract.ReadRow(body.CandidateRowJson); var identity = body.Identity; var render = body.Render;
        var snapshot = Snapshot(body.OriginalSnapshotJson);
        if (row.Id != body.CandidateId || row.EnvelopeId != body.RecordId || identity.EnvelopeId != body.RecordId || row.SignerId != identity.SignerId ||
            row.SourceObjectId != identity.DocumentId || !IsHash(identity.DocumentHash) || !IsHash(identity.DisclosureHash) || identity.SessionId == Guid.Empty ||
            identity.PublicId is not { Length: > 0 and <= 128 } || identity.Email is not { Length: > 0 and <= 320 } ||
            row.UsedAt is not null || row.SupersededAt is not null || row.PreparedAt.Offset != TimeSpan.Zero || row.ExpiresAt.Offset != TimeSpan.Zero ||
            body.AccessExpiresAt.Offset != TimeSpan.Zero || body.AccessExpiresAt > identity.SessionExpiresAt || row.ExpiresAt > body.AccessExpiresAt ||
            row.PreparedAt >= row.ExpiresAt || row.ExpiresAt > row.PreparedAt.AddMinutes(10) || row.ProspectiveDate != DateOnly.FromDateTime(row.PreparedAt.UtcDateTime) ||
            row.ExpiresAt > new DateTimeOffset(row.PreparedAt.UtcDateTime.Date.AddDays(1), TimeSpan.Zero) ||
            row.RendererVersion != SignerPdfRenderer.Version || row.SnapshotVersion != "signer-review-v1" ||
            Hex(row.SourceSha256) != identity.DocumentHash || Hex(row.DisclosureSha256) != identity.DisclosureHash ||
            Hex(row.SessionSha256) != Hash(JsonSerializer.SerializeToUtf8Bytes(identity)) || Hex(row.SnapshotSha256) != Hash(Utf8.GetBytes(body.OriginalSnapshotJson)) ||
            snapshot.version != row.SnapshotVersion || snapshot.EnvelopeId != body.RecordId || snapshot.SignerId != row.SignerId || snapshot.DocumentId != row.SourceObjectId ||
            snapshot.DocumentHash != identity.DocumentHash || snapshot.DisclosureHash != identity.DisclosureHash || snapshot.RowVersion is not { Length: 8 } ||
            snapshot.signerVersion is not { Length: 8 } || snapshot.PageCount != body.Pages.Length || snapshot.adoptionId != row.AdoptionId ||
            snapshot.FullName != render.FullName || snapshot.ConsentAt is null || snapshot.ConsentAt > row.PreparedAt ||
            render.EnvelopeId != body.RecordId || render.SignerId != row.SignerId || render.AdoptionId != row.AdoptionId || render.FinishAt != row.PreparedAt ||
            render.Fields.Length != snapshot.fields.Length || render.Marks is not { } marks || marks.AdoptionId != row.AdoptionId ||
            marks.SignatureObjectId == Guid.Empty || marks.InitialsObjectId == Guid.Empty || marks.SignatureObjectId == marks.InitialsObjectId ||
            marks.SignatureObjectId == row.PdfObjectId || marks.InitialsObjectId == row.PdfObjectId || marks.SignatureObjectId == row.SourceObjectId || marks.InitialsObjectId == row.SourceObjectId ||
            marks.NormalizationVersion != SignaturePng.Version || snapshot.NormalizationVersion != marks.NormalizationVersion ||
            !Same(snapshot.SignatureSha256, marks.SignatureSha256) || !Same(snapshot.InitialsSha256, marks.InitialsSha256)) throw Invalid();
        if (snapshot.PageSizesJson is null || snapshot.PageSizesJson.Length > 256 * 1024) throw Invalid();
        var geometryBytes = Utf8.GetBytes(snapshot.PageSizesJson); GuardJson(geometryBytes);
        var originalPages = JsonSerializer.Deserialize<PageGeometry[]>(geometryBytes, Json) ?? throw Invalid();
        if (originalPages.Length is < 1 or > 200 || body.Pages.Any(p => p is null || p.MediaBox is not { Length: 4 } || p.CropBox is not { Length: 4 }) ||
            !SenderPdfRenderer.GeometryMatches(originalPages, body.Pages)) throw Invalid();
        var ids = new HashSet<Guid>();
        foreach (var field in snapshot.fields)
        {
            if (field is null || field.Id == Guid.Empty || !ids.Add(field.Id) || field.EnvelopeId != body.RecordId || field.SignerId != row.SignerId ||
                field.RowVersion is not { Length: 8 } || field.Label is { Length: > 512 } || field.Placeholder is { Length: > 512 } || field.DateFormat is { Length: > 512 } ||
                field.Value is { Length: > 4000 } || !Enum.IsDefined(field.Source) || !Enum.IsDefined(field.Type)) throw Invalid();
            var expected = new SignerPdfField(field.Id, field.EnvelopeId, field.SignerId, field.RowVersion, field.Type, field.Page, field.X, field.Y, field.Width,
                field.Height, field.Required, field.Value, field.FilledAt, field.FilledBy, field.SignatureAdoptionId, field.ImageSha256);
            var actual = render.Fields.SingleOrDefault(x => x.Id == field.Id) ?? throw Invalid();
            if (!JsonSerializer.SerializeToUtf8Bytes(expected).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(actual))) throw Invalid();
        }
        if (Hex(row.RecipeSha256) != Binding(render, body.Pages.Length, row.SourceSha256)) throw Invalid();
    }
    internal static string Binding(ReviewRenderInputV1 request, int pageCount, byte[] sourceHash)
    {
        var name = Canonical(request.FullName); var values = new Dictionary<Guid, string>(); var marks = request.Marks;
        foreach (var field in request.Fields)
        {
            if (field.Id == Guid.Empty || field.Revision is not { Length: 8 } || field.EnvelopeId != request.EnvelopeId || field.SignerId != request.SignerId ||
                !Enum.IsDefined(field.Type) || field.Page < 1 || field.Page > pageCount || !FieldGeometry.InBounds(field.X, field.Y, field.Width, field.Height)) throw Invalid();
            if (field.Type == FieldType.DateSigned)
            {
                if (field.Value is not null || field.FilledAt is not null || field.FilledBy is not null || field.AdoptionId is not null || field.ImageSha256 is not null) throw Invalid();
                values.Add(field.Id, request.FinishAt.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)); continue;
            }
            var empty = field.Value is null && field.FilledAt is null && field.FilledBy is null && field.AdoptionId is null && field.ImageSha256 is null;
            if (empty) { if (field.Required) throw Invalid(); continue; }
            if (field.Value is null || field.FilledAt is null || field.FilledAt > request.FinishAt || field.FilledBy != PartyType.Signer) throw Invalid();
            if (field.Type is FieldType.Signature or FieldType.Initials)
            {
                if (marks is null || field.AdoptionId != marks.AdoptionId || field.Value != (field.Type == FieldType.Signature ? marks.SignatureObjectId : marks.InitialsObjectId).ToString("N") ||
                    !Same(field.ImageSha256, field.Type == FieldType.Signature ? marks.SignatureSha256 : marks.InitialsSha256)) throw Invalid();
                values.Add(field.Id, field.Value); continue;
            }
            if (field.AdoptionId is not null || field.ImageSha256 is not null) throw Invalid();
            var value = Canonical(field.Value); if (field.Type == FieldType.FullName && value != name) throw Invalid();
            if (field.Type == FieldType.Text && string.IsNullOrWhiteSpace(value)) { if (field.Required) throw Invalid(); continue; }
            SenderPdfRenderer.ValidateValue(new(field.Id, null, field.Type == FieldType.FullName ? "Text" : field.Type.ToString(), field.Page, field.X, field.Y, field.Width, field.Height, value));
            values.Add(field.Id, field.Type == FieldType.FullName ? name : value);
        }
        return Hash(JsonSerializer.SerializeToUtf8Bytes(new {
            renderer = SignerPdfRenderer.Version, request.EnvelopeId, request.SignerId, sourceSha256 = Hex(sourceHash), fullName = name, finishAt = request.FinishAt.ToUniversalTime(), request.AdoptionId,
            signatureSha256 = marks?.SignatureSha256, initialsSha256 = marks?.InitialsSha256, normalization = marks?.NormalizationVersion,
            fields = request.Fields.OrderBy(f => f.Id).Select(f => new { f.Id, f.Revision, f.Type, f.Page, f.X, f.Y, f.Width, f.Height, f.Required,
                value = values.GetValueOrDefault(f.Id), f.FilledAt, f.FilledBy, f.AdoptionId, f.ImageSha256 }) }));
    }
    private static string Canonical(string value)
    {
        if (value is null || value.Length > 4000) throw Invalid();
        try { _ = Utf8.GetByteCount(value); return value.Replace("\r\n", "\n").Replace('\r', '\n').Normalize(NormalizationForm.FormC); }
        catch (ArgumentException error) { throw new InvalidDataException("The original review text is malformed.", error); }
    }
    internal static string Hash(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(SHA256.HashData(value));
    internal static bool IsHash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    internal static string Hex(byte[] value) => value is { Length: 32 } ? Convert.ToHexStringLower(value) : throw Invalid();
    private static bool Same(byte[]? first, byte[]? second) => first is { Length: 32 } && second is { Length: 32 } && CryptographicOperations.FixedTimeEquals(first, second);
    internal static InvalidDataException Invalid() => new("The exact retained original review input could not be verified.");
}

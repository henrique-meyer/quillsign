using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Lifecycle;

// Immutable factual projection only. Complete preservation must separately bind
// EVERY preview to its retained normalized-byte write plan and committed outcome.
// Hash inventory facts do not by themselves attest to PNG pixels or write authority.
internal sealed record HoldVerifiedSignaturePreview(Guid Id, Guid SignerId, Guid DocumentId, Guid SignatureObjectId, Guid InitialsObjectId,
    string SignatureSha256, string InitialsSha256, string DocumentSha256, string DisclosureSha256, string SessionSha256, string BaselineSignerVersion,
    int SignatureWidth, int SignatureHeight, int InitialsWidth, int InitialsHeight, SignatureMethod Method, string? TypedName, string? TypedInitials,
    string NormalizationVersion, string AdoptionVersion, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, DateTimeOffset? UsedAt);
internal sealed record HoldSignatureProgress(HoldInitialSignerStage Initial, bool HasProgress, IReadOnlyList<HoldVerifiedSignaturePreview> Previews,
    IReadOnlyList<FieldInput>? Prepared);

internal static class ProductionHoldSignaturePreviewReferences
{
    // Freeze the supported historical producer, independently of future runtime
    // enum members/normalizers. v1 crops visible ink and adds eight pixels/side.
    private const string Normalizer = "png-rgba-crop-v1", Adoption = "2026-10-16.1";
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly HashSet<string> PreviewColumns = new(StringComparer.Ordinal) {
        "Id", "EnvelopeId", "SignerId", "DocumentId", "SignatureObjectId", "InitialsObjectId", "SignatureSha256", "InitialsSha256",
        "DocumentSha256", "DisclosureSha256", "SessionSha256", "BaselineSignerVersion", "SignatureWidth", "SignatureHeight", "InitialsWidth", "InitialsHeight",
        "Method", "TypedName", "TypedInitials", "NormalizationVersion", "AdoptionVersion", "CreatedAt", "ExpiresAt", "UsedAt" };
    private static bool Added(string? name) => name is "signature_adopted" or "field_filled" or "field_cleared";

    internal static HoldSignatureProgress ReadVerified(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys, Guid invitationId)
    {
        try { return Verify(sql, objects, keys, invitationId); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException or OverflowException or NullReferenceException)
        { throw Invalid(); }
    }
    private static HoldSignatureProgress Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys, Guid invitationId)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        var raw = tables["SignaturePreviews"]; if (raw.GetArrayLength() > SignatureAdoption.MaximumPreviewsPerSigner) throw Invalid();
        foreach (var row in raw.EnumerateArray())
        {
            var columns = row.EnumerateObject().Select(x => x.Name).ToArray();
            if (columns.Length != PreviewColumns.Count || !PreviewColumns.SetEquals(columns)) throw Invalid();
        }
        var auditRows = tables["AuditEvents"]; if (auditRows.GetArrayLength() > 4096) throw Invalid();
        var added = auditRows.EnumerateArray().Where(x => Added(x.GetProperty("Event").GetString())).ToArray();
        if (raw.GetArrayLength() == 0 && added.Length == 0)
            return new(ProductionHoldInvitationDispatchReferences.Demand(sql, objects, keys, invitationId), false, [], null);
        var id = sql.GetProperty("RecordId").GetGuid(); var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var e = tables["Envelopes"].Deserialize<Envelope[]>(Rows)!.Single();
        var first = tables["Signers"].Deserialize<Signer[]>(Rows)!.Single(x => x.Order == 1);
        var audits = auditRows.Deserialize<AuditEvent[]>(Rows)!; var consent = audits.Single(x => x.Event == "consent_given");
        if (e.Id != id || first.EnvelopeId != id || first.Status != SignerStatus.Viewed || first.ConsentAt is not { } accepted ||
            accepted.Offset != TimeSpan.Zero || captured.Offset != TimeSpan.Zero || consent.ActorId != first.Id ||
            added.Any(x => x.GetProperty("Sequence").GetInt64() <= consent.Sequence || x.GetProperty("ActorType").GetString() != nameof(PartyType.Signer) ||
                x.GetProperty("ActorId").GetGuid() != first.Id || x.GetProperty("ActorEmail").GetString() != first.Email)) throw Invalid();

        // Only these THREE newly known schemas are removed from this factual
        // dispatch projection, after full-chain validation in the caller. Their
        // original complete rows are then verified below, never rehashed,
        // relabelled, or omitted from the actual business snapshot/manifest.
        using var dispatch = JsonDocument.Parse(JsonSerializer.Serialize(new {
            RecordId = id, CapturedAt = captured, Tables = tables.Select(x => new { Table = x.Key, Rows = x.Key == "SignaturePreviews"
                ? JsonSerializer.SerializeToElement(Array.Empty<SignaturePreview>(), Rows) : x.Key == "AuditEvents"
                    ? JsonSerializer.SerializeToElement(audits.Where(x => !Added(x.Event)).ToArray(), Rows) : x.Value })
        }));
        var initial = ProductionHoldInvitationDispatchReferences.Demand(dispatch.RootElement, objects, keys, invitationId);
        if (initial != HoldInitialSignerStage.Consented) throw Invalid();
        var documents = ProductionHoldDocumentAuditReferences.ReadVerified(sql, objects);
        if (documents.Count == 0) throw Invalid();
        var definitions = ProductionHoldPreparationAuditReferences.ReadVerified(sql, documents);
        ProductionHoldFinalizedFieldReferences.Demand(sql, objects, definitions);
        var previews = raw.Deserialize<SignaturePreview[]>(Rows)!;
        if (previews.Select(x => x.Id).Distinct().Count() != previews.Length || previews.SelectMany(x => new[] { x.SignatureObjectId, x.InitialsObjectId }).Distinct().Count() != previews.Length * 2) throw Invalid();
        var result = new List<HoldVerifiedSignaturePreview>();
        foreach (var p in previews)
        {
            if (p.Id == Guid.Empty || p.EnvelopeId != id || p.SignerId != first.Id || p.DocumentId.ToString("N") != e.SentPdfBlob ||
                p.SignatureObjectId == Guid.Empty || p.InitialsObjectId == Guid.Empty || p.SignatureObjectId == p.InitialsObjectId ||
                new[] { p.SignatureObjectId, p.InitialsObjectId }.Any(x => x.ToString("N") == e.SentPdfBlob || x.ToString("N") == e.PdfBlob || x.ToString("N") == e.OriginalBlob) || p.CreatedAt.Offset != TimeSpan.Zero ||
                p.CreatedAt < consent.At || p.CreatedAt > captured || p.ExpiresAt.Offset != TimeSpan.Zero || p.ExpiresAt <= p.CreatedAt ||
                p.ExpiresAt > p.CreatedAt.AddMinutes(SignatureAdoption.PreviewMinutes) || e.ExpiresAt is { } deadline && p.ExpiresAt > deadline ||
                p.UsedAt is { } used && (used.Offset != TimeSpan.Zero || used < p.CreatedAt || used >= p.ExpiresAt || used > captured) ||
                p.SessionSha256 is not { Length: 32 } || p.BaselineSignerVersion is not { Length: 8 } ||
                p.SignatureWidth is < 17 or > SignaturePng.MaximumWidth || p.InitialsWidth is < 17 or > SignaturePng.MaximumWidth ||
                p.SignatureHeight is < 17 or > SignaturePng.MaximumHeight || p.InitialsHeight is < 17 or > SignaturePng.MaximumHeight ||
                p.Method is not (SignatureMethod.Typed or SignatureMethod.Drawn or SignatureMethod.Uploaded) ||
                p.NormalizationVersion != Normalizer || p.AdoptionVersion != Adoption ||
                (p.Method == SignatureMethod.Typed ? !Descriptor(p.TypedName, 200) || !Descriptor(p.TypedInitials, 20) : p.TypedName is not null || p.TypedInitials is not null) ||
                Hex(p.DocumentSha256) != Hex(e.SentPdfSha256!) || Hex(p.DisclosureSha256) != Hex(e.ErsdSha256!)) throw Invalid();
            Match(p.SignatureObjectId, p.SignatureSha256); Match(p.InitialsObjectId, p.InitialsSha256);
            result.Add(new(p.Id, p.SignerId, p.DocumentId, p.SignatureObjectId, p.InitialsObjectId, Hex(p.SignatureSha256), Hex(p.InitialsSha256),
                Hex(p.DocumentSha256), Hex(p.DisclosureSha256), Hex(p.SessionSha256), Convert.ToBase64String(p.BaselineSignerVersion),
                p.SignatureWidth, p.SignatureHeight, p.InitialsWidth, p.InitialsHeight, p.Method, p.TypedName, p.TypedInitials,
                p.NormalizationVersion, p.AdoptionVersion, p.CreatedAt, p.ExpiresAt, p.UsedAt));
        }
        // Historical concurrency bound at each saved creation, not at today's
        // clock. Later use/expiry never excuses an impossible sixth active row.
        foreach (var p in previews)
            if (previews.Count(x => x.CreatedAt <= p.CreatedAt && x.ExpiresAt > p.CreatedAt &&
                (x.UsedAt is null || x.UsedAt > p.CreatedAt)) > SignatureAdoption.MaximumActivePreviews) throw Invalid();
        ProductionHoldConsentAuditReferences.Demand(sql, objects);
        var adoptions = ProductionHoldAdoptionAuditReferences.ReadVerified(sql, objects);
        ProductionHoldFieldAuditReferences.Demand(sql, objects, definitions, adoptions);
        return new(initial, true, result.AsReadOnly(), definitions);

        void Match(Guid objectId, byte[] hash)
        {
            if (!objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == $"{id:N}/{objectId:N}" &&
                x.Address.Length is > 0 and <= SignaturePng.MaximumBytes && x.Sha256 == Hex(hash))) throw Invalid();
        }
    }
    private static string Hex(byte[] value) => value is { Length: 32 } ? Convert.ToHexStringLower(value) : throw Invalid();
    private static bool Descriptor(string? value)
    {
        if (value is null) return false;
        _ = new UTF8Encoding(false, true).GetByteCount(value);
        return value.Trim() == value && value.IsNormalized(NormalizationForm.FormC) &&
            !value.EnumerateRunes().Any(x => Rune.GetUnicodeCategory(x) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate);
    }
    private static bool Descriptor(string? value, int maximum) => value is { Length: > 0 } && value.Length <= maximum && Descriptor(value);
    private static InvalidDataException Invalid() => new("The closed prepared marks and first-signer field history could not be verified.");
}

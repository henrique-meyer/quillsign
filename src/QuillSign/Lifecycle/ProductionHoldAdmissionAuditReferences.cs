using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Lifecycle;

// Historical normal-production admission only. No token/session is issued,
// consumed, renewed or read against current options. Mail payload authentication
// remains the separate protected-notification registry's responsibility.
internal static class ProductionHoldAdmissionAuditReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    internal static void Demand(JsonElement sql)
    {
        try { Verify(sql); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or
            ArgumentException or FormatException or OverflowException) { throw Invalid(); }
    }

    private static void Verify(JsonElement sql)
    {
        var id = sql.GetProperty("RecordId").GetGuid(); var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        if (id == Guid.Empty || captured == default || captured.Offset != TimeSpan.Zero || tables["Envelopes"].GetArrayLength() != 1 ||
            tables["ProductionRetentionPolicies"].GetArrayLength() != 1 || tables["AuditEvents"].GetArrayLength() is < 3 or > 4096 ||
            tables["AuthTokens"].GetArrayLength() > 4096) throw Invalid();
        var e = tables["Envelopes"].EnumerateArray().Single().Deserialize<Envelope>(Rows) ?? throw Invalid();
        if (e.Id != id || e.IsDemo || e.CreatedAt == default || e.CreatedAt.Offset != TimeSpan.Zero || e.CreatedAt > captured ||
            e.PublicId is not { Length: 32 } || !Guid.TryParseExact(e.PublicId, "N", out var publicId) || publicId == Guid.Empty ||
            e.PublicId != publicId.ToString("N") || !Enum.IsDefined(e.Status) || e.SenderEmail is not { Length: > 0 and <= 320 } || EmailAddress.Normalize(e.SenderEmail) != e.SenderEmail) throw Invalid();
        var encoded = tables["AuditEvents"].EnumerateArray().Where(x => x.GetProperty("Event").GetString() is
            ProductionRetentionLedger.EnrollmentEvent or "draft_created" or "sender_verification_requested" or "sender_email_verified").ToArray();
        if (encoded.Length is < 3 or > 4) throw Invalid();
        var events = new List<AuditEvent>();
        foreach (var row in encoded)
        {
            var name = row.GetProperty("Event").GetString(); var raw = row.GetProperty("DataJson").GetString();
            if (raw is null || raw.Length > 2048 || name != ProductionRetentionLedger.EnrollmentEvent && raw != "{}") throw Invalid();
            var audit = row.Deserialize<AuditEvent>(Rows) ?? throw Invalid();
            if (audit.Id < 1 || audit.EnvelopeId != id || audit.Sequence < 1 || audit.At.Offset != TimeSpan.Zero ||
                audit.At < e.CreatedAt || audit.At > captured || audit.Hash is not { Length: 32 } ||
                !audit.Hash.AsSpan().SequenceEqual(AuditHash.Compute(audit)) ||
                audit.Ip is { Length: > 45 } || audit.UserAgent is { Length: > 2048 }) throw Invalid();
            if (name != ProductionRetentionLedger.EnrollmentEvent && (audit.ActorType != PartyType.Sender || audit.ActorId is not null || audit.ActorEmail != e.SenderEmail)) throw Invalid();
            events.Add(audit);
        }
        var enrollment = events.Single(x => x.Event == ProductionRetentionLedger.EnrollmentEvent);
        var draft = events.Single(x => x.Event == "draft_created");
        var requested = events.Single(x => x.Event == "sender_verification_requested");
        var verified = events.SingleOrDefault(x => x.Event == "sender_email_verified");
        if (enrollment.Sequence != 1 || enrollment.PrevHash is not null || enrollment.ActorType != PartyType.System ||
            enrollment.ActorId is not null || enrollment.ActorEmail is not null || enrollment.Ip is not null || enrollment.UserAgent is not null ||
            draft.Sequence != 2 || requested.Sequence != 3 || !Same(draft.PrevHash, enrollment.Hash) || !Same(requested.PrevHash, draft.Hash) ||
            draft.At < enrollment.At || requested.At < draft.At || draft.Ip != requested.Ip || draft.UserAgent != requested.UserAgent) throw Invalid();

        var policyRow = tables["ProductionRetentionPolicies"].EnumerateArray().Single().Deserialize<ProductionRetentionPolicyRecord>(Rows) ?? throw Invalid();
        var frozen = ProductionRetentionPolicyContract.Read(policyRow.PolicyJson, policyRow.PolicySha256);
        var origin = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { e.Id, e.PublicId, e.SenderEmail, e.CreatedAt, e.IsDemo }));
        var enrollmentData = JsonSerializer.Serialize(new { version = "production-retention-enrollment-v1", policyRow.EnvelopeId,
            policyRow.OriginalCreatedAt, policyRow.EnrolledAt, policyRow.PolicySha256, originSha256 = Convert.ToHexStringLower(origin) });
        if (policyRow.EnvelopeId != id || policyRow.OriginalCreatedAt != e.CreatedAt || frozen.RecordId != id ||
            frozen.CreatedAt != ProductionRetentionLedger.Seconds(e.CreatedAt) || policyRow.EnrolledAt.Offset != TimeSpan.Zero ||
            policyRow.EnrolledAt < e.CreatedAt || policyRow.EnrolledAt > enrollment.At || policyRow.AuditSequence != 1 ||
            !Same(policyRow.OriginSha256, origin) || !Same(policyRow.AuditHash, enrollment.Hash) || enrollment.DataJson != enrollmentData) throw Invalid();

        var tokens = new List<AuthToken>();
        foreach (var row in tables["AuthTokens"].EnumerateArray().Where(x => x.GetProperty("Purpose").GetString() == nameof(TokenPurpose.SenderVerify)))
        {
            var token = row.Deserialize<AuthToken>(Rows) ?? throw Invalid();
            if (token.Id == Guid.Empty || token.EnvelopeId != id || token.Email != e.SenderEmail || token.PartyType != PartyType.Sender || token.PartyId is not null ||
                token.TokenSha256 is not { Length: 32 } || token.DocumentId is not null || token.DocumentSha256 is not null ||
                token.DisclosureSha256 is not null || token.SignerContactRevisionId is not null || token.EmailPilotLookupRequestId is not null ||
                token.CompletionPublicationId is not null || token.CompletionRecipeSha256 is not null || token.CompletionPartySha256 is not null || token.Ip is not null ||
                token.ExpiresAt.Offset != TimeSpan.Zero || token.ExpiresAt < requested.At || token.UsedAt is { } used &&
                (used.Offset != TimeSpan.Zero || used < requested.At || used > captured || used >= token.ExpiresAt)) throw Invalid();
            tokens.Add(token);
        }
        if (tokens.Count > 1 || tokens.Select(x => x.Id).Distinct().Count() != tokens.Count || tokens.Select(x => Convert.ToHexStringLower(x.TokenSha256)).Distinct().Count() != tokens.Count) throw Invalid();
        var consumed = tokens.Where(x => x.UsedAt is not null).ToArray();
        if (e.SenderVerifiedAt is not { } at)
        {
            if (verified is not null || consumed.Length != 0 || e.Status != EnvelopeStatus.Draft) throw Invalid();
            return; // A never-submitted queued verification legitimately has no token.
        }
        if (at.Offset != TimeSpan.Zero || at < requested.At || at > captured || verified is null || verified.Sequence <= requested.Sequence ||
            verified.At < at || consumed.Length != 1 || consumed[0].UsedAt != at) throw Invalid();
        // The structural chain guard authenticates any intervening operational
        // events; retain the exact stored time instead of inventing a receipt.
        var lower = tables["AuditEvents"].EnumerateArray().Where(x => x.GetProperty("Sequence").GetInt64() < verified.Sequence)
            .Max(x => x.GetProperty("At").GetDateTimeOffset());
        if (lower > at) throw Invalid();
    }
    private static bool Same(byte[]? a, byte[]? b) => a is { Length: 32 } && b is { Length: 32 } && CryptographicOperations.FixedTimeEquals(a, b);
    private static InvalidDataException Invalid() => new("Historical production admission evidence could not be verified.");
}

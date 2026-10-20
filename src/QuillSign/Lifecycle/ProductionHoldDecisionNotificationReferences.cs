using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Historical evidence only: never dispatch, issue tokens or consult live link
// deadlines. Completion/void payloads and the full audit registry are separate.
internal static class ProductionHoldDecisionNotificationReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { MaxDepth = 4, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private sealed record DeclinedEvidence(string? reason, Guid notificationId, string documentSha256, string disclosureSha256);

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
    {
        try { Verify(sql, objects, keys); }
        catch (Exception error) when (error is CryptographicException or JsonException or KeyNotFoundException or
            InvalidOperationException or ArgumentException or FormatException)
        { throw Invalid(); }
    }

    private static void Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        var selected = tables["EmailOutbox"].EnumerateArray().Where(x => x.GetProperty("Template").GetString() is
            "sender-verification" or "signer-declined").ToArray();
        if (selected.Length == 0) return;
        var id = sql.GetProperty("RecordId").GetGuid();
        if (id == Guid.Empty || selected.Length > 4096) throw Invalid();
        var envelope = tables["Envelopes"].EnumerateArray().Single().Deserialize<Envelope>(Rows) ?? throw Invalid();
        if (envelope.Id != id || EmailAddress.Normalize(envelope.SenderEmail) != envelope.SenderEmail) throw Invalid();
        foreach (var encoded in selected)
        {
            var row = encoded.Deserialize<EmailOutbox>(Rows) ?? throw Invalid();
            if (row.Id == Guid.Empty || row.EnvelopeId != id || row.To != envelope.SenderEmail || row.AttachmentsJson != "[]" ||
                !Enum.IsDefined(row.Status) || row.Attempts < 0 || !Bounded(row.PayloadJson, 16 * 1024)) throw Invalid();
            var wrapper = JsonSerializer.Deserialize<ProtectedWorkPayload>(row.PayloadJson, Strict) ?? throw Invalid();
            if (wrapper.Protected is not { Length: > 0 } || JsonSerializer.Serialize(wrapper) != row.PayloadJson) throw Invalid();
            if (row.Template == "sender-verification")
            {
                var payload = new EmailPayloadProtection(keys).Unprotect(row.PayloadJson);
                Canonical(payload, "QuillSign.EmailPayload.v1", wrapper, keys);
                if (payload.TokenId == Guid.Empty || payload.Token is not { Length: 43 }) throw Invalid();
                var decoded = WebEncoders.Base64UrlDecode(payload.Token);
                try { if (decoded.Length != 32 || WebEncoders.Base64UrlEncode(decoded) != payload.Token) throw Invalid(); }
                finally { CryptographicOperations.ZeroMemory(decoded); }
                var tokenRows = tables["AuthTokens"].EnumerateArray().Where(x => x.GetProperty("Id").GetGuid() == payload.TokenId).ToArray();
                if (tokenRows.Length > 1 || (tokenRows.Length == 0 && (row.SubmissionStartedAt is not null ||
                    row.Status is EmailStatus.Sent or EmailStatus.Bounced or EmailStatus.Complained))) throw Invalid();
                // A queued, never submitted payload legitimately precedes token
                // issuance. Existing expired/used tokens remain readable evidence.
                if (tokenRows.Length == 1)
                {
                    var token = tokenRows[0].Deserialize<AuthToken>(Rows) ?? throw Invalid();
                    if (token.EnvelopeId != id || token.Purpose != TokenPurpose.SenderVerify || token.PartyType != PartyType.Sender ||
                        token.PartyId is not null || token.Email != row.To || token.DocumentId is not null || token.DocumentSha256 is not null ||
                        token.DisclosureSha256 is not null || token.SignerContactRevisionId is not null || token.EmailPilotLookupRequestId is not null ||
                        token.CompletionPublicationId is not null || token.CompletionRecipeSha256 is not null || token.CompletionPartySha256 is not null ||
                        token.TokenSha256 is not { Length: 32 } ||
                        !token.TokenSha256.AsSpan().SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes(payload.Token)))) throw Invalid();
                }
            }
            else
            {
                var payload = new DeclinePayloadProtection(keys).Read(row.PayloadJson);
                Canonical(payload, "QuillSign.DeclineNotification.v1", wrapper, keys);
                if (payload.Title is not { Length: > 0 and <= 512 } || payload.Title != envelope.Title ||
                    payload.SignerName is not { Length: > 0 and <= 512 } || payload.Reason is { Length: > 512 } ||
                    payload.Reason?.Trim() != payload.Reason || payload.Reason?.Any(c => char.IsControl(c) && c is not ('\n' or '\r' or '\t')) == true ||
                    EmailAddress.Normalize(payload.SignerEmail) != payload.SignerEmail || envelope.Status != EnvelopeStatus.Declined ||
                    envelope.ErsdSha256 is not { Length: 32 }) throw Invalid();
                var candidates = new List<(AuditEvent Audit, DeclinedEvidence Data)>();
                foreach (var saved in tables["AuditEvents"].EnumerateArray().Where(x => x.GetProperty("Event").GetString() == "declined"))
                {
                    var audit = saved.Deserialize<AuditEvent>(Rows) ?? throw Invalid();
                    if (!Bounded(audit.DataJson)) throw Invalid();
                    var data = JsonSerializer.Deserialize<DeclinedEvidence>(audit.DataJson, Strict) ?? throw Invalid();
                    if (JsonSerializer.Serialize(data) != audit.DataJson) throw Invalid();
                    if (data.notificationId == row.Id) candidates.Add((audit, data));
                }
                if (candidates.Count != 1) throw Invalid();
                var (evidence, declined) = candidates[0];
                if (evidence.Id < 1 || evidence.EnvelopeId != id || evidence.Sequence < 1 || evidence.ActorType != PartyType.Signer ||
                    evidence.ActorId is null || evidence.ActorEmail != payload.SignerEmail || evidence.Hash is not { Length: 32 } ||
                    (evidence.Sequence == 1) != (evidence.PrevHash is null) || evidence.PrevHash is { Length: not 32 } ||
                    !evidence.Hash.AsSpan().SequenceEqual(AuditHash.Compute(evidence)) ||
                    declined.reason != payload.Reason || declined.disclosureSha256 != Convert.ToHexStringLower(envelope.ErsdSha256) ||
                    !Digest(declined.documentSha256)) throw Invalid();
                var signer = tables["Signers"].EnumerateArray().Single(x => x.GetProperty("Id").GetGuid() == evidence.ActorId).Deserialize<Signer>(Rows) ?? throw Invalid();
                if (signer.EnvelopeId != id || signer.Email != payload.SignerEmail || signer.FullName != payload.SignerName ||
                    signer.Status != SignerStatus.Declined || signer.DeclineReason != payload.Reason ||
                    !objects.Any(x => x.Address.Area == "normalized" && x.Sha256 == declined.documentSha256 &&
                        x.Address.Name.StartsWith($"{id:N}/", StringComparison.Ordinal) &&
                        Guid.TryParseExact(x.Address.Name[(id.ToString("N").Length + 1)..], "N", out var objectId) && objectId != Guid.Empty)) throw Invalid();
            }
        }
    }

    private static void Canonical(object value, string purpose, ProtectedWorkPayload wrapper, IDataProtectionProvider keys)
    {
        var plain = keys.CreateProtector(purpose).Unprotect(wrapper.Protected);
        if (!Bounded(plain) || plain != JsonSerializer.Serialize(value, value.GetType())) throw Invalid();
    }
    private static bool Bounded(string? value, int maximum = 12000) => value is { Length: > 0 } && value.Length <= maximum && Encoding.UTF8.GetByteCount(value) <= maximum;
    private static bool Digest(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    private static InvalidDataException Invalid() => new("Protected historical verification or decline evidence could not be verified.");
}

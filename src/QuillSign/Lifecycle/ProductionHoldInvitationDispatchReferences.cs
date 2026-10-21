using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

internal enum HoldInitialSignerStage { Queued, Dispatched, Opened, Consented }

// Factual stage projection, never a dispatch/token/session capability. Only the
// first original invitation is covered; retries, successors and contact epochs
// remain separate requirements. Saved expiry is read, never renewed/reconstructed.
internal static class ProductionHoldInvitationDispatchReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 4 };
    private sealed record Submitted(Guid emailId, Guid tokenId, string documentSha256, string disclosureSha256, Guid signerId,
        string recipient, string provider, string providerMessageId, string meaning);

    internal static HoldInitialSignerStage Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects,
        IDataProtectionProvider keys, Guid invitationId)
    {
        try { return Verify(sql, objects, keys, invitationId); }
        catch (Exception error) when (error is JsonException or CryptographicException or KeyNotFoundException or InvalidOperationException or
            ArgumentException or FormatException or OverflowException) { throw Invalid(); }
    }

    private static HoldInitialSignerStage Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects,
        IDataProtectionProvider keys, Guid invitationId)
    {
        var id = sql.GetProperty("RecordId").GetGuid(); var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        T[] Table<T>(string name, int maximum)
        { var rows = tables[name]; if (rows.GetArrayLength() > maximum) throw Invalid(); return rows.Deserialize<T[]>(Rows) ?? throw Invalid(); }
        var envelope = Table<Envelope>("Envelopes", 1).Single(); var parties = Table<Signer>("Signers", 100);
        var first = parties.OrderBy(x => x.Order).First(); var mail = Table<EmailOutbox>("EmailOutbox", 2).Single(x => x.Id == invitationId);
        var work = Table<WorkItem>("WorkItems", 3).Single(x => x.Id == invitationId); var tokens = Table<AuthToken>("AuthTokens", 2);
        var audits = Table<AuditEvent>("AuditEvents", 4096); var sent = audits.Single(x => x.Event == "sent");
        if (id == Guid.Empty || invitationId == Guid.Empty || envelope.Id != id || envelope.Status != EnvelopeStatus.Sent ||
            first.Id == Guid.Empty || first.EnvelopeId != id || first.Order != 1 || captured.Offset != TimeSpan.Zero ||
            mail.EnvelopeId != id || mail.Template != "signer-invitation" || mail.To != first.Email || mail.AttachmentsJson != "[]" ||
            mail.LastError is not null || mail.LeaseOwner is not null || mail.LeaseExpiresAt is not null || mail.AvailableAt.Offset != TimeSpan.Zero ||
            mail.AvailableAt < envelope.SentAt || mail.AvailableAt > sent.At ||
            work.EnvelopeId != id || work.Kind != WorkKind.Email || work.PayloadJson != "{}" || work.LastError is not null ||
            work.LeaseOwner is not null || work.LeaseExpiresAt is not null || work.AvailableAt.Offset != TimeSpan.Zero) throw Invalid();
        ProductionHoldInvitationReferences.Demand(sql, objects, keys);
        var payload = new SignerInvitationProtection(keys).Read(mail.PayloadJson);
        if (payload.SignerId != first.Id || payload.ContactRevisionId != Guid.Empty || payload.ContactRevisionNumber != 0 ||
            payload.DocumentId.ToString("N") != envelope.SentPdfBlob || payload.DocumentSha256 != Hex(envelope.SentPdfSha256) ||
            payload.DisclosureSha256 != Hex(envelope.ErsdSha256)) throw Invalid();
        var tail = audits.Where(x => x.Sequence > sent.Sequence).OrderBy(x => x.Sequence).ToArray();
        if (audits.Any(x => x.Event == "invitation_submitted" && x.Sequence <= sent.Sequence) ||
            tail.Any(x => x.Event is not ("invitation_submitted" or "link_opened" or "consent_given"))) throw Invalid();
        var submitted = tail.Where(x => x.Event == "invitation_submitted").ToArray();
        if (submitted.Length == 0)
        {
            if (tail.Length != 0 || payload.LastTokenId is not null || tokens.Length != 1 || tokens[0].Purpose != TokenPurpose.SenderVerify ||
                mail.Status != EmailStatus.Queued || mail.Attempts != 0 || mail.SubmissionStartedAt is not null || mail.Provider is not null || mail.ProviderMessageId is not null ||
                work.Status != WorkStatus.Queued || work.Attempts != 0 || work.AvailableAt != mail.AvailableAt) throw Invalid();
            ProductionHoldConsentAuditReferences.Demand(sql, objects); return HoldInitialSignerStage.Queued;
        }
        if (submitted.Length != 1 || tokens.Length != 2 || tokens.Count(x => x.Purpose == TokenPurpose.SenderVerify) != 1 || tail[0] != submitted[0]) throw Invalid();
        var row = submitted[0];
        if (row.EnvelopeId != id || row.ActorType != PartyType.System || row.ActorId is not null || row.ActorEmail is not null || row.Ip is not null || row.UserAgent is not null ||
            row.At.Offset != TimeSpan.Zero || row.At < sent.At || row.At > captured || row.Hash is not { Length: 32 } ||
            !row.Hash.AsSpan().SequenceEqual(AuditHash.Compute(row)) || row.DataJson is not { Length: > 0 and <= 8192 } || Encoding.UTF8.GetByteCount(row.DataJson) > 8192) throw Invalid();
        var proof = JsonSerializer.Deserialize<Submitted>(row.DataJson, Strict) ?? throw Invalid();
        if (JsonSerializer.Serialize(proof) != row.DataJson || proof.emailId != invitationId || proof.tokenId == Guid.Empty || proof.tokenId != payload.LastTokenId ||
            proof.signerId != first.Id || proof.recipient != first.Email || proof.documentSha256 != payload.DocumentSha256 || proof.disclosureSha256 != payload.DisclosureSha256 ||
            proof.meaning != "provider_accepted_not_proof_of_delivery" || !ProviderText(proof.provider) || !ProviderText(proof.providerMessageId) ||
            mail.Provider != proof.provider || mail.ProviderMessageId != proof.providerMessageId || mail.Status != EmailStatus.Sent || mail.Attempts != 1 ||
            mail.SubmissionStartedAt is not { Offset: var offset } at || offset != TimeSpan.Zero || at < sent.At || at > row.At ||
            work.Status != WorkStatus.Completed || work.Attempts != mail.Attempts || work.AvailableAt < row.At || work.AvailableAt > captured) throw Invalid();
        var token = tokens.Single(x => x.Id == proof.tokenId);
        if (token.EnvelopeId != id || token.PartyType != PartyType.Signer || token.PartyId != first.Id || token.Purpose != TokenPurpose.SignerAccess || token.Email != first.Email ||
            token.TokenSha256 is not { Length: 32 } || token.DocumentId != payload.DocumentId || token.DocumentSha256 is not { Length: 32 } sourceHash ||
            token.DisclosureSha256 is not { Length: 32 } disclosureHash || Hex(sourceHash) != proof.documentSha256 || Hex(disclosureHash) != proof.disclosureSha256 ||
            token.SignerContactRevisionId is not null || token.EmailPilotLookupRequestId is not null || token.CompletionPublicationId is not null ||
            token.CompletionRecipeSha256 is not null || token.CompletionPartySha256 is not null || token.Ip is not null ||
            token.ExpiresAt.Offset != TimeSpan.Zero || token.ExpiresAt <= at || token.UsedAt is { } used && used < at ||
            envelope.ExpiresAt is { } deadline && token.ExpiresAt > deadline) throw Invalid();
        var links = tail.Where(x => x.Event == "link_opened").ToArray(); var consents = tail.Where(x => x.Event == "consent_given").ToArray();
        if (links.Length > 1 || consents.Length > 1 || links.Length == 0 && (consents.Length != 0 || token.UsedAt is not null) ||
            links.Length == 1 && (links[0].ActorId != first.Id || links[0].Sequence <= row.Sequence || token.UsedAt is null) ||
            consents.Length == 1 && (consents[0].ActorId != first.Id || consents[0].Sequence <= links.Single().Sequence)) throw Invalid();
        // Existing typed link/consent reader owns canonical shapes, one-use token
        // correspondence, epoch/source/disclosure and saved consent clock/IP/UA.
        ProductionHoldConsentAuditReferences.Demand(sql, objects);
        return consents.Length == 1 ? HoldInitialSignerStage.Consented : links.Length == 1 ? HoldInitialSignerStage.Opened : HoldInitialSignerStage.Dispatched;
    }
    private static bool ProviderText(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static string Hex(byte[]? value) => value is { Length: 32 } ? Convert.ToHexStringLower(value) : throw Invalid();
    private static InvalidDataException Invalid() => new("The closed first invitation dispatch and progress could not be verified.");
}

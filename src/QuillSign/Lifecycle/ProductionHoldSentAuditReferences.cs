using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Complete acceptance of current production Send through its FIRST original
// invitation, one-use opening, consent, prepared marks/adoption and editable
// first-signer fields. Review/Finish and later signers remain separate stages.
internal static class ProductionHoldSentAuditReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 4 };
    private sealed record Sent(string documentSha256, string sourceSha256, string disclosureVersion, string disclosureSha256,
        Guid invitationWorkId, string dispatch, bool exclusionsAcknowledged, Guid? expiryWorkId, DateTimeOffset? signingDeadline,
        string reviewedVersion, bool senderConfirmed, string senderStatementVersion, string senderStatement, string senderStatementSha256,
        string reminderPolicy, string reminderPolicySha256, string reminderSchedulingVersion);
    private static readonly string[] EmptyTables = ["SignerReviewCandidates", "SignerFinishAcceptances", "SignerContactRevisions",
        "SignerContactSessions", "CompletionCandidates", "CompletionSealOutputs", "CompletionPublicationIntents", "CompletionPublicationResults",
        "ProductionRetentionTerminals", "DocumentRetentionSnapshots"];

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
        => _ = ReadVerified(sql, objects, keys);

    internal static IReadOnlyList<HoldVerifiedSignaturePreview> ReadVerified(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
    {
        try { return Verify(sql, objects, keys, true); }
        catch (Exception error) when (error is JsonException or CryptographicException or KeyNotFoundException or InvalidOperationException or
            ArgumentException or FormatException or OverflowException) { throw Invalid(); }
    }

    // Only the connected review codec calls this after validating the ORIGINAL
    // full chain and proving every row removed from its older-stage projection.
    // The projection is never a new SQL capture or a replacement fingerprint.
    internal static IReadOnlyList<HoldVerifiedSignaturePreview> ReadVerifiedReviewProjection(JsonElement projection,
        IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys, JsonElement typedHistory) => Verify(projection, objects, keys, false, typedHistory);

    private static IReadOnlyList<HoldVerifiedSignaturePreview> Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys, bool fullChain, JsonElement? typedHistory = null)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        if (tables.Values.Any(x => x.ValueKind != JsonValueKind.Array || x.GetArrayLength() > 4096) || tables.Values.Sum(x => x.GetArrayLength()) > 4096) throw Invalid();
        var e = tables["Envelopes"].EnumerateArray().Single().Deserialize<Envelope>(Rows) ?? throw Invalid();
        // Draft acceptance belongs to the existing complete Draft registry.
        if (e.Status == EnvelopeStatus.Draft) return [];
        var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        if (e.Status != EnvelopeStatus.Sent || e.IsDemo || e.Id != sql.GetProperty("RecordId").GetGuid() || e.Id == Guid.Empty ||
            !Utc(captured) || !Utc(e.CreatedAt) || !Utc(e.SenderVerifiedAt) || !Utc(e.PreviewConfirmedAt) || !Utc(e.SentAt) ||
            e.CreatedAt > e.SenderVerifiedAt || e.SenderVerifiedAt > e.PreviewConfirmedAt || e.PreviewConfirmedAt > e.SentAt || e.SentAt > captured ||
            !Utc(e.ExclusionsAckAt) || e.ExclusionsAckAt != e.SentAt || e.ExpiresAt is { } expiry && (!Utc(expiry) || expiry <= e.SentAt) ||
            e.CurrentFinishId is not null || e.CurrentCopyVersion != 0 || e.CompletedAt is not null || e.PurgeAfter is not null ||
            e.FinalBlob is not null || e.FinalSha256 is not null || e.CertificateBlob is not null || e.CertificateSha256 is not null ||
            e.SealProvider is not null || e.SealCertThumbprint is not null || e.TsaUrl is not null || EmptyTables.Any(x => tables[x].GetArrayLength() != 0)) throw Invalid();
        if (fullChain) ProductionHoldAuditChain.Demand(sql);
        ProductionHoldAdmissionAuditReferences.Demand(sql);
        var audits = tables["AuditEvents"].Deserialize<AuditEvent[]>(Rows) ?? throw Invalid();
        var sent = audits.Single(x => x.Event == "sent");
        if (sent.DataJson.Length > 16384 || Encoding.UTF8.GetByteCount(sent.DataJson) > 16384) throw Invalid();
        var p = JsonSerializer.Deserialize<Sent>(sent.DataJson, Strict) ?? throw Invalid();
        if (JsonSerializer.Serialize(p) != sent.DataJson || !p.exclusionsAcknowledged || !p.senderConfirmed || p.dispatch != "queued" ||
            p.senderStatementVersion != SenderSendStatement.Version || p.senderStatement != SenderSendStatement.Text || p.senderStatementSha256 != SenderSendStatement.Sha256 ||
            p.disclosureVersion != ProductionRetentionDisclosure.Version || p.disclosureVersion != e.ErsdVersion ||
            p.documentSha256 != Hex(e.SentPdfSha256) || p.sourceSha256 != Hex(e.PdfSha256) || p.disclosureSha256 != Hex(e.ErsdSha256) ||
            p.invitationWorkId == Guid.Empty || p.reminderSchedulingVersion != SignerReminderEvidence.Version ||
            !SignerReminderPolicy.Read(p.reminderPolicy, p.reminderPolicySha256).Days.IsEmpty || !ReviewedVersion(p.reviewedVersion)) throw Invalid();
        if (!ElectronicRecordDisclosure.Verify(new(e.ErsdVersion!, e.PublicId, e.Title!, e.SenderEmail, e.ErsdText!, e.ErsdSha256!))) throw Invalid();
        var policy = tables["ProductionRetentionPolicies"].EnumerateArray().Single().Deserialize<ProductionRetentionPolicyRecord>(Rows) ?? throw Invalid();
        var snapshot = ProductionRetentionPolicyContract.Read(policy.PolicyJson, policy.PolicySha256);
        var enrollment = new VerifiedProductionRetention(snapshot, policy.OriginalCreatedAt, policy.EnrolledAt, policy.AuditSequence, Hex(policy.AuditHash));
        if (e.SentAt >= ProductionRetentionPolicyContract.AddDays(enrollment.OriginalCreatedAt, snapshot.Policy.AbandonedDraftDays) ||
            !e.ErsdText!.EndsWith(ProductionRetentionDisclosure.Notice(enrollment), StringComparison.Ordinal)) throw Invalid();

        if (tables["Signers"].GetArrayLength() is < 1 or > 100 || tables["Recipients"].GetArrayLength() > 100) throw Invalid();
        var signers = tables["Signers"].Deserialize<Signer[]>(Rows) ?? throw Invalid();
        if (signers.Select(x => x.Id).Distinct().Count() != signers.Length || signers.Select(x => x.Email).Distinct(StringComparer.OrdinalIgnoreCase).Count() != signers.Length) throw Invalid();
        var recipients = tables["Recipients"].Deserialize<Recipient[]>(Rows) ?? throw Invalid();
        if (recipients.Select(x => x.Id).Distinct().Count() != recipients.Length || recipients.Select(x => x.Email).Distinct(StringComparer.OrdinalIgnoreCase).Count() != recipients.Length ||
            recipients.Any(x => x.Id == Guid.Empty || x.EnvelopeId != e.Id || !Address(x.Email) || string.IsNullOrWhiteSpace(x.Name) || x.Name.Length > 512 || x.Name.Any(char.IsControl))) throw Invalid();
        signers = signers.OrderBy(x => x.Order).ToArray();
        var marks = typedHistory is { } originalHistory
            ? ProductionHoldSignaturePreviewReferences.ReadVerifiedReviewProjection(sql, originalHistory, objects, keys, p.invitationWorkId)
            : ProductionHoldSignaturePreviewReferences.ReadVerified(sql, objects, keys, p.invitationWorkId);
        var progress = marks.Initial;
        for (var i = 0; i < signers.Length; i++)
        {
            var s = signers[i];
            var consented = i == 0 && progress == HoldInitialSignerStage.Consented;
            var status = i != 0 || progress == HoldInitialSignerStage.Queued ? SignerStatus.Pending : consented ? SignerStatus.Viewed : SignerStatus.Notified;
            if (s.Id == Guid.Empty || s.EnvelopeId != e.Id || s.Order != i + 1 || s.Status != status ||
                !Address(s.Email) || string.IsNullOrWhiteSpace(s.FullName) || s.FullName.Length > 512 || s.FullName.Any(char.IsControl) ||
                !consented && (s.ConsentAt is not null || s.ConsentIp is not null || s.ConsentUa is not null) || s.SignedAt is not null || s.SignedIp is not null || s.SignedUa is not null ||
                s.DeclineReason is not null || !(i == 0 && marks.HasProgress) && (s.SignatureImageBlob is not null || s.InitialsImageBlob is not null || s.SignatureMethod is not null ||
                s.SignatureAdoptionId is not null || s.SignatureImageSha256 is not null || s.InitialsImageSha256 is not null || s.SignatureAdoptedAt is not null ||
                s.SignatureTypedName is not null || s.SignatureTypedInitials is not null || s.SignatureNormalizationVersion is not null || s.SignatureAdoptionVersion is not null)) throw Invalid();
        }
        if (tables["Fields"].GetArrayLength() > 200) throw Invalid();
        var fields = tables["Fields"].Deserialize<DocumentField[]>(Rows) ?? throw Invalid();
        foreach (var f in fields)
            if (f.SignerId is { } signer && (!signers.Any(x => x.Id == signer) || !(marks.HasProgress && signer == signers[0].Id) &&
                    (f.Value is not null || f.FilledAt is not null || f.FilledBy is not null || f.SignatureAdoptionId is not null || f.ImageSha256 is not null)) ||
                f.SignerId is null && (f.Value is null ? f.FilledAt is not null || f.FilledBy is not null :
                    f.FilledBy != PartyType.Sender || !Utc(f.FilledAt) || f.FilledAt < e.PreviewConfirmedAt || f.FilledAt > e.SentAt) ||
                f.SignerId is null && (f.SignatureAdoptionId is not null || f.ImageSha256 is not null)) throw Invalid();
        // Progress uses the actual verified saved preparation, never changed
        // current editable values. The existing codec owns SQL ordering,
        // decimal scale, exact field digest, actor/time/hash and event adjacency.
        ProductionHoldFinalizedFieldReferences.Demand(sql, objects, marks.Prepared ?? fields.Select(f => new FieldInput(f.Id, f.SignerId, f.Type.ToString(),
            f.Page, f.X, f.Y, f.Width, f.Height, f.Required, f.Label, f.Value)).ToArray());
        if (e.PdfBlob == e.SentPdfBlob) throw Invalid();
        Match("originals", e.OriginalBlob, Hex(e.OriginalSha256)); Match("normalized", e.PdfBlob, p.sourceSha256); Match("normalized", e.SentPdfBlob, p.documentSha256);

        if (tables["EmailOutbox"].GetArrayLength() != 2 || tables["WorkItems"].GetArrayLength() != (e.ExpiresAt is null ? 2 : 3)) throw Invalid();
        var mail = tables["EmailOutbox"].Deserialize<EmailOutbox[]>(Rows) ?? throw Invalid();
        var work = tables["WorkItems"].Deserialize<WorkItem[]>(Rows) ?? throw Invalid();
        if (mail.Select(x => x.Id).Distinct().Count() != mail.Length || work.Select(x => x.Id).Distinct().Count() != work.Length ||
            mail.Any(x => x.EnvelopeId != e.Id) || work.Any(x => x.EnvelopeId != e.Id)) throw Invalid();
        var invitation = mail.Single(x => x.Id == p.invitationWorkId);
        if (invitation.Template != "signer-invitation" || invitation.To != signers[0].Email || invitation.AttachmentsJson != "[]" ||
            invitation.LastError is not null || invitation.LeaseOwner is not null || invitation.LeaseExpiresAt is not null ||
            !Utc(invitation.AvailableAt) || invitation.AvailableAt < e.SentAt || invitation.AvailableAt > sent.At ||
            invitation.PayloadJson is not { Length: > 0 and <= 12000 } || Encoding.UTF8.GetByteCount(invitation.PayloadJson) > 12000) throw Invalid();
        var wrapped = JsonSerializer.Deserialize<ProtectedWorkPayload>(invitation.PayloadJson, Strict) ?? throw Invalid();
        var payload = new SignerInvitationProtection(keys).Read(invitation.PayloadJson);
        if (JsonSerializer.Serialize(wrapped) != invitation.PayloadJson ||
            keys.CreateProtector("QuillSign.SignerInvitationPayload.v1").Unprotect(wrapped.Protected) != JsonSerializer.Serialize(payload) ||
            payload.SignerId != signers[0].Id || payload.ContactRevisionId != Guid.Empty || payload.ContactRevisionNumber != 0 ||
            payload.DocumentId.ToString("N") != e.SentPdfBlob || payload.DocumentSha256 != p.documentSha256 || payload.DisclosureSha256 != p.disclosureSha256) throw Invalid();
        var verification = mail.Single(x => x.Id != invitation.Id);
        var verificationWork = work.Single(x => x.Id == verification.Id);
        if (verification.Id == Guid.Empty || verification.Template != "sender-verification" || verification.Status != EmailStatus.Sent || verification.To != e.SenderEmail ||
            verification.Attempts < 1 || verification.SubmissionStartedAt is not { } started || !Utc(started) || started < e.CreatedAt || started > e.SenderVerifiedAt ||
            !Utc(verification.AvailableAt) || verification.AvailableAt < e.CreatedAt || verification.AvailableAt > started ||
            verification.LeaseOwner is not null || verification.LeaseExpiresAt is not null || verification.LastError is not null ||
            string.IsNullOrWhiteSpace(verification.Provider) || string.IsNullOrWhiteSpace(verification.ProviderMessageId) ||
            verificationWork.Kind != WorkKind.Email || verificationWork.Status != WorkStatus.Completed || verificationWork.Attempts != verification.Attempts ||
            !Utc(verificationWork.AvailableAt) || verificationWork.AvailableAt < started || verificationWork.AvailableAt > e.SenderVerifiedAt ||
            verificationWork.LeaseOwner is not null || verificationWork.LeaseExpiresAt is not null || verificationWork.LastError is not null ||
            verificationWork.PayloadJson != JsonSerializer.Serialize(new { emailId = verification.Id })) throw Invalid();
        ProductionHoldDecisionNotificationReferences.Demand(sql, objects, keys);
        var token = tables["AuthTokens"].EnumerateArray().Single(x => x.GetProperty("Purpose").GetString() == nameof(TokenPurpose.SenderVerify)).Deserialize<AuthToken>(Rows) ?? throw Invalid();
        if (token.Purpose != TokenPurpose.SenderVerify || token.UsedAt != e.SenderVerifiedAt) throw Invalid();
        if (e.ExpiresAt is { } deadline)
        {
            var id = SigningExpiryJobs.WorkId(e.Id);
            if (p.expiryWorkId != id || p.signingDeadline != deadline || !Utc(p.signingDeadline)) throw Invalid();
            DemandQueued(work.Single(x => x.Id == id), WorkKind.Expiry, deadline, SigningExpiryJobs.Bind(e));
        }
        else if (p.expiryWorkId is not null || p.signingDeadline is not null) throw Invalid();
        return marks.Previews;

        void Match(string area, string? raw, string hash)
        {
            if (!Guid.TryParseExact(raw, "N", out var id) || id == Guid.Empty || !objects.Any(x => x.Address.Area == area &&
                x.Address.Name == $"{e.Id:N}/{id:N}" && x.Address.Length > 0 && x.Sha256 == hash)) throw Invalid();
        }
    }

    private static void DemandQueued(WorkItem row, WorkKind kind, DateTimeOffset due, string payload)
    {
        if (row.Id == Guid.Empty || row.Kind != kind || row.Status != WorkStatus.Queued || row.Attempts != 0 || row.LeaseOwner is not null ||
            row.LeaseExpiresAt is not null || row.LastError is not null || row.AvailableAt != due || !Utc(row.AvailableAt) || row.PayloadJson != payload) throw Invalid();
    }
    private static bool ReviewedVersion(string value)
    {
        Span<byte> bytes = stackalloc byte[8];
        return value is { Length: 12 } && Convert.TryFromBase64String(value, bytes, out var count) && count == 8 && Convert.ToBase64String(bytes) == value;
    }
    private static bool Utc(DateTimeOffset? at) => at is { Offset: var offset } && offset == TimeSpan.Zero;
    private static bool Address(string value) { try { return EmailAddress.Normalize(value) == value; } catch (ArgumentException) { return false; } }
    private static string Hex(byte[]? value) => value is { Length: 32 } ? Convert.ToHexStringLower(value) : throw Invalid();
    private static InvalidDataException Invalid() => new("The closed initial production Send evidence could not be verified.");
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Historical notification references, not a download/session capability or a
// complete publication/audit-chain verification service.
internal static class ProductionHoldCompletionNotificationReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { MaxDepth = 16, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private sealed record Documents(FinalStoredDocument Executed, FinalStoredDocument Certificate);

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
    {
        try { Verify(sql, objects, keys); }
        catch (Exception error) when (error is CryptographicException or JsonException or KeyNotFoundException or InvalidOperationException or
            ArgumentException or FormatException or NullReferenceException)
        { throw Invalid(); }
    }

    private static void Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        JsonElement[] Table(string name) => tables[name].EnumerateArray().ToArray();
        T Row<T>(JsonElement row) => row.Deserialize<T>(Rows) ?? throw Invalid();
        var selected = Table("EmailOutbox").Where(x => x.GetProperty("Template").GetString() == CompletionNotificationJobs.Template).ToArray();
        if (selected.Length == 0) return;
        var id = sql.GetProperty("RecordId").GetGuid();
        if (id == Guid.Empty || selected.Length > 201) throw Invalid();
        var envelope = Row<Envelope>(Table("Envelopes").Single());
        var result = Row<CompletionPublicationResult>(Table("CompletionPublicationResults").Single());
        var intent = Row<CompletionPublicationIntent>(Table("CompletionPublicationIntents").Single());
        if (envelope.Id != id || envelope.Status != EnvelopeStatus.Completed || result.Id == Guid.Empty || result.EnvelopeId != id ||
            intent.Id == Guid.Empty || intent.EnvelopeId != id || result.IntentId != intent.Id || result.RowVersion is not { Length: 8 } ||
            result.AuditSequence is < 1 or > 512 || result.CompletedAt.Offset != TimeSpan.Zero || intent.PreparedAt.Offset != TimeSpan.Zero ||
            result.CompletedAt < intent.PreparedAt || envelope.CompletedAt != result.CompletedAt || !Bounded(result.FinalDocumentsJson, 16384) ||
            !Bounded(intent.BeforeEnvelopeJson, 262144) || !Bounded(intent.StageBindingsJson, 16384) ||
            !Same(intent.RecipeSha256, CompletionPublication.Recipe(intent)) || !Same(result.IntentRecipeSha256, intent.RecipeSha256) ||
            !Same(result.RecipeSha256, CompletionPublication.Recipe(result))) throw Invalid();
        var before = Canonical<Envelope>(intent.BeforeEnvelopeJson);
        if (before.Id != id || before.Status != EnvelopeStatus.Sent || before.SenderEmail != envelope.SenderEmail || before.IsDemo != envelope.IsDemo ||
            new PublishedCompletionSource(intent.BeforeEnvelopeJson, result.AfterEnvelopeSha256, result.AuditSequence).Project(envelope).Id != id) throw Invalid();
        var documents = Canonical<Documents>(result.FinalDocumentsJson);
        Match(documents.Executed, FinalDocumentKind.Executed, intent.ExecutedObjectId);
        Match(documents.Certificate, FinalDocumentKind.Certificate, intent.CertificateObjectId);
        if (intent.ExecutedObjectId == intent.CertificateObjectId || envelope.FinalBlob != intent.ExecutedObjectId.ToString("N") ||
            envelope.CertificateBlob != intent.CertificateObjectId.ToString("N") || !Same(envelope.FinalSha256, documents.Executed.Sha256) ||
            !Same(envelope.CertificateSha256, documents.Certificate.Sha256)) throw Invalid();
        var audits = Table("AuditEvents").Select(Row<AuditEvent>).ToArray();
        var prepared = Proof("completion_publication_prepared", CompletionPublication.Evidence(intent));
        var completed = Proof("completed", CompletionPublication.Evidence(result));
        if (prepared.At < intent.PreparedAt || completed.At < result.CompletedAt || prepared.Sequence >= completed.Sequence || completed.Sequence != result.AuditSequence) throw Invalid();

        foreach (var encoded in selected)
        {
            var row = Row<EmailOutbox>(encoded);
            if (row.EnvelopeId != id || row.Id == Guid.Empty || row.AttachmentsJson != "[]" || !Enum.IsDefined(row.Status) || row.Attempts < 0 ||
                EmailAddress.Normalize(row.To) != row.To || !Bounded(row.PayloadJson, 8192)) throw Invalid();
            var wrapper = Canonical<ProtectedWorkPayload>(row.PayloadJson);
            var payload = new CompletionNotificationProtection(keys).Read(row.PayloadJson);
            var plain = keys.CreateProtector("QuillSign.CompletionNotification.v1").Unprotect(wrapper.Protected);
            if (!Bounded(plain, 8192) || plain != JsonSerializer.Serialize(payload) || CompletionNotificationJobs.Id(payload) != row.Id ||
                payload.EnvelopeId != id || payload.PublicationId != result.Id || payload.Recipe != Hex(result.RecipeSha256) ||
                payload.Revision != Convert.ToBase64String(result.RowVersion) || payload.IsDemo != envelope.IsDemo ||
                payload.ExecutedReference != Hex(DownloadPublication.Reference(documents.Executed)) ||
                payload.CertificateReference != Hex(DownloadPublication.Reference(documents.Certificate))) throw Invalid();
            string email; string? name; int? order = null;
            if (payload.Party == PartyType.Sender) { email = envelope.SenderEmail; name = envelope.SenderName; }
            else if (payload.Party == PartyType.Signer)
            {
                var signer = Row<Signer>(Table("Signers").Single(x => x.GetProperty("Id").GetGuid() == payload.PartyId));
                if (signer.EnvelopeId != id || signer.Status != SignerStatus.Signed) throw Invalid();
                email = signer.Email; name = signer.FullName; order = signer.Order;
            }
            else
            {
                var recipient = Row<Recipient>(Table("Recipients").Single(x => x.GetProperty("Id").GetGuid() == payload.PartyId));
                if (recipient.EnvelopeId != id) throw Invalid(); email = recipient.Email; name = recipient.Name;
            }
            var membership = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { version = CompletionAccessProtection.Version,
                EnvelopeId = id, publicationId = result.Id, publicationRevision = result.RowVersion, type = payload.Party, id = payload.PartyId, name, email, order }));
            if (email != row.To || Hex(membership) != payload.PartyHash) throw Invalid();
            var queue = Proof("completion_notification_queued", CompletionNotificationJobs.Queued(row.Id, row.To, payload), row.Id);
            if (queue.Sequence <= completed.Sequence || queue.At < completed.At) throw Invalid();
            if (payload.LastTokenId is Guid tokenId)
            {
                var token = Row<AuthToken>(Table("AuthTokens").Single(x => x.GetProperty("Id").GetGuid() == tokenId));
                if (token.EnvelopeId != id || token.Purpose != TokenPurpose.CompletionAccess || token.PartyType != payload.Party || token.PartyId != payload.PartyId ||
                    token.Email != row.To || token.CompletionPublicationId != result.Id || !Same(token.CompletionRecipeSha256, result.RecipeSha256) ||
                    !Same(token.CompletionPartySha256, membership) || token.TokenSha256 is not { Length: 32 } || token.DocumentId is not null ||
                    token.DocumentSha256 is not null || token.DisclosureSha256 is not null || token.SignerContactRevisionId is not null || token.EmailPilotLookupRequestId is not null) throw Invalid();
            }
            else if (row.SubmissionStartedAt is not null || row.Status is EmailStatus.Sent or EmailStatus.Bounced or EmailStatus.Complained) throw Invalid();
        }

        void Match(FinalStoredDocument value, FinalDocumentKind kind, Guid target)
        {
            if (value.Document.EnvelopeId != id || value.Document.Kind != kind || target == Guid.Empty || value.Document.ObjectId != target ||
                value.Length is < 1 or > 64 * 1024 * 1024 || value.Sha256 is not { Length: 32 } || string.IsNullOrEmpty(value.VersionId) || string.IsNullOrEmpty(value.ETag) ||
                !Enum.IsDefined(value.Protection) || value.CreatedAt == default || value.CreatedAt.Offset != TimeSpan.Zero || value.CreatedAt > result.CompletedAt.AddMinutes(1) ||
                value.Protection != FinalProtection.LockedTime && value.ProtectedUntil is not null ||
                value.Protection == FinalProtection.LockedTime && (value.ProtectedUntil is null || value.ProtectedUntil.Value.Offset != TimeSpan.Zero || value.ProtectedUntil <= result.CompletedAt) ||
                value.Protection == FinalProtection.DevelopmentWriteOnce && (!envelope.IsDemo || !intent.DevelopmentWriteOnce) ||
                !objects.Any(x => x.Address.Area == "final" && x.Address.Name == $"{id:N}/{kind.ToString().ToLowerInvariant()}/{target:N}" &&
                    x.Address.VersionId == value.VersionId && x.Address.Snapshot == "" && x.Address.ETag == value.ETag && x.Address.Length == value.Length && x.Sha256 == Hex(value.Sha256))) throw Invalid();
        }
        AuditEvent Proof(string kind, string expected, Guid? notification = null)
        {
            var candidates = audits.Where(x => x.Event == kind).Where(x => notification is null || Notification(x.DataJson) == notification).ToArray();
            if (candidates.Length != 1) throw Invalid(); var value = candidates[0];
            if (value.Id < 1 || value.EnvelopeId != id || value.Sequence < 1 || value.At == default || value.At.Offset != TimeSpan.Zero ||
                value.ActorType != PartyType.System || value.ActorId is not null || value.ActorEmail is not null || value.Ip is not null || value.UserAgent is not null ||
                value.DataJson != expected || (value.Sequence == 1) != (value.PrevHash is null) || value.PrevHash is { Length: not 32 } || !Same(value.Hash, AuditHash.Compute(value))) throw Invalid();
            return value;
        }
    }

    private static Guid Notification(string raw)
    {
        if (!Bounded(raw, 16384)) throw Invalid();
        using var json = JsonDocument.Parse(raw, new() { MaxDepth = 8 });
        return json.RootElement.GetProperty("notificationId").GetGuid();
    }
    private static T Canonical<T>(string raw)
    {
        var value = JsonSerializer.Deserialize<T>(raw, Strict) ?? throw Invalid();
        return JsonSerializer.Serialize(value) == raw ? value : throw Invalid();
    }
    private static bool Bounded(string? raw, int maximum) => raw is { Length: > 0 } && raw.Length <= maximum && Encoding.UTF8.GetByteCount(raw) <= maximum;
    private static bool Same(byte[]? left, byte[]? right) => left is { Length: 32 } && right is { Length: 32 } && left.AsSpan().SequenceEqual(right);
    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    private static InvalidDataException Invalid() => new("Protected historical completion notification evidence could not be verified.");
}

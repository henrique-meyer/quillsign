using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Historical reference validation only. Full Finish/audit graph verification and
// the effective hold lifecycle remain separate; this grants no live authority.
internal static class ProductionHoldVoidNotificationReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { MaxDepth = 8, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };

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
        T[] Table<T>(string name) => tables[name].Deserialize<T[]>(Rows) ?? throw Invalid();
        var selected = Table<EmailOutbox>("EmailOutbox").Where(x => x.Template == VoidNotificationJobs.Template).ToArray();
        if (selected.Length == 0) return;
        var id = sql.GetProperty("RecordId").GetGuid(); var e = Table<Envelope>("Envelopes").Single();
        if (id == Guid.Empty || e.Id != id || selected.Length > 101 || e.Status != EnvelopeStatus.Voided || e.RowVersion is not { Length: 8 } ||
            e.SentAt is null || e.SentAt.Value.Offset != TimeSpan.Zero || e.SenderVerifiedAt is null || e.SenderVerifiedAt > e.SentAt ||
            e.CompletedAt is not null || e.FinalBlob is not null || e.CertificateBlob is not null ||
            !Guid.TryParseExact(e.SentPdfBlob, "N", out var sent) || sent == Guid.Empty || e.SentPdfSha256 is not { Length: 32 } || e.ErsdSha256 is not { Length: 32 } ||
            EmailAddress.Normalize(e.SenderEmail) != e.SenderEmail) throw Invalid();
        var audits = Table<AuditEvent>("AuditEvents"); var action = audits.Single(x => x.Event == "voided");
        Audit(action);
        if (action.ActorType != PartyType.Sender || action.ActorId is not null || action.ActorEmail != e.SenderEmail || action.Sequence < 2 ||
            !Bounded(action.DataJson, 16384)) throw Invalid();
        var saved = Canonical<SenderVoidEvidence>(action.DataJson);
        var previous = audits.Single(x => x.Sequence == action.Sequence - 1); Audit(previous);
        if (previous.At > action.At || !Same(previous.Hash, action.PrevHash) || !Revision(saved.ReviewedVersion) ||
            saved.VoidedAt.Offset != TimeSpan.Zero || saved.VoidedAt < e.SentAt || saved.VoidedAt > action.At || e.ExpiresAt <= saved.VoidedAt ||
            !SenderVoidState.Reason(saved.Reason, out var reason) || reason != saved.Reason) throw Invalid();
        var signers = Table<Signer>("Signers").OrderBy(x => x.Order).ToArray();
        // SQL ORDER BY uniqueidentifier differs from Guid.CompareTo. Keep the
        // runtime roster's original SQL ordering when verifying its digest.
        var recipients = Table<Recipient>("Recipients").OrderBy(x => new SqlGuid(x.Id)).ToArray();
        if (signers.Length is < 1 or > 100 || recipients.Length > 100 ||
            signers.Where((x, i) => x.Order != i + 1 || x.Id == Guid.Empty || x.EnvelopeId != id || !Enum.IsDefined(x.Status) || x.Status == SignerStatus.Declined).Any() ||
            signers.Select(x => x.Id).Distinct().Count() != signers.Length || recipients.Any(x => x.Id == Guid.Empty || x.EnvelopeId != id) ||
            recipients.Select(x => x.Id).Distinct().Count() != recipients.Length) throw Invalid();
        foreach (var address in signers.Select(x => x.Email).Concat(recipients.Select(x => x.Email)))
            if (EmailAddress.Normalize(address) != address) throw Invalid();
        var signed = signers.TakeWhile(x => x.Status == SignerStatus.Signed).ToArray();
        if (signers.Skip(signed.Length).Any(x => x.Status == SignerStatus.Signed)) throw Invalid();
        var finishes = Table<SignerFinishAcceptance>("SignerFinishAcceptances").Where(x => x.ProcessedAt is not null).ToArray();
        if (finishes.Length != signed.Length) throw Invalid();
        var current = sent; var hash = e.SentPdfSha256; Guid? finishId = null;
        foreach (var signer in signed)
        {
            var finish = finishes.Single(x => x.SignerId == signer.Id);
            if (finish.Id == Guid.Empty || finish.EnvelopeId != id || finish.SourceObjectId != current || !Same(finish.SourceSha256, hash) ||
                !Same(finish.DisclosureSha256, e.ErsdSha256) || finish.PdfObjectId == Guid.Empty || finish.PdfSha256 is not { Length: 32 } ||
                signer.SignedAt != finish.FinishedAt || finish.ProcessedAt > saved.VoidedAt || finish.FinishedAt > finish.ProcessedAt) throw Invalid();
            current = finish.PdfObjectId; hash = finish.PdfSha256; finishId = finish.Id;
        }
        var source = new SignerCurrentSource(current, hash, signed.Length, finishId);
        if (e.CurrentCopyVersion != signed.Length || e.CurrentFinishId != finishId ||
            action.DataJson != JsonSerializer.Serialize(SenderVoidState.Bind(e, source, saved.ReviewedVersion, reason, saved.VoidedAt))) throw Invalid();
        Match(sent, e.SentPdfSha256); Match(current, hash);
        var roster = Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { e.SenderName, e.SenderEmail,
            signers = signers.Select(x => new { x.Id, x.Order, x.FullName, x.Email, x.Role }), recipients = recipients.Select(x => new { x.Id, x.Name, x.Email }) })));
        var members = new List<(PartyType Type, Guid? Id, string? Name, string Email, string? Role, int? Order)> { (PartyType.Sender, null, e.SenderName, e.SenderEmail, null, null) };
        members.AddRange(signers.Select(x => (PartyType.Signer, (Guid?)x.Id, (string?)x.FullName, x.Email, x.Role, (int?)x.Order)));
        var destinations = members.GroupBy(x => x.Email, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).ToArray();
        foreach (var row in selected)
        {
            if (row.Id == Guid.Empty || row.EnvelopeId != id || row.AttachmentsJson != "[]" || !Enum.IsDefined(row.Status) || row.Attempts < 0 ||
                EmailAddress.Normalize(row.To) != row.To || !Bounded(row.PayloadJson, 8192)) throw Invalid();
            var wrapper = Canonical<ProtectedWorkPayload>(row.PayloadJson);
            var payload = new VoidNotificationProtection(keys).Read(row.PayloadJson);
            var plain = keys.CreateProtector("QuillSign.VoidNotification.v1").Unprotect(wrapper.Protected);
            if (!Bounded(plain, 8192) || JsonSerializer.Serialize(payload) != plain || VoidNotificationJobs.Id(payload) != row.Id || payload.EnvelopeId != id ||
                payload.VoidAuditId != action.Id || payload.VoidHash != Hex(action.Hash) || payload.Revision != Convert.ToBase64String(e.RowVersion) ||
                payload.RosterHash != roster || payload.IsDemo != e.IsDemo) throw Invalid();
            var member = destinations.Single(x => x.Type == payload.Party && x.Id == payload.PartyId && x.Email == row.To);
            var type = member.Type; var memberId = member.Id; var name = member.Name; var email = member.Email; var role = member.Role; var order = member.Order;
            var memberHash = Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { version = VoidNotificationJobs.Version, envelopeId = id,
                voidAuditId = action.Id, voidHash = Hex(action.Hash), type, id = memberId, name, email, role, order })));
            if (memberHash != payload.PartyHash) throw Invalid();
            var queued = audits.Where(x => x.Event == "void_notification_queued" && Notification(x.DataJson) == row.Id).Single(); Audit(queued);
            if (queued.ActorType != PartyType.System || queued.ActorId is not null || queued.ActorEmail is not null || queued.Ip is not null || queued.UserAgent is not null ||
                queued.Sequence <= action.Sequence || queued.At < action.At || queued.DataJson != VoidNotificationJobs.Queued(row.Id, row.To, payload)) throw Invalid();
        }

        void Match(Guid objectId, byte[] digest)
        {
            if (!objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == $"{id:N}/{objectId:N}" && x.Sha256 == Hex(digest))) throw Invalid();
        }
        void Audit(AuditEvent value)
        {
            if (value.Id < 1 || value.EnvelopeId != id || value.Sequence < 1 || value.At == default || value.At.Offset != TimeSpan.Zero || !Enum.IsDefined(value.ActorType) ||
                (value.Sequence == 1) != (value.PrevHash is null) || value.PrevHash is { Length: not 32 } || !Same(value.Hash, AuditHash.Compute(value))) throw Invalid();
        }
    }

    private static Guid Notification(string raw)
    {
        if (!Bounded(raw, 16384)) throw Invalid(); using var json = JsonDocument.Parse(raw, new() { MaxDepth = 8 });
        return json.RootElement.GetProperty("notificationId").GetGuid();
    }
    private static T Canonical<T>(string raw)
    {
        var value = JsonSerializer.Deserialize<T>(raw, Strict) ?? throw Invalid(); return JsonSerializer.Serialize(value) == raw ? value : throw Invalid();
    }
    private static bool Revision(string? value) => value is not null && Convert.FromBase64String(value) is { Length: 8 } bytes && Convert.ToBase64String(bytes) == value;
    private static bool Same(byte[]? left, byte[]? right) => left is { Length: 32 } && right is { Length: 32 } && left.AsSpan().SequenceEqual(right);
    private static bool Bounded(string? raw, int maximum) => raw is { Length: > 0 } && raw.Length <= maximum && Encoding.UTF8.GetByteCount(raw) <= maximum;
    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    private static InvalidDataException Invalid() => new("Protected historical void notification evidence could not be verified.");
}

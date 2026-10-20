using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Historical invitation references only. Other protected notifications and audit
// payloads still require their separate coverage before complete preservation.
internal static class ProductionHoldInvitationReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions History = new(JsonSerializerDefaults.Web) { MaxDepth = 4 };

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
    {
        try { Verify(sql, objects, keys); }
        catch (Exception error) when (error is CryptographicException or JsonException or KeyNotFoundException or
            InvalidOperationException or ArgumentException or FormatException)
        { throw Invalid(); }
    }

    private static void Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
    {
        var id = sql.GetProperty("RecordId").GetGuid();
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        var selected = tables["EmailOutbox"].EnumerateArray().Where(x => x.GetProperty("Template").GetString() is
            "signer-invitation" or InvitationResendProtection.Template or InvitationSuccessorProtection.Template).ToArray();
        if (selected.Length == 0) return;
        if (id == Guid.Empty || selected.Length > 4096) throw Invalid();
        var envelope = tables["Envelopes"].EnumerateArray().Single();
        if (envelope.GetProperty("Id").GetGuid() != id) throw Invalid();
        var disclosure = envelope.GetProperty("ErsdSha256").GetBytesFromBase64();
        if (disclosure.Length != 32) throw Invalid();
        var parties = tables["Signers"].EnumerateArray().ToDictionary(x => x.GetProperty("Id").GetGuid(), x => {
            if (x.GetProperty("EnvelopeId").GetGuid() != id) throw Invalid();
            return new HashSet<string>(StringComparer.Ordinal) { x.GetProperty("Email").GetString()! };
        });
        var revisions = new List<SignerContactRevision>();
        foreach (var row in tables["SignerContactRevisions"].EnumerateArray())
        {
            var raw = row.GetProperty("EvidenceJson").GetString();
            if (raw is null || raw.Length > 8192 || Encoding.UTF8.GetByteCount(raw) > 8192) throw Invalid();
            var revision = JsonSerializer.Deserialize<SignerContactRevision>(raw, History) ?? throw Invalid();
            if (SignerContactHistory.Canonical(revision) != raw || revision.EnvelopeId != id ||
                row.GetProperty("EnvelopeId").GetGuid() != id || row.GetProperty("SignerId").GetGuid() != revision.SignerId ||
                row.GetProperty("Id").GetGuid() != revision.Id || row.GetProperty("Number").GetInt32() != revision.Number ||
                !parties.TryGetValue(revision.SignerId, out var addresses)) throw Invalid();
            addresses.Add(revision.OldEmail); addresses.Add(revision.NewEmail);
            revisions.Add(revision);
        }
        var epochs = new Dictionary<(Guid, Guid, int), string>();
        foreach (var signer in tables["Signers"].EnumerateArray())
        {
            var signerId = signer.GetProperty("Id").GetGuid(); var current = signer.GetProperty("Email").GetString()!;
            var history = revisions.Where(x => x.SignerId == signerId).OrderBy(x => x.Number).ToArray();
            if (history.Length > SignerContactHistory.MaximumCorrections) throw Invalid();
            var address = history.FirstOrDefault()?.OldEmail ?? current; var previous = Guid.Empty; var number = 0;
            epochs.Add((signerId, previous, number), address);
            foreach (var revision in history)
            {
                if (revision.Number != ++number || revision.PreviousRevisionId != previous || revision.OldEmail != address) throw Invalid();
                address = revision.NewEmail; previous = revision.Id;
                epochs.Add((signerId, previous, number), address);
            }
            if (address != current) throw Invalid();
        }
        foreach (var encoded in selected)
        {
            var payload = encoded.GetProperty("PayloadJson").GetString();
            if (payload is null || payload.Length is < 1 or > 12000 || Encoding.UTF8.GetByteCount(payload) > 12000) throw Invalid();
            var row = encoded.Deserialize<EmailOutbox>(Rows) ?? throw Invalid();
            if (row.Id == Guid.Empty || row.EnvelopeId != id || row.AttachmentsJson != "[]" ||
                !Enum.IsDefined(row.Status) || row.Attempts < 0 || EmailAddress.Normalize(row.To) != row.To) throw Invalid();
            Guid signer; Guid document; string? hash; string? disclosureHash;
            switch (row.Template)
            {
                case "signer-invitation":
                    var initial = new SignerInvitationProtection(keys).Read(payload);
                    if (initial.LastTokenId == Guid.Empty || initial.ContactRevisionNumber is < 0 or > SignerContactHistory.MaximumCorrections ||
                        (initial.ContactRevisionNumber == 0) != (initial.ContactRevisionId == Guid.Empty) ||
                        !epochs.TryGetValue((initial.SignerId, initial.ContactRevisionId, initial.ContactRevisionNumber), out var initialAddress) ||
                        initialAddress != row.To) throw Invalid();
                    (signer, document, hash, disclosureHash) = (initial.SignerId, initial.DocumentId, initial.DocumentSha256, initial.DisclosureSha256);
                    break;
                case InvitationResendProtection.Template:
                    var resend = new InvitationResendProtection(keys).Read(row).Request;
                    if (resend.SenderEmail != envelope.GetProperty("SenderEmail").GetString()) throw Invalid();
                    (signer, document, hash, disclosureHash) = (resend.SignerId, resend.DocumentId, resend.DocumentSha256, resend.DisclosureSha256);
                    break;
                default:
                    var successor = new InvitationSuccessorProtection(keys).Read(row).Scope;
                    if (successor.SenderEmail != envelope.GetProperty("SenderEmail").GetString() ||
                        !epochs.TryGetValue((successor.SignerId, successor.Contact.RevisionId, successor.Contact.Number), out var successorAddress) ||
                        successorAddress != row.To) throw Invalid();
                    (signer, document, hash, disclosureHash) = (successor.SignerId, successor.DocumentId, successor.DocumentSha256, successor.DisclosureSha256);
                    break;
            }
            if (signer == Guid.Empty || document == Guid.Empty || !parties.TryGetValue(signer, out var known) || !known.Contains(row.To) ||
                hash is not { Length: 64 } || !hash.All(char.IsAsciiHexDigitLower) ||
                disclosureHash != Convert.ToHexStringLower(disclosure) || !objects.Any(x => x.Address.Area == "normalized" &&
                    x.Address.Name == $"{id:N}/{document:N}" && x.Sha256 == hash)) throw Invalid();
        }
    }

    private static InvalidDataException Invalid() => new("Protected historical invitation evidence could not be verified.");
}

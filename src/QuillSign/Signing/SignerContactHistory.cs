using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Signing;

public sealed record SignerContactEpoch(Guid RevisionId, int Number)
{
    public static SignerContactEpoch Legacy { get; } = new(Guid.Empty, 0);
}
public sealed record SignerContactParty(Guid Id, int Order, string Name, string Email, string? Role, SignerContactEpoch Epoch);
public sealed record SignerContactScope(Guid EnvelopeId, string SenderEmail, long SentSequence, DateTimeOffset SentAt, DateTimeOffset Now);
public sealed record SignerContactRevision(string Version, Guid Id, Guid EnvelopeId, Guid SignerId, Guid PreviousRevisionId,
    int Number, string OldEmail, string NewEmail, DateTimeOffset ChangedAt, DateTimeOffset SenderTicketExpiresAt,
    string ReviewedEnvelopeVersion, string ReviewedSignerVersion, Guid DocumentId, string DocumentSha256,
    string DisclosureSha256, string RetirementSha256, string? PreviousCorrectionSha256, string StatementVersion, string StatementSha256);

// An integrity contract for future correction integration, not an admission or authorization
// service. The caller must authenticate the sender, verify the complete audit chain and
// original roster, lock current immutable/revision evidence, and check Finish/retention.
// No existing signer identity, session bytes, database model or runtime path uses this yet.
public static class SignerContactHistory
{
    public const string Event = "signer_contact_corrected";
    public const string Version = "signer-contact-revision-v1";
    public const string StatementVersion = "signer-contact-correction-v1";
    public const string Statement = "Correct the email address for this same named signer. Revoke prior access and discard unfinished entries. The corrected mailbox must consent and sign again. Previously read information and submitted email cannot be recalled.";
    public static string StatementSha256 => Hex(SHA256.HashData(Encoding.UTF8.GetBytes(Statement)));
    public const int MaximumCorrections = 100;
    private const int MaximumDataBytes = 8192;
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, MaxDepth = 4,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static string Canonical(SignerContactRevision revision)
    {
        Validate(revision);
        var text = JsonSerializer.Serialize(revision, Json);
        if (Encoding.UTF8.GetByteCount(text) > MaximumDataBytes) throw Invalid();
        return text;
    }
    public static string Digest(SignerContactRevision revision) => Hex(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(revision))));

    // Current projection includes the latest persisted epoch even when its address equals
    // the original address. Otherwise deletion of an A -> B -> A history could look legacy.
    public static IReadOnlyList<SignerContactParty> Verify(SignerContactScope scope,
        IReadOnlyList<SignerContactParty> original, IReadOnlyList<AuditEvent> corrections,
        IReadOnlyList<SignerContactParty> current)
    {
        if (scope is null || scope.EnvelopeId == Guid.Empty || !Address(scope.SenderEmail) || scope.SentSequence < 1 ||
            !Utc(scope.SentAt) || !Utc(scope.Now) || scope.Now < scope.SentAt || original is null || current is null || corrections is null ||
            original.Count is < 1 or > 100 || current.Count != original.Count || corrections.Count > MaximumCorrections) throw Invalid();
        var folded = original.ToArray();
        if (folded.Where((x, i) => !Party(x) || x.Order != i + 1 || x.Epoch != SignerContactEpoch.Legacy).Any() ||
            folded.Select(x => x.Id).Distinct().Count() != folded.Length || folded.Select(x => x.Email).Distinct().Count() != folded.Length) throw Invalid();
        var revisions = new HashSet<Guid>(); var hashes = new Dictionary<Guid, string>();
        var lastSequence = scope.SentSequence; var lastAt = scope.SentAt;
        foreach (var entry in corrections)
        {
            if (entry is null || entry.EnvelopeId != scope.EnvelopeId || entry.Event != Event || entry.ActorType != PartyType.Sender ||
                entry.ActorId is not null || entry.ActorEmail != scope.SenderEmail || entry.Sequence <= lastSequence ||
                !Utc(entry.At) || entry.At < lastAt || entry.At > scope.Now || entry.DataJson is null || entry.DataJson.Length > MaximumDataBytes ||
                Encoding.UTF8.GetByteCount(entry.DataJson) > MaximumDataBytes || entry.Hash is not { Length: 32 } ||
                entry.PrevHash is not null and not { Length: 32 }) throw Invalid();
            SignerContactRevision revision;
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(AuditHash.Compute(entry), entry.Hash)) throw Invalid();
                revision = JsonSerializer.Deserialize<SignerContactRevision>(entry.DataJson, Json) ?? throw Invalid();
            }
            catch (JsonException) { throw Invalid(); }
            if (entry.DataJson != Canonical(revision) || revision.EnvelopeId != scope.EnvelopeId || revision.ChangedAt != entry.At ||
                revision.ChangedAt.Offset != entry.At.Offset || !revisions.Add(revision.Id)) throw Invalid();
            var index = Array.FindIndex(folded, x => x.Id == revision.SignerId);
            if (index < 0) throw Invalid();
            var previous = folded[index];
            if (revision.PreviousRevisionId != previous.Epoch.RevisionId || revision.Number != previous.Epoch.Number + 1 ||
                revision.OldEmail != previous.Email || revision.PreviousCorrectionSha256 != hashes.GetValueOrDefault(previous.Id) ||
                folded.Any(x => x.Id != previous.Id && x.Email == revision.NewEmail)) throw Invalid();
            folded[index] = previous with { Email = revision.NewEmail, Epoch = new(revision.Id, revision.Number) };
            hashes[previous.Id] = Digest(revision); lastSequence = entry.Sequence; lastAt = entry.At;
        }
        for (var i = 0; i < folded.Length; i++)
            if (!Party(current[i]) || current[i] != folded[i]) throw Invalid();
        return Array.AsReadOnly(folded);
    }

    private static bool Party(SignerContactParty? party) => party is not null && party.Id != Guid.Empty && party.Order is >= 1 and <= 100 &&
        party.Name is { Length: > 0 and <= 512 } && !string.IsNullOrWhiteSpace(party.Name) && !party.Name.Any(char.IsControl) &&
        (party.Role is null || party.Role.Length <= 512 && !party.Role.Any(char.IsControl)) && Address(party.Email) && party.Epoch is not null &&
        (party.Epoch.Number == 0 ? party.Epoch.RevisionId == Guid.Empty : party.Epoch.Number is > 0 and <= MaximumCorrections && party.Epoch.RevisionId != Guid.Empty);
    private static void Validate(SignerContactRevision? r)
    {
        if (r is null || r.Version != Version || r.Id == Guid.Empty || r.EnvelopeId == Guid.Empty || r.SignerId == Guid.Empty || r.DocumentId == Guid.Empty ||
            r.Id == r.PreviousRevisionId || r.Number is < 1 or > MaximumCorrections ||
            (r.Number == 1 ? r.PreviousRevisionId != Guid.Empty || r.PreviousCorrectionSha256 is not null : r.PreviousRevisionId == Guid.Empty || !Hash(r.PreviousCorrectionSha256)) ||
            !Address(r.OldEmail) || !Address(r.NewEmail) || r.OldEmail == r.NewEmail || !Utc(r.ChangedAt) || !Utc(r.SenderTicketExpiresAt) ||
            r.SenderTicketExpiresAt <= r.ChangedAt || !RowVersion(r.ReviewedEnvelopeVersion) || !RowVersion(r.ReviewedSignerVersion) ||
            !Hash(r.DocumentSha256) || !Hash(r.DisclosureSha256) || !Hash(r.RetirementSha256) ||
            r.StatementVersion != StatementVersion || r.StatementSha256 != StatementSha256) throw Invalid();
    }
    private static bool RowVersion(string? value)
    {
        if (value is not { Length: 12 }) return false;
        try { return Convert.FromBase64String(value).Length == 8 && Convert.ToBase64String(Convert.FromBase64String(value)) == value; }
        catch (FormatException) { return false; }
    }
    private static bool Address(string? value)
    {
        if (value is null) return false;
        try { return EmailAddress.Normalize(value) == value; }
        catch (ArgumentException) { return false; }
    }
    private static bool Utc(DateTimeOffset value) => value.Offset == TimeSpan.Zero;
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= 'a' and <= 'f' or >= '0' and <= '9');
    private static string Hex(byte[] value) => Convert.ToHexStringLower(value);
    private static InvalidDataException Invalid() => new("Signer contact history could not be verified.");
}

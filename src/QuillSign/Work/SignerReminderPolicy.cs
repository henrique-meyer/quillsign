using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using QuillSign.Email;

namespace QuillSign.Work;

// Optional runtime configuration. Demo Send always freezes an empty policy.
public sealed class SignerReminderOptions
{
    public bool Enabled { get; set; }
    public int[] Days { get; set; } = [3, 7];
    public int? DailyRequests { get; set; }
    public int? DailySenderRequests { get; set; }
    public int? DailyAddressRequests { get; set; }

    public void Validate()
    {
        SignerReminderPolicy.ValidateDays(Days);
        if (Enabled && (DailyRequests is null or < 1 or > 1000 ||
            DailySenderRequests is null or < 1 || DailyAddressRequests is null or < 1 ||
            DailySenderRequests > DailyRequests || DailyAddressRequests > DailyRequests))
            throw new InvalidOperationException("Configure explicit bounded reminder limits before enabling reminders.");
    }

    public SignerReminderPolicy Freeze(bool isDemo)
    {
        Validate();
        return SignerReminderPolicy.FromDays(Enabled && !isDemo ? Days : []);
    }
}

public sealed class SignerReminderPolicy:IEquatable<SignerReminderPolicy>
{
    public const string Version = "signer-reminder-policy-v1";
    public ImmutableArray<int> Days { get; }
    public string CanonicalJson { get; }
    public string Sha256 { get; }
    public bool Equals(SignerReminderPolicy? other)=>other is not null && CanonicalJson==other.CanonicalJson;
    public override bool Equals(object? other)=>other is SignerReminderPolicy policy && Equals(policy);
    public override int GetHashCode()=>StringComparer.Ordinal.GetHashCode(CanonicalJson);

    private SignerReminderPolicy(ImmutableArray<int> days)
    {
        Days = days;
        CanonicalJson = JsonSerializer.Serialize(new { version = Version, days });
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(CanonicalJson)));
    }

    internal static void ValidateDays(int[]? days)
    {
        if (days is null || days.Length > 2 || days.Any(x => x is < 1 or > 30) ||
            days.Length == 2 && days[0] >= days[1])
            throw new InvalidOperationException("Reminder days must be at most two strictly increasing whole days between 1 and 30.");
    }

    internal static SignerReminderPolicy FromDays(int[] days)
    {
        // Validate the owned copy so a caller cannot alter the array between
        // validation and freezing it into evidence.
        var snapshot = days.ToArray();
        ValidateDays(snapshot);
        return new(ImmutableArray.CreateRange(snapshot));
    }

    // A persisted snapshot must be exactly canonical. Unknown/duplicate fields,
    // alternate encodings and an old mutable-envelope JSON array are not proofs.
    public static SignerReminderPolicy Read(string canonicalJson, string expectedSha256)
    {
        if (canonicalJson is null || canonicalJson.Length > 256 || !Hash(expectedSha256)) throw Invalid();
        try
        {
            using var json = JsonDocument.Parse(canonicalJson, new() { MaxDepth = 3 });
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 2 ||
                root.GetProperty("version").GetString() != Version || root.GetProperty("days").ValueKind != JsonValueKind.Array ||
                root.GetProperty("days").GetArrayLength() > 2) throw Invalid();
            var days = root.GetProperty("days").EnumerateArray().Select(x => x.GetInt32()).ToArray();
            var policy = FromDays(days);
            if (policy.CanonicalJson != canonicalJson || policy.Sha256 != expectedSha256) throw Invalid();
            return policy;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        {
            throw Invalid();
        }
    }

    internal static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static InvalidDataException Invalid() => new("The frozen reminder policy could not be verified.");
}

public sealed record ScheduledSignerReminder(Guid WorkId, int Day, DateTimeOffset DueAt, string EpochSha256);

// Pure immutable identity and date calculations. The caller must separately
// verify current database authority under the envelope lock before admission.
public sealed class SignerReminderEpoch
{
    public const string Version = "signer-reminder-epoch-v1";
    public string CanonicalJson { get; }
    public string Sha256 { get; }
    public ImmutableArray<ScheduledSignerReminder> Schedule { get; }

    public SignerReminderEpoch(Guid envelopeId, Guid signerId, Guid invitationId, Guid contactRevisionId,
        string recipient, Guid documentId, string documentSha256, string disclosureSha256,
        SignerReminderPolicy policy, DateTimeOffset invitedAt, DateTimeOffset? signingDeadline, DateTimeOffset? retentionDeadline)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (envelopeId == Guid.Empty || signerId == Guid.Empty || invitationId == Guid.Empty || contactRevisionId == Guid.Empty ||
            documentId == Guid.Empty || !SignerReminderPolicy.Hash(documentSha256) || !SignerReminderPolicy.Hash(disclosureSha256) ||
            EmailAddress.Normalize(recipient) != recipient || signingDeadline <= invitedAt || retentionDeadline <= invitedAt)
            throw new ArgumentException("A reminder epoch requires an exact valid invitation, contact, document and deadline scope.");
        invitedAt = invitedAt.ToUniversalTime();
        signingDeadline = signingDeadline?.ToUniversalTime(); retentionDeadline = retentionDeadline?.ToUniversalTime();
        CanonicalJson = JsonSerializer.Serialize(new {
            version = Version, envelopeId, signerId, invitationId, contactRevisionId, recipient, documentId,
            documentSha256, disclosureSha256, policySha256 = policy.Sha256, invitedAt, signingDeadline, retentionDeadline
        });
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(CanonicalJson)));
        var schedule = ImmutableArray.CreateBuilder<ScheduledSignerReminder>();
        foreach (var day in policy.Days)
        {
            var due = invitedAt.AddDays(day);
            if (signingDeadline is { } end && due >= end || retentionDeadline is { } cutoff && due >= cutoff) continue;
            var id = new Guid(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(Version + ":" + Sha256 + ":" + day.ToString(System.Globalization.CultureInfo.InvariantCulture))).AsSpan(0, 16));
            schedule.Add(new(id, day, due, Sha256));
        }
        Schedule = schedule.ToImmutable();
    }
}

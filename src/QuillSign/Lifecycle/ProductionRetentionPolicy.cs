using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace QuillSign.Lifecycle;

// All intervals and operator text are explicit; new records freeze a canonical copy.
public sealed class ProductionRetentionPolicyOptions
{
    public string Version { get; set; } = "";
    public string ArchiveResponsibility { get; set; } = "";
    public int? AbandonedDraftDays { get; set; }
    public int? ExpiredDays { get; set; }
    public int? DeclinedDays { get; set; }
    public int? VoidedDays { get; set; }
    public int? CompletedDays { get; set; }
}

internal sealed record ProductionRetentionPolicy(string Version, string ArchiveResponsibility,
    int AbandonedDraftDays, int ExpiredDays, int DeclinedDays, int VoidedDays, int CompletedDays);
internal sealed record ProductionRetentionSnapshot(string FormatVersion, Guid RecordId,
    DateTimeOffset CreatedAt, ProductionRetentionPolicy Policy);

internal static class ProductionRetentionPolicyContract
{
    internal const string FormatVersion = "production-retention-v1";
    private const int MaximumDays = 36500, MaximumBytes = 8192;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly JsonSerializerOptions Json = new()
        { MaxDepth = 8, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };

    internal static ProductionRetentionSnapshot Freeze(Guid recordId, DateTimeOffset createdAt,
        ProductionRetentionPolicyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.AbandonedDraftDays is not int draft || options.ExpiredDays is not int expired ||
            options.DeclinedDays is not int declined || options.VoidedDays is not int voided ||
            options.CompletedDays is not int completed)
            throw new InvalidOperationException("Configure every production retention rule explicitly.");
        var value = new ProductionRetentionSnapshot(FormatVersion, recordId, createdAt,
            new(options.Version, options.ArchiveResponsibility, draft, expired, declined, voided, completed));
        Validate(value);
        return value;
    }

    internal static string Serialize(ProductionRetentionSnapshot value)
    {
        Validate(value);
        var json = JsonSerializer.Serialize(value, Json);
        if (Utf8.GetByteCount(json) > MaximumBytes) throw Invalid();
        return json;
    }

    // Correlation with trusted provenance, never an authentication or deletion capability.
    internal static string Digest(ProductionRetentionSnapshot value) =>
        Convert.ToHexStringLower(SHA256.HashData(Utf8.GetBytes(Serialize(value))));

    internal static ProductionRetentionSnapshot Read(string json, string expectedDigest)
    {
        try
        {
            if (json is null || json.Length > MaximumBytes || Utf8.GetByteCount(json) > MaximumBytes ||
                expectedDigest is not { Length: 64 } || expectedDigest.Any(c => !char.IsAsciiHexDigitLower(c)))
                throw Invalid();
            var value = JsonSerializer.Deserialize<ProductionRetentionSnapshot>(json, Json) ?? throw Invalid();
            // Persisted form is exact canonical JSON. This also rejects duplicate/missing properties,
            // alternate encodings and extra whitespace instead of silently normalizing evidence.
            if (!string.Equals(Serialize(value), json, StringComparison.Ordinal) ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Utf8.GetBytes(json)), Convert.FromHexString(expectedDigest)))
                throw Invalid();
            return value;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or OverflowException)
        { throw new InvalidDataException("The production retention snapshot could not be verified.", e); }
    }

    internal static void Validate(ProductionRetentionSnapshot value)
    {
        if (value is null || value.FormatVersion != FormatVersion || value.RecordId == Guid.Empty ||
            value.CreatedAt == default || !WholeUtc(value.CreatedAt) || value.Policy is not { } p ||
            p.Version is not { Length: >= 1 and <= 64 } || !char.IsAsciiLetterOrDigit(p.Version[0]) ||
            p.Version.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_')) ||
            !Text(p.ArchiveResponsibility) || !Positive(p.AbandonedDraftDays) || !Positive(p.ExpiredDays) ||
            !Positive(p.DeclinedDays) || !Positive(p.VoidedDays) || p.CompletedDays is < 0 or > MaximumDays)
            throw Invalid();
        // Reject a policy whose earliest possible deadlines cannot be represented.
        foreach (var days in new[] { p.AbandonedDraftDays, p.ExpiredDays, p.DeclinedDays, p.VoidedDays, p.CompletedDays })
            _ = AddDays(value.CreatedAt, days);
    }

    internal static bool WholeUtc(DateTimeOffset value) => value.Offset == TimeSpan.Zero && value.Ticks % TimeSpan.TicksPerSecond == 0;
    internal static DateTimeOffset AddDays(DateTimeOffset at, int days)
    {
        try { return at.AddDays(days); }
        catch (ArgumentOutOfRangeException e) { throw new InvalidDataException("The retention deadline is outside the supported date range.", e); }
    }
    private static bool Positive(int days) => days is >= 1 and <= MaximumDays;
    private static bool Text(string value)
    {
        if (value is not { Length: >= 1 and <= 1024 } || value != value.Trim() || value.Any(char.IsControl)) return false;
        try { _ = Utf8.GetByteCount(value); return true; }
        catch (EncoderFallbackException) { return false; }
    }
    private static InvalidDataException Invalid() => new("The production retention policy is missing, invalid or unsupported.");
}

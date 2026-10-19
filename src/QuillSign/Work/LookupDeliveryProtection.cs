using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Work;

public sealed class LookupDeliveryOptions
{
    public int DailyAddressRequests { get; set; } = 3;
    public int DailyIpRequests { get; set; } = 10;
    public int DailyRequests { get; set; } = 50;
    public int RequestHours { get; set; } = 24;
    internal void Validate()
    {
        if (DailyRequests is < 1 or > 1000 || DailyAddressRequests < 1 || DailyAddressRequests > DailyRequests ||
            DailyIpRequests < 1 || DailyIpRequests > DailyRequests || RequestHours is < 1 or > 24)
            throw new InvalidOperationException("Configure bounded lookup delivery limits.");
    }
}

internal sealed record LookupIssuedToken(Guid Id, string Revision, string Sha256, DateTimeOffset ExpiresAt);
internal sealed record LookupMailPayload(string Version, Guid Id, string Email, string IpHash, DateTimeOffset RequestedAt,
    DateTimeOffset Deadline, LookupIssuedToken? Issued,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] Guid? PilotRunId = null);

public sealed class LookupDeliveryProtection(IDataProtectionProvider provider)
{
    public const string Template = "document-lookup";
    private readonly IDataProtector protector = provider.CreateProtector("QuillSign.LookupDelivery.Payload.v1");
    internal string Protect(LookupMailPayload payload) => JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(JsonSerializer.Serialize(payload))));
    internal LookupMailPayload Read(EmailOutbox row)
    {
        if (row.EnvelopeId is not null || row.Template != Template || row.AttachmentsJson != "[]" || row.PayloadJson.Length is < 1 or > 8000) throw Invalid();
        LookupMailPayload p;
        try {
            var wrapper = JsonSerializer.Deserialize<ProtectedWorkPayload>(row.PayloadJson);
            p = JsonSerializer.Deserialize<LookupMailPayload>(protector.Unprotect(wrapper?.Protected ?? throw Invalid())) ?? throw Invalid();
        } catch (JsonException) { throw Invalid(); }
        if (p.Version != "lookup-mail-v1" || p.Id == Guid.Empty || p.Id != row.Id || p.Email != row.To || !Hash(p.IpHash) ||
            p.RequestedAt.Offset != TimeSpan.Zero || p.RequestedAt != row.AvailableAt || p.Deadline.Offset != TimeSpan.Zero ||
            p.Deadline <= p.RequestedAt || p.Deadline > p.RequestedAt.AddHours(24) || p.PilotRunId == Guid.Empty) throw Invalid();
        try { if (EmailAddress.Normalize(p.Email) != p.Email) throw Invalid(); } catch (ArgumentException) { throw Invalid(); }
        if (p.Issued is { } issued) {
            if (issued.Id == Guid.Empty || !Hash(issued.Sha256) || issued.Revision is not { Length: 12 } ||
                issued.ExpiresAt.Offset != TimeSpan.Zero || issued.ExpiresAt <= p.RequestedAt || issued.ExpiresAt > p.Deadline.AddMinutes(60)) throw Invalid();
            try { if (Convert.FromBase64String(issued.Revision) is not { Length: 8 } bytes || Convert.ToBase64String(bytes) != issued.Revision) throw Invalid(); }
            catch (FormatException) { throw Invalid(); }
        }
        if (row.SubmissionStartedAt is not null && p.Issued is null) throw Invalid();
        return p;
    }
    internal static string IpHash(string? value)
    {
        if (value is null || value.Length > 45 || !IPAddress.TryParse(value, out var ip)) throw new ArgumentException("A valid request IP address is required.");
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && ip.ScopeId != 0) throw new ArgumentException("A valid request IP address is required.");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("lookup-ip-v1|" + ip)));
    }
    internal static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static InvalidDataException Invalid() => new("Lookup mail scope is unavailable.");
}

internal static class LookupDeliveryRules
{
    internal static Task LockAsync(QuillSignDbContext db, CancellationToken ct) => db.Database.ExecuteSqlRawAsync("""
        DECLARE @result int;
        EXEC @result = sys.sp_getapplock @Resource = N'lookup-delivery-v1', @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = 5000;
        IF @result < 0 THROW 50002, 'Lookup request is temporarily busy.', 1;
        """, ct);
    internal static async Task<bool> WithinCapsAsync(QuillSignDbContext db, LookupDeliveryOptions options, LookupDeliveryProtection protection,
        string email, string ipHash, DateTimeOffset now, bool dispatch, CancellationToken ct)
    {
        options.Validate();
        var start = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero);
        var end = start.AddDays(1);
        var query = db.EmailOutbox.AsNoTracking().Where(x => x.Template == LookupDeliveryProtection.Template);
        query = dispatch ? query.Where(x => x.SubmissionStartedAt >= start && x.SubmissionStartedAt < end) : query.Where(x => x.AvailableAt >= start && x.AvailableAt < end);
        var rows = await query.OrderBy(x => x.Id).Take(options.DailyRequests + 1).ToArrayAsync(ct);
        if (rows.Length >= options.DailyRequests) return false;
        var payloads = rows.Select(protection.Read).ToArray();
        return payloads.Count(x => x.Email == email) < options.DailyAddressRequests && payloads.Count(x => x.IpHash == ipHash) < options.DailyIpRequests;
    }
}

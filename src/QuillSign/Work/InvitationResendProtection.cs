using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Work;

public sealed class InvitationResendOptions
{
    public bool Enabled { get; set; }
    public int? DailyAddressRequests { get; set; }
    public int? DailyIpRequests { get; set; }
    public int? DailySenderRequests { get; set; }
    public int? DailyRequests { get; set; }
    public void Validate()
    {
        if (!Enabled) return;
        if (DailyRequests is null or < 1 or > 1000 || DailyAddressRequests is null or < 1 || DailyIpRequests is null or < 1 ||
            DailySenderRequests is null or < 1 || DailyAddressRequests > DailyRequests || DailyIpRequests > DailyRequests || DailySenderRequests > DailyRequests)
            throw new InvalidOperationException("Configure explicit bounded invitation resend limits before enabling resend.");
    }
}

internal sealed record ResendRequest(string Version, Guid Id, Guid EnvelopeId, Guid SignerId, Guid PreviousId,
    string Email, string SenderEmail, string IpHash, string ReviewedVersion, Guid DocumentId, string DocumentSha256,
    string DisclosureSha256, DateTimeOffset RequestedAt, DateTimeOffset SenderTicketExpiresAt, DateTimeOffset Deadline, DateTimeOffset CounterUntil);
internal sealed record ResendToken(Guid Id, string Sha256, DateTimeOffset ExpiresAt);
internal sealed record ResendMail(ResendRequest Request, ResendToken? Issued = null);
internal sealed record ResendEvidence(string Version, Guid Id, Guid SignerId, ResendRequest Request, string StatementVersion, string StatementSha256);

public sealed class InvitationResendProtection(IDataProtectionProvider provider)
{
    public const string Template = "signer-invitation-resend";
    internal const string Event = "invitation_resend_requested";
    private readonly IDataProtector protector = provider.CreateProtector("QuillSign.InvitationResend.Payload.v1");
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, MaxDepth = 8 };
    internal string Protect(ResendMail value) => JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(JsonSerializer.Serialize(value, Json))));
    internal ResendMail Read(EmailOutbox row)
    {
        if (row.Template != Template || row.EnvelopeId is null || row.AttachmentsJson != "[]" || row.PayloadJson.Length is < 1 or > 12000) throw Invalid();
        ResendMail value;
        try { value = JsonSerializer.Deserialize<ResendMail>(protector.Unprotect(JsonSerializer.Deserialize<ProtectedWorkPayload>(row.PayloadJson)?.Protected ?? throw Invalid()), Json) ?? throw Invalid(); }
        catch (JsonException) { throw Invalid(); }
        var p = value.Request; Validate(p);
        if (p.Id != row.Id || p.EnvelopeId != row.EnvelopeId || p.Email != row.To || p.RequestedAt != row.AvailableAt || !Enum.IsDefined(row.Status)) throw Invalid();
        if (value.Issued is { } token && (token.Id == Guid.Empty || !Hash(token.Sha256) || token.ExpiresAt <= p.RequestedAt ||
            token.ExpiresAt.Offset != TimeSpan.Zero || token.ExpiresAt > p.CounterUntil.AddDays(7))) throw Invalid();
        if ((row.SubmissionStartedAt is null) != (value.Issued is null)) throw Invalid();
        return value;
    }
    internal static string Evidence(ResendRequest p) => JsonSerializer.Serialize(new ResendEvidence("resend-admission-v1", p.Id, p.SignerId, p,
        QuillSign.Sender.InvitationResendStatement.Version, QuillSign.Sender.InvitationResendStatement.Sha256), Json);
    internal static ResendRequest ReadEvidence(AuditEvent row)
    {
        if (row.Event != Event || row.ActorType != PartyType.Sender || row.ActorId is not null || row.DataJson.Length > 12000 ||
            !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(row), row.Hash)) throw Invalid();
        ResendEvidence evidence;
        try { evidence = JsonSerializer.Deserialize<ResendEvidence>(row.DataJson, Json) ?? throw Invalid(); }
        catch (JsonException) { throw Invalid(); }
        var p = evidence.Request; Validate(p);
        if (row.EnvelopeId != p.EnvelopeId || row.ActorEmail != p.SenderEmail || row.At < p.RequestedAt || row.At >= p.CounterUntil ||
            row.DataJson != Evidence(p) || IpHash(row.Ip) != p.IpHash) throw Invalid();
        return p;
    }
    private static void Validate(ResendRequest? p)
    {
        if (p is null || p.Version != "resend-request-v1" || p.Id == Guid.Empty || p.EnvelopeId == Guid.Empty || p.SignerId == Guid.Empty ||
            p.PreviousId == Guid.Empty || p.PreviousId == p.Id || p.DocumentId == Guid.Empty || !Hash(p.IpHash) || !Hash(p.DocumentSha256) || !Hash(p.DisclosureSha256) ||
            !RowVersion(p.ReviewedVersion) || p.RequestedAt.Offset != TimeSpan.Zero || p.SenderTicketExpiresAt.Offset != TimeSpan.Zero ||
            p.SenderTicketExpiresAt <= p.RequestedAt || p.Deadline.Offset != TimeSpan.Zero || p.Deadline <= p.RequestedAt || p.Deadline > p.CounterUntil ||
            p.CounterUntil != DayEnd(p.RequestedAt)) throw Invalid();
        try { if (EmailAddress.Normalize(p.Email) != p.Email || EmailAddress.Normalize(p.SenderEmail) != p.SenderEmail) throw Invalid(); }
        catch (ArgumentException) { throw Invalid(); }
    }
    internal static DateTimeOffset DayEnd(DateTimeOffset at) => new DateTimeOffset(at.UtcDateTime.Date, TimeSpan.Zero).AddDays(1);
    internal static string IpHash(string? value)
    {
        if (value is null || value.Length > 45 || !IPAddress.TryParse(value, out var ip)) throw new ArgumentException("A valid request IP is required.");
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && ip.ScopeId != 0) throw new ArgumentException("A valid request IP is required.");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("invitation-resend-ip-v1|" + ip)));
    }
    internal static bool RowVersion(string? value)
    {
        if (value is not { Length: 12 }) return false;
        try { var bytes = Convert.FromBase64String(value); return bytes.Length == 8 && Convert.ToBase64String(bytes) == value; } catch (FormatException) { return false; }
    }
    internal static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= 'a' and <= 'f' or >= '0' and <= '9');
    internal static InvalidDataException Invalid() => new("Invitation resend scope is unavailable.");
}

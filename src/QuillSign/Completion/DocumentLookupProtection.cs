using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Email;

namespace QuillSign.Completion;

public sealed class DocumentLookupOptions
{
    public int LinkMinutes { get; set; } = 15;
    public int SessionMinutes { get; set; } = 30;
    public int PageSize { get; set; } = 5;
    internal void Validate()
    {
        if (LinkMinutes is < 1 or > 60 || SessionMinutes is < 1 or > 60 || PageSize is < 1 or > 10)
            throw new InvalidOperationException("Configure bounded document lookup lifetimes and page size.");
    }
}

public sealed record DocumentLookupIdentity(Guid TokenId, string TokenRevision, string TokenSha256, string Email,
    Guid SessionId, DateTimeOffset IssuedAt, DateTimeOffset LinkExpiresAt, DateTimeOffset RedeemedAt, DateTimeOffset ExpiresAt);
public sealed record DocumentLookupSession(DocumentLookupIdentity Identity, string Receipt);
public sealed record DocumentLookupLink(Guid TokenId, string Transport, DateTimeOffset ExpiresAt);
internal sealed record LookupIssuance(Guid TokenId, string TokenRevision, string RawToken, string Email, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);
internal sealed record LookupCursor(Guid SessionId, Guid TokenId, string TokenRevision, DateTimeOffset CompletedAt, string PublicId);

// Distinct purposes keep mailbox lookup separate from envelope readers and all edit authority.
// The protected issuance transport is required alongside its persisted random token hash.
public sealed class DocumentLookupProtection(IDataProtectionProvider provider, TimeProvider time)
{
    public const string Scheme = "QuillSign.DocumentLookup";
    private readonly IDataProtector links = provider.CreateProtector("QuillSign.DocumentLookup.Link.v1");
    private readonly IDataProtector sessions = provider.CreateProtector("QuillSign.DocumentLookup.Session.v1");
    private readonly IDataProtector cursors = provider.CreateProtector("QuillSign.DocumentLookup.Cursor.v1");
    internal string Link(LookupIssuance value) => Write(links, value);
    internal LookupIssuance? Link(string? value)
    {
        var i = Read<LookupIssuance>(links, value);
        return i is not null && i.TokenId != Guid.Empty && Revision(i.TokenRevision) && Mailbox(i.Email) && Utc(i.IssuedAt) && Utc(i.ExpiresAt) &&
            i.IssuedAt <= time.GetUtcNow() && i.ExpiresAt > time.GetUtcNow() && i.ExpiresAt > i.IssuedAt &&
            i.ExpiresAt <= i.IssuedAt.AddMinutes(60) && Signing.SignerInvitationFactory.TokenHash(i.RawToken) is not null ? i : null;
    }
    internal string Session(DocumentLookupIdentity value) => Write(sessions, value);
    internal DocumentLookupIdentity? Session(string? value)
    {
        var i = Read<DocumentLookupIdentity>(sessions, value);
        if (i is null || i.TokenId == Guid.Empty || i.SessionId == Guid.Empty || !Mailbox(i.Email) || !Hash(i.TokenSha256) ||
            !Utc(i.IssuedAt) || !Utc(i.LinkExpiresAt) || !Utc(i.RedeemedAt) || !Utc(i.ExpiresAt) || i.IssuedAt > i.RedeemedAt ||
            i.LinkExpiresAt <= i.RedeemedAt || i.LinkExpiresAt > i.IssuedAt.AddMinutes(60) ||
            i.RedeemedAt > time.GetUtcNow() || i.ExpiresAt <= time.GetUtcNow() || i.ExpiresAt <= i.RedeemedAt ||
            i.ExpiresAt > i.RedeemedAt.AddMinutes(60)) return null;
        return Revision(i.TokenRevision) ? i : null;
    }
    internal string Cursor(LookupCursor value) => Write(cursors, value);
    internal LookupCursor? Cursor(string? value, DocumentLookupIdentity i)
    {
        var c = Read<LookupCursor>(cursors, value);
        return c is not null && c.SessionId == i.SessionId && c.TokenId == i.TokenId && c.TokenRevision == i.TokenRevision &&
            Utc(c.CompletedAt) && c.CompletedAt <= i.RedeemedAt && Guid.TryParseExact(c.PublicId, "N", out var id) && id != Guid.Empty ? c : null;
    }
    public static ClaimsPrincipal Principal(DocumentLookupIdentity i) => new(new ClaimsIdentity([
        new("quillsign:lookup-token", i.TokenId.ToString("N")), new("quillsign:lookup-session", i.SessionId.ToString("N")),
        new(ClaimTypes.Email, i.Email), new("quillsign:lookup-expiry", i.ExpiresAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
    ], Scheme));
    internal static bool Matches(ClaimsPrincipal principal, DocumentLookupIdentity i)
    {
        var identities = principal.Identities.Where(x => x.IsAuthenticated).ToArray();
        if (identities.Length != 1 || identities[0].AuthenticationType != Scheme) return false;
        var expected = Principal(i).Claims.ToArray(); var actual = identities[0].Claims.ToArray();
        return actual.Length == expected.Length && expected.All(c => actual.Count(x => x.Type == c.Type && x.Value == c.Value) == 1);
    }
    private static bool Mailbox(string? value)
    {
        try { return value is not null && EmailAddress.Normalize(value) == value; }
        catch (ArgumentException) { return false; }
    }
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Revision(string? value)
    {
        if (value is not { Length: 12 }) return false;
        try { return Convert.FromBase64String(value) is { Length: 8 } bytes && Convert.ToBase64String(bytes) == value; }
        catch (FormatException) { return false; }
    }
    private static bool Utc(DateTimeOffset value) => value.Offset == TimeSpan.Zero;
    private static string Write<T>(IDataProtector p, T value)
    {
        var result = p.Protect(JsonSerializer.Serialize(value));
        return result.Length <= 3800 ? result : throw new InvalidDataException("Document lookup proof exceeds its bound.");
    }
    private static T? Read<T>(IDataProtector p, string? value) where T : class
    {
        if (value is not { Length: > 0 and <= 3800 }) return null;
        try { return JsonSerializer.Deserialize<T>(p.Unprotect(value)); }
        catch (Exception e) when (e is CryptographicException or JsonException or ArgumentException) { return null; }
    }
}

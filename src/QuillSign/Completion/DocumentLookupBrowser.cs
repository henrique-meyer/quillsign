using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Documents;

namespace QuillSign.Completion;

internal sealed record LookupBrowserSession(ClaimsPrincipal Principal, string Receipt, DocumentLookupIdentity Identity, DateTimeOffset Until);

public sealed class DocumentLookupBrowser(IDataProtectionProvider provider, DocumentLookupProtection proof, TimeProvider time,
    IHostEnvironment environment, Func<DocumentLookup> lookup)
{
    public const string PendingCookie = "QuillSign.Lookup.Pending", ReceiptCookie = "QuillSign.Lookup.Receipt", PageCookie = "QuillSign.Lookup.Page";
    private const string NoticeCookie = "QuillSign.Lookup.Notice";
    private sealed record Pending(string Version, string Code, Guid Nonce, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);
    private readonly IDataProtector pending = provider.CreateProtector("QuillSign.DocumentLookup.Pending.v1");
    private readonly ITimeLimitedDataProtector notices = provider.CreateProtector("QuillSign.DocumentLookup.Notice.v1").ToTimeLimitedDataProtector();

    public bool Begin(HttpContext http, string? code)
    {
        var link = proof.Link(code); if (link is null) return false;
        var now = time.GetUtcNow(); var until = new[] { now.AddMinutes(10), link.ExpiresAt }.Min();
        var value = pending.Protect(JsonSerializer.Serialize(new Pending("lookup-pending-v1", code!, Guid.NewGuid(), now, until)));
        if (value.Length > 3800) return false;
        var options = Options(http, "/find/access"); options.MaxAge = until - now;
        http.Response.Cookies.Append(PendingCookie, value, options); return true;
    }
    public Guid? PendingNonce(HttpContext http) => ReadPending(http)?.Nonce;
    public string? PendingCode(HttpContext http, string? nonce)
    {
        var p = ReadPending(http);
        return p is not null && Guid.TryParseExact(nonce, "N", out var id) && id == p.Nonce ? p.Code : null;
    }
    public void ClearPending(HttpContext http) => http.Response.Cookies.Delete(PendingCookie, Options(http, "/find/access"));
    private Pending? ReadPending(HttpContext http)
    {
        var raw = Get(http, PendingCookie); if (raw is null) return null;
        try
        {
            var p = JsonSerializer.Deserialize<Pending>(pending.Unprotect(raw)); var now = time.GetUtcNow();
            return p?.Version == "lookup-pending-v1" && p.Nonce != Guid.Empty && p.IssuedAt <= now && p.ExpiresAt > now &&
                p.ExpiresAt > p.IssuedAt && p.ExpiresAt <= p.IssuedAt.AddMinutes(10) && proof.Link(p.Code) is not null ? p : null;
        }
        catch (Exception e) when (e is CryptographicException or JsonException or ArgumentException) { return null; }
    }
    public async Task SignInAsync(HttpContext http, DocumentLookupSession session)
    {
        var i = session.Identity;
        if (session.Receipt.Length is < 1 or > 3800 || i.ExpiresAt <= time.GetUtcNow()) throw new InvalidDataException("Lookup session is unavailable.");
        await http.SignInAsync(DocumentLookupProtection.Scheme, DocumentLookupProtection.Principal(i), new AuthenticationProperties
        { IssuedUtc = time.GetUtcNow(), ExpiresUtc = i.ExpiresAt, IsPersistent = false, AllowRefresh = false });
        var options = Options(http, "/find"); options.MaxAge = i.ExpiresAt - time.GetUtcNow();
        if (options.MaxAge <= TimeSpan.Zero) throw new InvalidDataException("Lookup session expired.");
        http.Response.Cookies.Append(ReceiptCookie, session.Receipt, options); ClearPage(http);
    }
    internal async Task<LookupBrowserSession?> AuthenticateAsync(HttpContext http, CancellationToken ct)
    {
        var ticket = await http.AuthenticateAsync(DocumentLookupProtection.Scheme); var now = time.GetUtcNow();
        if (!ticket.Succeeded || ticket.Principal is null || ticket.Properties?.ExpiresUtc is not { } until || until <= now) return null;
        var receipt = Get(http, ReceiptCookie); if (receipt is null) return null;
        var i = await lookup().AuthenticateAsync(ticket.Principal, receipt, ct); if (i is null) return null;
        until = new[] { until, i.ExpiresAt }.Min();
        return until > time.GetUtcNow() ? new(ticket.Principal, receipt, i, until) : null;
    }
    internal string? PageCursor(HttpContext http) => http.Request.Cookies.ContainsKey(PageCookie) ? Get(http, PageCookie) ?? "" : null;
    internal bool SetPage(HttpContext http, LookupBrowserSession session, string? cursor)
    {
        if (proof.Cursor(cursor, session.Identity) is null || session.Until <= time.GetUtcNow()) return false;
        var options = Options(http, "/find/documents"); options.MaxAge = session.Until - time.GetUtcNow();
        http.Response.Cookies.Append(PageCookie, cursor!, options); return true;
    }
    public void ClearPage(HttpContext http) => http.Response.Cookies.Delete(PageCookie, Options(http, "/find/documents"));
    public void ExpiredNotice(HttpContext http)
    {
        http.Response.Cookies.Delete(ReceiptCookie, Options(http, "/find")); ClearPage(http);
        var options = Options(http, "/find"); options.MaxAge = TimeSpan.FromMinutes(2);
        http.Response.Cookies.Append(NoticeCookie, notices.Protect("expired", TimeSpan.FromMinutes(2)), options);
    }
    public string? TakeNotice(HttpContext http)
    {
        if (!http.Request.Cookies.ContainsKey(NoticeCookie)) return null;
        var value = Get(http, NoticeCookie); http.Response.Cookies.Delete(NoticeCookie, Options(http, "/find"));
        try { return value is not null && notices.Unprotect(value) == "expired" ? "Your document lookup session has expired or is unavailable. Use a fresh lookup link." : null; }
        catch (CryptographicException) { return null; }
    }
    private CookieOptions Options(HttpContext http, string path) => new()
    { Path = path, HttpOnly = true, SameSite = SameSiteMode.Strict, Secure = !environment.IsDevelopment() || http.Request.IsHttps, IsEssential = true };
    private static string? Get(HttpContext http, string name)
    {
        if (!http.Request.Cookies.TryGetValue(name, out var value) || value.Length is < 1 or > 3800) return null;
        var count = http.Request.Headers.Cookie.Sum(header => (header ?? "").Split(';').Count(part => part.TrimStart().StartsWith(name + "=", StringComparison.Ordinal)));
        return count == 1 ? value : null;
    }
    internal static bool Unavailable(Exception e) => Pages.Sign.FieldsModel.StorageError(e) || e is DocumentRetentionExpiredException or PreparationRetentionEvidenceException;
}

public static class DocumentLookupBrowserConfiguration
{
    public static IServiceCollection AddDocumentLookupBrowser(this IServiceCollection services, IHostEnvironment environment)
    {
        services.TryAddScoped<DocumentLookupBrowser>(); services.TryAddScoped<Func<DocumentLookup>>(sp => () => sp.GetRequiredService<DocumentLookup>());
        services.TryAddScoped<Func<LookupPacketAccess>>(sp => () => sp.GetRequiredService<LookupPacketAccess>());
        services.TryAddScoped<Func<QuillSign.Work.DocumentLookupRequests>>(sp => () => sp.GetRequiredService<QuillSign.Work.DocumentLookupRequests>());
        services.TryAddScoped<Func<QuillSign.Sender.BrowserNotices>>(sp => () => sp.GetRequiredService<QuillSign.Sender.BrowserNotices>());
        services.AddAuthentication().AddCookie(DocumentLookupProtection.Scheme, cookie =>
        {
            cookie.Cookie.Name = environment.IsDevelopment() ? "QuillSign.DocumentLookup" : "__Host-QuillSign.DocumentLookup";
            cookie.Cookie.Path = "/"; cookie.Cookie.HttpOnly = true; cookie.Cookie.SameSite = SameSiteMode.Strict;
            cookie.Cookie.SecurePolicy = environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            cookie.ExpireTimeSpan = TimeSpan.FromMinutes(30); cookie.SlidingExpiration = false;
            cookie.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; };
            cookie.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
        });
        services.AddOptions<CookieAuthenticationOptions>(DocumentLookupProtection.Scheme).Configure<TimeProvider>((cookie, clock) => cookie.TimeProvider = clock);
        return services;
    }
    public static IApplicationBuilder UseDocumentLookupBrowser(this IApplicationBuilder app) => app.Use((http, next) =>
    {
        if (http.Request.Path.StartsWithSegments("/find"))
        { http.Response.Headers.CacheControl = "no-store"; http.Response.Headers["Referrer-Policy"] = "no-referrer"; http.Response.Headers["X-Content-Type-Options"] = "nosniff"; }
        return next();
    });
}

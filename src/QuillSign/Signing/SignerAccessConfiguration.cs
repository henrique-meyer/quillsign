using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using QuillSign.Storage;

namespace QuillSign.Signing;

public sealed class SignerAccessOptions
{
    public int InvitationHours { get; set; } = 24;
    public int SessionHours { get; set; } = 2;
}
public sealed record VerifiedSigner(Guid EnvelopeId,string PublicId,Guid SignerId,string Email,Guid DocumentId,
    string DocumentHash,string DisclosureHash,DateTimeOffset SessionExpiresAt);

public static class SignerAccessConfiguration
{
    public const string Scheme = "QuillSign.Signer";
    public const string PublicIdClaim = "quillsign:signer-public-id";
    public const string SignerClaim = "quillsign:signer";
    public const string DocumentClaim = "quillsign:signer-document";
    public const string DocumentHashClaim = "quillsign:signer-document-hash";
    public const string DisclosureHashClaim = "quillsign:signer-disclosure-hash";
    public const string ExpiryClaim = "quillsign:signer-session-expiry";

    public static IServiceCollection AddQuillSignSignerAccess(this IServiceCollection services,IConfiguration config,IHostEnvironment environment)
    {
        var options = config.GetSection("SignerAccess").Get<SignerAccessOptions>() ?? new();
        if (options.InvitationHours is < 1 or > 168 || options.SessionHours is < 1 or > 24)
            throw new InvalidOperationException("SignerAccess supports 1–168 invitation hours and 1–24 session hours.");
        services.AddSingleton(options); services.AddSingleton<SignerInvitationFactory>(); services.AddScoped<SignerAccess>();
        services.AddAuthentication().AddCookie(Scheme,cookie =>
        {
            cookie.Cookie.Name = environment.IsDevelopment() ? "QuillSign.Signer" : "__Host-QuillSign.Signer";
            cookie.Cookie.Path = "/"; cookie.Cookie.HttpOnly = true; cookie.Cookie.SameSite = SameSiteMode.Lax;
            cookie.Cookie.SecurePolicy = environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            cookie.ExpireTimeSpan = TimeSpan.FromHours(options.SessionHours); cookie.SlidingExpiration = false;
            cookie.Events.OnValidatePrincipal = context =>
            {
                var now = context.HttpContext.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();
                if (context.Principal is null || ReadIdentity(context.Principal,now) is null) context.RejectPrincipal();
                return Task.CompletedTask;
            };
            cookie.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; };
            cookie.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
        });
        services.AddOptions<CookieAuthenticationOptions>(Scheme).Configure<TimeProvider>((cookie,time) => cookie.TimeProvider = time);
        return services;
    }
    public static IServiceCollection AddQuillSignSignerConsent(this IServiceCollection services)
    {
        services.AddScoped<SignerReceiptProtection>(); services.AddScoped<SignerPdfAccess>(); services.AddScoped<SignerConsent>();
        return services;
    }
    public static ClaimsPrincipal Principal(VerifiedSigner signer) => new(new ClaimsIdentity([
        new(EnvelopeStorageAuthorization.EnvelopeClaim,signer.EnvelopeId.ToString("N")), new(PublicIdClaim,signer.PublicId),
        new(SignerClaim,signer.SignerId.ToString("N")), new(ClaimTypes.Email,signer.Email), new(DocumentClaim,signer.DocumentId.ToString("N")),
        new(DocumentHashClaim,signer.DocumentHash), new(DisclosureHashClaim,signer.DisclosureHash),
        new(ExpiryClaim,signer.SessionExpiresAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
    ],Scheme));
    public static AuthenticationProperties Ticket(VerifiedSigner signer) => new()
    { ExpiresUtc = signer.SessionExpiresAt, IsPersistent = false, AllowRefresh = false };

    public static VerifiedSigner? ReadIdentity(ClaimsPrincipal principal,DateTimeOffset now)
    {
        var identities = principal.Identities.Where(x => x.IsAuthenticated).ToArray();
        if (identities.Length != 1 || identities[0].AuthenticationType != Scheme) return null;
        var identity = identities[0];
        string? One(string type) { var claims = identity.FindAll(type).ToArray(); return claims.Length == 1 ? claims[0].Value : null; }
        var publicId = One(PublicIdClaim); var email = One(ClaimTypes.Email);
        var documentHash = One(DocumentHashClaim); var disclosureHash = One(DisclosureHashClaim);
        if (!Guid.TryParseExact(One(EnvelopeStorageAuthorization.EnvelopeClaim),"N",out var envelope) || envelope == Guid.Empty ||
            !Guid.TryParseExact(One(SignerClaim),"N",out var signer) || signer == Guid.Empty ||
            !Guid.TryParseExact(One(DocumentClaim),"N",out var document) || document == Guid.Empty ||
            publicId is not { Length: 32 } || !publicId.All(char.IsAsciiHexDigit) ||
            string.IsNullOrWhiteSpace(email) || email.Length > 320 || email.Any(char.IsControl) ||
            documentHash is not { Length: 64 } || !documentHash.All(char.IsAsciiHexDigit) ||
            disclosureHash is not { Length: 64 } || !disclosureHash.All(char.IsAsciiHexDigit) ||
            !long.TryParse(One(ExpiryClaim),NumberStyles.None,CultureInfo.InvariantCulture,out var expiry)) return null;
        DateTimeOffset expires;
        try { expires = DateTimeOffset.FromUnixTimeSeconds(expiry); } catch (ArgumentOutOfRangeException) { return null; }
        return expires > now ? new(envelope,publicId,signer,email,document,documentHash,disclosureHash,expires) : null;
    }
}

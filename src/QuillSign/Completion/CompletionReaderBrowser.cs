using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using QuillSign.Signing;

namespace QuillSign.Completion;

internal sealed record CompletionBrowserSession(ClaimsPrincipal Principal,string Receipt,CompletionReaderView View,byte[] CookieHash,DateTimeOffset Until);

// Public entry uses only protected browser state until the explicit redemption POST.
public sealed class CompletionReaderBrowser(IDataProtectionProvider protection,TimeProvider time,IHostEnvironment environment,
    IOptionsMonitor<CookieAuthenticationOptions> cookies,Func<CompletionAccess> access)
{
    public const string PendingCookie="QuillSign.Completion.Pending",ReceiptCookie="QuillSign.Completion.Receipt";
    private sealed record Pending(string Version,string Code,Guid Nonce,DateTimeOffset IssuedAt,DateTimeOffset ExpiresAt);
    private readonly IDataProtector pending=protection.CreateProtector("QuillSign.CompletionReader.Pending.v1");
    public bool Begin(HttpContext http,string? code)
    {
        if(SignerInvitationFactory.TokenHash(code) is null)return false;
        var now=time.GetUtcNow(); var until=now.AddMinutes(10);
        var value=pending.Protect(JsonSerializer.Serialize(new Pending("completion-pending-v1",code!,Guid.NewGuid(),now,until)));
        if(value.Length>3800)throw new InvalidDataException("Completion entry exceeds its bound.");
        var options=Options(http,"/complete/access"); options.MaxAge=until-now; http.Response.Cookies.Append(PendingCookie,value,options); return true;
    }
    public Guid? PendingNonce(HttpContext http)=>ReadPending(http)?.Nonce;
    public string? PendingCode(HttpContext http,string? nonce)
    {
        var value=ReadPending(http);
        return value is not null && Guid.TryParseExact(nonce,"N",out var id) && id==value.Nonce ? value.Code : null;
    }
    public void ClearPending(HttpContext http)=>http.Response.Cookies.Delete(PendingCookie,Options(http,"/complete/access"));
    private Pending? ReadPending(HttpContext http)
    {
        var raw=Get(http,PendingCookie); if(raw is null)return null;
        try {
            var p=JsonSerializer.Deserialize<Pending>(pending.Unprotect(raw)); var now=time.GetUtcNow();
            return p?.Version=="completion-pending-v1" && p.Nonce!=Guid.Empty && p.IssuedAt<=now && p.ExpiresAt>now &&
                p.ExpiresAt>p.IssuedAt && p.ExpiresAt<=p.IssuedAt.AddMinutes(10) && SignerInvitationFactory.TokenHash(p.Code) is not null ? p : null;
        } catch(Exception e) when(e is CryptographicException or JsonException or ArgumentException) {return null;}
    }
    public async Task SignInAsync(HttpContext http,CompletionReaderSession session)
    {
        var i=session.Identity; if(session.Receipt.Length>3800 || i.ExpiresAt<=time.GetUtcNow())throw new InvalidDataException("Completion session is unavailable.");
        await http.SignInAsync(CompletionAccessProtection.Scheme,CompletionAccessProtection.Principal(i),new AuthenticationProperties {
            IssuedUtc=time.GetUtcNow(),ExpiresUtc=i.ExpiresAt,IsPersistent=false,AllowRefresh=false });
        var options=Options(http,"/complete/"+i.PublicId); options.MaxAge=i.ExpiresAt-time.GetUtcNow();
        if(options.MaxAge<=TimeSpan.Zero)throw new InvalidDataException("Completion session expired.");
        http.Response.Cookies.Append(ReceiptCookie,session.Receipt,options);
    }
    internal async Task<CompletionBrowserSession?> AuthenticateAsync(HttpContext http,string publicId,CancellationToken ct,bool locked=false)
    {
        if(!Guid.TryParseExact(publicId,"N",out var id) || id==Guid.Empty)return null;
        var ticket=await http.AuthenticateAsync(CompletionAccessProtection.Scheme); var now=time.GetUtcNow();
        if(!ticket.Succeeded || ticket.Principal is null || ticket.Properties?.ExpiresUtc is not { } until || until<=now)return null;
        var receipt=Get(http,ReceiptCookie); if(receipt is null)return null;
        var settings=cookies.Get(CompletionAccessProtection.Scheme); var raw=settings.CookieManager.GetRequestCookie(http,settings.Cookie.Name!);
        if(string.IsNullOrEmpty(raw) || raw.Length>32768)return null;
        var view=locked ? await access().AuthenticateLockedAsync(ticket.Principal,publicId,receipt,ct) : await access().AuthenticateAsync(ticket.Principal,publicId,receipt,ct);
        if(view is null)return null;
        until=new[]{until,view.Identity.ExpiresAt,view.RetainedUntil??DateTimeOffset.MaxValue}.Min();
        return until<=time.GetUtcNow() ? null : new(ticket.Principal,receipt,view,SHA256.HashData(Encoding.UTF8.GetBytes(raw)),until);
    }
    private CookieOptions Options(HttpContext http,string path)=>new() {Path=path,HttpOnly=true,SameSite=SameSiteMode.Strict,
        Secure=!environment.IsDevelopment() || http.Request.IsHttps,IsEssential=true};
    private static string? Get(HttpContext http,string name)=>http.Request.Cookies.TryGetValue(name,out var value) && value.Length is >0 and <=3800 ? value : null;
}

public static class CompletionReaderBrowserConfiguration
{
    public static IServiceCollection AddCompletionReaderBrowser(this IServiceCollection services,IHostEnvironment environment)
    {
        services.AddScoped<CompletionReaderBrowser>(); services.AddScoped<Func<CompletionAccess>>(sp=>()=>sp.GetRequiredService<CompletionAccess>());
        services.AddAuthentication().AddCookie(CompletionAccessProtection.Scheme,cookie=> {
            cookie.Cookie.Name=environment.IsDevelopment() ? "QuillSign.CompletionReader" : "__Host-QuillSign.CompletionReader";
            cookie.Cookie.Path="/"; cookie.Cookie.HttpOnly=true; cookie.Cookie.SameSite=SameSiteMode.Strict;
            cookie.Cookie.SecurePolicy=environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            cookie.ExpireTimeSpan=TimeSpan.FromHours(1); cookie.SlidingExpiration=false;
            cookie.Events.OnRedirectToLogin=context=> {context.Response.StatusCode=401;return Task.CompletedTask;};
            cookie.Events.OnRedirectToAccessDenied=context=> {context.Response.StatusCode=403;return Task.CompletedTask;};
        });
        services.AddOptions<CookieAuthenticationOptions>(CompletionAccessProtection.Scheme).Configure<TimeProvider>((cookie,clock)=>cookie.TimeProvider=clock);
        return services;
    }
}

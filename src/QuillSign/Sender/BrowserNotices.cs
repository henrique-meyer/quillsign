using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Sender;

public enum NoticeCode { CheckInbox, InvalidLink, SessionRequired, Unavailable, Retry, DocumentUploaded, PreviewConfirmed }

public sealed class BrowserNotices(IDataProtectionProvider protection, IHostEnvironment environment)
{
    private const string CookieName = "QuillSign.Notice";
    private readonly ITimeLimitedDataProtector protector = protection.CreateProtector("QuillSign.BrowserNotice.v1").ToTimeLimitedDataProtector();
    private CookieOptions Options(HttpContext context) => new()
    {
        HttpOnly = true, SameSite = SameSiteMode.Lax, Path = "/", IsEssential = true,
        Secure = !environment.IsDevelopment() || context.Request.IsHttps
    };

    public void Set(HttpContext context, NoticeCode code)
    {
        var options = Options(context);
        options.MaxAge = TimeSpan.FromMinutes(2);
        context.Response.Cookies.Append(CookieName, protector.Protect(code.ToString(), TimeSpan.FromMinutes(2)), options);
    }

    public string? Take(HttpContext context)
    {
        if (!context.Request.Cookies.TryGetValue(CookieName, out var cookie)) return null;
        context.Response.Cookies.Delete(CookieName, Options(context));
        try
        {
            return cookie.Length <= 4096 && Enum.TryParse<NoticeCode>(protector.Unprotect(cookie), out var code) && Enum.IsDefined(code) ? Text(code) : null;
        }
        catch (CryptographicException) { return null; }
    }

    public static string Text(NoticeCode code) => code switch
    {
        NoticeCode.CheckInbox => "Check your inbox. If email can be sent to that address, a verification link will arrive shortly.",
        NoticeCode.InvalidLink => "This verification link is invalid, expired, or already used. Request a new link to start a draft.",
        NoticeCode.SessionRequired => "Verify your email to open a draft. Your previous session may have expired.",
        NoticeCode.Unavailable => "Email delivery is currently unavailable. Please try again later.",
        NoticeCode.DocumentUploaded => "PDF uploaded. Review the preview, then confirm it matches your document.",
        NoticeCode.PreviewConfirmed => "Preview confirmed. Your document is still a draft; it hasn't been sent for signing.",
        _ => "We couldn't complete that request right now. Please try again shortly."
    };
}

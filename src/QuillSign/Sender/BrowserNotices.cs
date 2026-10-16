using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Sender;

public enum NoticeCode { CheckInbox, InvalidLink, SessionRequired, Unavailable, Retry, DocumentUploaded, PreviewConfirmed, SignerSaved, SignerRemoved, SignersReordered, PreviewRequired, DetailsSaved, RecipientSaved, RecipientRemoved, SignatureAdopted, SignerFieldSaved, SignerReviewPrepared, SignerFinishAccepted, RequestSent }

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
        NoticeCode.SignerSaved => "Signer saved. No invitation has been sent.",
        NoticeCode.SignerRemoved => "Signer removed from this draft.",
        NoticeCode.SignersReordered => "Signing order updated.",
        NoticeCode.PreviewRequired => "Confirm the current PDF preview before continuing.",
        NoticeCode.DetailsSaved => "Document details saved. Nothing has been sent.",
        NoticeCode.RecipientSaved => "Completion recipient saved. Nothing has been sent.",
        NoticeCode.RecipientRemoved => "Completion recipient removed from this draft.",
        NoticeCode.SignatureAdopted => "Your signature and initials were adopted. Apply each field deliberately and review saved entries. Signing is not complete.",
        NoticeCode.SignerFieldSaved => "Field saved. Signing is not complete.",
        NoticeCode.SignerReviewPrepared => "Review prepared. Open the exact PDF, check it and confirm your intent before Finish.",
        NoticeCode.SignerFinishAccepted => "Your Finish was accepted. Your entries are frozen.",
        NoticeCode.RequestSent => "The request was sent. Check its private status below.",
        _ => "We couldn't complete that request right now. Please try again shortly."
    };
}

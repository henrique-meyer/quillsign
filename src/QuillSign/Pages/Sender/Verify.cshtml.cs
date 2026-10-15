using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Pages.Sender;

public sealed class VerifyModel(Func<SenderWorkflow> workflow, SenderAvailability availability, SenderOptions options, BrowserNotices notices, TimeProvider time) : PageModel
{
    public async Task<IActionResult> OnGetAsync(string? token, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        VerifiedSender? verified;
        try
        {
            verified = availability.CanVerify ? await workflow().VerifyAsync(token, HttpContext.Connection.RemoteIpAddress?.ToString(), Request.Headers.UserAgent.ToString(), cancellationToken) : null;
        }
        catch (Exception error) when (error is Microsoft.Data.SqlClient.SqlException || Data.SqlResume.IsUnavailable(error))
        {
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(NoticeCode.Retry) }) { StatusCode = 503 };
            notices.Set(HttpContext, NoticeCode.Retry);
            return Redirect("/");
        }
        if (verified is null)
        {
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(NoticeCode.InvalidLink) }) { StatusCode = 400 };
            notices.Set(HttpContext, NoticeCode.InvalidLink);
            return Redirect("/");
        }
        var now = time.GetUtcNow();
        await HttpContext.SignInAsync(EnvelopeStorageAuthorization.SenderScheme, SenderConfiguration.Principal(verified),
            new AuthenticationProperties { IssuedUtc = now, ExpiresUtc = now.AddHours(options.SessionHours), IsPersistent = false, AllowRefresh = false });
        var draft = "/draft/" + verified.PublicId;
        if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { location = draft });
        return Redirect(draft);
    }
}

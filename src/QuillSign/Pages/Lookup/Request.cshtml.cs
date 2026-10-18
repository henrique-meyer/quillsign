using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Completion;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Pages.Lookup;

[RequestSizeLimit(8192)]
public sealed class RequestModel(EmailOptions email, WorkOptions work, LookupContactRetentionOptions retention,
    Func<DocumentLookupRequests> requests, Func<BrowserNotices> notices) : PageModel
{
    [BindProperty, FromForm, Required, StringLength(320)] public string Email { get; set; } = "";
    public bool CanRequest => email.Enabled && work.Enabled && retention.Days is >= 1 and <= 36500;
    public string? Notice { get; private set; }
    public string? Message { get; private set; }
    public const string Unavailable = "Email delivery is currently unavailable. You can still use a document lookup link you already received.";
    private const string Unconfirmed = "We couldn't confirm this request. If a link arrives, use it; otherwise wait before requesting another.";

    public void OnGet()
    {
        // Normal framework cookies retain their protections. No private request
        // backend, membership query or issuance is needed to display this page.
        if (CanRequest) Notice = notices().Take(HttpContext);
    }
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        if (!CanRequest) return Failure(503, Unavailable);
        if (ModelState.IsValid) {
            try { Email = EmailAddress.Normalize(Email); }
            catch (ArgumentException) { ModelState.AddModelError(nameof(Email), "Enter a valid email address."); }
        }
        if (!ModelState.IsValid) {
            Response.StatusCode = 400;
            return SenderConfiguration.WantsJson(HttpContext)
                ? new JsonResult(new { message = "Enter a valid email address." }) { StatusCode = 400 } : Page();
        }
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (ip is null) return Failure(503, Unavailable);
        try {
            // Caller-supplied identifiers are never accepted. The identifier is
            // internal bookkeeping, not anonymous lookup authority.
            var result = await requests().RequestAsync(Guid.NewGuid(), Email, ip, ct);
            if (result == LookupRequestOutcome.Unavailable) return Failure(503, Unavailable);
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(NoticeCode.LookupRequested) });
            notices().Set(HttpContext, NoticeCode.LookupRequested);
            return Redirect("/find/request");
        }
        catch (Exception e) when (DocumentLookupBrowser.Unavailable(e) || e is CryptographicException or InvalidOperationException or ArgumentException || Data.SqlResume.IsUnavailable(e))
        { return Failure(503, Unconfirmed); }
    }
    private IActionResult Failure(int status, string message)
    {
        // Private input and authority are never carried in notices or redirects.
        ModelState.Clear(); Email = ""; Message = message; Response.StatusCode = status;
        return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new { message }) { StatusCode = status } : Page();
    }
}

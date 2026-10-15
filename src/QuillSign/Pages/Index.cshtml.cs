using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
using QuillSign.Email;
using QuillSign.Sender;

namespace QuillSign.Pages;

public sealed class IndexModel(SenderAvailability availability, Func<SenderWorkflow> workflow, BrowserNotices notices) : PageModel
{
    [BindProperty, Required, StringLength(320)] public string Email { get; set; } = "";
    public bool CanSend => availability.CanSend;
    public string? Notice { get; private set; }
    public void OnGet()
    {
        Response.Headers.CacheControl = "no-store";
        Notice = notices.Take(HttpContext);
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        if (ModelState.IsValid)
        {
            try { Email = EmailAddress.Normalize(Email); }
            catch (ArgumentException) { ModelState.AddModelError(nameof(Email), "Enter a valid email address."); }
        }
        if (!ModelState.IsValid)
        {
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = "Enter a valid email address." }) { StatusCode = 400 };
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Page();
        }
        NoticeCode code;
        var status = StatusCodes.Status200OK;
        try
        {
            var result = CanSend ? await workflow().RequestAsync(Email, HttpContext.Connection.RemoteIpAddress?.ToString(), Request.Headers.UserAgent.ToString(), cancellationToken)
                : SenderRequestOutcome.Unavailable;
            code = result == SenderRequestOutcome.Unavailable ? NoticeCode.Unavailable : NoticeCode.CheckInbox;
            if (result == SenderRequestOutcome.Unavailable) status = StatusCodes.Status503ServiceUnavailable;
        }
        catch (RecipientSuppressedException) { code = NoticeCode.CheckInbox; }
        catch (Exception e) when (e is SqlException or Azure.RequestFailedException or IOException or System.Security.Cryptography.CryptographicException || SqlResumeUnavailable(e))
        { code = NoticeCode.Retry; status = StatusCodes.Status503ServiceUnavailable; }
        if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(code) }) { StatusCode = status };
        notices.Set(HttpContext, code);
        return Redirect("/");
    }

    private static bool SqlResumeUnavailable(Exception error) => Data.SqlResume.IsUnavailable(error);
}

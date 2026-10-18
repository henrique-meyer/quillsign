using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Completion;
using QuillSign.Sender;

namespace QuillSign.Pages.Lookup;

[RequestSizeLimit(8192)]
public sealed class AccessModel(DocumentLookupBrowser browser, Func<DocumentLookup> lookup) : PageModel
{
    public Guid? PendingNonce { get; private set; }
    public string? Message { get; private set; }
    public void OnGet() { Message = browser.TakeNotice(HttpContext); PendingNonce = browser.PendingNonce(HttpContext); }
    public IActionResult OnPostBegin(string? code)
    {
        ModelState.Clear();
        if (!browser.Begin(HttpContext, code))
        { browser.ClearPending(HttpContext); return Error(400, "Enter the complete access code from your document lookup link."); }
        return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new { url = "/find/access" }) : Redirect("/find/access");
    }
    public async Task<IActionResult> OnPostRedeemAsync(string? nonce, CancellationToken ct)
    {
        ModelState.Clear(); var code = browser.PendingCode(HttpContext, nonce);
        if (code is null) return Error(409, "This pending link expired or another link was prepared in another tab. Return to access entry and check the link you want to open.");
        browser.ClearPending(HttpContext);
        try
        {
            var session = await lookup().RedeemAsync(code, ct);
            if (session is null) return Error(400, "This lookup link is invalid, expired, already used or unavailable. Use a fresh lookup link, or return to a document list you already opened.");
            await browser.SignInAsync(HttpContext, session); return Redirect("/find/documents");
        }
        catch (Exception e) when (DocumentLookupBrowser.Unavailable(e))
        { return Error(503, "Access could not be confirmed. The link may already have been used. Return to your document list if you already opened it, or use a fresh lookup link."); }
    }
    private IActionResult Error(int status, string message)
    {
        Message = message; Response.StatusCode = status;
        return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new { message }) { StatusCode = status } : Page();
    }
}

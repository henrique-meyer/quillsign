using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Completion;
using QuillSign.Sender;

namespace QuillSign.Pages.Complete;

[RequestSizeLimit(8192)]
public sealed class AccessModel(CompletionReaderBrowser browser,Func<CompletionAccess> access) : PageModel
{
    public Guid? PendingNonce {get;private set;}
    public string? Message {get;private set;}
    public void OnGet() {Private();PendingNonce=browser.PendingNonce(HttpContext);}
    public IActionResult OnPostBegin(string? code)
    {
        Private(); ModelState.Clear();
        if(!browser.Begin(HttpContext,code)) {
            browser.ClearPending(HttpContext); return Error(400,"Enter the complete access code from your completion link.");
        }
        return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new {url="/complete/access"}) : Redirect("/complete/access");
    }
    public async Task<IActionResult> OnPostRedeemAsync(string? nonce,CancellationToken ct)
    {
        Private(); ModelState.Clear(); var code=browser.PendingCode(HttpContext,nonce);
        if(code is null)return Error(409,"This pending link expired or another link was prepared in another tab. Return to access entry and check the link you want to open.");
        browser.ClearPending(HttpContext);
        try {
            var session=await access().RedeemAsync(code,ct);
            if(session is null)return Error(400,"This link is invalid, expired, already used or unavailable. If you cannot access your records, contact the sender for another copy.");
            await browser.SignInAsync(HttpContext,session); return Redirect("/complete/"+session.Identity.PublicId);
        } catch(Exception e) when(Sign.FieldsModel.StorageError(e)) {
            return Error(503,"Access could not be confirmed. The link may already have been used. Return to your records if you already opened them, or contact the sender for another copy.");
        }
    }
    private IActionResult Error(int status,string message) {
        Message=message; Response.StatusCode=status;
        return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new {message}) {StatusCode=status} : Page();
    }
    private void Private() {Response.Headers.CacheControl="no-store";Response.Headers["Referrer-Policy"]="no-referrer";}
}

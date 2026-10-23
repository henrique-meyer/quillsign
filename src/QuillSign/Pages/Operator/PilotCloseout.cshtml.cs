using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Data;
using QuillSign.Email.Pilot;
using QuillSign.Sender;

namespace QuillSign.Pages.Operator;

[RequestSizeLimit(8192)]
public sealed class PilotCloseoutModel(EmailPilotCloseoutOperatorBrowser browser,Func<EmailPilotCloseoutOperator> backend):PageModel
{
    [BindProperty,FromForm] public string Capability {get;set;}="";
    public bool Unlocked {get;private set;}
    public EmailPilotCloseoutOperatorStatus? Saved {get;private set;}
    public string? Message {get;private set;}
    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);if(!browser.Available)return NotFound();
        var session=browser.Read(HttpContext);Unlocked=session is not null;if(session is null)return Page();Message=Text(browser.TakeNotice(HttpContext,session));
        try {Saved=await backend().ReadAsync(session,ct);}catch(Exception e)when(Unavailable(e)){Message=Text(EmailPilotOperatorNotice.Unavailable);Response.StatusCode=503;}
        return Page();
    }
    public IActionResult OnPostUnlock()
    {
        EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);var supplied=Capability;Capability="";ModelState.Clear();
        if(!browser.Available)return NotFound();if(!browser.Unlock(HttpContext,supplied))return Failure(403,"Closeout operator access is unavailable.");
        return SenderConfiguration.WantsJson(HttpContext)?new JsonResult(new{message="Closeout controls opened."}):Redirect(EmailPilotCloseoutOperatorBrowser.Path);
    }
    public IActionResult OnPostLock(){EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);browser.Lock(HttpContext);return Redirect(EmailPilotCloseoutOperatorBrowser.Path);}
    public async Task<IActionResult> OnPostReceiptAsync(CancellationToken ct)
    {
        EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);Capability="";ModelState.Clear();
        var session=browser.ReadReceipt(HttpContext);if(session is null)return Failure(403,"A live closeout receipt session is required.");
        try {return new JsonResult(await backend().ReadCommittedReceiptAsync(session,ct),new JsonSerializerOptions{PropertyNamingPolicy=null});}
        catch(Exception e)when(Unavailable(e)){return Failure(503,"The committed receipt is unavailable.");}
    }
    public Task<IActionResult> OnPostStartAsync(CancellationToken ct)=>Act((b,s)=>b.StartAsync(s,ct));
    public Task<IActionResult> OnPostVerificationAsync(CancellationToken ct)=>Act((b,s)=>b.VerifyDeclineAsync(s,ct));
    public Task<IActionResult> OnPostLookupAsync(CancellationToken ct)=>Act((b,s)=>b.LookupAsync(s,HttpContext.Connection.RemoteIpAddress?.ToString(),ct));
    private async Task<IActionResult> Act(Func<EmailPilotCloseoutOperator,EmailPilotCloseoutOperatorSession,Task<EmailPilotOperatorNotice>> action)
    {
        EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);Capability="";ModelState.Clear();if(!browser.Available)return NotFound();
        var session=browser.Read(HttpContext);if(session is null)return Failure(403,"Closeout operator access is required.");
        EmailPilotOperatorNotice code;try {code=await action(backend(),session);}catch(Exception e)when(Unavailable(e)){return Failure(503,"The outcome is unconfirmed. Check saved status before the same action.");}
        if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new{message=Text(code)});
        browser.SetNotice(HttpContext,session,code);return Redirect(EmailPilotCloseoutOperatorBrowser.Path);
    }
    private IActionResult Failure(int status,string message)
    {Capability="";ModelState.Clear();Message=message;Response.StatusCode=status;return SenderConfiguration.WantsJson(HttpContext)?new JsonResult(new{message}){StatusCode=status}:Page();}
    private static bool Unavailable(Exception e)=>e is InvalidOperationException or InvalidDataException or CryptographicException or JsonException or ArgumentException or IOException or HttpRequestException or Azure.RequestFailedException or EmailPilotAccessUnavailableException || SqlResume.IsUnavailable(e);
    private static string? Text(EmailPilotOperatorNotice? n)=>n switch {
        EmailPilotOperatorNotice.EnvelopeSaved=>"The selected work is saved. Continue only through the ordinary test inbox links.",
        EmailPilotOperatorNotice.LookupSaved=>"The single lookup is saved. Delivery is not yet confirmed.",
        EmailPilotOperatorNotice.WakePending=>"The saved work wakeup is unconfirmed. Check its status; no new step or allowance is created.",
        EmailPilotOperatorNotice.Unavailable=>"This closeout action is unavailable. Check the fixed deadline and saved evidence.",_=>null};
}

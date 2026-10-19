using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Data;
using QuillSign.Email.Pilot;
using QuillSign.Sender;

namespace QuillSign.Pages.Operator;

[RequestSizeLimit(8192)]
public sealed class PilotModel(EmailPilotOperatorBrowser browser,Func<EmailPilotOperator> backend):PageModel
{
    [BindProperty,FromForm] public string Capability {get;set;}="";
    public bool Unlocked {get;private set;}
    public EmailPilotOperatorStatus? Saved {get;private set;}
    public string? Message {get;private set;}
    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);
        if(!browser.Available)return NotFound();
        var session=browser.Read(HttpContext);Unlocked=session is not null;
        if(session is null)return Page();
        Message=Text(browser.TakeNotice(HttpContext,session));
        try {Saved=await backend().ReadAsync(session,ct);}
        catch(Exception e)when(Unavailable(e)){Message=Text(EmailPilotOperatorNotice.Unavailable);Response.StatusCode=503;}
        return Page();
    }
    public IActionResult OnPostUnlock()
    {
        EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);
        var supplied=Capability;Capability="";ModelState.Clear();
        if(!browser.Available)return NotFound();
        if(!browser.Unlock(HttpContext,supplied))return Failure(403,"Operator access is unavailable.");
        return SenderConfiguration.WantsJson(HttpContext)?new JsonResult(new{message="Operator access opened."}):Redirect(EmailPilotOperatorBrowser.Path);
    }
    public IActionResult OnPostLock()
    {EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);browser.Lock(HttpContext);return Redirect(EmailPilotOperatorBrowser.Path);}
    public Task<IActionResult> OnPostEnvelopeAsync([FromForm]EmailPilotScenario scenario,CancellationToken ct)=>
        Act((b,s)=>b.EnvelopeAsync(s,scenario,HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct));
    public Task<IActionResult> OnPostLookupAsync(CancellationToken ct)=>
        Act((b,s)=>b.LookupAsync(s,HttpContext.Connection.RemoteIpAddress?.ToString(),ct));
    public Task<IActionResult> OnPostSimulatorAsync([FromForm]EmailPilotSimulatorKind kind,CancellationToken ct)=>Act((b,s)=>b.SimulatorAsync(s,kind,ct));
    private async Task<IActionResult> Act(Func<EmailPilotOperator,EmailPilotOperatorSession,Task<EmailPilotOperatorNotice>> action)
    {
        EmailPilotOperatorBrowser.PrivateHeaders(HttpContext);Capability="";ModelState.Clear();
        if(!browser.Available)return NotFound();
        var session=browser.Read(HttpContext);if(session is null)return Failure(403,"Operator access is required.");
        EmailPilotOperatorNotice code;
        try {code=await action(backend(),session);}
        catch(Exception e)when(Unavailable(e)){return Failure(503,"The outcome is unconfirmed. Check saved status before retrying the same action.");}
        if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new{message=Text(code)});
        browser.SetNotice(HttpContext,session,code);return Redirect(EmailPilotOperatorBrowser.Path);
    }
    private IActionResult Failure(int status,string message)
    {Capability="";ModelState.Clear();Message=message;Response.StatusCode=status;return SenderConfiguration.WantsJson(HttpContext)?new JsonResult(new{message}){StatusCode=status}:Page();}
    private static bool Unavailable(Exception e)=>e is InvalidOperationException or CryptographicException or JsonException or ArgumentException or IOException or HttpRequestException or Azure.RequestFailedException or EmailPilotAccessUnavailableException || SqlResume.IsUnavailable(e);
    private static string? Text(EmailPilotOperatorNotice? notice)=>notice switch {
        EmailPilotOperatorNotice.EnvelopeSaved=>"The scenario is saved. Open the sender verification message in the test inbox to continue normally.",
        EmailPilotOperatorNotice.LookupSaved=>"The lookup request is saved. Use its message in the test inbox; delivery is not yet confirmed.",
        EmailPilotOperatorNotice.SimulatorSaved=>"The simulator request is saved. Check signed feedback evidence before recording a result.",
        EmailPilotOperatorNotice.WakePending=>"Work is saved but its wakeup is unconfirmed. Retry the same action to recover it; no new run or budget is created.",
        EmailPilotOperatorNotice.Unavailable=>"This action is unavailable. Check saved status and the fixed deadline before retrying.",_=>null};
}

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes=EnvelopeStorageAuthorization.SenderScheme)]
[ResponseCache(NoStore=true,Location=ResponseCacheLocation.None)]
[RequestSizeLimit(16000)]
[RequestFormLimits(ValueLengthLimit=2048,ValueCountLimit=8)]
public sealed class VoidModel(SenderVoidState state,SenderVoid action,BrowserNotices notices) : PageModel
{
    public SenderVoidPreview? Data {get;private set;}
    public string? ErrorMessage {get;private set;}
    public bool ReloadRequired {get;private set;}
    [BindProperty] public string? Version {get;set;}
    [BindProperty] public string? Reason {get;set;}
    [BindProperty] public bool Confirmed {get;set;}
    [BindProperty] public string? StatementVersion {get;set;}
    private void Private() {Response.Headers.CacheControl="no-store";Response.Headers["Referrer-Policy"]="no-referrer";}
    private async Task<AuthenticateResult?> Ticket(string publicId)
    {
        var ticket=await HttpContext.AuthenticateAsync(EnvelopeStorageAuthorization.SenderScheme);
        return ticket.Succeeded && ticket.Principal is not null && ticket.Properties?.ExpiresUtc is not null &&
            SendDraftWorkflow.Identity(ticket.Principal,publicId) is not null ? ticket : null;
    }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Private();var ticket=await Ticket(publicId);if(ticket is null)return NotFound();
        try {
            Data=await state.PreviewAsync(ticket.Principal!,publicId,ticket.Properties!.ExpiresUtc!.Value,ct);if(Data is null)return NotFound();
            Version=Data.Version;StatementVersion=SenderVoidStatement.Version;
            return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(Data) : Page();
        } catch(Exception e) when(ReviewModel.StorageError(e)) {return Unavailable();}
    }
    public async Task<IActionResult> OnPostRefreshAsync(string publicId,CancellationToken ct)
    {
        Private();var ticket=await Ticket(publicId);if(ticket is null)return NotFound();
        // Refresh is metadata-only. Keep the attempted reason and require a new affirmation.
        try {
            Data=await state.PreviewAsync(ticket.Principal!,publicId,ticket.Properties!.ExpiresUtc!.Value,ct);if(Data is null)return NotFound();
            ModelState.Remove(nameof(Version));ModelState.Remove(nameof(Confirmed));ModelState.Remove(nameof(StatementVersion));
            Version=Data.Version;Confirmed=false;StatementVersion=SenderVoidStatement.Version;
            return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new {Data,reason=Reason,confirmed=false}) : Page();
        } catch(Exception e) when(ReviewModel.StorageError(e)) {return Unavailable();}
    }
    public async Task<IActionResult> OnPostAsync(string publicId,CancellationToken ct)
    {
        Private();var ticket=await Ticket(publicId);if(ticket is null)return NotFound();
        byte[] version;
        try {version=Convert.FromBase64String(Version??"");}
        catch(FormatException) {return await Failure(ticket,publicId,409,"Refresh the saved details before confirming a void.",true,ct);}
        if(version.Length!=8 || Convert.ToBase64String(version)!=Version)return await Failure(ticket,publicId,409,"Refresh the saved details before confirming a void.",true,ct);
        if(!ModelState.IsValid || !Confirmed || StatementVersion!=SenderVoidStatement.Version || !SenderVoidState.Reason(Reason,out _))
            return await Failure(ticket,publicId,400,"Check the reason and affirm the void statement before confirming.",false,ct);
        try {
            var result=await action.VoidAsync(ticket.Principal!,publicId,ticket.Properties!.ExpiresUtc!.Value,version,Confirmed,StatementVersion,Reason,
                HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
            if(result.Outcome is SenderVoidOutcome.Voided or SenderVoidOutcome.AlreadyVoided) {
                var target="/draft/"+publicId+"/sent";
                if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new {message=BrowserNotices.Text(NoticeCode.RequestVoided),confirmation=target,action=result.Action});
                notices.Set(HttpContext,NoticeCode.RequestVoided);return Redirect(target);
            }
            if(result.Outcome==SenderVoidOutcome.InvalidContext)return NotFound();
            return await Failure(ticket,publicId,result.Outcome==SenderVoidOutcome.InvalidConfirmation ? 400 : 409,
                result.Outcome==SenderVoidOutcome.Closed ? "This request is closed and cannot be voided. Check its saved status." : "These details changed. Refresh and review the saved request before confirming again.",true,ct);
        } catch(Exception e) when(ReviewModel.StorageError(e)) {
            return await Failure(ticket,publicId,503,"Void could not be confirmed from this response. Check saved status before retrying; do not assume the request is unchanged or that notices were delivered.",true,ct);
        }
    }
    private async Task<IActionResult> Failure(AuthenticateResult ticket,string publicId,int status,string message,bool reload,CancellationToken ct)
    {
        if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new {message,checkStatus="/draft/"+publicId+"/sent"}) {StatusCode=status};
        ErrorMessage=message;ReloadRequired=reload;Response.StatusCode=status;
        if(reload) {Confirmed=false;ModelState.Remove(nameof(Confirmed));}
        try {Data=await state.PreviewAsync(ticket.Principal!,publicId,ticket.Properties!.ExpiresUtc!.Value,ct);}
        catch(Exception e) when(ReviewModel.StorageError(e)) { }
        return Page();
    }
    private IActionResult Unavailable()
    {
        const string message="Saved request details could not be verified. Retry later; no void was requested by this read.";
        ErrorMessage=message;Response.StatusCode=503;
        return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new {message}) {StatusCode=503} : Page();
    }
}

using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Signing;

namespace QuillSign.Pages.Sign;
[Authorize(AuthenticationSchemes=SignerAccessConfiguration.Scheme)]
[RequestSizeLimit(32000)]
[RequestFormLimits(ValueLengthLimit=8192,ValueCountLimit=8)]
public sealed class DeclineModel(SignerAccess access,SignerConsent consent):PageModel
{
    public SignerReadContext? Context {get;private set;}
    public string? ErrorMessage {get;private set;}
    [BindProperty,StringLength(512)] public string? Reason {get;set;}
    [BindProperty] public bool ConfirmDecline {get;set;}
    private void Private(){Response.Headers.CacheControl="no-store";Response.Headers["Referrer-Policy"]="no-referrer";}
    private async Task<bool> Load(string publicId,CancellationToken ct)
    {Context=await access.GetContextAsync(User,publicId,ct);return Context is not null && access.IsLive(Context);}
    private async Task<bool> WasDeclined(string publicId,CancellationToken ct)
        =>await access.GetContextAsync(User,publicId,ct,declinedConfirmation:true) is not null;
    private IActionResult Confirmed(string publicId)=>Redirect("/sign/"+publicId+"/declined");
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Private();
        try {return await Load(publicId,ct) ? Page() : NotFound();}
        catch(Exception e) when(FieldsModel.StorageError(e)){return Failure();}
    }
    public async Task<IActionResult> OnPostAsync(string publicId,CancellationToken ct)
    {
        Private();
        try
        {
            if(!await Load(publicId,ct))return await WasDeclined(publicId,ct) ? Confirmed(publicId) : NotFound();
            if(!ConfirmDecline)ModelState.AddModelError(nameof(ConfirmDecline),"Confirm that you choose to decline this signing request.");
            if(!ModelState.IsValid){Response.StatusCode=400;return Page();}
            var saved=await consent.DeclineAsync(User,publicId,Reason,HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
            if(saved is not null || await WasDeclined(publicId,ct))return Confirmed(publicId);
            return NotFound();
        }
        catch(ArgumentException error){ModelState.AddModelError("",error.Message);Response.StatusCode=400;return Page();}
        catch(Exception e) when(FieldsModel.StorageError(e))
        {
            // A lost commit/publication response must not report a false failure or create another decline.
            try {if(await WasDeclined(publicId,ct))return Confirmed(publicId);}
            catch(Exception read) when(FieldsModel.StorageError(read)){ }
            return Failure();
        }
    }
    private IActionResult Failure()
    {Context=null;ErrorMessage="The saved request could not be verified. Reload later to check its state; do not assume your decline was recorded.";Response.StatusCode=503;return Page();}
}

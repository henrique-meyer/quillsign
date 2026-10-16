using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Signing;

namespace QuillSign.Pages.Sign;

[Authorize(AuthenticationSchemes=SignerAccessConfiguration.Scheme)]
[RequestSizeLimit(32000)]
[RequestFormLimits(ValueLengthLimit=8192,ValueCountLimit=12)]
public sealed class FieldsModel(SignerFieldView view,SignerFields fields,SignerAccess access,BrowserNotices notices) : PageModel
{
    public SignerFieldViewData? Data { get; private set; }
    public string? ErrorMessage { get; private set; }
    public string? Notice { get; private set; }
    [BindProperty] public Guid FieldId { get; set; }
    [BindProperty] public string? Version { get; set; }
    [BindProperty] public string? Action { get; set; }
    [BindProperty, System.ComponentModel.DataAnnotations.DisplayFormat(ConvertEmptyStringToNull=false)] public string? Value { get; set; }
    [BindProperty] public Guid? AdoptionId { get; set; }
    private void Private() { Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer"; }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Private();
        try { Data=await view.ReadAsync(User,publicId,true,ct); if(Data is null)return NotFound(); Notice=notices.Take(HttpContext); return Page(); }
        catch(Exception e) when(StorageError(e)) { ErrorMessage="The document or adopted marks could not be verified. Reload later; no field was changed."; Response.StatusCode=503; return Page(); }
    }
    public async Task<IActionResult> OnGetSnapshotAsync(string publicId,CancellationToken ct)
    {
        Private();
        try { var data=await view.ReadAsync(User,publicId,false,ct); return data is null ? NotFound() : new JsonResult(new { data.Snapshot,data.Marks },SignerFieldViewData.Json); }
        catch(Exception e) when(StorageError(e)) { return Error(503,"Saved marks could not be verified. Your attempted entry is still in this browser. Reload or retry later."); }
    }
    public async Task<IActionResult> OnPostAsync(string publicId,CancellationToken ct)
    {
        Private(); if((await access.GetContextAsync(User,publicId,ct))?.ConsentAt is null)return NotFound();
        if(!ModelState.IsValid || !Enum.TryParse<SignerFieldAction>(Action,false,out var action) || !Enum.IsDefined(action) || action.ToString()!=Action || Version is null)
            return Error(400,"Choose an explicit Apply or Clear action for the selected field.");
        try
        {
            var result=await fields.ChangeAsync(User,publicId,new(FieldId,Version,action,Value,AdoptionId),
                HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
            if(result.Outcome==SignerFieldOutcome.NotFound)return NotFound();
            var status=result.Outcome switch { SignerFieldOutcome.Applied or SignerFieldOutcome.AlreadyApplied=>200,SignerFieldOutcome.Conflict or SignerFieldOutcome.InvalidAdoption=>409,_=>400 };
            var message=result.Outcome switch {
                SignerFieldOutcome.Applied or SignerFieldOutcome.AlreadyApplied=>"Field saved. Signing is not complete.",
                SignerFieldOutcome.Conflict=>"This field changed in another tab. Your attempted entry is preserved. Review the latest saved value before explicitly trying again.",
                SignerFieldOutcome.InvalidAdoption=>"Your adopted marks changed or are unavailable. Reload the saved state before explicitly applying a mark again.",
                SignerFieldOutcome.ReadOnly=>"Date Signed is set by the server only at Finish.",_=>"This value was not saved. Check the field format and try again." };
            if(status==200 && !SenderConfiguration.WantsJson(HttpContext)) { notices.Set(HttpContext,NoticeCode.SignerFieldSaved); return Redirect("/sign/"+publicId+"/fields"); }
            return new JsonResult(new { message,outcome=result.Outcome,field=result.Field },SignerFieldViewData.Json) { StatusCode=status };
        }
        catch(Exception e) when(StorageError(e)) { return Error(503,"Saving could not be confirmed. Your attempted entry is preserved. Refresh saved state before retrying; do not assume it was accepted."); }
    }
    internal static bool StorageError(Exception e) => e is RequestFailedException or IOException or InvalidDataException or DocumentRejectedException or DbUpdateException or Microsoft.Data.SqlClient.SqlException;
    private static JsonResult Error(int status,string message)=>new(new { message }) { StatusCode=status };
}

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;
using QuillSign.Signing;

namespace QuillSign.Pages.Sign;
[Authorize(AuthenticationSchemes=SignerAccessConfiguration.Scheme)]
[RequestSizeLimit(32000)]
[RequestFormLimits(ValueLengthLimit=8192,ValueCountLimit=12)]
public sealed class ReviewModel(SignerFieldView view,SignerReviewCandidates reviews,SignerReviewProtection protection,
    SignerReviewBrowser browser,SignerFinish finish,SignerCheckpointReads checkpoints,BrowserNotices notices) : PageModel
{
    public SignerFieldViewData? Data { get; private set; }
    public SignerReviewPrepared? Candidate { get; private set; }
    public string? ErrorMessage { get; private set; }
    public string? Notice { get; private set; }
    [BindProperty] public bool Reviewed { get; set; }
    [BindProperty] public bool Acknowledged { get; set; }
    [BindProperty] public string? AccessMethod { get; set; }
    [BindProperty] public string? StatementVersion { get; set; }
    private void Private() { Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer"; }
    private async Task<bool> Load(string publicId,CancellationToken ct)
    {
        Data=await view.ReadAsync(User,publicId,true,ct); if(Data is null)return false;
        var receipt=browser.Get(HttpContext,SignerReviewBrowser.ReviewCookie);
        if(receipt is not null) {
            Candidate=(await reviews.ReadAsync(User,publicId,receipt,ct))?.Candidate;
            if(Candidate is null) {
                ErrorMessage??="The earlier review expired or changed. Prepare a new review after checking your saved entries.";
                browser.Clear(HttpContext,SignerReviewBrowser.ReviewCookie,publicId); browser.Clear(HttpContext,SignerReviewBrowser.AccessCookie,publicId);
            }
        }
        return true;
    }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Private();
        try { if(!await Load(publicId,ct))return NotFound(); Notice=notices.Take(HttpContext); return Page(); }
        catch(Exception e) when(FieldsModel.StorageError(e)) { return await Failure(publicId,503,"The saved document or marks could not be verified. Retry later; signing is not complete.",ct,false); }
    }
    public async Task<IActionResult> OnPostPrepareAsync(string publicId,CancellationToken ct)
    {
        Private();
        try {
            Data=await view.ReadAsync(User,publicId,true,ct); if(Data is null)return NotFound();
            if(!ModelState.IsValid || Data.Missing!=0 || Data.Stale!=0 || Data.Marks is null)
                return await Failure(publicId,400,"Save all required entries and reapply or clear stale marks before preparing the review.",ct);
            var prepared=await reviews.PrepareAsync(User,publicId,HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
            if(prepared is null)return await Failure(publicId,409,"Saved entries changed. Check them and explicitly prepare a new review.",ct);
            browser.Put(HttpContext,SignerReviewBrowser.ReviewCookie,prepared.Receipt,Data.Context.Identity);
            browser.Clear(HttpContext,SignerReviewBrowser.AccessCookie,publicId);
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { message="Review prepared. Open the exact PDF before Finish.",prepared.ExpiresAt,prepared.ProspectiveDate });
            notices.Set(HttpContext,NoticeCode.SignerReviewPrepared); return Redirect("/sign/"+publicId+"/review");
        }
        catch(Exception e) when(FieldsModel.StorageError(e) || e is InvalidOperationException)
        { return await Failure(publicId,503,"Review preparation could not be confirmed. Retry explicitly later; Finish was not requested.",ct,false); }
    }
    public async Task<IActionResult> OnGetPdfAsync(string publicId,bool download,CancellationToken ct)
    {
        Private();
        try {
            var identity=browser.Identity(HttpContext,publicId); if(identity is null)return NotFound();
            var receipt=browser.Get(HttpContext,SignerReviewBrowser.ReviewCookie);
            if(protection.Read(receipt,identity) is null)return NotFound();
            var data=await reviews.ReadAsync(User,publicId,receipt,ct); if(data is null)return NotFound();
            // Full exact bytes and current snapshot were checked before issuing access evidence.
            browser.PreparedPdf(HttpContext,data.Candidate,receipt!,identity);
            var result=new FileContentResult(data.Pdf,"application/pdf") { EnableRangeProcessing=false };
            if(download)result.FileDownloadName="signer-review.pdf"; return result;
        }
        catch(Exception e) when(FieldsModel.StorageError(e)) { return StatusCode(503,"The exact review PDF could not be verified. Retry later; Finish is unavailable."); }
    }
    public async Task<IActionResult> OnPostFinishAsync(string publicId,CancellationToken ct)
    {
        Private();
        try {
            var identity=browser.Identity(HttpContext,publicId); if(identity is null)return NotFound();
            var receipt=browser.Get(HttpContext,SignerReviewBrowser.ReviewCookie); var token=protection.ReadAccepted(receipt,identity);
            if(token is null)return await Failure(publicId,400,"Prepare a current review and open its PDF before selecting Finish.",ct);
            var accepted=await checkpoints.ConfirmAsync(User,publicId,receipt,ct);
            if(!ModelState.IsValid || !Reviewed || !Acknowledged || AccessMethod is not ("preview" or "download") ||
                StatementVersion!=SignerFinishStatement.Version || !browser.HasAccess(HttpContext,token,receipt!,accepted is not null))
                return await Failure(publicId,400,"Open this exact review PDF, confirm your review and intent, then select Finish. Your entries have not been changed by this attempt.",ct);
            var result=await finish.AcceptAsync(User,publicId,receipt,true,StatementVersion,HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
            if(result.Outcome==SignerFinishOutcome.InvalidContext)return NotFound();
            if(result.Outcome is not (SignerFinishOutcome.Accepted or SignerFinishOutcome.AlreadyAccepted))
                return await Failure(publicId,409,"This review is expired or changed. Check saved entries and explicitly prepare a new review before Finish.",ct);
            browser.Put(HttpContext,SignerReviewBrowser.AcceptedCookie,receipt!,identity);
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { message="Finish accepted. Your entries are frozen.",confirmation="/sign/"+publicId+"/confirmed",result.Acceptance });
            notices.Set(HttpContext,NoticeCode.SignerFinishAccepted); return Redirect("/sign/"+publicId+"/confirmed");
        }
        catch(Exception e) when(FieldsModel.StorageError(e) || e is InvalidOperationException)
        { return await Failure(publicId,503,"Finish could not be confirmed. Reload to check for an accepted Finish before retrying.",ct); }
    }
    private async Task<IActionResult> Failure(string publicId,int status,string message,CancellationToken ct,bool load=true)
    {
        if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { message }) { StatusCode=status };
        ErrorMessage=message; Response.StatusCode=status;
        if(load)try { _=await Load(publicId,ct); } catch(Exception e) when(FieldsModel.StorageError(e)) { Candidate=null; }
        return Page();
    }
}

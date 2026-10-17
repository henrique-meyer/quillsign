using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Pages.Sign;
[Authorize(AuthenticationSchemes=SignerAccessConfiguration.Scheme)]
public sealed class ConfirmedModel(SignerReviewBrowser browser,SignerReviewProtection protection,SignerCheckpointReads checkpoints,BrowserNotices notices,Func<CompletionDownloads>? downloads=null,TimeProvider? time=null) : PageModel
{
    public FinalDownloadAvailability? Final {get;private set;}
    public SignerFinishAccepted? Acceptance { get; private set; }
    public string? Notice { get; private set; }
    public string? ErrorMessage { get; private set; }
    private void Private() { Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer"; }
    private string? Receipt()=>browser.Get(HttpContext,SignerReviewBrowser.AcceptedCookie)??browser.Get(HttpContext,SignerReviewBrowser.ReviewCookie);
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Private();
        try {
            var identity=browser.Identity(HttpContext,publicId); if(identity is null)return NotFound();
            var receipt=Receipt(); if(protection.ReadAccepted(receipt,identity) is null)return NotFound();
            var scope=await checkpoints.ConfirmScopeAsync(User,publicId,receipt,ct);if(scope is null)return NotFound();Acceptance=scope.Acceptance;
            if(downloads is not null)Final=await downloads().AvailabilityAsync(HttpContext,publicId,PartyType.Signer,ct);
            DocumentRetentionAccess.Check(scope.RetentionDeadline,time??TimeProvider.System);
            if(identity.SessionExpiresAt<=(time??TimeProvider.System).GetUtcNow()){Acceptance=null;Final=null;return NotFound();}
            browser.Put(HttpContext,SignerReviewBrowser.AcceptedCookie,receipt!,identity); Notice=notices.Take(HttpContext); return Page();
        }
        catch(Exception e) when(FieldsModel.StorageError(e)) { Acceptance=null;Final=null;ErrorMessage="Your saved Finish could not be verified right now. Retry later; do not assume signing failed."; Response.StatusCode=503; return Page(); }
    }
    public async Task<IActionResult> OnGetPdfAsync(string publicId,CancellationToken ct)
    {
        Private();
        try {
            var identity=browser.Identity(HttpContext,publicId); if(identity is null)return NotFound();
            var receipt=Receipt(); if(protection.ReadAccepted(receipt,identity) is null)return NotFound();
            var data=await checkpoints.ReadAsync(User,publicId,receipt,ct); return data is null ? NotFound() : File(data.Pdf,"application/pdf","your-signing-copy.pdf");
        }
        catch(Exception e) when(FieldsModel.StorageError(e)) { return StatusCode(503,"Your signing copy could not be verified. Retry later."); }
    }
    public async Task<IActionResult> OnPostDownloadAsync(string publicId,string kind,CancellationToken ct)
    {
        Private();
        try {
            var prepared=downloads is null ? null : await downloads().PrepareAsync(HttpContext,publicId,PartyType.Signer,kind,ct);
            if(prepared is null)return NotFound("A final download is not available in this session. Refresh your signing confirmation.");
            return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(prepared) : new RedirectResult(prepared.Url);
        } catch(Exception e) when(FieldsModel.StorageError(e)) {
            const string message="The final download could not be verified. Your Finish is unchanged. Return to your signing confirmation or try preparing the download again later.";
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new {message}) {StatusCode=503};
            var result=await OnGetAsync(publicId,ct); ErrorMessage=message; Response.StatusCode=503; return result;
        }
    }
}

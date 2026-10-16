using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;
using QuillSign.Signing;

namespace QuillSign.Pages.Sign;
[Authorize(AuthenticationSchemes=SignerAccessConfiguration.Scheme)]
public sealed class ConfirmedModel(SignerReviewBrowser browser,SignerCheckpointReads checkpoints,BrowserNotices notices) : PageModel
{
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
            var receipt=Receipt(); Acceptance=await checkpoints.ConfirmAsync(User,publicId,receipt,ct); if(Acceptance is null)return NotFound();
            browser.Put(HttpContext,SignerReviewBrowser.AcceptedCookie,receipt!,identity); Notice=notices.Take(HttpContext); return Page();
        }
        catch(Exception e) when(FieldsModel.StorageError(e)) { ErrorMessage="Your saved Finish could not be verified right now. Retry later; do not assume signing failed."; Response.StatusCode=503; return Page(); }
    }
    public async Task<IActionResult> OnGetPdfAsync(string publicId,CancellationToken ct)
    {
        Private();
        try { var data=await checkpoints.ReadAsync(User,publicId,Receipt(),ct); return data is null ? NotFound() : File(data.Pdf,"application/pdf","your-signing-copy.pdf"); }
        catch(Exception e) when(FieldsModel.StorageError(e)) { return StatusCode(503,"Your signing copy could not be verified. Retry later."); }
    }
}

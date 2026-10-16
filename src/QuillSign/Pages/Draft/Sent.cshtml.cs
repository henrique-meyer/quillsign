using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;
[Authorize(AuthenticationSchemes=EnvelopeStorageAuthorization.SenderScheme)]
public sealed class SentModel(SenderSentStatus status,BrowserNotices notices) : PageModel
{
    public SenderSentSnapshot? Data { get; private set; }
    public string? Notice { get; private set; }
    public string? ErrorMessage { get; private set; }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer";
        try {
            Data=await status.GetAsync(User,publicId,ct:ct); if(Data is null)return NotFound();
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { Data.PublicId,Data.Title,state=Data.State,Data.SentAt,Data.ExpiresAt,Data.Signers,Data.Recipients });
            Notice=notices.Take(HttpContext); return Page();
        }
        catch(Exception e) when(ReviewModel.StorageError(e)) { ErrorMessage="Saved request status could not be verified. Retry later; do not assume delivery or completion."; Response.StatusCode=503; return Page(); }
    }
}

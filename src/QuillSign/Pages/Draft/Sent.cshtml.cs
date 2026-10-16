using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Completion;
using QuillSign.Data;

namespace QuillSign.Pages.Draft;
[Authorize(AuthenticationSchemes=EnvelopeStorageAuthorization.SenderScheme)]
public sealed class SentModel(SenderSentStatus status,BrowserNotices notices,Func<CompletionDownloads>? downloads=null) : PageModel
{
    public FinalDownloadAvailability? Final {get;private set;}
    public SenderSentSnapshot? Data { get; private set; }
    public string? Notice { get; private set; }
    public string? ErrorMessage { get; private set; }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer";
        try {
            Data=await status.GetAsync(User,publicId,ct:ct); if(Data is null)return NotFound();
            if(downloads is not null)Final=await downloads().AvailabilityAsync(HttpContext,publicId,PartyType.Sender,ct);
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { Data.PublicId,Data.Title,state=Data.State,Data.SentAt,Data.ExpiresAt,Data.Signers,Data.Recipients });
            Notice=notices.Take(HttpContext); return Page();
        }
        catch(Exception e) when(ReviewModel.StorageError(e)) { ErrorMessage="Saved request status could not be verified. Retry later; do not assume delivery or completion."; Response.StatusCode=503; return Page(); }
    }
    public async Task<IActionResult> OnPostDownloadAsync(string publicId,string kind,CancellationToken ct)
    {
        Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer";
        try {
            var prepared=downloads is null ? null : await downloads().PrepareAsync(HttpContext,publicId,PartyType.Sender,kind,ct);
            if(prepared is null)return NotFound("A final download is not available in this session. Refresh your private request status.");
            return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(prepared) : new RedirectResult(prepared.Url);
        } catch(Exception e) when(ReviewModel.StorageError(e)) {
            const string message="The final download could not be verified. Your saved request is unchanged. Return to private status or try preparing the download again later.";
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new {message}) {StatusCode=503};
            var result=await OnGetAsync(publicId,ct); ErrorMessage=message; Response.StatusCode=503; return result;
        }
    }
}

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Completion;
using QuillSign.Sender;

namespace QuillSign.Pages.Complete;

public sealed class RecordsModel(CompletionReaderBrowser browser,Func<CompletionDownloads> downloads) : PageModel
{
    public CompletionReaderView? Records {get;private set;}
    public string? Message {get;private set;}
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Private();
        try {
            Records=(await browser.AuthenticateAsync(HttpContext,publicId,ct))?.View;
            if(Records is null) {Message="Completed records are unavailable in this session. Use your completion link or contact the sender for another copy.";Response.StatusCode=404;}
        } catch(Exception e) when(Sign.FieldsModel.StorageError(e)) {Message="Completed records could not be verified right now. Refresh this page to try again later.";Response.StatusCode=503;}
        return Page();
    }
    public async Task<IActionResult> OnPostDownloadAsync(string publicId,string kind,CancellationToken ct)
    {
        Private();
        try {
            var prepared=await downloads().PrepareReaderAsync(HttpContext,publicId,kind,ct);
            if(prepared is null) {Message="A download is unavailable in this session. Refresh your completed records or use your completion link.";Response.StatusCode=404;return Page();}
            return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(prepared) : Redirect(prepared.Url);
        } catch(Exception e) when(Sign.FieldsModel.StorageError(e)) {
            Message="The saved final files could not be verified. Refresh your completed records to try preparing the download again later.";Response.StatusCode=503;
            return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new {message=Message}) {StatusCode=503} : Page();
        }
    }
    private void Private() {Response.Headers.CacheControl="no-store";Response.Headers["Referrer-Policy"]="no-referrer";}
}

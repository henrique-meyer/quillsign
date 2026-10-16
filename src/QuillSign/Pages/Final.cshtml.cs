using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Completion;
using QuillSign.Data;

namespace QuillSign.Pages;

public sealed class FinalModel(CompletionDownloads downloads) : PageModel
{
    public string ConfirmationUrl {get;private set;}="/";
    public string Message {get;private set;}="";
    public async Task<IActionResult> OnGetAsync(string audience,string publicId,string kind,CancellationToken ct)
    {
        Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer"; Response.Headers["X-Content-Type-Options"]="nosniff";
        if(audience is not ("draft" or "sign") || !Guid.TryParseExact(publicId,"N",out var id) || id==Guid.Empty)return NotFound();
        ConfirmationUrl="/"+audience+"/"+publicId+(audience=="draft" ? "/sent" : "/confirmed");
        try {
            var file=await downloads.ReadAsync(HttpContext,publicId,audience=="draft" ? PartyType.Sender : PartyType.Signer,kind,ct);
            if(file is not null)return File(file.Bytes,"application/pdf",file.FileName);
            Message="Prepare a new download from your private confirmation page while your session is live."; Response.StatusCode=404; return Page();
        }
        catch(Exception e) when(Sign.FieldsModel.StorageError(e)) {Message="The saved final file could not be verified. Return to your private confirmation page to try preparing the download again later."; Response.StatusCode=503; return Page();}
    }
}

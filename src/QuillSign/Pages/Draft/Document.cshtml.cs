using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme)]
public sealed class DocumentModel(DocumentWorkflow documents) : PageModel
{
    public async Task<IActionResult> OnGetAsync(string publicId, string documentId, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers["Referrer-Policy"]="no-referrer";
        Stream? stream;
        try { stream=await documents.ReadAsync(User,publicId,documentId,cancellationToken); }
        catch(DocumentRetentionExpiredException error) {return new ContentResult{Content=error.Message,ContentType="text/plain",StatusCode=410};}
        catch(Exception error) when(error is InvalidDataException or IOException or Azure.RequestFailedException ||
            error.GetBaseException() is Microsoft.Data.SqlClient.SqlException || QuillSign.Data.SqlResume.IsUnavailable(error))
        {return new ContentResult{Content="The saved document could not be verified. Retry later.",ContentType="text/plain",StatusCode=503};}
        if (stream is null) return NotFound();
        Response.Headers.ContentDisposition = "inline; filename=\"document.pdf\"";
        return new FileStreamResult(stream, "application/pdf");
    }
}

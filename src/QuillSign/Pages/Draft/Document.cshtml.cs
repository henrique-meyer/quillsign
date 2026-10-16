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
        var stream = await documents.ReadAsync(User, publicId, documentId, cancellationToken);
        if (stream is null) return NotFound();
        Response.Headers.ContentDisposition = "inline; filename=\"document.pdf\"";
        return new FileStreamResult(stream, "application/pdf");
    }
}

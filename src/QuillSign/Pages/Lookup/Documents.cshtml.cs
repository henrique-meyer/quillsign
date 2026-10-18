using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Completion;
using QuillSign.Sender;

namespace QuillSign.Pages.Lookup;

[RequestSizeLimit(8192)]
public sealed class DocumentsModel(DocumentLookupBrowser browser, Func<DocumentLookup> lookup, Func<LookupPacketAccess> packets,
    CompletionReaderBrowser readers, TimeProvider time) : PageModel
{
    public DocumentLookupPage? Documents { get; private set; }
    public DateTimeOffset? Until { get; private set; }
    public string? Message { get; private set; }
    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        try
        {
            var session = await browser.AuthenticateAsync(HttpContext, ct); if (session is null) return Entry(); Until = session.Until;
            Documents = await lookup().ListAsync(session.Principal, session.Receipt, browser.PageCursor(HttpContext), ct);
            return Documents is null ? Error(409, "This page no longer belongs to your current view. Start at the first document.") : Page();
        }
        catch (Exception e) when (DocumentLookupBrowser.Unavailable(e)) { return Error(503, "Your documents could not be verified right now. Refresh this view to try again."); }
    }
    public async Task<IActionResult> OnPostNextAsync(string? cursor, CancellationToken ct)
    {
        ModelState.Clear();
        try
        {
            var session = await browser.AuthenticateAsync(HttpContext, ct); if (session is null) return Entry(); Until = session.Until;
            return browser.SetPage(HttpContext, session, cursor) ? Redirect("/find/documents") : Error(409, "This next page no longer belongs to your current view. Start at the first document.");
        }
        catch (Exception e) when (DocumentLookupBrowser.Unavailable(e)) { return Error(503, "Your document view could not be confirmed. Refresh and try again."); }
    }
    public async Task<IActionResult> OnPostFirstAsync(CancellationToken ct)
    {
        ModelState.Clear();
        try
        {
            if (await browser.AuthenticateAsync(HttpContext, ct) is null) return Entry(); browser.ClearPage(HttpContext); return Redirect("/find/documents");
        }
        catch (Exception e) when (DocumentLookupBrowser.Unavailable(e)) { return Error(503, "Your document view could not be confirmed. Refresh and try again."); }
    }
    public async Task<IActionResult> OnPostOpenAsync(string? publicId, CancellationToken ct)
    {
        ModelState.Clear();
        try
        {
            var session = await browser.AuthenticateAsync(HttpContext, ct); if (session is null) return Entry(); Until = session.Until;
            var reader = await packets().OpenAsync(session.Principal, session.Receipt, publicId!, ct);
            if (reader is null || session.Until <= time.GetUtcNow()) return Error(404, "That document is unavailable in this session. Refresh your list or use a fresh lookup link.");
            await readers.SignInAsync(HttpContext, reader); return Redirect("/complete/" + reader.Identity.PublicId);
        }
        catch (Exception e) when (DocumentLookupBrowser.Unavailable(e))
        { return Error(503, "The completed records could not be verified. Refresh your list and try opening the document again later."); }
    }
    private IActionResult Entry() { browser.ExpiredNotice(HttpContext); return Redirect("/find/access"); }
    private IActionResult Error(int status, string message)
    {
        Message = message; Response.StatusCode = status;
        return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new { message }) { StatusCode = status } : Page();
    }
}

using System.Text;
using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Documents;
using QuillSign.Signing;

namespace QuillSign.Pages.Sign;
[Authorize(AuthenticationSchemes = SignerAccessConfiguration.Scheme)]
public sealed class IndexModel(SignerAccess access,SignerPdfAccess pdf,SignerReceiptProtection receipts,SignerConsent consent) : PageModel
{
    public SignerReadContext Context { get; private set; } = null!;
    public string? AccessError { get; private set; }
    [BindProperty] public string? Receipt { get; set; }
    [BindProperty] public bool Agreement { get; set; }
    [BindProperty] public bool CanRetain { get; set; }
    [BindProperty] public string? AccessMethod { get; set; }
    [BindProperty] public string? Reason { get; set; }
    private void Private() { Response.Headers.CacheControl = "no-store"; Response.Headers["Referrer-Policy"] = "no-referrer"; }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Private(); var context = await access.GetContextAsync(User,publicId,ct); if (context is null) return NotFound(); Context = context;
        try
        {
            _ = await pdf.PrepareAsync(User,Context,ct);
            if (await access.GetContextAsync(User,publicId,ct) is null) return NotFound();
            Receipt = receipts.Create(Context.Identity);
        }
        catch (Exception e) when (e is DocumentRejectedException or RequestFailedException or IOException)
        { AccessError = "The saved PDF is unavailable or could not be verified. Consent is unavailable. Try again later or contact the sender."; Response.StatusCode = 503; }
        return Page();
    }
    public async Task<IActionResult> OnGetPdfAsync(string publicId,bool download,CancellationToken ct)
    {
        Private(); var context = await access.GetContextAsync(User,publicId,ct); if (context is null) return NotFound();
        try
        {
            var bytes = await pdf.PrepareAsync(User,context,ct);
            // Recheck state after storage/validation: an intervening decline ends this read.
            if (await access.GetContextAsync(User,publicId,ct) is null) return NotFound();
            var result = new FileContentResult(bytes,"application/pdf") { EnableRangeProcessing = false };
            if (download) result.FileDownloadName = "document.pdf"; return result;
        }
        catch (Exception e) when (e is DocumentRejectedException or RequestFailedException or IOException)
        { return StatusCode(503,"The saved document is unavailable or could not be verified."); }
    }
    public async Task<IActionResult> OnGetDisclosureAsync(string publicId,CancellationToken ct)
    {
        Private(); var context = await access.GetContextAsync(User,publicId,ct); if (context is null) return NotFound();
        return File(new UTF8Encoding(false,true).GetBytes(context.Disclosure.Text),"text/plain; charset=utf-8","electronic-record-disclosure.txt");
    }
    public async Task<IActionResult> OnPostAsync(string publicId,CancellationToken ct)
    {
        Private(); var context = await access.GetContextAsync(User,publicId,ct); if (context is null) return NotFound(); Context = context;
        if (context.ConsentAt is null && receipts.Read(Receipt,context.Identity) is not null)
        {
            try { _ = await pdf.PrepareAsync(User,context,ct); }
            catch (Exception e) when (e is DocumentRejectedException or RequestFailedException or IOException)
            {
                Receipt = null; ModelState.Remove(nameof(Receipt));
                AccessError = "The saved PDF is unavailable or could not be verified. Consent was not recorded. Reload this page or contact the sender.";
                Response.StatusCode = 503; return Page();
            }
        }
        var result = await consent.AcceptAsync(User,publicId,Receipt,Agreement,CanRetain,AccessMethod,
            HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
        if (result == ConsentResult.InvalidContext) return NotFound();
        if (result is ConsentResult.Accepted or ConsentResult.AlreadyAccepted) return Redirect("/sign/" + publicId);
        ModelState.AddModelError("","Open the verified PDF and confirm both statements. Access evidence expires after ten minutes; reload this page if needed.");
        context = await access.GetContextAsync(User,publicId,ct); if (context is null) return NotFound(); Context = context;
        Response.StatusCode = 400; return Page();
    }
    public async Task<IActionResult> OnPostDeclineAsync(string publicId,CancellationToken ct)
    {
        Private();
        try
        {
            var context = await consent.DeclineAsync(User,publicId,Reason,HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
            return context is null ? NotFound() : Redirect("/sign/" + publicId + "/declined");
        }
        catch (ArgumentException error)
        {
            ModelState.AddModelError("",error.Message); var context = await access.GetContextAsync(User,publicId,ct);
            if (context is null) return NotFound(); Context = context; Response.StatusCode = 400; return Page();
        }
    }
}

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Completion;
using QuillSign.Sender;
using QuillSign.Verification;

namespace QuillSign.Pages;

[AllowAnonymous]
[VerificationUploadRequired]
[ResponseCache(NoStore=true,Location=ResponseCacheLocation.None)]
public sealed class VerifyModel(Func<UploadedPdfVerification>? verifier=null,UploadedPdfVerificationOptions? limits=null) : PageModel
{
    public bool Available=>verifier is not null;
    public int MaximumBytes=>limits?.MaximumBytes??UploadedPdfVerificationOptions.HardMaximumBytes;
    [BindProperty] public IFormFile? Upload {get;set;}
    public UploadedPdfVerificationResult? Result {get;private set;}
    public string? Message {get;private set;}
    public IActionResult OnGet() {
        VerificationBrowser.Private(HttpContext);return Request.QueryString.HasValue ? Redirect("/verify") : Page();
    }
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        VerificationBrowser.Private(HttpContext);
        if(verifier is null)return Reply(503,"Verification is unavailable. No integrity result is confirmed. Choose your PDF again to retry later.");
        if(!ModelState.IsValid || Upload is null || Request.Form.Files.Count!=1 || Upload.Length is <16 || Upload.Length>MaximumBytes)
            return Reply(400,"Choose one PDF within the displayed verification size limit.");
        try {
            using var input=Upload.OpenReadStream();Result=await verifier().VerifyAsync(input,Upload.Length,ct);
            return Reply(Result.Status switch {UploadedPdfVerificationStatus.RejectedInput=>400,UploadedPdfVerificationStatus.EvidenceMismatch=>422,UploadedPdfVerificationStatus.Unavailable=>503,_=>200},Result.Status switch {
                UploadedPdfVerificationStatus.Verified=>"The supplied PDF matches a completed file retained by this instance. Its seal and timestamp evidence verified.",
                UploadedPdfVerificationStatus.NotRecognized=>"This PDF was not recognized as a retained completed file on this instance. It may be from another instance, changed, or no longer retained. This result alone does not prove an invalid signature.",
                UploadedPdfVerificationStatus.RejectedInput=>"The supplied file could not be accepted as one bounded PDF. Choose a PDF within the displayed size limit.",
                UploadedPdfVerificationStatus.EvidenceMismatch=>"This instance could not verify the stored record's evidence. No seal or timestamp integrity result is confirmed.",
                _=>"Verification is temporarily unavailable. No integrity result is confirmed. Choose your PDF again to retry later."
            });
        } catch(Exception e) when(e is InvalidOperationException or IOException or Microsoft.Data.SqlClient.SqlException or Azure.RequestFailedException) {
            return Reply(503,"Verification is temporarily unavailable. No integrity result is confirmed. Choose your PDF again to retry later.");
        }
    }
    private IActionResult Reply(int status,string message)
    {
        Message=message;Response.StatusCode=status;
        if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new {status=Result?.Status.ToString()??(status==400 ? "RejectedInput" : "Unavailable"),sha256=Result?.Sha256,kind=Result?.Kind?.ToString(),
            sealIntegrity=Result?.SealIntegrity??false,timestampIntegrity=Result?.TimestampIntegrity??false,message}) {StatusCode=status};
        return Page();
    }
}

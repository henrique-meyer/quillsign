using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme)]
public sealed class IndexModel(DocumentWorkflow documents, DocumentOptions limits, BrowserNotices notices) : PageModel
{
    public Envelope Draft { get; private set; } = null!;
    public DocumentOptions Limits => limits;
    public string? Notice { get; private set; }
    public string? Error { get; private set; }
    [BindProperty] public IFormFile? Upload { get; set; }
    [BindProperty] public string Version { get; set; } = "";
    [BindProperty] public string? DocumentId { get; set; }
    [BindProperty] public bool PreviewMatches { get; set; }

    public async Task<IActionResult> OnGetAsync(string publicId, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        if (!await LoadAsync(publicId, cancellationToken)) return NotFound();
        Notice = notices.Take(HttpContext);
        return Page();
    }

    public Task<IActionResult> OnPostUploadAsync(string publicId, CancellationToken cancellationToken) => MutateAsync(publicId, async () =>
    {
        if (!ModelState.IsValid) throw new DocumentRejectedException("Choose one PDF within the upload size limit.");
        if (Upload is null || Request.Form.Files.Count != 1) throw new DocumentRejectedException("Choose one PDF to upload.");
        await using var source = Upload.OpenReadStream();
        return await documents.UploadAsync(User, publicId, ExpectedVersion(), Upload.FileName, source, Upload.Length,
            HttpContext.Connection.RemoteIpAddress?.ToString(), Request.Headers.UserAgent.ToString(), cancellationToken);
    }, NoticeCode.DocumentUploaded, cancellationToken);

    public Task<IActionResult> OnPostConfirmAsync(string publicId, CancellationToken cancellationToken) => MutateAsync(publicId,
        () => documents.ConfirmAsync(User, publicId, ExpectedVersion(), DocumentId ?? "", PreviewMatches,
            HttpContext.Connection.RemoteIpAddress?.ToString(), Request.Headers.UserAgent.ToString(), cancellationToken), NoticeCode.PreviewConfirmed, cancellationToken);

    private byte[] ExpectedVersion()
    {
        try { return Version.Length <= 24 ? Convert.FromBase64String(Version) : []; }
        catch (FormatException) { return []; }
    }
    private async Task<bool> LoadAsync(string publicId, CancellationToken ct)
    {
        var draft = await documents.GetAsync(User, publicId, ct);
        if (draft is null) return false;
        Draft = draft; Version = Convert.ToBase64String(draft.RowVersion); DocumentId = draft.PdfBlob ?? "";
        return true;
    }
    private async Task<IActionResult> MutateAsync(string publicId, Func<Task<bool>> action, NoticeCode notice, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        var status = StatusCodes.Status400BadRequest;
        try
        {
            if (!await action()) return NotFound();
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(notice), location = "/draft/" + publicId });
            notices.Set(HttpContext, notice);
            return Redirect("/draft/" + publicId);
        }
        catch (DocumentRejectedException error) { Error = error.Message; }
        catch (DocumentConflictException error) { Error = error.Message; status = StatusCodes.Status409Conflict; }
        catch (DbUpdateConcurrencyException) { Error = "This draft changed. Reload it before trying again."; status = StatusCodes.Status409Conflict; }
        catch (Exception error) when (error.GetBaseException() is Microsoft.Data.SqlClient.SqlException ||
            error is Azure.RequestFailedException or IOException || SqlResume.IsUnavailable(error))
        {
            Error = "We couldn't verify that change right now. Reload the draft before trying again.";
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = Error }) { StatusCode = 503 };
            return new ContentResult { Content = Error, ContentType = "text/plain", StatusCode = 503 };
        }
        if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = Error }) { StatusCode = status };
        if (!await LoadAsync(publicId, ct)) return NotFound();
        Response.StatusCode = status;
        ModelState.Clear();
        return Page();
    }
}

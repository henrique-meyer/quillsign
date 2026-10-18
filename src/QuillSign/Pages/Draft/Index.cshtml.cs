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
public sealed class IndexModel(DocumentWorkflow documents, DocumentOptions limits, BrowserNotices notices,
    DocxDocumentWorkflow docx, ImageDocumentWorkflow images, GotenbergOptions conversion,IHostEnvironment environment,TextDocumentWorkflow text,OfficeDocumentWorkflow office) : PageModel
{
    public Envelope Draft { get; private set; } = null!;
    public DocumentOptions Limits => limits;
    public bool ImagesAvailable => limits.MaximumBytes <= 64 * 1024 * 1024;
    public bool DocxAvailable
    {
        get {if(!ImagesAvailable)return false;try{return conversion.IsAvailable(environment);}catch(InvalidOperationException){return false;}}
    }
    public bool TextAvailable => limits.EnableTextUploads && DocxAvailable;
    public bool OfficeAvailable(OfficeSourceKind kind)=>office.IsAvailable(kind);
    public string OfficeExtensions=>string.Concat(Enum.GetValues<OfficeSourceKind>().Where(OfficeAvailable).Select(x=>","+OfficeDocumentWorkflow.Family(x).Extension));
    public string Extensions => ".pdf" + (ImagesAvailable ? ",.png,.jpg,.jpeg" : "") + (DocxAvailable ? ",.docx" : "") + (TextAvailable ? ",.txt" : "")+OfficeExtensions;
    public string? Notice { get; private set; }
    public string? Error { get; private set; }
    public bool RetentionExpired {get;private set;}
    [BindProperty] public IFormFile? Upload { get; set; }
    [BindProperty] public string Version { get; set; } = "";
    [BindProperty] public string? DocumentId { get; set; }
    [BindProperty] public bool PreviewMatches { get; set; }

    public async Task<IActionResult> OnGetAsync(string publicId, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers["Referrer-Policy"]="no-referrer";
        try {if (!await LoadAsync(publicId,cancellationToken))return NotFound();}
        catch(Exception error) when(error is InvalidDataException or IOException or Azure.RequestFailedException ||
            error.GetBaseException() is Microsoft.Data.SqlClient.SqlException || SqlResume.IsUnavailable(error))
        {return new ContentResult{Content="The saved document could not be verified. Retry later.",ContentType="text/plain",StatusCode=503};}
        Notice = notices.Take(HttpContext);
        return Page();
    }

    public Task<IActionResult> OnPostUploadAsync(string publicId, CancellationToken cancellationToken) => MutateAsync(publicId, async () =>
    {
        if (!ModelState.IsValid) throw new DocumentRejectedException("Choose one supported document within the upload size limit.");
        if (Upload is null || Request.Form.Files.Count != 1) throw new DocumentRejectedException("Choose one supported document to upload.");
        await using var source = Upload.OpenReadStream();
        var extension = Path.GetExtension(Upload.FileName).ToLowerInvariant();
        var version = ExpectedVersion(); var ip = HttpContext.Connection.RemoteIpAddress?.ToString(); var ua = Request.Headers.UserAgent.ToString();
        return extension switch
        {
            ".pdf" => await documents.UploadAsync(User, publicId, version, Upload.FileName, source, Upload.Length, ip, ua, cancellationToken),
            ".docx" when DocxAvailable => await docx.UploadAsync(User, publicId, version, Upload.FileName, source, Upload.Length, ip, ua, cancellationToken),
            ".docx" => throw new DocumentConversionUnavailableException("DOCX conversion is unavailable. Export your document to PDF and try again."),
            ".txt" when TextAvailable => await text.UploadAsync(User, publicId, version, Upload.FileName, source, Upload.Length, ip, ua, cancellationToken),
            ".txt" => throw new DocumentConversionUnavailableException("Text upload is unavailable. Export your document to PDF and try again."),
            ".pptx" => await office.UploadAsync(User,publicId,version,OfficeSourceKind.Pptx,Upload.FileName,source,Upload.Length,ip,ua,cancellationToken),
            ".xlsx" => await office.UploadAsync(User,publicId,version,OfficeSourceKind.Xlsx,Upload.FileName,source,Upload.Length,ip,ua,cancellationToken),
            ".odt" => await office.UploadAsync(User,publicId,version,OfficeSourceKind.Odt,Upload.FileName,source,Upload.Length,ip,ua,cancellationToken),
            ".rtf" => await office.UploadAsync(User,publicId,version,OfficeSourceKind.Rtf,Upload.FileName,source,Upload.Length,ip,ua,cancellationToken),
            ".png" or ".jpg" or ".jpeg" when ImagesAvailable => await images.UploadAsync(User, publicId, version, Upload.FileName, source, Upload.Length, ip, ua, cancellationToken),
            _ => throw new DocumentRejectedException("Choose a supported document shown on the upload form, or export it to PDF.")
        };
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
        Envelope? draft;
        try {draft=await documents.GetAsync(User,publicId,ct);}
        catch(DocumentRetentionExpiredException) {RetentionExpired=true;Response.StatusCode=410;return true;}
        if (draft is null) return false;
        Draft = draft; Version = Convert.ToBase64String(draft.RowVersion); DocumentId = draft.PdfBlob ?? "";
        return true;
    }
    private async Task<IActionResult> MutateAsync(string publicId, Func<Task<bool>> action, NoticeCode notice, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        var status = StatusCodes.Status400BadRequest;
        try
        {
            if (!await action()) return NotFound();
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(notice), location = "/draft/" + publicId });
            notices.Set(HttpContext, notice);
            return Redirect("/draft/" + publicId);
        }
        catch(DocumentRetentionExpiredException error)
        {
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new{message=error.Message}){StatusCode=410};
            RetentionExpired=true;Response.StatusCode=410;return Page();
        }
        catch (DocumentRejectedException error) { Error = error.Message; }
        catch (DocumentConversionUnavailableException error) { Error = error.Message; status = StatusCodes.Status503ServiceUnavailable; }
        catch (DocumentConflictException error) { Error = error.Message; status = StatusCodes.Status409Conflict; }
        catch (DbUpdateConcurrencyException) { Error = "This draft changed. Reload it before trying again."; status = StatusCodes.Status409Conflict; }
        catch (Exception error) when (error.GetBaseException() is Microsoft.Data.SqlClient.SqlException ||
            error is Azure.RequestFailedException or IOException or InvalidDataException || SqlResume.IsUnavailable(error))
        {
            Error = "We couldn't verify that change right now. Reload the draft before trying again.";
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = Error }) { StatusCode = 503 };
            return new ContentResult { Content = Error, ContentType = "text/plain", StatusCode = 503 };
        }
        if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = Error }) { StatusCode = status };
        if (!await LoadAsync(publicId, ct)) return NotFound();
        if(RetentionExpired)return Page();
        Response.StatusCode = status;
        ModelState.Clear();
        return Page();
    }
}

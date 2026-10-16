using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme)]
public sealed class SignersModel(SignerSetup setup, SignerSetupOptions options, BrowserNotices notices) : PageModel
{
    public SignerSetupSnapshot Draft { get; private set; } = null!;
    public int MaximumSigners => options.MaximumSigners;
    public string? Notice { get; private set; }
    [BindProperty] public SignerInput Input { get; set; } = new();
    [BindProperty] public string Version { get; set; } = "";
    [BindProperty] public Guid? SignerId { get; set; }
    [BindProperty] public string? Direction { get; set; }

    public async Task<IActionResult> OnGetAsync(string publicId, Guid? editId, bool useMyEmail, CancellationToken cancellationToken)
    {
        var access = await LoadAsync(publicId, cancellationToken);
        if (access is not null) return access;
        Notice = notices.Take(HttpContext);
        if (editId is not null)
        {
            var signer = Draft.Signers.SingleOrDefault(x => x.Id == editId);
            if (signer is null) return NotFound();
            Input = new() { Id = signer.Id, FullName = signer.FullName, Email = signer.Email, Role = signer.Role };
        }
        else if (useMyEmail) Input = new() { FullName = Draft.SenderName ?? "", Email = Draft.SenderEmail };
        return Page();
    }

    public Task<IActionResult> OnPostSaveAsync(string publicId, CancellationToken cancellationToken) =>
        MutateAsync(publicId, new(SignerChangeKind.Save, Version, Input.Id, Input.FullName, Input.Email, Input.Role),
            NoticeCode.SignerSaved, cancellationToken);

    public Task<IActionResult> OnPostRemoveAsync(string publicId, CancellationToken cancellationToken) =>
        MutateAsync(publicId, new(SignerChangeKind.Remove, Version, SignerId), NoticeCode.SignerRemoved, cancellationToken);

    public Task<IActionResult> OnPostMoveAsync(string publicId, CancellationToken cancellationToken) =>
        MutateAsync(publicId, new(Direction == "up" ? SignerChangeKind.MoveUp : Direction == "down" ?
            SignerChangeKind.MoveDown : (SignerChangeKind)(-1), Version, SignerId), NoticeCode.SignersReordered, cancellationToken);

    private async Task<IActionResult?> LoadAsync(string publicId, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        var draft = await setup.GetAsync(User, publicId, ct);
        if (draft is null) return NotFound();
        if (!draft.PreviewConfirmed)
        {
            if (SenderConfiguration.WantsJson(HttpContext))
                return new JsonResult(new { message = BrowserNotices.Text(NoticeCode.PreviewRequired) }) { StatusCode = 409 };
            notices.Set(HttpContext, NoticeCode.PreviewRequired);
            return Redirect("/draft/" + publicId);
        }
        Draft = draft;
        Version = draft.Version;
        return null;
    }

    private async Task<IActionResult> MutateAsync(string publicId, SignerChange change, NoticeCode notice, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        // Unrelated add/edit fields are absent from the per-row move/remove forms.
        if (change.Kind != SignerChangeKind.Save) ModelState.Clear();
        SignerChangeResult result;
        try
        {
            result = ModelState.IsValid
                ? await setup.ChangeAsync(User, publicId, change, HttpContext.Connection.RemoteIpAddress?.ToString(),
                    Request.Headers.UserAgent.ToString(), ct)
                : new(SignerSetupError.Invalid, "Check the signer details below.");
        }
        catch (DbUpdateConcurrencyException) { result = new(SignerSetupError.Conflict, "This draft changed. Reload it before trying again."); }
        catch (Exception error) when (error.GetBaseException() is Microsoft.Data.SqlClient.SqlException || SqlResume.IsUnavailable(error))
        {
            const string message = "We couldn't verify that change. Reload the signer list before trying again.";
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message }) { StatusCode = 503 };
            return new ContentResult { Content = message, ContentType = "text/plain", StatusCode = 503 };
        }
        if (result.Error == SignerSetupError.NotFound) return NotFound();
        if (result.Error == SignerSetupError.None)
        {
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new
            {
                message = BrowserNotices.Text(notice), location = "/draft/" + publicId + "/signers"
            });
            notices.Set(HttpContext, notice);
            return Redirect("/draft/" + publicId + "/signers");
        }
        var status = result.Error is SignerSetupError.Conflict or SignerSetupError.PreviewRequired ? 409 : 400;
        if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = result.Message }) { StatusCode = status };
        ModelState.AddModelError(result.Field is null ? "" : "Input." + result.Field, result.Message ?? "The change could not be saved.");
        // Preserve attempted signer text while refreshing only the shared version for a safe retry.
        var access = await LoadAsync(publicId, ct);
        if (access is not null) return access;
        ModelState.Remove(nameof(Version));
        Response.StatusCode = status;
        return Page();
    }

    public sealed class SignerInput
    {
        public Guid? Id { get; set; }
        [Required, StringLength(512)] public string FullName { get; set; } = "";
        [Required, StringLength(320)] public string Email { get; set; } = "";
        [StringLength(512)] public string? Role { get; set; }
    }
}

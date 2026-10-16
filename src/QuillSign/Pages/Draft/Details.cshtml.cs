using System.ComponentModel.DataAnnotations;
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
public sealed class DetailsModel(DraftDetails details, PreparationOptions options, BrowserNotices notices) : PageModel
{
    public DraftDetailsSnapshot Draft { get; private set; } = null!;
    public int MaximumRecipients => options.MaximumRecipients;
    public string? Notice { get; private set; }
    public bool Conflict { get; private set; }
    [BindProperty(Name = nameof(Details))] public DetailInput Details { get; set; } = new();
    [BindProperty(Name = nameof(Recipient))] public RecipientInput Recipient { get; set; } = new();
    [BindProperty] public string Version { get; set; } = "";
    [BindProperty] public Guid? RecipientId { get; set; }

    public async Task<IActionResult> OnGetAsync(string publicId, Guid? editId, CancellationToken ct)
    {
        var access = await LoadAsync(publicId, ct); if (access is not null) return access;
        Notice = notices.Take(HttpContext); FillDetails();
        if (editId is not null)
        {
            var recipient = Draft.Recipients.SingleOrDefault(x => x.Id == editId); if (recipient is null) return NotFound();
            Recipient = new() { Id = recipient.Id, Name = recipient.Name, Email = recipient.Email };
        }
        return Page();
    }
    public Task<IActionResult> OnPostSaveDetailsAsync(string publicId, CancellationToken ct) => MutateAsync(publicId,
        new(DetailsChangeKind.SaveDetails, Version, Title: Details.Title, Message: Details.Message), NoticeCode.DetailsSaved, ct);
    public Task<IActionResult> OnPostSaveRecipientAsync(string publicId, CancellationToken ct) => MutateAsync(publicId,
        new(DetailsChangeKind.SaveRecipient, Version, Recipient.Id, Name: Recipient.Name, Email: Recipient.Email), NoticeCode.RecipientSaved, ct);
    public Task<IActionResult> OnPostRemoveRecipientAsync(string publicId, CancellationToken ct) => MutateAsync(publicId,
        new(DetailsChangeKind.RemoveRecipient, Version, RecipientId), NoticeCode.RecipientRemoved, ct);

    private void FillDetails() => Details = new() { Title = Draft.Title ?? "", Message = Draft.Message };
    private async Task<IActionResult?> LoadAsync(string publicId, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        var draft = await details.GetAsync(User, publicId, ct); if (draft is null) return NotFound();
        if (!draft.PreviewConfirmed)
        {
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(NoticeCode.PreviewRequired) }) { StatusCode = 409 };
            notices.Set(HttpContext, NoticeCode.PreviewRequired); return Redirect("/draft/" + publicId);
        }
        Draft = draft; Version = draft.Version; return null;
    }
    private async Task<IActionResult> MutateAsync(string publicId, DetailsChange change, NoticeCode notice, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        if (change.Kind == DetailsChangeKind.RemoveRecipient) ModelState.Clear();
        else
        {
            var unrelated = change.Kind == DetailsChangeKind.SaveDetails ? "Recipient." : "Details.";
            foreach (var key in ModelState.Keys.Where(x => x.StartsWith(unrelated, StringComparison.Ordinal)).ToArray()) ModelState.Remove(key);
        }
        DetailsResult result;
        try
        {
            result = ModelState.IsValid ? await details.ChangeAsync(User, publicId, change,
                HttpContext.Connection.RemoteIpAddress?.ToString(), Request.Headers.UserAgent.ToString(), ct)
                : new(DetailsError.Invalid, "Check the details below.");
        }
        catch (DbUpdateConcurrencyException) { result = new(DetailsError.Conflict, "This draft changed. Review the saved details before trying again."); }
        catch (Exception error) when (error.GetBaseException() is Microsoft.Data.SqlClient.SqlException || SqlResume.IsUnavailable(error))
        {
            const string message = "We couldn't confirm that change. Return to your edits and reload the saved draft before trying again.";
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message }) { StatusCode = 503 };
            return new ContentResult { Content = message, ContentType = "text/plain", StatusCode = 503 };
        }
        if (result.Error == DetailsError.NotFound) return NotFound();
        if (result.Error == DetailsError.None)
        {
            if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(notice), location = "/draft/" + publicId + "/details" });
            notices.Set(HttpContext, notice); return Redirect("/draft/" + publicId + "/details");
        }
        var status = result.Error is DetailsError.Conflict or DetailsError.PreviewRequired ? 409 : 400;
        if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = result.Message }) { StatusCode = status };
        ModelState.AddModelError(result.Field ?? "", result.Message ?? "The change could not be saved.");
        var access = await LoadAsync(publicId, ct); if (access is not null) return access;
        ModelState.Remove(nameof(Version)); Conflict = result.Error == DetailsError.Conflict;
        if (change.Kind != DetailsChangeKind.SaveDetails) FillDetails();
        Response.StatusCode = status; return Page();
    }
    public sealed class DetailInput
    {
        [Required, StringLength(512)] public string Title { get; set; } = "";
        [StringLength(4000)] public string? Message { get; set; }
    }
    public sealed class RecipientInput
    {
        public Guid? Id { get; set; }
        [Required, StringLength(512)] public string Name { get; set; } = "";
        [Required, StringLength(320)] public string Email { get; set; } = "";
    }
}

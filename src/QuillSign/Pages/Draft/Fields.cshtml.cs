using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Signing;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme)]
public sealed class FieldsModel(FieldEditor editor, FieldEditorOptions options, SignerSetup setup, BrowserNotices notices) : PageModel
{
    public FieldEditorSnapshot Draft { get; private set; } = null!;
    public int MaximumFields => options.MaximumFields;
    public string InitialJson => JsonSerializer.Serialize(Draft, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    public async Task<IActionResult> OnGetAsync(string publicId, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        var draft = await editor.GetAsync(User, publicId, ct);
        if (draft is null)
        {
            if (await setup.GetAsync(User, publicId, ct) is null) return NotFound();
            notices.Set(HttpContext, NoticeCode.PreviewRequired);
            return Redirect("/draft/" + publicId);
        }
        Draft = draft;
        return Page();
    }
}

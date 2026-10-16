using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Signing;

namespace QuillSign.Pages.Sign;
[Authorize(AuthenticationSchemes=SignerAccessConfiguration.Scheme)]
public sealed class ReviewModel(SignerFieldView view) : PageModel
{
    public SignerFieldViewData? Data { get; private set; }
    public string? ErrorMessage { get; private set; }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer";
        try { Data=await view.ReadAsync(User,publicId,true,ct); return Data is null ? NotFound() : Page(); }
        catch(Exception e) when(FieldsModel.StorageError(e)) { ErrorMessage="The saved document or adopted marks could not be verified. Review is unavailable. Reload later; signing is not complete."; Response.StatusCode=503; return Page(); }
    }
}

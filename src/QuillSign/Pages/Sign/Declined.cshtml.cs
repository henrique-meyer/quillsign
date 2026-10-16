using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Signing;
namespace QuillSign.Pages.Sign;
[Authorize(AuthenticationSchemes = SignerAccessConfiguration.Scheme)]
public sealed class DeclinedModel(SignerAccess access) : PageModel
{
    public SignerReadContext Context { get; private set; } = null!;
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store"; Response.Headers["Referrer-Policy"] = "no-referrer";
        var context = await access.GetContextAsync(User,publicId,ct,declinedConfirmation:true); if (context is null) return NotFound();
        Context = context; await HttpContext.SignOutAsync(SignerAccessConfiguration.Scheme); return Page();
    }
}

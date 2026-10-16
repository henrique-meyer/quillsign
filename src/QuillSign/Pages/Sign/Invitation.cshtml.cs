using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Signing;

namespace QuillSign.Pages.Sign;
public sealed class InvitationModel(SignerAccess access) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Token { get; set; }
    public bool HasToken => SignerInvitationFactory.TokenHash(Token) is not null;
    public bool Invalid { get; private set; }
    public void OnGet() { Response.Headers.CacheControl = "no-store"; Response.Headers["Referrer-Policy"] = "no-referrer"; }
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        OnGet();
        var verified = await access.RedeemAsync(Token,HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
        if (verified is null) { Invalid = true; Response.StatusCode = 400; return Page(); }
        await HttpContext.SignInAsync(SignerAccessConfiguration.Scheme,SignerAccessConfiguration.Principal(verified),SignerAccessConfiguration.Ticket(verified));
        return Redirect("/sign/" + verified.PublicId);
    }
}

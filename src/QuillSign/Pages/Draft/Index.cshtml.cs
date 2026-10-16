using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme)]
public sealed class IndexModel(QuillSignDbContext db) : PageModel
{
    public string SenderEmail { get; private set; } = "";
    public async Task<IActionResult> OnGetAsync(string publicId, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        var claims = User.FindAll(EnvelopeStorageAuthorization.EnvelopeClaim).ToArray();
        if (claims.Length != 1 || !Guid.TryParse(claims[0].Value, out var id)) return NotFound();
        var email = User.FindFirstValue(ClaimTypes.Email);
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(cancellationToken), cancellationToken);
        var envelope = await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.PublicId == publicId &&
            x.SenderVerifiedAt != null && x.SenderEmail == email && x.Status == EnvelopeStatus.Draft, cancellationToken);
        if (envelope is null) return NotFound();
        SenderEmail = envelope.SenderEmail;
        return Page();
    }
}

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class ReviewModel(DraftReview review) : PageModel
{
    public DraftReviewSnapshot Draft { get; private set; } = null!;
    public async Task<IActionResult> OnGetAsync(string publicId, CancellationToken ct)
    {
        var snapshot = await review.GetAsync(User, publicId, ct);
        if (snapshot is null) return NotFound();
        Draft = snapshot; return Page();
    }
    public string StepUrl(string step) => "/draft/" + Draft.PublicId + (step.Length == 0 ? "" : "/" + step);
}

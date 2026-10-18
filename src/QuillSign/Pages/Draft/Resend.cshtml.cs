using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[RequestSizeLimit(20000)]
[RequestFormLimits(ValueLengthLimit = 8192, ValueCountLimit = 8)]
public sealed class ResendModel(Func<InvitationResends> action, InvitationResendReviewProtection reviews, BrowserNotices notices,
    InvitationResendOptions? options = null, EmailOptions? email = null, WorkOptions? work = null) : PageModel
{
    public InvitationResendPreview? Data { get; private set; }
    public string? ErrorMessage { get; private set; }
    public bool CanConfirm { get; private set; }
    [BindProperty] public string? ReviewProof { get; set; }
    [BindProperty] public bool Confirmed { get; set; }
    [BindProperty] public string? StatementVersion { get; set; }
    private bool Enabled => options?.Enabled == true && email?.Enabled == true && work?.Enabled == true;
    private async Task<AuthenticateResult?> Ticket(string publicId)
    {
        SenderConfiguration.PrivateStatusHeaders(HttpContext);
        var ticket = await HttpContext.AuthenticateAsync(EnvelopeStorageAuthorization.SenderScheme);
        return ticket.Succeeded && ticket.Principal is not null && ticket.Properties?.ExpiresUtc is not null &&
            SendDraftWorkflow.Identity(ticket.Principal, publicId) is not null ? ticket : null;
    }
    public async Task<IActionResult> OnGetAsync(string publicId, CancellationToken ct)
    {
        var ticket = await Ticket(publicId); if (ticket is null) return NotFound();
        if (!Enabled) return Failure(503, Message(InvitationResendOutcome.Unavailable));
        try {
            Data = await action().PreviewAsync(ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value, ct);
            if (Data is null) return Failure(409, Message(InvitationResendOutcome.Closed));
            if (Data.Blocked is { } blocked) return Failure(409, Message(blocked));
            ReviewProof = reviews.Create(ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value, Data);
            CanConfirm = true; return Result();
        } catch (Exception e) when (Unavailable(e)) { return Failure(503, "Saved resend details could not be verified. Retry later; this read did not request an invitation."); }
    }
    public async Task<IActionResult> OnPostAsync(string publicId, CancellationToken ct)
    {
        var ticket = await Ticket(publicId); if (ticket is null) return NotFound();
        if (!Enabled) return Failure(503, Message(InvitationResendOutcome.Unavailable));
        var proof = reviews.Read(ReviewProof, ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value);
        if (proof is null) return Failure(409, "This review is invalid or expired. Check saved status, then review current details before confirming again.");
        Data = new(proof.Title, proof.Review, null);
        if (!ModelState.IsValid || !Confirmed || StatementVersion != InvitationResendStatement.Version)
            return Failure(400, "Review the recipient and affirm the replacement-invitation statement before confirming.", true);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        try { _ = InvitationResendProtection.IpHash(ip); }
        catch (ArgumentException) { return Failure(503, "The request network context could not be verified. Check saved status before retrying.", true); }
        try {
            var outcome = await action().RequestAsync(ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value, proof.Id, proof.Review,
                true, StatementVersion, ip, Request.Headers.UserAgent.ToString(), ct, proof.ExpiresAt);
            if (outcome is InvitationResendOutcome.Queued or InvitationResendOutcome.AlreadyRequested) {
                var target = "/draft/" + publicId + "/sent";
                if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(NoticeCode.InvitationResendQueued), confirmation = target });
                notices.Set(HttpContext, NoticeCode.InvitationResendQueued); return Redirect(target);
            }
            if (outcome == InvitationResendOutcome.InvalidContext) return NotFound();
            return Failure(outcome == InvitationResendOutcome.Capped ? 429 : outcome == InvitationResendOutcome.Unavailable ? 503 : 409, Message(outcome));
        } catch (Exception e) when (Unavailable(e)) {
            // Keep this exact command proof. A lost acknowledgement must not
            // silently become a new admission on the next confirmation.
            return Failure(503, "Confirmation could not be verified. Check saved request status before retrying this same confirmation; a replacement may already be queued. Email delivery is not confirmed.", true);
        }
    }
    private IActionResult Failure(int status, string message, bool retry = false)
    {
        ErrorMessage = message; CanConfirm = retry && Data is not null; Confirmed = false;
        ModelState.Remove(nameof(Confirmed)); Response.StatusCode = status; return Result();
    }
    private IActionResult Result() => SenderConfiguration.WantsJson(HttpContext)
        ? new JsonResult(new { title = Data?.Title, signer = Data is null ? null : new { Data.Review.Name, Data.Review.Email }, canResend = CanConfirm,
            reviewProof = CanConfirm ? ReviewProof : null, statement = InvitationResendStatement.Text, statementVersion = InvitationResendStatement.Version, message = ErrorMessage,
            checkStatus = "/draft/" + RouteData.Values["publicId"] + "/sent" }) { StatusCode = Response.StatusCode }
        : Page();
    private static bool Unavailable(Exception e) => ReviewModel.StorageError(e) || e is System.Security.Cryptography.CryptographicException;
    internal static string Message(InvitationResendOutcome outcome) => outcome switch {
        InvitationResendOutcome.Busy => "An invitation is pending or its submission is uncertain. Check saved status; a replacement cannot bypass it.",
        InvitationResendOutcome.Capped => "The resend limit was reached. Wait before reviewing another replacement; no new resend was confirmed.",
        InvitationResendOutcome.Suppressed => "Invitation sending is unavailable for this recipient. Contact the instance operator; no replacement was confirmed.",
        InvitationResendOutcome.Unavailable => "Resending is unavailable with the current delivery settings or retention window. No replacement was confirmed.",
        InvitationResendOutcome.Closed => "This request is closed or has no eligible unfinished signer. Check its saved status.",
        _ => "The request changed. Check saved status, then review current details and affirm again. No new resend was confirmed."
    };
}

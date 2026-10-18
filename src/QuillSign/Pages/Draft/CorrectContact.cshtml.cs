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
[RequestSizeLimit(40000)]
[RequestFormLimits(ValueLengthLimit = SignerContactCorrectionBrowser.MaximumProofLength, ValueCountLimit = 9)]
public sealed class CorrectContactModel(Func<SignerContactCorrections> action, SignerContactCorrectionBrowser reviews, BrowserNotices notices,
    SignerContactCorrectionOptions? options = null, EmailOptions? email = null, WorkOptions? work = null) : PageModel
{
    public SignerContactCorrectionPreview? Data { get; private set; }
    public string? ErrorMessage { get; private set; }
    public bool CanReview { get; private set; }
    public bool CanConfirm { get; private set; }
    [BindProperty] public string? Step { get; set; }
    [BindProperty] public string? NewEmail { get; set; }
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
        if (!Enabled) return Failure(503, Message(SignerContactCorrectionOutcome.Unavailable));
        return await Preview(ticket, publicId, null, ct);
    }

    public async Task<IActionResult> OnPostAsync(string publicId, CancellationToken ct)
    {
        var ticket = await Ticket(publicId); if (ticket is null) return NotFound();
        if (!Enabled) return Failure(503, Message(SignerContactCorrectionOutcome.Unavailable));
        if (Step == "review")
        {
            ReviewProof = null; ModelState.Remove(nameof(ReviewProof));
            Confirmed = false; ModelState.Remove(nameof(Confirmed));
            if (!ModelState.IsValid || NewEmail is not { Length: > 0 and <= 254 } || string.IsNullOrWhiteSpace(NewEmail))
                return await InvalidAddress(ticket, publicId, ct);
            return await Preview(ticket, publicId, NewEmail, ct);
        }
        if (Step != "confirm") return Failure(400, "Choose review or confirmation from this page.");
        var proof = reviews.Read(ReviewProof, ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value);
        if (proof is null) return Failure(409, "This review is invalid or expired. Check saved status and review current details again.");
        Data = new(proof.Title, proof.Review, null); NewEmail = proof.Review.NewEmail; ModelState.Remove(nameof(NewEmail));
        if (!ModelState.IsValid || !Confirmed || StatementVersion != SignerContactCorrectionStatement.Version)
            return Failure(400, "Read the correction statement and affirm it before confirming.", true);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (!System.Net.IPAddress.TryParse(ip, out _))
            return Failure(503, "The request network context could not be verified. Check saved status before retrying.", true);
        try
        {
            var outcome = await action().RequestAsync(ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value,
                proof.Id, proof.Review, true, StatementVersion, ip, Request.Headers.UserAgent.ToString(), ct, proof.ExpiresAt);
            if (outcome is SignerContactCorrectionOutcome.Queued or SignerContactCorrectionOutcome.AlreadyRequested)
            {
                var target = "/draft/" + publicId + "/sent";
                if (SenderConfiguration.WantsJson(HttpContext)) return new JsonResult(new { message = BrowserNotices.Text(NoticeCode.ContactCorrectionQueued), confirmation = target });
                notices.Set(HttpContext, NoticeCode.ContactCorrectionQueued); return Redirect(target);
            }
            if (outcome == SignerContactCorrectionOutcome.InvalidContext) return NotFound();
            CanReview = outcome is SignerContactCorrectionOutcome.Conflict or SignerContactCorrectionOutcome.InvalidConfirmation or
                SignerContactCorrectionOutcome.DuplicateAddress or SignerContactCorrectionOutcome.Suppressed or SignerContactCorrectionOutcome.Capped;
            return Failure(outcome == SignerContactCorrectionOutcome.Capped ? 429 : outcome == SignerContactCorrectionOutcome.Unavailable ? 503 : 409,
                Message(outcome));
        }
        catch (Exception e) when (Unavailable(e))
        {
            // Preserve the command ID through an uncertain acknowledgement.
            // The backend, not a new review, resolves an already-admitted request.
            return Failure(503, "Confirmation could not be verified. Check saved status before retrying this same confirmation; the correction may already be recorded. Inbox delivery is not confirmed.", true);
        }
    }

    private async Task<IActionResult> Preview(AuthenticateResult ticket, string publicId, string? address, CancellationToken ct)
    {
        try
        {
            Data = await action().PreviewAsync(ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value, address, ct);
            if (Data is null) return Failure(409, Message(SignerContactCorrectionOutcome.Closed));
            if (Data.Blocked is { } blocked) return Failure(409, Message(blocked));
            CanReview = true;
            if (address is not null)
            {
                ReviewProof = reviews.Create(ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value, Data);
                ModelState.Remove(nameof(ReviewProof)); CanConfirm = true; NewEmail = Data.Review.NewEmail;
                ModelState.Remove(nameof(NewEmail));
            }
            return Result();
        }
        catch (ArgumentException) { return await InvalidAddress(ticket, publicId, ct); }
        catch (Exception e) when (Unavailable(e)) { return Failure(503, "Saved correction details could not be verified. Retry later; this review did not change the signer."); }
    }

    private async Task<IActionResult> InvalidAddress(AuthenticateResult ticket, string publicId, CancellationToken ct)
    {
        try { Data = await action().PreviewAsync(ticket.Principal!, publicId, ticket.Properties!.ExpiresUtc!.Value, null, ct); }
        catch (Exception e) when (Unavailable(e)) { return Failure(503, "Saved correction details could not be verified. Check saved status before retrying."); }
        CanReview = Data is { Blocked: null };
        return Failure(400, "Enter a valid different email address for this same named signer.");
    }

    private IActionResult Failure(int status, string message, bool retry = false)
    {
        ErrorMessage = message; CanConfirm = retry && Data is not null; Confirmed = false;
        if (!retry) { ReviewProof = null; ModelState.Remove(nameof(ReviewProof)); }
        ModelState.Remove(nameof(Confirmed)); Response.StatusCode = status; return Result();
    }
    private IActionResult Result() => SenderConfiguration.WantsJson(HttpContext)
        ? new JsonResult(new { title = Data?.Title, signer = Data is null ? null : new { Data.Review.Name, Data.Review.OldEmail, Data.Review.NewEmail },
            attemptedEmail = NewEmail is { Length: > 254 } ? NewEmail[..254] : NewEmail, canReview = CanReview, canConfirm = CanConfirm, reviewProof = CanConfirm ? ReviewProof : null,
            statement = SignerContactCorrectionStatement.Text, statementVersion = SignerContactCorrectionStatement.Version, message = ErrorMessage,
            checkStatus = "/draft/" + RouteData.Values["publicId"] + "/sent" }) { StatusCode = Response.StatusCode }
        : Page();
    private static bool Unavailable(Exception e) => ReviewModel.StorageError(e) || e is System.Security.Cryptography.CryptographicException;
    internal static string Message(SignerContactCorrectionOutcome outcome) => outcome switch
    {
        SignerContactCorrectionOutcome.Busy => "An invitation submission is pending or uncertain. Check saved status before correcting the contact.",
        SignerContactCorrectionOutcome.Capped => "The correction limit was reached. Check saved status and wait before reviewing another correction.",
        SignerContactCorrectionOutcome.Suppressed => "Sending is unavailable for this address. Contact the instance operator; no new correction was confirmed.",
        SignerContactCorrectionOutcome.DuplicateAddress => "That address already belongs to another party in this request. Review a different address for this same signer.",
        SignerContactCorrectionOutcome.Unavailable => "Contact correction is unavailable with the current delivery settings or retention window.",
        SignerContactCorrectionOutcome.Closed => "This request is closed or the signer has already finished. Check saved status.",
        _ => "The request changed. Check saved status, then review the current signer and address again before confirming."
    };
}

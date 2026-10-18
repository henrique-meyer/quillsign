using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Completion;
using QuillSign.Data;
using Microsoft.AspNetCore.Authentication;
using QuillSign.Documents;

namespace QuillSign.Pages.Draft;
[Authorize(AuthenticationSchemes=EnvelopeStorageAuthorization.SenderScheme)]
public sealed class SentModel(SenderSentStatus status,BrowserNotices notices,Func<CompletionDownloads>? downloads=null,
    Func<SenderVoidState>? voids=null,TimeProvider? time=null,Func<InvitationResends>? resends=null,
    QuillSign.Work.InvitationResendOptions? resendOptions=null,QuillSign.Email.EmailOptions? email=null,QuillSign.Work.WorkOptions? work=null,
    Func<SignerContactCorrections>? corrections=null,SignerContactCorrectionOptions? correctionOptions=null) : PageModel
{
    public SignerContactCorrectionPreview? Correction {get;private set;}
    public InvitationResendPreview? Resend {get;private set;}
    public SenderVoidPreview? Void {get;private set;}
    public FinalDownloadAvailability? Final {get;private set;}
    public SenderSentSnapshot? Data { get; private set; }
    public string? Notice { get; private set; }
    public string? ErrorMessage { get; private set; }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        SenderConfiguration.PrivateStatusHeaders(HttpContext);
        try {
            Data=await status.GetAsync(User,publicId,ct:ct); if(Data is null)return NotFound();
            if(voids is not null && Data.Status is EnvelopeStatus.Sent or EnvelopeStatus.Voided) {
                var ticket=await HttpContext.AuthenticateAsync(EnvelopeStorageAuthorization.SenderScheme);
                if(!ticket.Succeeded || ticket.Principal is null || ticket.Properties?.ExpiresUtc is not { } until)return NotFound();
                Void=await voids().PreviewAsync(ticket.Principal,publicId,until,ct)??throw new InvalidDataException("Void status could not be verified.");
            }
            if(downloads is not null)Final=await downloads().AvailabilityAsync(HttpContext,publicId,PartyType.Sender,ct);
            if(Data.Status==EnvelopeStatus.Sent && resends is not null && resendOptions?.Enabled==true && email?.Enabled==true && work?.Enabled==true) {
                var ticket=await HttpContext.AuthenticateAsync(EnvelopeStorageAuthorization.SenderScheme);
                if(!ticket.Succeeded || ticket.Principal is null || ticket.Properties?.ExpiresUtc is not { } until)return NotFound();
                Resend=await resends().PreviewAsync(ticket.Principal,publicId,until,ct);
            }
            if(Data.Status==EnvelopeStatus.Sent && corrections is not null && correctionOptions?.Enabled==true && email?.Enabled==true && work?.Enabled==true) {
                var ticket=await HttpContext.AuthenticateAsync(EnvelopeStorageAuthorization.SenderScheme);
                if(!ticket.Succeeded || ticket.Principal is null || ticket.Properties?.ExpiresUtc is not { } until)return NotFound();
                Correction=await corrections().PreviewAsync(ticket.Principal,publicId,until,null,ct);
            }
            DocumentRetentionAccess.Check(Data.RetentionDeadline,time??TimeProvider.System);
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { Data.PublicId,Data.Title,state=Data.State,Data.SentAt,Data.ExpiresAt,Data.Signers,Data.Recipients,voidAction=Void?.Action,canVoid=Void?.CanVoid??false,
                canResend=Resend is {Blocked:null},resendMessage=Resend?.Blocked is { } blocked ? ResendModel.Message(blocked) : null,
                canCorrectContact=Correction is {Blocked:null},correctionMessage=Correction?.Blocked is { } correctionBlocked ? CorrectContactModel.Message(correctionBlocked) : null });
            Notice=notices.Take(HttpContext); return Page();
        }
        catch(Exception e) when(ReviewModel.StorageError(e) || e is System.Security.Cryptography.CryptographicException) {
            Data=null;Final=null;Void=null;Resend=null;Correction=null;ErrorMessage="Saved request status could not be verified. Retry later; do not assume delivery or completion.";
            Response.StatusCode=503; return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(new {message=ErrorMessage}){StatusCode=503} : Page();
        }
    }
    public async Task<IActionResult> OnPostDownloadAsync(string publicId,string kind,CancellationToken ct)
    {
        Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer";
        try {
            var prepared=downloads is null ? null : await downloads().PrepareAsync(HttpContext,publicId,PartyType.Sender,kind,ct);
            if(prepared is null)return NotFound("A final download is not available in this session. Refresh your private request status.");
            return SenderConfiguration.WantsJson(HttpContext) ? new JsonResult(prepared) : new RedirectResult(prepared.Url);
        } catch(Exception e) when(ReviewModel.StorageError(e)) {
            const string message="The final download could not be verified. Your saved request is unchanged. Return to private status or try preparing the download again later.";
            if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new {message}) {StatusCode=503};
            var result=await OnGetAsync(publicId,ct); ErrorMessage=message; Response.StatusCode=503; return result;
        }
    }
}

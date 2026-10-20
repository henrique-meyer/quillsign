using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Pages.Draft;

[Authorize(AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[RequestSizeLimit(32000)]
[RequestFormLimits(ValueLengthLimit=8192,ValueCountLimit=12)]
public sealed class ReviewModel(DraftReview review,SenderSendReadiness readiness,BrowserNotices notices,
    Func<SendDraftWorkflow> send,Func<SenderSentStatus> sentStatus) : PageModel
{
    public DraftReviewSnapshot Draft { get; private set; } = null!;
    public SendReadiness? Readiness { get; private set; }
    public string? Notice { get; private set; }
    public string? ErrorMessage { get; private set; }
    public bool ReloadRequired { get; private set; }
    [BindProperty] public string? Version { get; set; }
    [BindProperty] public bool ExclusionsAcknowledged { get; set; }
    [BindProperty] public bool SendAcknowledged { get; set; }
    [BindProperty] public string? StatementVersion { get; set; }
    [BindProperty] public string? RetentionSha256 {get;set;}
    [BindProperty] public string? DisclosureSha256 {get;set;}
    [BindProperty] public string? ReminderSha256 {get;set;}
    [BindProperty] public string? ReminderSchedulingVersion {get;set;}
    private void Private() { Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer"; }
    public async Task<IActionResult> OnGetAsync(string publicId, CancellationToken ct)
    {
        Private();
        DraftReviewSnapshot? snapshot;
        try { snapshot=await review.GetAsync(User,publicId,ct); }
        catch(Exception e) when(StorageError(e)) { ErrorMessage="Saved preparation could not be verified. Retry later; no Send was requested."; Response.StatusCode=503; return Page(); }
        if(snapshot is null) {
            if(SendDraftWorkflow.Identity(User,publicId) is null)return NotFound();
            try { return await sentStatus().GetAsync(User,publicId,ct:ct) is null ? NotFound() : Redirect("/draft/"+publicId+"/sent"); }
            catch(Exception e) when(StorageError(e)) { return StatusCode(503,"Saved request status could not be verified. Retry later."); }
        }
        Draft=snapshot; Version=snapshot.Version; RetentionSha256=snapshot.RetentionSha256; Readiness=await readiness.ReadAsync(User,snapshot,ct);
        DisclosureSha256=Readiness.Disclosure is null ? null : Convert.ToHexStringLower(Readiness.Disclosure.Sha256);
        ReminderSchedulingVersion=QuillSign.Work.SignerReminderEvidence.Version;ReminderSha256=Readiness.Reminders?.Sha256;Notice=notices.Take(HttpContext); return Page();
    }
    public async Task<IActionResult> OnPostSendAsync(string publicId,CancellationToken ct)
    {
        Private(); if(SendDraftWorkflow.Identity(User,publicId) is null)return NotFound();
        byte[] version;
        try { version=Convert.FromBase64String(Version??""); }
        catch(FormatException) { return await Failure(publicId,400,"Reload the draft review before sending.",true,ct); }
        if(!ModelState.IsValid || version.Length!=8 || Convert.ToBase64String(version)!=Version || !ExclusionsAcknowledged || !SendAcknowledged || StatementVersion!=SenderSendStatement.Version)
            return await Failure(publicId,400,"Review the draft and confirm both statements before sending.",false,ct);
        try {
            // This also recovers a committed Send when its original response was lost.
            var existing=await sentStatus().GetAsync(User,publicId,version,ct);
            if(existing is not null && !readiness.CanDispatch)return Success(publicId);
            var result=await send().SendAsync(User,publicId,version,true,SendAcknowledged,StatementVersion,HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct,RetentionSha256,ReminderSha256,ReminderSchedulingVersion,DisclosureSha256);
            return result is null ? NotFound() : Success(publicId);
        }
        catch(DocumentConflictException) { return await Failure(publicId,409,"This review changed. Reload and check the current draft before sending again.",true,ct); }
        catch(DisclosureRejectedException) { return await Failure(publicId,400,"Electronic-record disclosure settings or document details are incomplete. Check the draft or contact this instance's operator.",false,ct); }
        catch(DocumentRejectedException) { return await Failure(publicId,400,"The request was not sent. Check preparation, suitability and expiry before trying again.",true,ct); }
        catch(Exception e) when(e is EmailDisabledException or RecipientSuppressedException) { return await Failure(publicId,503,"Invitation sending is unavailable for this request. No new Send was confirmed.",false,ct); }
        catch(Exception e) when(StorageError(e)) {
            try { if(await sentStatus().GetAsync(User,publicId,version,ct) is not null)return Success(publicId); } catch(Exception recovery) when(StorageError(recovery) || recovery is DocumentConflictException) { }
            return await Failure(publicId,503,"Sending could not be confirmed. Reload to check saved status before retrying; do not assume the invitation was delivered.",true,ct);
        }
    }
    private IActionResult Success(string publicId)
    {
        if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { message=BrowserNotices.Text(NoticeCode.RequestSent),confirmation="/draft/"+publicId+"/sent" });
        notices.Set(HttpContext,NoticeCode.RequestSent); return Redirect("/draft/"+publicId+"/sent");
    }
    private async Task<IActionResult> Failure(string publicId,int status,string message,bool reload,CancellationToken ct)
    {
        if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { message }) { StatusCode=status };
        ErrorMessage=message; ReloadRequired=reload; Response.StatusCode=status;
        try { Draft=(await review.GetAsync(User,publicId,ct))!; if(Draft is not null)Readiness=await readiness.ReadAsync(User,Draft,ct); }
        catch(Exception e) when(StorageError(e)) { }
        return Page();
    }
    internal static bool StorageError(Exception e)=>e is Azure.RequestFailedException or IOException or InvalidDataException or Microsoft.EntityFrameworkCore.DbUpdateException or Microsoft.Data.SqlClient.SqlException or InvalidOperationException;
    public string StepUrl(string step) => "/draft/" + Draft.PublicId + (step.Length == 0 ? "" : "/" + step);
}

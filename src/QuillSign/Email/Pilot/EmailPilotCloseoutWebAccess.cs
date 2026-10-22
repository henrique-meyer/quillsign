using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

// Read-only, request-scoped denial checks. This returns no capability. Every
// original backend still reacquires its transaction/cohort/row/session proof.
internal sealed class EmailPilotCloseoutWebAccess(EmailPilotCloseout closeout,QuillSignDbContext db,
    EmailPilotCloseoutOperatorBrowser operators,TimeProvider time,IServiceProvider services)
{
    private DateTimeOffset Now=>time.GetUtcNow();
    private static string? One(IFormCollection form,string name)=>form.TryGetValue(name,out var v)&&v.Count==1?v[0]:null;
    internal async Task<bool> AllowsAsync(HttpContext http,CloseoutWebRoute route,CancellationToken ct)
    {
        var options=closeout.HostOptions;
        if(options.HostRole!=EmailPilotCloseoutHostRole.Web||options.WebInput is null)return false;
        var input=options.CaptureReceiptConfiguration().Coexistence?.WebInput;
        if(input is null)return false;
        var post=http.Request.Method=="POST";var form=post?http.Request.Form:null;
        if(route.Area==CloseoutWebArea.Operator)
        {
            if(route.Handler=="Lock")return true;
            if(route.Handler=="Receipt")return operators.ReadReceipt(http) is not null;
            if(!operators.Available)return false;
            if(route.Handler=="Unlock")return closeout.CanAdmit&&closeout.MatchesCapability(One(form!,"Capability"));
            if(!post)return true;
            return closeout.CanAdmit&&operators.Read(http) is not null;
        }
        if(!closeout.Available||((post||route.Area==CloseoutWebArea.Verify)&&!closeout.CanAdmit))return false;
        var state=await closeout.ReadAsync(ct);
        if(state?.Configuration.Coexistence?.WebInput!=input)return false;
        var envelope=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==state.DeclineRecord,ct);
        var completion=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==state.CompletionRecord,ct);
        if(envelope is null||completion is null||!envelope.IsDemo||envelope.SenderEmail!=state.Mailboxes.Sender)return false;
        await EmailPilotAdmission.ReadSourceAsync(db,state.Parent(state.DeclineRecord),state.Enrollment(state.DeclineRecord),
            ()=>services.GetRequiredService<EmailPayloadProtection>(),ct);
        await EmailPilotAdmission.ReadSourceAsync(db,state.Parent(state.CompletionRecord),state.Enrollment(state.CompletionRecord),
            ()=>services.GetRequiredService<EmailPayloadProtection>(),ct);
        bool allowed;
        if(route.Area is CloseoutWebArea.Verify or CloseoutWebArea.Invitation)
        {
            if(post&&http.Request.Query.Count!=0)return false;
            var raw=post?One(form!,"Token"):http.Request.Query["token"].SingleOrDefault();
            allowed=await TokenAsync(raw,route.Area==CloseoutWebArea.Verify,state,ct);
        }
        else if(route.Area is CloseoutWebArea.Draft or CloseoutWebArea.Document or CloseoutWebArea.Signers or CloseoutWebArea.Review or CloseoutWebArea.Sent)
        {
            if(route.PublicId!=envelope.PublicId)return false;
            var ticket=await http.AuthenticateAsync(EnvelopeStorageAuthorization.SenderScheme);
            var identity=ticket.Succeeded&&ticket.Principal is not null?SendDraftWorkflow.Identity(ticket.Principal,envelope.PublicId):null;
            if(identity is null||identity.Value.Id!=envelope.Id||identity.Value.Email!=state.Mailboxes.Sender||ticket.Properties?.ExpiresUtc is not {} until||until<=Now||until>state.Until)return false;
            var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).Take(2).ToArrayAsync(ct);
            var fields=await db.Fields.AnyAsync(x=>x.EnvelopeId==envelope.Id,ct);
            var recipients=await db.Recipients.AnyAsync(x=>x.EnvelopeId==envelope.Id,ct);
            if(!Preparation(envelope,signers,fields,recipients,state.Mailboxes.FirstSigner,input))return false;
            if(post&&!Version(One(form!,"Version"),envelope.RowVersion))return false;
            allowed=true;
            if(route.Area==CloseoutWebArea.Document)allowed=route.ObjectId==envelope.PdfBlob;
            else if(route is {Area:CloseoutWebArea.Draft,Handler:"Upload"})
                allowed=envelope.Status==EnvelopeStatus.Draft&&envelope.OriginalBlob is null&&envelope.PdfBlob is null&&
                    signers.Length==0&&await EmailPilotCloseoutWeb.InputAsync(form!.Files[0],input,ct);
            else if(route is {Area:CloseoutWebArea.Draft,Handler:"Confirm"})
                allowed=envelope.Status==EnvelopeStatus.Draft&&envelope.PdfBlob is not null&&One(form!,"DocumentId")==envelope.PdfBlob;
            else if(route is {Area:CloseoutWebArea.Signers,Handler:"Save"})
                allowed=envelope.Status==EnvelopeStatus.Draft&&envelope.PreviewConfirmedAt is not null&&
                    SignerForm(form!,signers,state.Mailboxes.FirstSigner);
            else if(route.Area==CloseoutWebArea.Review)
                allowed=envelope.Status==EnvelopeStatus.Draft&&envelope.PreviewConfirmedAt is not null&&signers.Length==1;
            else if(route.Area==CloseoutWebArea.Sent)allowed=envelope.Status is EnvelopeStatus.Sent or EnvelopeStatus.Declined;
        }
        else if(route.Area is CloseoutWebArea.Sign or CloseoutWebArea.Decline or CloseoutWebArea.Declined)
        {
            if(route.PublicId!=envelope.PublicId)return false;
            var ticket=await http.AuthenticateAsync(SignerAccessConfiguration.Scheme);
            var identity=ticket.Succeeded&&ticket.Principal is not null?SignerAccessConfiguration.ReadIdentity(ticket.Principal,Now):null;
            if(identity is null||identity.EnvelopeId!=envelope.Id||identity.Email!=state.Mailboxes.FirstSigner||identity.PublicId!=envelope.PublicId||identity.SessionExpiresAt>state.Until)return false;
            var signer=await db.Signers.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==identity.SignerId&&x.EnvelopeId==envelope.Id,ct);
            allowed=signer is not null&&FixedSigner(signer,state.Mailboxes.FirstSigner)&&
                (await services.GetRequiredService<SignerAccess>().GetContextAsync(ticket.Principal!,envelope.PublicId,ct,route.Area==CloseoutWebArea.Declined)) is not null;
        }
        else if(route.Area==CloseoutWebArea.LookupEntry)
        {
            if(!post)return true;
            var browser=services.GetRequiredService<DocumentLookupBrowser>();
            var raw=route.Handler=="Begin"?One(form!,"code"):browser.PendingCode(http,One(form!,"nonce"));
            var issuance=services.GetRequiredService<DocumentLookupProtection>().Link(raw);
            if(issuance is null||issuance.Email!=state.Mailboxes.Sender)return false;
            var token=await services.GetRequiredService<EmailPilotCloseoutLookup>().TokenAsync(issuance.TokenId,issuance.Email,ct);
            var stored=await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==issuance.TokenId,ct);
            allowed=token is {Known:true,Allowed:true}&&token.RecordId==state.CompletionRecord&&stored is {UsedAt:null}&&
                CryptographicOperations.FixedTimeEquals(stored.TokenSha256,SignerInvitationFactory.TokenHash(issuance.RawToken)??[]);
        }
        else if(route.Area==CloseoutWebArea.LookupList)
        {
            var session=await services.GetRequiredService<DocumentLookupBrowser>().AuthenticateAsync(http,ct);
            if(session is null||session.Identity.Email!=state.Mailboxes.Sender||session.Until>state.Until)return false;
            var restriction=await services.GetRequiredService<DocumentLookup>().RestrictionAsync(session.Identity,ct);
            allowed=restriction is {Allowed:true}&&restriction.CloseoutRecord==state.CompletionRecord&&
                (!post||route.Handler!="Open"||One(form!,"publicId")==completion.PublicId);
        }
        else if(route.Area is CloseoutWebArea.Complete or CloseoutWebArea.Final)
        {
            if(route.PublicId!=completion.PublicId)return false;
            var session=await services.GetRequiredService<CompletionReaderBrowser>().AuthenticateAsync(http,completion.PublicId,ct);
            allowed=session is not null&&session.Until<=state.Until&&session.View.Identity.EnvelopeId==state.CompletionRecord&&
                session.View.Identity.Party==PartyType.Sender&&session.View.Identity.PartyId is null&&session.View.Identity.Email==state.Mailboxes.Sender&&
                (!post||One(form!,"kind") is "executed" or "certificate");
        }
        else return false;
        // Original transaction guards remain authoritative after this snapshot.
        return allowed&&closeout.Available&&(!post||closeout.CanAdmit)&&
            (await closeout.ReadAsync(ct)) is {} fresh&&Same(fresh.Configuration,state.Configuration);
    }
    private static bool Same(EmailPilotCloseoutConfiguration a,EmailPilotCloseoutConfiguration b)=>
        CryptographicOperations.FixedTimeEquals(EmailPilotCanonical.Hash(a),EmailPilotCanonical.Hash(b));
    internal static bool Version(string? raw,byte[] current)
    {
        try {return raw is {Length:12}&&Convert.FromBase64String(raw) is {Length:8} bytes&&
            Convert.ToBase64String(bytes)==raw&&current.AsSpan().SequenceEqual(bytes);}
        catch(FormatException){return false;}
    }
    internal static bool FixedSigner(Signer s,string mailbox)=>s.Order==1&&s.FullName=="Synthetic first"&&s.Email==mailbox&&s.Role is null;
    internal static bool SignerForm(IFormCollection form,IReadOnlyList<Signer> existing,string mailbox)
    {
        var id=One(form,"Input.Id");
        return existing.Count<=1&&One(form,"Input.FullName")=="Synthetic first"&&One(form,"Input.Email")==mailbox&&
            string.IsNullOrEmpty(One(form,"Input.Role"))&&(string.IsNullOrEmpty(id)?existing.Count==0:
            existing.Count==1&&Guid.TryParse(id,out var parsed)&&parsed==existing[0].Id);
    }
    internal static bool Preparation(Envelope e,IReadOnlyList<Signer> signers,bool fields,bool recipients,string mailbox,EmailPilotCloseoutWebInput input)=>
        e.IsDemo&&e.SenderName is null&&e.Message is null&&!fields&&!recipients&&signers.Count<=1&&signers.All(s=>FixedSigner(s,mailbox))&&
        (e.OriginalBlob is null&&e.PdfBlob is null&&e.Title is null||e.Title==input.Filename&&e.OriginalBlob is not null&&e.PdfBlob is not null&&
            e.OriginalMime=="application/pdf"&&e.OriginalSha256 is {Length:32}&&Convert.ToHexStringLower(e.OriginalSha256)==input.Sha256);
    private async Task<bool> TokenAsync(string? raw,bool sender,EmailPilotCloseoutSnapshot prior,CancellationToken ct)
    {
        var hash=SignerInvitationFactory.TokenHash(raw);if(hash is null||db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())return false;
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        try
        {
            var current=await closeout.ReadLockedAsync(db,ct);
            if(current is null||current.AuthorizationId!=prior.AuthorizationId||!Same(current.Configuration,prior.Configuration))return false;
            var step=sender?EmailPilotCloseoutStep.DeclineVerification:EmailPilotCloseoutStep.DeclineInvitation;
            var id=await closeout.ReadStepLockedAsync(db,current,step,ct);
            if(id is null)return false;
            var mail=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
            var token=await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x=>x.TokenSha256==hash,ct);
            if(mail is null||mail.Status!=EmailStatus.Sent||mail.Attempts!=1||mail.SubmissionStartedAt is null||
                string.IsNullOrEmpty(mail.Provider)||string.IsNullOrEmpty(mail.ProviderMessageId)||
                mail.EnvelopeId!=current.DeclineRecord||token is null||token.EnvelopeId!=current.DeclineRecord||
                token.UsedAt is not null||token.ExpiresAt<=Now||token.ExpiresAt>current.Until)return false;
            await closeout.DemandWebCandidateLockedAsync(db,current,step,id.Value,ct);
            if(sender)
            {
                var payload=services.GetRequiredService<EmailPayloadProtection>().Unprotect(mail.PayloadJson);
                return token.Purpose==TokenPurpose.SenderVerify&&token.PartyType==PartyType.Sender&&token.PartyId is null&&
                    mail.To==current.Mailboxes.Sender&&token.Email==mail.To&&payload.TokenId==token.Id&&payload.Token==raw;
            }
            var invite=services.GetRequiredService<SignerInvitationProtection>().Read(mail.PayloadJson);
            var signer=await db.Signers.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==invite.SignerId&&x.EnvelopeId==current.DeclineRecord,ct);
            return signer is not null&&FixedSigner(signer,current.Mailboxes.FirstSigner)&&token.Purpose==TokenPurpose.SignerAccess&&
                token.PartyType==PartyType.Signer&&token.PartyId==signer.Id&&token.Email==current.Mailboxes.FirstSigner&&mail.To==token.Email&&
                invite.LastTokenId==token.Id&&token.DocumentId==invite.DocumentId&&
                Convert.ToHexStringLower(token.DocumentSha256??[])==invite.DocumentSha256&&
                Convert.ToHexStringLower(token.DisclosureSha256??[])==invite.DisclosureSha256;
        }
        finally {await tx.RollbackAsync(ct);}
    }
}

public sealed partial class EmailPilotCloseout
{
    // Reuse the existing protected Kind0/Kind1 and current candidate checks;
    // this authenticates a read only and never reserves or consumes a token.
    internal async Task DemandWebCandidateLockedAsync(QuillSignDbContext current,EmailPilotCloseoutSnapshot snapshot,
        EmailPilotCloseoutStep step,Guid id,CancellationToken ct)
    {
        if(!ReferenceEquals(current,database())||current.Database.CurrentTransaction is null||current.ChangeTracker.HasChanges())throw Invalid();
        var state=await Current(current,snapshot,ct);
        var receipt=(await Operations(current,state,ct)).SingleOrDefault(x=>x.Kind==1&&x.Step==step&&x.WorkId==id)??throw Invalid();
        var mail=await current.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
        var item=await current.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
        if(mail.Status!=EmailStatus.Sent||mail.Attempts!=1||item.Attempts!=1||item.Status is not(WorkStatus.Leased or WorkStatus.Completed)||receipt.At>Now)throw Invalid();
        await DemandCandidateRowsLockedAsync(current,state,step,mail,item,item.Status==WorkStatus.Completed,ct);
    }
}

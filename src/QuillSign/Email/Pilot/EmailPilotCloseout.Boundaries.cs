using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotCloseout
{
    internal Func<CompletionNotificationProtection>? CompletionPayloads {get;init;}

    internal async Task<EmailPilotEnvelopeCohort?> ReadEnvelopeLockedAsync(QuillSignDbContext db,Guid recordId,Func<EmailPayloadProtection> payloads,CancellationToken ct)
    {
        var state=await ReadLockedAsync(db,ct);
        if(state is null || recordId!=state.CompletionRecord && recordId!=state.VoidRecord && recordId!=state.DeclineRecord)return null;
        var record=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={recordId}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(record is null || !record.IsDemo || record.SenderEmail!=state.Mailboxes.Sender ||
            recordId==state.CompletionRecord && record.Status!=EnvelopeStatus.Completed || recordId==state.VoidRecord && record.Status!=EnvelopeStatus.Voided ||
            recordId==state.DeclineRecord && record.Status is not (EnvelopeStatus.Draft or EnvelopeStatus.Sent or EnvelopeStatus.Declined))throw Invalid();
        var parent=state.Parent(recordId);var enrollment=state.Enrollment(recordId);
        await EmailPilotAdmission.ReadSourceAsync(db,parent,enrollment,payloads,ct);
        var deadline=await DocumentRetentionAccess.ReadAsync(db,record,time,ct);DocumentRetentionAccess.Check(deadline,time);
        if(!Available || state.Until<=Now)throw Invalid();
        return new(recordId,parent.RunId,parent,enrollment,true,closeout:state);
    }

    internal async Task BindDeclineWorkLockedAsync(QuillSignDbContext db,Guid recordId,EmailPilotCloseoutStep step,Guid workId,CancellationToken ct)
    {
        var state=await ReadLockedAsync(db,ct);
        if(state is null || recordId!=state.DeclineRecord)return;
        if(step is not (EmailPilotCloseoutStep.DeclineInvitation or EmailPilotCloseoutStep.DeclineNotice))throw Invalid();
        await BindNewWorkLockedAsync(db,state,step,workId,ct);
    }

    // Called before WorkStore changes any attempt/lease/status. Reclaiming a
    // selected closeout item is refused; ambiguous prior effects remain intact.
    internal async Task DemandClaimLockedAsync(QuillSignDbContext db,WorkItem item,CancellationToken ct)
    {
        if(!ReferenceEquals(db,database()) || db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges())throw Invalid();
        var bound=await RecognizesWorkAsync(db,item.Id,ct);
        var selected=ConfiguredNotice(item.Id);
        if(!bound && !selected)return;
        var state=await ReadLockedAsync(db,ct)??throw Invalid();
        var known=state.Manifest.Queue.SingleOrDefault(x=>x.WorkId==item.Id);
        var binding=(await Operations(db,state,ct)).SingleOrDefault(x=>x.Kind==0&&x.WorkId==item.Id);
        if(known is null && binding is null)throw Invalid();
        var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==item.Id,ct);
        if(item.Status!=WorkStatus.Queued || item.Attempts!=0 || item.LeaseOwner is not null || item.LeaseExpiresAt is not null ||
            mail.Status!=EmailStatus.Queued || mail.Attempts!=0 || mail.SubmissionStartedAt is not null || mail.Provider is not null || mail.ProviderMessageId is not null ||
            item.AvailableAt>Now || mail.AvailableAt>Now || await db.Suppressions.AnyAsync(x=>x.Email==mail.To,ct))throw Invalid();
        if(known is not null) {
            DemandQueuedPair(known,mail,item);
        } else if(binding!.RequestSha256!=Hash(new{Mail=Raw(mail),Work=Raw(item)}))throw Invalid();
        if(!Available)throw Invalid();
    }

    internal static void DemandQueuedPair(EmailPilotCloseoutQueue known,EmailOutbox mail,WorkItem item)
    { if(Raw(item)!=known.WorkJson || Raw(mail)!=known.MailJson)throw Invalid(); }

    internal static void DemandOriginalQueue(EmailPilotCloseoutQueue known,EmailOutbox mail,WorkItem item,CompletionNotificationProtection? completion)
    {
        var originalMail=JsonSerializer.Deserialize<EmailOutbox>(known.MailJson,Json)??throw Invalid();
        var originalWork=JsonSerializer.Deserialize<WorkItem>(known.WorkJson,Json)??throw Invalid();
        if(item.Id!=originalWork.Id || item.EnvelopeId!=originalWork.EnvelopeId || item.Kind!=originalWork.Kind ||
            item.PayloadJson!=originalWork.PayloadJson || item.AvailableAt!=originalWork.AvailableAt || item.LastError!=originalWork.LastError ||
            mail.Id!=originalMail.Id || mail.EnvelopeId!=originalMail.EnvelopeId || mail.To!=originalMail.To || mail.Template!=originalMail.Template ||
            mail.AttachmentsJson!=originalMail.AttachmentsJson || mail.AvailableAt!=originalMail.AvailableAt || mail.LastError!=originalMail.LastError)throw Invalid();
        if(known.Step<=EmailPilotCloseoutStep.CompletionRecipient) {
            var codec=completion??throw Invalid();
            var prior=codec.Read(originalMail.PayloadJson);var current=codec.Read(mail.PayloadJson);
            if(prior.LastTokenId is not null || CompletionNotificationJobs.Digest(prior)!=CompletionNotificationJobs.Digest(current))throw Invalid();
        } else if(mail.PayloadJson!=originalMail.PayloadJson)throw Invalid();
    }
}

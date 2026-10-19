using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;

namespace QuillSign.Work;

// Informative only. No session, signing link, attachment or signing key is needed.
public sealed class VoidNotificationDelivery(QuillSignDbContext db,VoidNotificationJobs jobs,VoidNotificationProtection protection,
    Func<VoidEmailTemplate> template,IEmailSender sender,EmailOptions options,AuditWriter audit,TimeProvider time,Email.Pilot.EmailPilotDispatch? pilot=null)
{
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        var pilotDecision=pilot is null ? null : await pilot.DecideAsync(lease,ct);
        if(pilotDecision?.Refusal is {} refusal)return refusal;
        if(pilotDecision is null && !options.Enabled)return new(WorkOutcome.Retry,"delivery-disabled");
        if(lease.Kind!=WorkKind.Email)return new(WorkOutcome.Failed,"invalid-void-notification");
        var email=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
        if(email?.EnvelopeId is not Guid envelopeId || email.Template!=VoidNotificationJobs.Template || email.AttachmentsJson!="[]")return new(WorkOutcome.Failed,"invalid-void-notification");
        VoidNotificationPayload payload;
        try {payload=protection.Read(email.PayloadJson);}
        catch(CryptographicException) {return new(WorkOutcome.Retry,"payload-unavailable");}
        catch(Exception e) when(e is JsonException or ArgumentException or InvalidDataException) {return new(WorkOutcome.Failed,"invalid-void-notification");}
        if(payload.EnvelopeId!=envelopeId || VoidNotificationJobs.Id(payload)!=lease.Id)return new(WorkOutcome.Failed,"invalid-void-notification");
        var remaining=lease.Until-time.GetUtcNow()-TimeSpan.FromSeconds(1);
        if(remaining<=TimeSpan.Zero)return new(WorkOutcome.Retry,"void-mail-lease-unavailable");
        using var deadline=new CancellationTokenSource(remaining,time);
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(ct,deadline.Token);var active=linked.Token;
        var intentMayExist=false;var called=false;
        try {
            OutgoingEmail outgoing;
            await using(var tx=await db.Database.BeginTransactionAsync(active)) {
                var saved=await Guard(lease,email.To,payload,false,active);
                if(await db.Suppressions.AnyAsync(x=>x.Email==email.To,active))return new(WorkOutcome.Failed,"recipient-suppressed");
                outgoing=await template().RenderAsync(saved,email.To,active);
                await Guard(lease,email.To,payload,false,active);
                var at=time.GetUtcNow();
                var changed=await db.EmailOutbox.Where(x=>x.Id==lease.Id && x.Status==EmailStatus.Queued && x.SubmissionStartedAt==null)
                    .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,at).SetProperty(x=>x.Attempts,lease.Attempt),active);
                if(changed!=1)throw new InvalidOperationException("Void submission is no longer available.");intentMayExist=true;
                await audit.AppendAsync(envelopeId,"void_notification_attempt",null,null,null,active,JsonSerializer.Serialize(new {
                    version=VoidNotificationJobs.Version,notificationId=lease.Id,scopeSha256=VoidNotificationJobs.Digest(payload),templateVersion=VoidEmailTemplate.Version,
                    meaning="Submission prepared; no provider acceptance or delivery is confirmed."
                }),PartyType.System);
                await Guard(lease,email.To,payload,true,active);await tx.CommitAsync(active);
            }
            // Recheck after asynchronous rendering, verification and acknowledged commit.
            await using(var tx=await db.Database.BeginTransactionAsync(active)) {
                await Guard(lease,email.To,payload,true,active);
                if(await db.Suppressions.AnyAsync(x=>x.Email==email.To,active))throw new RecipientSuppressedException();
                await tx.CommitAsync(active);
            }
            active.ThrowIfCancellationRequested();called=true;
            var delivery=pilot is null ? await sender.SendAsync(outgoing,active) : await pilot.SendAsync(lease,outgoing,active);
            await using(var tx=await db.Database.BeginTransactionAsync(active)) {
                await Guard(lease,email.To,payload,true,active);
                await db.EmailOutbox.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Provider,delivery.Provider)
                    .SetProperty(x=>x.ProviderMessageId,delivery.MessageId).SetProperty(x=>x.Status,EmailStatus.Sent),active);
                await audit.AppendAsync(envelopeId,"void_notification_submitted",null,null,null,active,JsonSerializer.Serialize(new {
                    version=VoidNotificationJobs.Version,notificationId=lease.Id,scopeSha256=VoidNotificationJobs.Digest(payload),
                    provider=delivery.Provider,providerMessageId=delivery.MessageId,templateVersion=VoidEmailTemplate.Version,
                    meaning="Provider accepted the message; inbox delivery and receipt are not confirmed."
                }),PartyType.System);
                if(await jobs.ResolveLocked(lease.Id,email.To,payload,active) is null)throw VoidNotificationJobs.Invalid();
                await Owned(lease,envelopeId,active);await tx.CommitAsync(active);
            }
            return new(WorkOutcome.Completed);
        }
        catch(EmailNotSubmittedException e) {
            return await ClearKnownUnsent(lease,email.To,payload) ? new(e.Retryable ? WorkOutcome.Retry : WorkOutcome.Failed,"provider-rejected") : new(WorkOutcome.Ambiguous,"void-submission-uncertain");
        }
        catch(Exception e) when(e is RecipientSuppressedException or EmailDisabledException or EmailAttachmentLimitException) {
            var cleared=await ClearKnownUnsent(lease,email.To,payload);
            return !cleared ? new(WorkOutcome.Ambiguous,"void-submission-uncertain") : new(e is RecipientSuppressedException ? WorkOutcome.Failed : WorkOutcome.Retry,
                e is RecipientSuppressedException ? "recipient-suppressed" : e is EmailDisabledException ? "delivery-disabled" : "void-message-limit");
        }
        catch(Exception e) when(!called && e is not OutOfMemoryException) {
            db.ChangeTracker.Clear();
            if(intentMayExist && !await ClearKnownUnsent(lease,email.To,payload))return new(WorkOutcome.Ambiguous,"void-preparation-uncertain");
            ct.ThrowIfCancellationRequested();
            return e is InvalidDataException or JsonException or ArgumentException ? new(WorkOutcome.Failed,"void-notification-integrity") : new(WorkOutcome.Retry,"void-notification-unavailable");
        }
        // Unknown acceptance or receipt commit leaves intent intact. Expired-lease
        // recovery stops ambiguous submissions instead of sending another message.
    }
    private async Task<SenderVoidScope> Guard(WorkLease lease,string to,VoidNotificationPayload p,bool submitted,CancellationToken ct)
    {
        var saved=await jobs.ResolveLocked(lease.Id,to,p,ct)??throw VoidNotificationJobs.Invalid();
        await Owned(lease,p.EnvelopeId,ct);
        var row=await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
        if(row.EnvelopeId!=p.EnvelopeId || row.To!=to || row.Template!=VoidNotificationJobs.Template || row.AttachmentsJson!="[]" || row.Status!=EmailStatus.Queued ||
            row.Provider is not null || row.ProviderMessageId is not null || (row.SubmissionStartedAt is not null)!=submitted || protection.Read(row.PayloadJson)!=p ||
            submitted && row.Attempts!=lease.Attempt)throw VoidNotificationJobs.Invalid();return saved;
    }
    private async Task Owned(WorkLease lease,Guid envelopeId,CancellationToken ct,bool live=true)
    {
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
        if(row.EnvelopeId!=envelopeId || row.Kind!=WorkKind.Email || row.PayloadJson!=VoidNotificationJobs.WorkJson(lease.Id) || row.Status!=WorkStatus.Leased || row.LeaseOwner!=lease.Owner ||
            row.Attempts!=lease.Attempt || row.LeaseExpiresAt!=lease.Until || live && (lease.Until<=time.GetUtcNow() || row.LeaseExpiresAt<=time.GetUtcNow()))throw new InvalidOperationException("Void email lease is unavailable.");
    }
    private async Task<bool> ClearKnownUnsent(WorkLease lease,string to,VoidNotificationPayload p)
    {
        db.ChangeTracker.Clear();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));var ct=timeout.Token;
        try {
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={p.EnvelopeId}").AsNoTracking().SingleAsync(ct);
            await Owned(lease,p.EnvelopeId,ct,live:false);
            var row=await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
            if(row.EnvelopeId!=p.EnvelopeId || row.To!=to || row.Template!=VoidNotificationJobs.Template || row.AttachmentsJson!="[]" || row.Provider is not null || row.ProviderMessageId is not null ||
                row.Status!=EmailStatus.Queued || protection.Read(row.PayloadJson)!=p || row.SubmissionStartedAt is not null && row.Attempts!=lease.Attempt)return false;
            if(row.SubmissionStartedAt is null) {await tx.CommitAsync(ct);return true;}
            await db.EmailOutbox.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,(DateTimeOffset?)null),ct);
            await audit.AppendAsync(p.EnvelopeId,"void_notification_not_submitted",null,null,null,ct,JsonSerializer.Serialize(new {
                version=VoidNotificationJobs.Version,notificationId=lease.Id,scopeSha256=VoidNotificationJobs.Digest(p),meaning="Known non-submission; another finite attempt may be made."
            }),PartyType.System);
            await tx.CommitAsync(ct);return true;
        } catch(Exception e) when(e is not OutOfMemoryException) {db.ChangeTracker.Clear();return false;}
    }
}

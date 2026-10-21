using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Work;

// Submission intent is committed before the provider call. Unknown acceptance is never resent.
public sealed class CompletionNotificationDelivery(QuillSignDbContext db,CompletionAccessState state,CompletionAccess access,
    CompletionNotificationJobs jobs,CompletionNotificationProtection protection,Func<CompletionEmailTemplate> template,IEmailSender sender,
    EmailOptions options,AuditWriter audit,TimeProvider time,Email.Pilot.EmailPilotDispatch? pilot=null)
{
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        var pilotDecision=pilot is null ? null : await pilot.DecideAsync(lease,ct);
        if(pilotDecision?.Refusal is {} refusal)return refusal;
        if(pilotDecision is null && !options.Enabled)return new(WorkOutcome.Retry,"delivery-disabled");
        if(lease.Kind!=WorkKind.Email)return new(WorkOutcome.Failed,"invalid-completion-notification");
        var email=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
        if(email?.EnvelopeId is not Guid envelopeId || email.Template!=CompletionNotificationJobs.Template || email.AttachmentsJson!="[]")return new(WorkOutcome.Failed,"invalid-completion-notification");
        CompletionNotificationPayload payload;
        try {payload=protection.Read(email.PayloadJson);}
        catch(CryptographicException) {return new(WorkOutcome.Retry,"payload-unavailable");}
        catch(Exception e) when(e is JsonException or ArgumentException or InvalidDataException) {return new(WorkOutcome.Failed,"invalid-completion-notification");}
        if(payload.EnvelopeId!=envelopeId)return new(WorkOutcome.Failed,"invalid-completion-notification");
        Email.Pilot.EmailPilotCloseout.AliasFact? alias=null;
        if(CompletionNotificationJobs.Id(payload)!=lease.Id)
        {
            if(pilot is null)return new(WorkOutcome.Failed,"invalid-completion-notification");
            try
            {
                await using var originalParent=await db.Database.BeginTransactionAsync(ct);
                alias=await pilot.ReadAliasLockedAsync(db,lease,email.To,ct);
                if(alias is null||alias.OriginalId!=CompletionNotificationJobs.Id(payload)||alias.AliasId!=lease.Id||alias.RecordId!=envelopeId||alias.Template!=CompletionNotificationJobs.Template)
                    return new(WorkOutcome.Failed,"invalid-completion-notification");
                await originalParent.RollbackAsync(ct);
            }
            catch(Exception error)when(error is InvalidDataException or CryptographicException or JsonException or ArgumentException or InvalidOperationException)
            {return new(WorkOutcome.Failed,"invalid-completion-notification");}
        }
        var remaining=lease.Until-time.GetUtcNow()-TimeSpan.FromSeconds(1);if(remaining<=TimeSpan.Zero)return new(WorkOutcome.Retry,"completion-mail-lease-unavailable");
        using var deadline=new CancellationTokenSource(remaining,time);using var linked=CancellationTokenSource.CreateLinkedTokenSource(ct,deadline.Token);var active=linked.Token;
        CompletionAccessLink? link=null;var intentMayExist=false;var called=false;PreparedCompletionEmail? outgoing=null;
        try {
            var prepared=await state.PrepareAsync(envelopeId,active);if(prepared is null)return new(WorkOutcome.Failed,"completion-not-retained");
            await using(var tx=await db.Database.BeginTransactionAsync(active)) {
                await Guard(prepared,lease,email.To,payload,false,alias,active);
                if(await db.Suppressions.AnyAsync(x=>x.Email==email.To,active))return new(WorkOutcome.Failed,"recipient-suppressed");
                link=await access.PrepareBoundedLockedAsync(prepared,payload.Party,payload.PartyId,active,pilotDecision?.Scope?.RunExpiresAt)??throw CompletionNotificationJobs.Invalid();
                outgoing=await template().RenderAsync(prepared,payload,email.To,link,active);
                await Guard(prepared,lease,email.To,payload,false,alias,active);Live(prepared,link);
                payload=payload with {LastTokenId=link.TokenId};var at=time.GetUtcNow();
                var changed=await db.EmailOutbox.Where(x=>x.Id==lease.Id && x.Status==EmailStatus.Queued && x.SubmissionStartedAt==null)
                    .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,at).SetProperty(x=>x.Attempts,lease.Attempt).SetProperty(x=>x.PayloadJson,protection.Protect(payload)),active);
                if(changed!=1)throw new InvalidOperationException("Completion submission is no longer available.");intentMayExist=true;
                await audit.AppendAsync(envelopeId,"completion_notification_attempt",null,null,null,active,JsonSerializer.Serialize(new {
                    version=CompletionNotificationJobs.Version,notificationId=lease.Id,scopeSha256=CompletionNotificationJobs.Digest(payload),tokenId=link.TokenId,
                    link.ExpiresAt,templateVersion=CompletionEmailTemplate.Version,linkOnly=outgoing.LinkOnly,
                    executedSha256=CompletionNotificationJobs.Hex(prepared.Saved.Executed.Sha256),certificateSha256=CompletionNotificationJobs.Hex(prepared.Saved.Certificate.Sha256),
                    meaning="Submission prepared; no provider acceptance or delivery is confirmed."
                }),PartyType.System);
                await Guard(prepared,lease,email.To,payload,true,alias,active);Live(prepared,link);if(pilotDecision?.Scope?.RunExpiresAt<=time.GetUtcNow())throw new EmailDisabledException();
                await tx.CommitAsync(active);
            }
            // The lease, token deadline and current frozen scope are checked again after
            // all asynchronous verification/rendering and the acknowledged intent commit.
            await using(var tx=await db.Database.BeginTransactionAsync(active)) {
                await Guard(prepared,lease,email.To,payload,true,alias,active);Live(prepared,link);await tx.CommitAsync(active);
            }
            active.ThrowIfCancellationRequested();called=true;
            var delivery=pilot is null ? await sender.SendAsync(outgoing.Message,active) : await pilot.SendAsync(lease,outgoing.Message,active);
            await using(var tx=await db.Database.BeginTransactionAsync(active)) {
                await Guard(prepared,lease,email.To,payload,true,alias,active);
                await db.EmailOutbox.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Provider,delivery.Provider)
                    .SetProperty(x=>x.ProviderMessageId,delivery.MessageId).SetProperty(x=>x.Status,x=>x.Status==EmailStatus.Queued ? EmailStatus.Sent : x.Status),active);
                await audit.AppendAsync(envelopeId,"completion_notification_submitted",null,null,null,active,JsonSerializer.Serialize(new {
                    version=CompletionNotificationJobs.Version,notificationId=lease.Id,scopeSha256=CompletionNotificationJobs.Digest(payload),tokenId=link.TokenId,
                    provider=delivery.Provider,providerMessageId=delivery.MessageId,linkOnly=outgoing.LinkOnly,templateVersion=CompletionEmailTemplate.Version,
                    executedSha256=CompletionNotificationJobs.Hex(prepared.Saved.Executed.Sha256),certificateSha256=CompletionNotificationJobs.Hex(prepared.Saved.Certificate.Sha256),
                    meaning="Provider accepted the message; inbox delivery, receipt and saving are not confirmed."
                }),PartyType.System);
                await state.RecheckLockedAsync(prepared.Saved,active);await Owned(lease,payload.EnvelopeId,active);await tx.CommitAsync(active);
            }
            return new(WorkOutcome.Completed);
        }
        catch(EmailNotSubmittedException e) {
            if(alias is not null)return new(WorkOutcome.Ambiguous,"completion-closeout-submission-unresolved");
            return await ClearKnownUnsent(lease,payload,link?.TokenId) ? new(e.Retryable ? WorkOutcome.Retry : WorkOutcome.Failed,e.FailureCode) : new(WorkOutcome.Ambiguous,"completion-submission-uncertain");
        }
        catch(Exception e) when(e is RecipientSuppressedException or EmailDisabledException or EmailAttachmentLimitException) {
            if(alias is not null)return new(WorkOutcome.Ambiguous,"completion-closeout-submission-unresolved");
            var cleared=await ClearKnownUnsent(lease,payload,link?.TokenId);
            return !cleared ? new(WorkOutcome.Ambiguous,"completion-submission-uncertain") : new(e is RecipientSuppressedException ? WorkOutcome.Failed : WorkOutcome.Retry,
                e is RecipientSuppressedException ? "recipient-suppressed" : e is EmailDisabledException ? "delivery-disabled" : "completion-message-limit");
        }
        catch(Exception e) when(!called && e is not OutOfMemoryException) {
            if(alias is not null){db.ChangeTracker.Clear();ct.ThrowIfCancellationRequested();return new(WorkOutcome.Ambiguous,"completion-closeout-preparation-unresolved");}
            db.ChangeTracker.Clear();
            if(intentMayExist && !await ClearKnownUnsent(lease,payload,link?.TokenId))return new(WorkOutcome.Ambiguous,"completion-preparation-uncertain");
            ct.ThrowIfCancellationRequested();
            if(e is InvalidDataException or JsonException or ArgumentException)return new(WorkOutcome.Failed,"completion-notification-integrity");
            return new(WorkOutcome.Retry,"completion-notification-unavailable");
        }
        // Failures after the provider call may follow acceptance. Keep intent intact;
        // WorkStore's expiry recovery forbids another send unless a receipt was committed.
    }

    private async Task Guard(CompletionAccessPreparation prepared,WorkLease lease,string to,CompletionNotificationPayload p,bool submitted,Email.Pilot.EmailPilotCloseout.AliasFact? alias,CancellationToken ct)
    {
        if(prepared.Until<=time.GetUtcNow())throw CompletionNotificationJobs.Invalid();
        if(alias is null)
        {if(await jobs.ResolveLocked(prepared.Saved,lease.Id,to,p,ct) is null)throw CompletionNotificationJobs.Invalid();}
        else
        {
            var currentAlias=await pilot!.ReadAliasLockedAsync(db,lease,to,ct)??throw CompletionNotificationJobs.Invalid();
            if(currentAlias.AuthorizationId!=alias.AuthorizationId||currentAlias.OriginalId!=alias.OriginalId||currentAlias.AliasId!=alias.AliasId||currentAlias.RecordId!=alias.RecordId||
                currentAlias.Template!=alias.Template||currentAlias.Recipient!=alias.Recipient||currentAlias.Until!=alias.Until||
                await jobs.ResolveCloseoutLocked(prepared.Saved,lease.Id,to,p,currentAlias,ct) is null)throw CompletionNotificationJobs.Invalid();
        }
        await Owned(lease,p.EnvelopeId,ct);
        var email=await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
        var current=protection.Read(email.PayloadJson);
        if(email.EnvelopeId!=p.EnvelopeId || email.To!=to || email.Template!=CompletionNotificationJobs.Template || email.AttachmentsJson!="[]" || email.Status!=EmailStatus.Queued ||
            email.Provider is not null || email.ProviderMessageId is not null || (email.SubmissionStartedAt is not null)!=submitted ||
            CompletionNotificationJobs.Digest(current)!=CompletionNotificationJobs.Digest(p) || current.LastTokenId!=p.LastTokenId || submitted && email.Attempts!=lease.Attempt)throw CompletionNotificationJobs.Invalid();
    }
    private async Task<WorkItem> Owned(WorkLease lease,Guid envelopeId,CancellationToken ct,bool live=true)
    {
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
        if(row.EnvelopeId!=envelopeId || row.Kind!=WorkKind.Email || row.PayloadJson!=CompletionNotificationJobs.WorkJson(lease.Id) || row.Status!=WorkStatus.Leased || row.LeaseOwner!=lease.Owner ||
            row.Attempts!=lease.Attempt || row.LeaseExpiresAt!=lease.Until || live && (lease.Until<=time.GetUtcNow() || row.LeaseExpiresAt<=time.GetUtcNow()))throw new InvalidOperationException("Completion email lease is unavailable.");return row;
    }
    private void Live(CompletionAccessPreparation prepared,CompletionAccessLink link) {
        if(prepared.Until<=time.GetUtcNow() || prepared.Saved.PurgeAfter<=time.GetUtcNow() || link.ExpiresAt<=time.GetUtcNow())throw CompletionNotificationJobs.Invalid();
    }
    private async Task<bool> ClearKnownUnsent(WorkLease lease,CompletionNotificationPayload p,Guid? tokenId)
    {
        db.ChangeTracker.Clear();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));var ct=timeout.Token;
        try {
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={p.EnvelopeId}").AsNoTracking().SingleAsync(ct);
            await Owned(lease,p.EnvelopeId,ct,live:false);
            var row=await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
            var current=protection.Read(row.PayloadJson);
            if(row.EnvelopeId!=p.EnvelopeId || row.Template!=CompletionNotificationJobs.Template || row.AttachmentsJson!="[]" || row.Provider is not null || row.ProviderMessageId is not null ||
                row.Status!=EmailStatus.Queued || CompletionNotificationJobs.Digest(current)!=CompletionNotificationJobs.Digest(p))return false;
            if(row.SubmissionStartedAt is null) {await tx.CommitAsync(ct);return true;}
            if(tokenId is null || current.LastTokenId!=tokenId || await db.AuthTokens.AnyAsync(x=>x.Id==tokenId && x.UsedAt!=null,ct))return false;
            await db.EmailOutbox.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,(DateTimeOffset?)null),ct);
            await audit.AppendAsync(p.EnvelopeId,"completion_notification_not_submitted",null,null,null,ct,JsonSerializer.Serialize(new {
                version=CompletionNotificationJobs.Version,notificationId=lease.Id,tokenId,scopeSha256=CompletionNotificationJobs.Digest(p),
                meaning="Known non-submission; unused completion hashes retain their original expiry."
            }),PartyType.System);
            await tx.CommitAsync(ct);return true;
        } catch(Exception e) when(e is not OutOfMemoryException) {db.ChangeTracker.Clear();return false;}
    }
}

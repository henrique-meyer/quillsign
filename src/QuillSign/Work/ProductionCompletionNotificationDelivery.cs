using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;

namespace QuillSign.Work;

public sealed partial class CompletionNotificationDelivery
{
    internal async Task<WorkResult> ExecuteAdmittedAsync(WorkLease lease,EmailOutbox original,IProductionWorkAdmission admission,CancellationToken ct)
    {
        try {return await ExecuteAdmittedCoreAsync(lease,original,admission,ct);}
        catch(Exception e) when(e is InvalidDataException or JsonException or CryptographicException or ArgumentException or QuillSign.Documents.DocumentConflictException)
        {throw new ProductionWorkBlockedException(e);}
    }
    private async Task<WorkResult> ExecuteAdmittedCoreAsync(WorkLease lease,EmailOutbox original,IProductionWorkAdmission admission,CancellationToken ct)
    {
        if(admission is not ProductionWorkAdmission {CompletionMail:{} gate} || db.Database.CurrentTransaction is not null ||
            db.ChangeTracker.HasChanges() || pilot is not null || !options.Enabled || lease.Kind!=WorkKind.Email || original.Id!=lease.Id)
            throw new ProductionWorkBlockedException();
        var payload=gate.Read(original.PayloadJson);
        if(original.EnvelopeId is not {} id || payload.LastTokenId is not null)throw new ProductionWorkBlockedException();
        CompletionAccessPreparation prepared;CompletionAccessLink link;PreparedCompletionEmail outgoing;
        DateTimeOffset? originalTokenUntil=null;
        ProductionRecordDispatchPermit permit;string submittedMail,tokenJson;
        await using(var tx=await db.Database.BeginTransactionAsync(ct))
        {
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleAsync(ct);
            await Initial();
            prepared=await state.PrepareLockedAsync(id,DemandInitial,LeaseClock,ct)??throw new ProductionWorkBlockedException();
            using var reads=CompletionReadRestriction.Enter(db,PreparedClock);
            await Initial();
            link=await access.PrepareBoundedLockedAsync(prepared,payload.Party,payload.PartyId,ct,null)??throw new ProductionWorkBlockedException();
            originalTokenUntil=link.ExpiresAt;
            Clocks();
            outgoing=await template().RenderAsync(prepared,payload,original.To,link,ct);
            Clocks();
            DemandAttachmentMode(prepared.Verified,outgoing);
            await Guard(prepared,lease,original.To,payload,false,null,ct);Clocks();
            var issued=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==link.TokenId,ct);
            tokenJson=JsonSerializer.Serialize(issued);
            payload=payload with{LastTokenId=link.TokenId};var at=time.GetUtcNow();
            if(await db.EmailOutbox.Where(x=>x.Id==lease.Id&&x.Status==EmailStatus.Queued&&x.SubmissionStartedAt==null)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,at).SetProperty(x=>x.Attempts,lease.Attempt)
                    .SetProperty(x=>x.PayloadJson,protection.Protect(payload)),ct)!=1)throw new ProductionWorkBlockedException();
            await audit.AppendAsync(id,"completion_notification_attempt",null,null,null,ct,
                AttemptEvidence(lease.Id,payload,link.ExpiresAt,outgoing.LinkOnly,prepared.Saved.Executed.Sha256,prepared.Saved.Certificate.Sha256),PartyType.System);
            await Guard(prepared,lease,original.To,payload,true,null,ct);Clocks();
            submittedMail=JsonSerializer.Serialize(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,ct));
            permit=await admission.PrepareDispatchLockedAsync(db,lease,id,ct)??throw new ProductionWorkBlockedException();
            Clocks();await tx.CommitAsync(ct);
        }
        await using(var proof=await db.Database.BeginTransactionAsync(ct))
        {
            using var reads=CompletionReadRestriction.Enter(db,Clocks);
            await ExactPrepared();
            await admission.ConsumeDispatchLockedAsync(db,permit,ct);Clocks();
            await proof.RollbackAsync(ct);
        }
        Clocks();ct.ThrowIfCancellationRequested();
        // No retry/reset branch here. Even known non-submission keeps the original
        // once-only operation and token parked for explicit reconciliation.
        var delivery=await sender.SendAsync(outgoing.Message,ct);
        await using(var tx=await db.Database.BeginTransactionAsync(ct))
        {
            using var reads=CompletionReadRestriction.Enter(db,Clocks);
            await ExactPrepared();
            await admission.DemandDispatchReceiptLockedAsync(db,permit,ct);Clocks();
            if(string.IsNullOrWhiteSpace(delivery.Provider)||delivery.Provider.Length>128||
                string.IsNullOrWhiteSpace(delivery.MessageId)||delivery.MessageId.Length>512)throw new ProductionWorkBlockedException();
            if(await db.EmailOutbox.Where(x=>x.Id==lease.Id&&x.Status==EmailStatus.Queued&&x.SubmissionStartedAt!=null)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Provider,delivery.Provider).SetProperty(x=>x.ProviderMessageId,delivery.MessageId)
                    .SetProperty(x=>x.Status,EmailStatus.Sent),ct)!=1)throw new ProductionWorkBlockedException();
            await audit.AppendAsync(id,"completion_notification_submitted",null,null,null,ct,
                SubmittedEvidence(lease.Id,payload,delivery.Provider,delivery.MessageId,outgoing.LinkOnly,prepared.Saved.Executed.Sha256,prepared.Saved.Certificate.Sha256),PartyType.System);
            await state.RecheckLockedAsync(prepared.Saved,ct);Clocks();
            await admission.PrepareHandlerOutcomeLockedAsync(db,lease,id,ct);Clocks();await tx.CommitAsync(ct);
        }
        return new(WorkOutcome.Completed);

        async Task DemandInitial(CancellationToken cancel) {
            await admission.DemandLockedAsync(db,lease.Id,id,lease.Kind,lease.Owner,lease.Attempt,false,cancel);
            if(lease.Until<=time.GetUtcNow())throw new ProductionWorkBlockedException();
        }
        async Task Initial() {
            var current=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,ct);
            if(JsonSerializer.Serialize(current)!=JsonSerializer.Serialize(original))throw new ProductionWorkBlockedException();
            await gate.DemandInitialAsync(db,current,ct);
            await Owned(lease,id,ct);await DemandInitial(ct);
            if(await db.Suppressions.AnyAsync(x=>x.Email==original.To,ct))throw new ProductionWorkBlockedException();
        }
        async Task ExactPrepared() {
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleAsync(ct);
            await Guard(prepared,lease,original.To,payload,true,null,ct);
            if(JsonSerializer.Serialize(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,ct))!=submittedMail ||
                JsonSerializer.Serialize(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==link.TokenId,ct))!=tokenJson)
                throw new ProductionWorkBlockedException();
            Clocks();
        }
        void Clocks() {
            PreparedClock();
            Live(prepared,link);
        }
        void PreparedClock() {LeaseClock();if(prepared.Until<=time.GetUtcNow() || prepared.Saved.PurgeAfter<=time.GetUtcNow() || originalTokenUntil<=time.GetUtcNow())throw new ProductionWorkBlockedException();}
        void LeaseClock() {ct.ThrowIfCancellationRequested();if(lease.Until<=time.GetUtcNow())throw new ProductionWorkBlockedException();}
    }

    internal static void DemandAttachmentMode(PublishedCompletion verified,PreparedCompletionEmail outgoing)
    {
        var attachments=outgoing.Message.Attachments;
        if(outgoing.LinkOnly) {if(attachments is not {Count:0})throw new ProductionWorkBlockedException();return;}
        if(attachments is not {Count:2} ||
            !attachments[0].CopyBytes().AsSpan().SequenceEqual(verified.ExecutedBytes) ||
            !attachments[1].CopyBytes().AsSpan().SequenceEqual(verified.CertificateBytes))throw new ProductionWorkBlockedException();
    }
    internal static string AttemptEvidence(Guid notificationId,CompletionNotificationPayload payload,DateTimeOffset expiresAt,bool linkOnly,byte[] executed,byte[] certificate)
        =>JsonSerializer.Serialize(new {version=CompletionNotificationJobs.Version,notificationId,scopeSha256=CompletionNotificationJobs.Digest(payload),tokenId=payload.LastTokenId,
            ExpiresAt=expiresAt,templateVersion=CompletionEmailTemplate.Version,linkOnly,
            executedSha256=CompletionNotificationJobs.Hex(executed),certificateSha256=CompletionNotificationJobs.Hex(certificate),
            meaning="Submission prepared; no provider acceptance or delivery is confirmed."});
    internal static string SubmittedEvidence(Guid notificationId,CompletionNotificationPayload payload,string provider,string providerMessageId,bool linkOnly,byte[] executed,byte[] certificate)
        =>JsonSerializer.Serialize(new {version=CompletionNotificationJobs.Version,notificationId,scopeSha256=CompletionNotificationJobs.Digest(payload),tokenId=payload.LastTokenId,
            provider,providerMessageId,linkOnly,templateVersion=CompletionEmailTemplate.Version,
            executedSha256=CompletionNotificationJobs.Hex(executed),certificateSha256=CompletionNotificationJobs.Hex(certificate),
            meaning="Provider accepted the message; inbox delivery, receipt and saving are not confirmed."});
}

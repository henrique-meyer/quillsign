using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Signing;
using QuillSign.Lifecycle;

namespace QuillSign.Work;

public sealed class SignerCheckpointHandler(QuillSignDbContext db,SignerCheckpointState state,SignerCheckpointBlobs blobs,
    SignerInvitationOutbox invitations,AuditWriter audit,TimeProvider time,CompletionJobs? completion=null,SignerReminderJobs? reminders=null) : IWorkHandler
{
    internal IProductionWorkAdmission? HoldAdmission {get;init;}
    public WorkKind Kind=>WorkKind.Rendering;
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        try
        {
            if(HoldAdmission is not null)ProductionSignerMutationAdmission.DemandStandalone(db);
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            var located=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
            if(lease.Kind!=Kind || located?.EnvelopeId is not Guid envelopeId || located.Kind!=Kind || located.PayloadJson.Length>1024)return new(WorkOutcome.Failed,"invalid-checkpoint-scope");
            SignerCheckpointPayload? payload;
            try { payload=JsonSerializer.Deserialize<SignerCheckpointPayload>(located.PayloadJson); } catch(JsonException) { return new(WorkOutcome.Failed,"invalid-checkpoint-payload"); }
            if(payload?.Version!=SignerCheckpointJobs.Version || payload.FinishId!=lease.Id)return new(WorkOutcome.Failed,"invalid-checkpoint-payload");
            await using var transaction=await db.Database.BeginTransactionAsync(ct);
            var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {envelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
            if(envelope is null || !await Owns(lease,located.PayloadJson,envelopeId,ct))return new(WorkOutcome.Retry,"checkpoint-lease-unavailable");
            var production=HoldAdmission is not null&&await HoldAdmission.DemandCheckpointLockedAsync(db,lease,envelopeId,ct);
            if(production&&located.PayloadJson!=JsonSerializer.Serialize(payload))throw new ProductionWorkBlockedException();
            if(!await Owns(lease,located.PayloadJson,envelopeId,ct))return new(WorkOutcome.Retry,"checkpoint-lease-unavailable");
            var f=await db.SignerFinishAcceptances.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==payload.FinishId && x.EnvelopeId==envelopeId,ct);
            var signer=f is null ? null : await db.Signers.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==f.SignerId && x.EnvelopeId==envelopeId,ct);
            if(f is null || signer is null || envelope.ErsdVersion is null || envelope.ErsdText is null || envelope.Title is null || envelope.ErsdSha256 is not { Length:32 } ||
                !ElectronicRecordDisclosure.Verify(new(envelope.ErsdVersion,envelope.PublicId,envelope.Title,envelope.SenderEmail,envelope.ErsdText,envelope.ErsdSha256)) ||
                !SignerCheckpointState.Same(f.DisclosureSha256,envelope.ErsdSha256))return new(WorkOutcome.Failed,"checkpoint-evidence-unavailable");
            var source=await state.CurrentAsync(envelope,ct); if(source is null)return new(WorkOutcome.Failed,"checkpoint-chain-unavailable");
            var adopted=await state.AcceptanceAsync(f,signer,ct); if(adopted is null)return new(WorkOutcome.Failed,"checkpoint-evidence-unavailable");
            if(production)await DemandWorkerLocked(lease,located.PayloadJson,envelopeId,ct);
            _=await blobs.PdfAsync(f,true,ct);
            if(production)await DemandWorkerLocked(lease,located.PayloadJson,envelopeId,ct);
            _=await blobs.PdfAsync(f,false,ct);
            if(production)await DemandWorkerLocked(lease,located.PayloadJson,envelopeId,ct);
            await blobs.AssetsAsync(f,adopted,ct);
            if(production)await DemandWorkerLocked(lease,located.PayloadJson,envelopeId,ct);
            if(!await Owns(lease,located.PayloadJson,envelopeId,ct))return new(WorkOutcome.Retry,"checkpoint-lease-unavailable");
            if(f.ProcessedAt is not null)
            {
                var evidence=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId && x.Event=="signer_completed" && x.ActorId==signer.Id).ToArrayAsync(ct);
                if(signer.Status!=SignerStatus.Signed || signer.SignedAt!=f.FinishedAt || !SignerCheckpointState.PublishedEvidence(evidence,f,signer))return new(WorkOutcome.Failed,"checkpoint-evidence-unavailable");
                if(production)
                {
                    // Admission verified the exact existing downstream work.
                    // Missing work is never repaired by a readonly replay.
                    await HoldAdmission!.PrepareHandlerOutcomeLockedAsync(db,lease,envelopeId,ct);
                    if(!await Owns(lease,located.PayloadJson,envelopeId,ct))throw new ProductionWorkBlockedException();
                    await transaction.CommitAsync(ct);return new(WorkOutcome.Completed);
                }
                var recovered=completion is not null && !await db.Signers.AnyAsync(x=>x.EnvelopeId==envelopeId && x.Order>signer.Order,ct) ? await completion.PrepareAsync(envelopeId,ct) : null;
                var recoveredReminders=reminders is null ? [] : await reminders.PrepareCurrentLockedAsync(envelopeId,ct);
                await transaction.CommitAsync(ct); await transaction.DisposeAsync();
                if(reminders is not null)await reminders.PublishAsync(recoveredReminders,ct);
                if(recovered is Guid recoveredWork)await completion!.PublishAsync(recoveredWork,ct);
                return new(WorkOutcome.Completed);
            }
            if(!Accepted(envelope,f) || signer.Status!=SignerStatus.Viewed || signer.SignedAt is not null || source.ObjectId!=f.SourceObjectId ||
                !SignerCheckpointState.Same(source.Sha256,f.SourceSha256) || await db.Signers.AnyAsync(x=>x.EnvelopeId==envelopeId && x.Order<signer.Order && x.Status!=SignerStatus.Signed,ct))
                return new(WorkOutcome.Failed,"checkpoint-not-current");
            var next=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId && x.Order>signer.Order).OrderBy(x=>x.Order).FirstOrDefaultAsync(ct);
            if(next is not null && next.Status!=SignerStatus.Pending)return new(WorkOutcome.Failed,"next-signer-not-pending");
            if(production&&(source.Version!=signer.Order-1||next is not null&&next.Order!=signer.Order+1||
                next is null&&(completion is null||completion.HoldAdmission is null)))throw new ProductionWorkBlockedException();
            var inviteNext=next is not null && (envelope.ExpiresAt is null || envelope.ExpiresAt>time.GetUtcNow());
            f.ProcessedAt=time.GetUtcNow(); f.NextInvitationId=inviteNext ? Guid.NewGuid() : null;
            var changed=await db.SignerFinishAcceptances.Where(x=>x.Id==f.Id && x.RowVersion==f.RowVersion && x.ProcessedAt==null)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ProcessedAt,f.ProcessedAt).SetProperty(x=>x.NextInvitationId,f.NextInvitationId),ct);
            if(changed!=1)return new(WorkOutcome.Retry,"checkpoint-conflict");
            var signerChanged=await db.Signers.Where(x=>x.Id==signer.Id && x.EnvelopeId==envelopeId && x.Status==SignerStatus.Viewed && x.RowVersion==signer.RowVersion)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Signed).SetProperty(x=>x.SignedAt,f.FinishedAt).SetProperty(x=>x.SignedIp,f.Ip).SetProperty(x=>x.SignedUa,f.UserAgent),ct);
            var envelopeChanged=await db.Envelopes.Where(x=>x.Id==envelopeId && x.RowVersion==envelope.RowVersion)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CurrentFinishId,f.Id).SetProperty(x=>x.CurrentCopyVersion,source.Version+1),ct);
            if(signerChanged!=1 || envelopeChanged!=1)return new(WorkOutcome.Retry,"checkpoint-conflict");
            await audit.AppendAsync(envelopeId,"signer_completed",signer.Email,f.Ip,f.UserAgent,ct,SignerCheckpointState.PublishedJson(f),PartyType.Signer,signer.Id);
            if(inviteNext)await invitations.PrepareAsync(envelopeId,next!.Id,next.Email,ct,f.NextInvitationId,
                production?(id,due,token)=>DemandInvitationHintLocked(lease,located.PayloadJson,envelope,f,next!,id,due,token):null);
            var reminderSchedule=reminders is null ? [] : await reminders.PrepareCurrentLockedAsync(envelopeId,ct,
                production?(id,due,token)=>DemandReminderHintLocked(lease,located.PayloadJson,envelopeId,id,due,token):null);
            var completionWork=next is null&&completion is not null?await completion.PrepareAsync(envelopeId,ct,
                production?(id,due,token)=>DemandCompletionHintLocked(lease,located.PayloadJson,envelope,f,signer.Order,id,due,token):null):null;
            if(production&&next is null&&completionWork!=CompletionJobs.WorkId(envelopeId))throw new ProductionWorkBlockedException();
            if(!Accepted(envelope,f) || inviteNext && envelope.ExpiresAt<=time.GetUtcNow() || !await Owns(lease,located.PayloadJson,envelopeId,ct))return new(WorkOutcome.Retry,"checkpoint-expired-during-publication");
            if(production)
            {
                await HoldAdmission!.PrepareHandlerOutcomeLockedAsync(db,lease,envelopeId,ct);
                if(!Accepted(envelope,f)||inviteNext&&envelope.ExpiresAt<=time.GetUtcNow()||!await Owns(lease,located.PayloadJson,envelopeId,ct))throw new ProductionWorkBlockedException();
            }
            await transaction.CommitAsync(ct); await transaction.DisposeAsync();
            if(f.NextInvitationId is Guid invitation)await invitations.PublishAsync(invitation,ct);
            if(reminders is not null)await reminders.PublishAsync(reminderSchedule,ct);
            if(completionWork is Guid finalization)await completion!.PublishAsync(finalization,ct);
            return new(WorkOutcome.Completed);
        }
        catch(ProductionWorkBlockedException){return new(WorkOutcome.Retry,"checkpoint-admission-unavailable");}
        catch(Exception e) when(e is IOException or Azure.RequestFailedException or HttpRequestException or EmailDisabledException)
        { return new(WorkOutcome.Retry,"checkpoint-storage-or-delivery-unavailable"); }
        catch(Exception e) when(e is InvalidDataException or SignatureImageRejectedException or DocumentRejectedException)
        { return new(WorkOutcome.Failed,"checkpoint-integrity-unavailable"); }
    }
    private async Task DemandWorkerLocked(WorkLease lease,string payload,Guid recordId,CancellationToken ct)
    {
        if(!await Owns(lease,payload,recordId,ct))throw new ProductionWorkBlockedException();
        await HoldAdmission!.DemandLockedAsync(db,lease.Id,recordId,lease.Kind,lease.Owner,lease.Attempt,false,ct);
        if(!await Owns(lease,payload,recordId,ct))throw new ProductionWorkBlockedException();
    }
    private async Task DemandInvitationHintLocked(WorkLease lease,string payload,Envelope original,SignerFinishAcceptance finish,Signer next,
        Guid id,DateTimeOffset due,CancellationToken ct)
    {
        if(id!=finish.NextInvitationId||original.ExpiresAt<=time.GetUtcNow()||!await Owns(lease,payload,original.Id,ct))throw new ProductionWorkBlockedException();
        await HoldAdmission!.DemandLockedAsync(db,lease.Id,original.Id,lease.Kind,lease.Owner,lease.Attempt,false,ct);
        var work=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        var mail=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        var current=await state.CurrentAsync(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==original.Id,ct),ct);
        if(work is null||mail is null||work.EnvelopeId!=original.Id||work.Kind!=WorkKind.Email||work.Status!=WorkStatus.Queued||work.Attempts!=0||
            work.LeaseOwner is not null||work.LeaseExpiresAt is not null||work.AvailableAt!=due||mail.EnvelopeId!=original.Id||mail.Template!="signer-invitation"||
            mail.To!=next.Email||mail.Status!=EmailStatus.Queued||mail.Attempts!=0||mail.SubmissionStartedAt is not null||mail.Provider is not null||mail.ProviderMessageId is not null||
            mail.AvailableAt!=due||mail.AttachmentsJson!="[]"||current is null||current.ObjectId!=finish.PdfObjectId||current.Version!=next.Order-1||current.FinishId!=finish.Id||
            !SignerCheckpointState.Same(current.Sha256,finish.PdfSha256)||original.ExpiresAt<=time.GetUtcNow()||!await Owns(lease,payload,original.Id,ct))throw new ProductionWorkBlockedException();
    }
    private async Task DemandReminderHintLocked(WorkLease lease,string payload,Guid recordId,Guid id,DateTimeOffset due,CancellationToken ct)
    {
        await DemandWorkerLocked(lease,payload,recordId,ct);
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct)??throw new ProductionWorkBlockedException();
        if(row.EnvelopeId!=recordId||row.Kind!=WorkKind.Reminder||row.Status!=WorkStatus.Queued||row.Attempts!=0||row.LeaseOwner is not null||
            row.LeaseExpiresAt is not null||row.AvailableAt!=due)throw new ProductionWorkBlockedException();
        _=await SignerReminderJobs.ReadWorkEpochLockedAsync(db,recordId,row,time,ct);
        await DemandWorkerLocked(lease,payload,recordId,ct);
    }
    private async Task DemandCompletionHintLocked(WorkLease lease,string payload,Envelope original,SignerFinishAcceptance finish,int copyVersion,
        Guid id,DateTimeOffset due,CancellationToken ct)
    {
        if(id!=CompletionJobs.WorkId(original.Id)||finish.NextInvitationId is not null||!Accepted(original,finish)||
            !await Owns(lease,payload,original.Id,ct))throw new ProductionWorkBlockedException();
        await HoldAdmission!.DemandLockedAsync(db,lease.Id,original.Id,lease.Kind,lease.Owner,lease.Attempt,false,ct);
        var work=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==original.Id,ct);
        var current=await state.CurrentAsync(envelope,ct);
        if(current is null||current.Version!=copyVersion||current.FinishId!=finish.Id||current.ObjectId!=finish.PdfObjectId||
            !SignerCheckpointState.Same(current.Sha256,finish.PdfSha256)||envelope.ErsdSha256 is not {Length:32}||
            await db.Signers.AnyAsync(x=>x.EnvelopeId==original.Id&&x.Status!=SignerStatus.Signed,ct)||
            work is null||work.EnvelopeId!=original.Id||work.Kind!=WorkKind.Sealing||work.Status!=WorkStatus.Queued||work.Attempts!=0||
            work.LeaseOwner is not null||work.LeaseExpiresAt is not null||work.AvailableAt!=due||
            work.PayloadJson!=JsonSerializer.Serialize(new CompletionWorkPayload(CompletionJobs.Version,finish.Id,copyVersion,
                Convert.ToHexStringLower(finish.PdfSha256),Convert.ToHexStringLower(envelope.ErsdSha256)))||
            !Accepted(original,finish)||!await Owns(lease,payload,original.Id,ct))throw new ProductionWorkBlockedException();
    }
    // The signer acted before the frozen deadline. Processing time must not discard
    // that acceptance, but later invitation issuance still requires a live deadline.
    private bool Accepted(Envelope envelope,SignerFinishAcceptance finish)=>envelope.Status==EnvelopeStatus.Sent && envelope.SenderVerifiedAt is not null &&
        envelope.SentAt<=finish.FinishedAt && finish.FinishedAt<=time.GetUtcNow() &&
        (envelope.ExpiresAt is null || finish.FinishedAt<envelope.ExpiresAt && finish.ReviewExpiresAt<=envelope.ExpiresAt);
    private async Task<bool> Owns(WorkLease lease,string payload,Guid recordId,CancellationToken ct)
    {
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        return row is not null && row.EnvelopeId==recordId && row.Kind==Kind && row.Status==WorkStatus.Leased && row.LeaseOwner==lease.Owner && row.Attempts==lease.Attempt &&
            row.LeaseExpiresAt==lease.Until && row.LeaseExpiresAt>time.GetUtcNow() && row.PayloadJson==payload;
    }
}

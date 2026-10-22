using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed record EmailPilotCloseoutPassResult(int CompletedFacts,int Processed,int Refused,int Ambiguous);
internal sealed record EmailPilotCloseoutPassTarget(Guid Id,bool Completed);

public sealed partial class EmailPilotCloseout
{
    internal Func<SignerInvitationProtection>? InvitationPayloads {get;init;}
    internal Func<LookupDeliveryProtection>? LookupPayloads {get;init;}
    internal bool HandoffHost=>options.HostRole==EmailPilotCloseoutHostRole.Handoff&&!options.Enabled&&email.Enabled&&work.Enabled;
    internal async Task<bool> HandoffLockedAsync(QuillSignDbContext db,Guid id,CancellationToken ct)
    {
        if(!ReferenceEquals(db,database())||db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw Invalid();
        if(!HandoffHost)return false;
        if(!options.PrivateSetBinding(email)||options.StartsAt>Now||options.Until<=Now)throw Invalid();
        var cfg=options.CaptureReceiptConfiguration();var state=await ReadSnapshotLockedAsync(db,cfg,ct)??throw Invalid();
        var known=state.Manifest.Queue.SingleOrDefault(x=>x.WorkId==id);
        var binding=(await Operations(db,state,ct)).SingleOrDefault(x=>x.Kind==0&&x.WorkId==id);
        if(known is null&&binding is null)throw Invalid();
        var item=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id,ct);var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
        if(item.Status==WorkStatus.Queued&&item.Attempts==0&&item.LeaseOwner is null&&item.LeaseExpiresAt is null&&mail.Status==EmailStatus.Queued&&mail.Attempts==0&&mail.SubmissionStartedAt is null&&mail.Provider is null&&mail.ProviderMessageId is null) {
            if(known is not null)DemandQueuedPair(known,mail,item);else if(binding!.RequestSha256!=Hash(new{Mail=Raw(mail),Work=Raw(item)}))throw Invalid();
        } else {
            if(item.Status!=WorkStatus.Leased||item.Attempts!=1||item.LeaseOwner is null||item.LeaseOwner==Guid.Empty||item.LeaseExpiresAt is not {} leaseUntil||leaseUntil.Offset!=TimeSpan.Zero||leaseUntil<=state.Manifest.CreatedAt||leaseUntil>state.Until||mail.Status is not (EmailStatus.Queued or EmailStatus.Sent)||mail.Attempts is <0 or >1)throw Invalid();
            var reserved=(await Operations(db,state,ct)).SingleOrDefault(x=>x.Kind==1&&x.Step==(known?.Step??binding!.Step));
            if(reserved is not null&&reserved.WorkId!=id||mail.Status==EmailStatus.Sent&&reserved is null)throw Invalid();
            if(mail.Attempts==0?(mail.SubmissionStartedAt is not null||mail.Status!=EmailStatus.Queued||mail.Provider is not null||mail.ProviderMessageId is not null):
                (mail.SubmissionStartedAt is not {} at||at<state.Manifest.CreatedAt||at>=state.Until||at>Now||
                    (mail.Status==EmailStatus.Queued?mail.Provider is not null||mail.ProviderMessageId is not null:mail.Provider is not {Length:>0}||mail.ProviderMessageId is not {Length:>0})))throw Invalid();
            await DemandCandidateRowsLockedAsync(db,state,known?.Step??binding!.Step,mail,item,false,ct);
        }
        if(!HandoffHost||!options.PrivateSetBinding(email)||Hash(options.CaptureReceiptConfiguration())!=Hash(cfg)||options.Until<=Now)throw Invalid();
        return true;
    }
    internal async Task<EmailPilotCloseoutPassTarget[]> PassTargetsAsync(CancellationToken ct)
    {
        if(!PassHost||!CanSend)throw Invalid();var db=database();Clean(db);
        await using var tx=await db.Database.BeginTransactionAsync(ct);var state=await ReadLockedAsync(db,ct)??throw Invalid();
        var operations=await Operations(db,state,ct);var targets=new List<EmailPilotCloseoutPassTarget>();
        foreach(var step in Enum.GetValues<EmailPilotCloseoutStep>())
        {
            var id=await ReadStepLockedAsync(db,state,step,ct);if(id is null)continue;
            var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
            var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
            if(row.Kind!=WorkKind.Email||mail.Id!=row.Id)throw Invalid();
            var completed=row.Status==WorkStatus.Completed&&mail.Status==EmailStatus.Sent&&row.Attempts==1&&mail.Attempts==1&&
                row.LeaseOwner is null&&row.LeaseExpiresAt is null&&mail.SubmissionStartedAt is not null&&
                mail.Provider is {Length:>0}&&mail.ProviderMessageId is {Length:>0}&&operations.Count(x=>x.Kind==1&&x.Step==step&&x.WorkId==id)==1;
            if(completed)await DemandCandidateRowsLockedAsync(db,state,step,mail,row,true,ct);
            else await DemandClaimLockedAsync(db,row,ct);
            targets.Add(new(id.Value,completed));
        }
        if(targets.Count>10||targets.Select(x=>x.Id).Distinct().Count()!=targets.Count||!CanSend)throw Invalid();
        await tx.RollbackAsync(ct);return targets.ToArray();
    }
    private async Task DemandCandidateRowsLockedAsync(QuillSignDbContext db,EmailPilotCloseoutSnapshot state,EmailPilotCloseoutStep step,EmailOutbox mail,WorkItem item,bool completed,CancellationToken ct)
    {
        var known=state.Manifest.Queue.SingleOrDefault(x=>x.WorkId==item.Id);var record=step==EmailPilotCloseoutStep.Lookup?state.CompletionRecord:step<=EmailPilotCloseoutStep.CompletionRecipient?state.CompletionRecord:step<=EmailPilotCloseoutStep.VoidSigner?state.VoidRecord:state.DeclineRecord;
        var role=step is EmailPilotCloseoutStep.CompletionFirstSigner or EmailPilotCloseoutStep.VoidSigner or EmailPilotCloseoutStep.DeclineInvitation?EmailPilotRole.FirstSigner:step==EmailPilotCloseoutStep.CompletionSecondSigner?EmailPilotRole.SecondSigner:step==EmailPilotCloseoutStep.CompletionRecipient?EmailPilotRole.Recipient:EmailPilotRole.Sender;
        var template=step switch {<=EmailPilotCloseoutStep.CompletionRecipient=>CompletionNotificationJobs.Template,<=EmailPilotCloseoutStep.VoidSigner=>VoidNotificationJobs.Template,EmailPilotCloseoutStep.DeclineVerification=>"sender-verification",EmailPilotCloseoutStep.DeclineInvitation=>"signer-invitation",EmailPilotCloseoutStep.DeclineNotice=>"signer-declined",EmailPilotCloseoutStep.Lookup=>LookupDeliveryProtection.Template,_=>throw Invalid()};
        if(Role(state.Mailboxes,mail.To)!=role||mail.Template!=template||item.Kind!=WorkKind.Email||item.LastError is not null||mail.LastError is not null||item.AvailableAt<state.Manifest.CreatedAt||item.AvailableAt>Now||
            (step==EmailPilotCloseoutStep.Lookup?mail.EnvelopeId is not null||item.EnvelopeId is not null:mail.EnvelopeId!=record||item.EnvelopeId!=record))throw Invalid();
        var queued=known??(await Operations(db,state,ct)).Single(x=>x.Kind==0&&x.Step==step&&x.WorkId==item.Id).Queued??throw Invalid();
        var originalMail=System.Text.Json.JsonSerializer.Deserialize<EmailOutbox>(queued.MailJson,Json)??throw Invalid();
        var originalWork=System.Text.Json.JsonSerializer.Deserialize<WorkItem>(queued.WorkJson,Json)??throw Invalid();
        var projectedMail=System.Text.Json.JsonSerializer.Deserialize<EmailOutbox>(Raw(mail),Json)??throw Invalid();
        var projectedWork=System.Text.Json.JsonSerializer.Deserialize<WorkItem>(Raw(item),Json)??throw Invalid();
        if(mail.Attempts==0){if(mail.PayloadJson!=originalMail.PayloadJson)throw Invalid();}
        else if(step<=EmailPilotCloseoutStep.CompletionRecipient){var codec=CompletionPayloads?.Invoke()??throw Invalid();var prior=codec.Read(originalMail.PayloadJson);var current=codec.Read(mail.PayloadJson);if(prior.LastTokenId is not null||current.LastTokenId is not {} tokenId||CompletionNotificationJobs.Digest(prior)!=CompletionNotificationJobs.Digest(current))throw Invalid();var token=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==tokenId,ct);if(token.Purpose!=TokenPurpose.CompletionAccess||token.EnvelopeId!=record||token.PartyType!=current.Party||token.PartyId!=current.PartyId||token.Email!=mail.To||token.CompletionPublicationId!=current.PublicationId||Convert.ToHexStringLower(token.CompletionRecipeSha256??[])!=current.Recipe||Convert.ToHexStringLower(token.CompletionPartySha256??[])!=current.PartyHash||token.ExpiresAt>state.Until)throw Invalid();}
        else if(step==EmailPilotCloseoutStep.DeclineInvitation){var codec=InvitationPayloads?.Invoke()??throw Invalid();var prior=codec.Read(originalMail.PayloadJson);var current=codec.Read(mail.PayloadJson);if(prior.LastTokenId is not null||current.LastTokenId is not {} tokenId||prior!=current with{LastTokenId=null})throw Invalid();var token=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==tokenId,ct);if(token.Purpose!=TokenPurpose.SignerAccess||token.EnvelopeId!=record||token.PartyType!=PartyType.Signer||token.PartyId!=current.SignerId||token.Email!=mail.To||token.DocumentId!=current.DocumentId||Convert.ToHexStringLower(token.DocumentSha256??[])!=current.DocumentSha256||Convert.ToHexStringLower(token.DisclosureSha256??[])!=current.DisclosureSha256||token.ExpiresAt>state.Until)throw Invalid();}
        else if(step==EmailPilotCloseoutStep.Lookup)await DemandLookupPayloadLockedAsync(db,state,originalMail,mail,item,ct);
        else if(mail.PayloadJson!=originalMail.PayloadJson)throw Invalid();
        if(mail.Attempts==1&&step==EmailPilotCloseoutStep.DeclineVerification){var payload=(Payloads?.Invoke()??throw Invalid()).Unprotect(mail.PayloadJson);var token=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==payload.TokenId,ct);if(token.Purpose!=TokenPurpose.SenderVerify||token.EnvelopeId!=record||token.PartyType!=PartyType.Sender||token.PartyId is not null||token.Email!=mail.To||!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(token.TokenSha256,System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(payload.Token)))||token.ExpiresAt>state.Until)throw Invalid();}
        // Exactly the real delivery/Finish transitions; original generated RVs and
        // protected bytes came from the immutable queued receipt, never guessed.
        projectedMail.Status=originalMail.Status;projectedMail.Attempts=originalMail.Attempts;projectedMail.SubmissionStartedAt=originalMail.SubmissionStartedAt;projectedMail.Provider=originalMail.Provider;projectedMail.ProviderMessageId=originalMail.ProviderMessageId;projectedMail.RowVersion=originalMail.RowVersion;projectedMail.PayloadJson=originalMail.PayloadJson;
        projectedWork.Status=originalWork.Status;projectedWork.Attempts=originalWork.Attempts;projectedWork.LeaseOwner=originalWork.LeaseOwner;projectedWork.LeaseExpiresAt=originalWork.LeaseExpiresAt;if(completed)projectedWork.AvailableAt=originalWork.AvailableAt;projectedWork.RowVersion=originalWork.RowVersion;
        if(Raw(projectedMail)!=queued.MailJson||Raw(projectedWork)!=queued.WorkJson)throw Invalid();
        await EmailPilotAdmission.ReadSourceAsync(db,state.Parent(record),state.Enrollment(record),Payloads??throw Invalid(),ct);
        var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==record,ct);
        var until=await QuillSign.Documents.DocumentRetentionAccess.ReadAsync(db,envelope,time,ct);QuillSign.Documents.DocumentRetentionAccess.Check(until,time);
        if(!envelope.IsDemo||envelope.SenderEmail!=state.Mailboxes.Sender||
            (record==state.CompletionRecord?envelope.Status!=EnvelopeStatus.Completed:record==state.VoidRecord?envelope.Status!=EnvelopeStatus.Voided:
                step==EmailPilotCloseoutStep.DeclineNotice?envelope.Status!=EnvelopeStatus.Declined:step==EmailPilotCloseoutStep.DeclineInvitation?envelope.Status is not (EnvelopeStatus.Sent or EnvelopeStatus.Declined):envelope.Status is not (EnvelopeStatus.Draft or EnvelopeStatus.Sent or EnvelopeStatus.Declined)))throw Invalid();
    }
    private async Task DemandLookupPayloadLockedAsync(QuillSignDbContext db,EmailPilotCloseoutSnapshot state,EmailOutbox original,EmailOutbox saved,WorkItem item,CancellationToken ct)
    {
        var codec=LookupPayloads?.Invoke()??throw Invalid();var prior=codec.Read(original);var current=codec.Read(saved);var issued=current.Issued??throw Invalid();
        var binding=(await Operations(db,state,ct)).Single(x=>x.Kind==0&&x.Step==EmailPilotCloseoutStep.Lookup).LookupBinding??throw Invalid();
        if(prior.Issued is not null||prior!=current with{Issued=null}||binding.RequestId!=saved.Id||EmailPilotLookupRules.OriginalRequestSha256(current)!=binding.RequestSha256||EmailPilotLookupRules.Hash(item.PayloadJson)!=binding.WorkSha256)throw Invalid();
        var policy=await db.LookupContactRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.RequestId==saved.Id,ct);LookupContactRetention.Check(policy,saved);
        var publication=await QuillSign.Completion.CompletionDownloadState.ReadAsync(db,state.CompletionRecord,time,ct)??throw Invalid();
        if(LookupContactRetention.Digest(policy)!=binding.RetentionSha256||policy.DeleteAfter<=Now||publication.Id!=binding.PublicationId||Convert.ToHexStringLower(publication.Recipe)!=binding.PublicationRecipeSha256)throw Invalid();
        var token=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==issued.Id,ct);
        if(token.Purpose!=TokenPurpose.Lookup||token.PartyType!=PartyType.System||token.PartyId!=saved.Id||token.EnvelopeId is not null||token.Email!=""||token.EmailPilotLookupRequestId is not null||token.ExpiresAt!=issued.ExpiresAt||Convert.ToHexStringLower(token.TokenSha256)!=issued.Sha256)throw Invalid();
    }
    // MAIN-only routing fact: no null owner or role flag is a capability. Each
    // mutation reacquires this fact in its own actual physical transaction.
    internal sealed class NullLookupFact
    {
        private NullLookupFact(EmailPilotCloseout owner,QuillSignDbContext db,Guid id,Guid record,string configuration)
        {Owner=owner;Database=db;Transaction=db.Database.CurrentTransaction!.GetDbTransaction();Id=id;RecordId=record;Configuration=configuration;}
        private EmailPilotCloseout Owner {get;}
        private QuillSignDbContext Database {get;}
        private System.Data.Common.DbTransaction Transaction {get;}
        internal Guid Id {get;}
        internal Guid RecordId {get;}
        internal string Configuration {get;}
        internal void DemandLocked(QuillSignDbContext db)
        {if(!ReferenceEquals(db,Database)||db.Database.CurrentTransaction is not {} tx||!ReferenceEquals(tx.GetDbTransaction(),Transaction)||Transaction.Connection?.State!=System.Data.ConnectionState.Open||!Owner.PassHost||Hash(Owner.HostOptions.Capture())!=Configuration)throw Invalid();}
        internal static async Task<NullLookupFact?> ReadLockedAsync(EmailPilotCloseout owner,QuillSignDbContext db,Guid id,WorkLease? lease,CancellationToken ct)
        {
            if(!ReferenceEquals(db,owner.AliasDatabase)||db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw Invalid();
            var item=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
            if(item is null)return null;
            if(item.EnvelopeId is not null) {
                if(await db.EmailPilotCloseoutOperations.AsNoTracking().AnyAsync(x=>x.WorkId==id&&x.Kind==0&&x.Step==(int)EmailPilotCloseoutStep.Lookup,ct))throw Invalid();
                return null;
            }
            if(!await RecognizesWorkAsync(db,id,ct))return null;
            if(!owner.PassHost)throw Invalid();
            var state=await owner.ReadLockedAsync(db,ct)??throw Invalid();
            var operation=(await owner.Operations(db,state,ct)).SingleOrDefault(x=>x.Kind==0&&x.Step==EmailPilotCloseoutStep.Lookup&&x.WorkId==id)??throw Invalid();
            if(id!=EmailPilotCloseoutLookup.RequestId(state.AuthorizationId)||operation.LookupBinding is null||operation.Queued is null||state.Configuration.Coexistence is null)throw Invalid();
            var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
            if(item.Kind!=WorkKind.Email||mail.EnvelopeId is not null||mail.Template!=LookupDeliveryProtection.Template)throw Invalid();
            if(lease is null)await owner.DemandClaimLockedAsync(db,item,ct);
            else {
                if(lease.Id!=id||lease.Kind!=WorkKind.Email||lease.Attempt!=1||lease.Owner==Guid.Empty||lease.Until.Offset!=TimeSpan.Zero||lease.Until<=owner.Now||lease.Until>state.Until||item.Status!=WorkStatus.Leased||item.Attempts!=1||item.LeaseOwner!=lease.Owner||item.LeaseExpiresAt!=lease.Until||mail.Attempts is <0 or >1||mail.Status is not (EmailStatus.Queued or EmailStatus.Sent))throw Invalid();
                var reservation=(await owner.Operations(db,state,ct)).SingleOrDefault(x=>x.Kind==1&&x.Step==EmailPilotCloseoutStep.Lookup);
                if(reservation is not null&&reservation.WorkId!=id||mail.Status==EmailStatus.Sent&&reservation is null)throw Invalid();
                if(mail.Attempts==0?(mail.SubmissionStartedAt is not null||mail.Status!=EmailStatus.Queued||mail.Provider is not null||mail.ProviderMessageId is not null):(mail.SubmissionStartedAt is not {} at||at.Offset!=TimeSpan.Zero||at<state.Manifest.CreatedAt||at>=state.Until||at>owner.Now||(mail.Status==EmailStatus.Queued?mail.Provider is not null||mail.ProviderMessageId is not null:mail.Provider is not {Length:>0}||mail.ProviderMessageId is not {Length:>0})))throw Invalid();
            }
            await owner.DemandCandidateRowsLockedAsync(db,state,EmailPilotCloseoutStep.Lookup,mail,item,false,ct);
            var result=new NullLookupFact(owner,db,id,state.CompletionRecord,Hash(state.Configuration));result.DemandLocked(db);return result;
        }
    }
    internal Task<NullLookupFact?> ReadNullLookupLockedAsync(QuillSignDbContext db,Guid id,WorkLease? lease,CancellationToken ct)
        =>NullLookupFact.ReadLockedAsync(this,db,id,lease,ct);
    internal async Task<NullLookupFact?> ReadNullLookupAsync(Guid id,WorkLease? lease,CancellationToken ct)
    {var db=database();Clean(db);await using var tx=await db.Database.BeginTransactionAsync(ct);var fact=await ReadNullLookupLockedAsync(db,id,lease,ct);await tx.RollbackAsync(ct);return fact;}

    internal async Task DemandPassTargetAsync(Guid id,CancellationToken ct)
    {if(!PassHost||!CanSend||!(await PassTargetsAsync(ct)).Any(x=>x.Id==id&&!x.Completed))throw Invalid();}
}

// No work-signal dependency: this command cannot consume/recover/ack/defer queue
// hints. Membership is server-derived anew before each real Claim.
public sealed class EmailPilotCloseoutPass(EmailPilotCloseout closeout,WorkStore store,EmailWorkHandler handler)
{
    public async Task<EmailPilotCloseoutPassResult> RunAsync(CancellationToken ct=default)
    {
        var facts=0;var processed=0;var refused=0;var ambiguous=0;
        EmailPilotCloseoutPassTarget[] targets;
        try{targets=await closeout.PassTargetsAsync(ct);}catch(Exception e)when(e is InvalidDataException or InvalidOperationException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or ArgumentException){return new(0,0,1,0);}
        foreach(var target in targets)
        {
            ct.ThrowIfCancellationRequested();if(target.Completed){facts++;continue;}
            try
            {
                await closeout.DemandPassTargetAsync(target.Id,ct);
                var claim=await store.ClaimAsync(target.Id,ct);
                if(claim.Lease is not {} lease||claim.Terminal||claim.PrivateHandoff){refused++;break;}
                var result=await handler.ExecuteAsync(lease,ct);
                await store.FinishAsync(lease,result,ct);
                if(result.Outcome==WorkOutcome.Completed)processed++;
                else{if(result.Outcome==WorkOutcome.Ambiguous)ambiguous++;else refused++;break;}
            }
            catch(Exception e)when(e is InvalidDataException or InvalidOperationException or IOException or HttpRequestException or OperationCanceledException or Azure.RequestFailedException or System.Security.Cryptography.CryptographicException)
            {ambiguous++;break;} // Never retry/reclassify an unknown claimed effect.
        }
        return new(facts,processed,refused,ambiguous);
    }
}

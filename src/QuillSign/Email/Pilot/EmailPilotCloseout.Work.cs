using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

internal sealed record EmailPilotCloseoutWorkScope(Guid AuthorizationId, EmailPilotCloseoutStep Step, Guid RecordId,
    WorkLease Lease, DateTimeOffset Until, DateTimeOffset CloseoutUntil, EmailPilotMailboxes Mailboxes, string Recipient, string SourceSha256);

public sealed partial class EmailPilotCloseout
{
    internal async Task<EmailPilotCloseoutWorkScope?> ReadWorkAsync(WorkLease lease, CancellationToken ct = default)
    {
        if (!Available || lease.Kind != WorkKind.Email || lease.Attempt != 1 || lease.Until.Offset != TimeSpan.Zero || lease.Until <= Now) {
            if(await RecognizesWorkAsync(database(),lease.Id,ct))throw Invalid();
            return null;
        }
        var db=database();Clean(db);await using var tx=await db.Database.BeginTransactionAsync(ct);
        var state=await ReadLockedAsync(db,ct);if(state is null) {
            if(await RecognizesWorkAsync(db,lease.Id,ct))throw Invalid();
            return null;
        }
        var known=state.Manifest.Queue.SingleOrDefault(x=>x.WorkId==lease.Id);
        var binding=(await Operations(db,state,ct)).SingleOrDefault(x=>x.Kind==0&&x.WorkId==lease.Id);
        if(known is null&&binding is null) {
            if(await RecognizesWorkAsync(db,lease.Id,ct))throw Invalid();
            return null;
        }
        var record=known?.RecordId??binding!.SubjectEnvelopeId;var step=known?.Step??binding!.Step;
        var item=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
        var mail=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
        if(item is null||mail is null||item.Kind!=WorkKind.Email||item.Status!=WorkStatus.Leased||item.Attempts!=1||item.LeaseOwner!=lease.Owner||item.LeaseExpiresAt!=lease.Until||
            item.AvailableAt>Now||mail.Status!=EmailStatus.Queued||mail.Provider is not null||mail.ProviderMessageId is not null||mail.Attempts is <0 or >1||mail.AvailableAt>Now||
            (step==EmailPilotCloseoutStep.Lookup?item.EnvelopeId is not null||mail.EnvelopeId is not null:item.EnvelopeId!=record||mail.EnvelopeId!=record))throw Invalid();
        if(known is not null)DemandOriginalQueue(known,mail,item,known.Step<=EmailPilotCloseoutStep.CompletionRecipient?CompletionPayloads?.Invoke():null);
        var template=step switch { <=EmailPilotCloseoutStep.CompletionRecipient=>CompletionNotificationJobs.Template,
            EmailPilotCloseoutStep.VoidSender or EmailPilotCloseoutStep.VoidSigner=>VoidNotificationJobs.Template,
            EmailPilotCloseoutStep.DeclineVerification=>"sender-verification",EmailPilotCloseoutStep.DeclineInvitation=>"signer-invitation",
            EmailPilotCloseoutStep.DeclineNotice=>"signer-declined",EmailPilotCloseoutStep.Lookup=>LookupDeliveryProtection.Template,_=>throw Invalid() };
        if(mail.Template!=template||Role(state.Mailboxes,mail.To)==EmailPilotRole.None||await db.Suppressions.AnyAsync(x=>x.Email==mail.To,ct))throw Invalid();
        var expected=step switch { EmailPilotCloseoutStep.CompletionFirstSigner or EmailPilotCloseoutStep.VoidSigner or EmailPilotCloseoutStep.DeclineInvitation=>EmailPilotRole.FirstSigner,
            EmailPilotCloseoutStep.CompletionSecondSigner=>EmailPilotRole.SecondSigner,EmailPilotCloseoutStep.CompletionRecipient=>EmailPilotRole.Recipient,_=>EmailPilotRole.Sender };
        if(Role(state.Mailboxes,mail.To)!=expected)throw Invalid();
        await EmailPilotAdmission.ReadSourceAsync(db,state.Parent(record),state.Enrollment(record),Payloads??throw Invalid(),ct);
        var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==record,ct);
        if(!envelope.IsDemo||envelope.SenderEmail!=state.Mailboxes.Sender||
            envelope.Status!=(record==state.CompletionRecord?EnvelopeStatus.Completed:record==state.VoidRecord?EnvelopeStatus.Voided:
                step==EmailPilotCloseoutStep.DeclineVerification?EnvelopeStatus.Draft:step==EmailPilotCloseoutStep.DeclineInvitation?EnvelopeStatus.Sent:EnvelopeStatus.Declined))throw Invalid();
        if(await db.SignerContactRevisions.AnyAsync(x=>x.EnvelopeId==record,ct))throw Invalid();
        var end=await DocumentRetentionAccess.ReadAsync(db,envelope,time,ct);DocumentRetentionAccess.Check(end,time);
        var until=new[]{state.Until,lease.Until,end??DateTimeOffset.MaxValue}.Min();if(until<=Now)throw Invalid();
        var value=new EmailPilotCloseoutWorkScope(state.AuthorizationId,step,record,lease,until,state.Until,state.Mailboxes,mail.To,
            Hash(new{Record=Raw(envelope),Mail=Raw(mail),Work=Raw(item),state.Manifest.ConfigurationSha256}));
        await tx.RollbackAsync(ct);if(!Available||value.Until<=Now)throw Invalid();return value;
    }

    internal async Task DemandWorkAsync(EmailPilotCloseoutWorkScope scope,CancellationToken ct)
    {var current=await ReadWorkAsync(scope.Lease,ct);if(current!=scope)throw Invalid();}

    internal async Task ReservePreparedAsync(EmailPilotCloseoutWorkScope scope,PreparedRawMime prepared,CancellationToken ct)
    {
        if(!CanSend||prepared.ByteCount is <1 or >EmailPilotLimits.MessageBytes||prepared.Recipient!=scope.Recipient||
            (scope.Step==EmailPilotCloseoutStep.Lookup?prepared.EnvelopeId is not null:prepared.EnvelopeId!=scope.RecordId))throw Invalid();
        await DemandWorkAsync(scope,ct);
        var db=database();Clean(db);await using var tx=await db.Database.BeginTransactionAsync(ct);await Lock(db,scope.AuthorizationId,ct);
        var state=await ReadLockedAsync(db,ct)??throw Invalid();var prior=await Operations(db,state,ct);
        if(state.AuthorizationId!=scope.AuthorizationId||prior.Any(x=>x.Kind==1&&x.Step==scope.Step)||prior.Count(x=>x.Kind==1)>=10||
            prior.Where(x=>x.Kind==1).Sum(x=>(long)x.EncodedBytes)+prepared.ByteCount>EmailPilotCloseoutLimits.EncodedBytes||scope.Until<=Now)throw Invalid();
        var receipt=new EmailPilotCloseoutReceipt(EmailPilotCloseoutLimits.Version,state.AuthorizationId,1,scope.Step,scope.RecordId,scope.Lease.Id,Now,prepared.ByteCount,
            Convert.ToHexStringLower(prepared.Sha256));db.EmailPilotCloseoutOperations.Add(Row(receipt));await db.SaveChangesAsync(ct);
        if(!CanSend||scope.Until<=Now)throw Invalid();await tx.CommitAsync(ct);
    }
}

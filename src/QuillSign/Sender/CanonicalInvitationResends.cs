using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Sender;

// Trusted integration for the existing deliberate resend action. No endpoint
// or sender session is created here; the browser supplies its protected ticket
// and exact review through InvitationResends after affirmation/CSRF checks.
public sealed class CanonicalInvitationResends(QuillSignDbContext db,InvitationResendOptions options,EmailOptions email,WorkOptions work,
    InvitationResendProtection legacy,InvitationSuccessorProtection protection,InvitationLineage lineage,SignerAccess access,
    AuditWriter audit,Func<IWorkSignals> signals,TimeProvider time,QuillSign.Email.Pilot.EmailPilotReadBounds? pilotBounds=null):IInvitationSuccessorPolicy
{
    public InvitationSuccessorReason Reason=>InvitationSuccessorReason.ManualResend;
    public bool Enabled=>options.Enabled && email.Enabled && work.Enabled;
    internal async Task<InvitationResendOutcome> PrepareLockedAsync(Envelope envelope,InvitationResendReview reviewed,DateTimeOffset ticketUntil,
        Guid id,string ipHash,string? ip,string? ua,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Canonical resend joins the sender transaction.");
        if(!Enabled)return InvitationResendOutcome.Unavailable;
        var current=await CurrentLockedAsync(envelope,reviewed.SignerId,ct);
        if(current is null)return InvitationResendOutcome.Closed;
        var (party,context,history)=current.Value;
        if(reviewed.Contact!=party.Epoch || reviewed.PreviousId is null || reviewed.Version!=Convert.ToBase64String(envelope.RowVersion) ||
            reviewed.Name!=context.SignerName || reviewed.Email!=party.Email || reviewed.DocumentId!=context.Identity.DocumentId ||
            reviewed.DocumentSha256!=context.Identity.DocumentHash || reviewed.DisclosureSha256!=context.Identity.DisclosureHash)return InvitationResendOutcome.Conflict;
        var prior=await CanonicalResendEvidence.FindAsync(db,id,envelope.Id,ct);
        if(prior is not null) {
            var saved=prior.Request;
            if(prior.Contact!=reviewed.Contact || saved.SignerId!=reviewed.SignerId || saved.PreviousId!=reviewed.PreviousId || saved.SenderTicketExpiresAt!=ticketUntil ||
                saved.IpHash!=ipHash || saved.ReviewedVersion!=reviewed.Version || saved.Email!=reviewed.Email || saved.DocumentId!=reviewed.DocumentId ||
                saved.DocumentSha256!=reviewed.DocumentSha256 || saved.DisclosureSha256!=reviewed.DisclosureSha256 || saved.SenderEmail!=envelope.SenderEmail)
                return InvitationResendOutcome.Conflict;
            await CheckSavedAsync(prior,ct);return InvitationResendOutcome.AlreadyRequested;
        }
        if(await db.WorkItems.AnyAsync(x=>x.Id==id,ct) || await db.EmailOutbox.AnyAsync(x=>x.Id==id,ct))return InvitationResendOutcome.Conflict;
        if(history.Latest.Id!=reviewed.PreviousId)return InvitationResendOutcome.Conflict;
        if(!await lineage.SettledLockedAsync(history.Latest,ct))return InvitationResendOutcome.Busy;
        if(await db.Suppressions.AnyAsync(x=>x.Email==party.Email,ct))return InvitationResendOutcome.Suppressed;
        var now=time.GetUtcNow();var counterUntil=InvitationResendProtection.DayEnd(now);
        var retention=await DocumentRetentionAccess.ReadAsync(db,envelope,ct,pilotBounds);
        if(retention<counterUntil)return InvitationResendOutcome.Unavailable;
        DocumentRetentionAccess.Check(retention,time);
        var deadline=envelope.ExpiresAt is { } expires && expires<counterUntil ? expires : counterUntil;
        if(deadline<=now || ticketUntil<=now)return InvitationResendOutcome.Closed;
        var p=new ResendRequest("resend-request-v1",id,envelope.Id,party.Id,history.Latest.Id,party.Email,envelope.SenderEmail,ipHash,
            reviewed.Version,reviewed.DocumentId,reviewed.DocumentSha256,reviewed.DisclosureSha256,now,ticketUntil,deadline,counterUntil);
        var reservation=new CanonicalResendAdmission(CanonicalResendEvidence.Version,p,party.Epoch,InvitationResendStatement.Version,InvitationResendStatement.Sha256);
        var counters=new InvitationResendReservations(db,legacy,protection,options,time);
        if(!await counters.WithinAsync(p,false,ct))return InvitationResendOutcome.Capped;
        var scope=CanonicalResendEvidence.Scope(reservation);
        db.EmailOutbox.Add(new() {Id=id,EnvelopeId=envelope.Id,To=party.Email,Template=InvitationSuccessorProtection.Template,
            AvailableAt=now,PayloadJson=protection.Protect(new(scope))});
        db.WorkItems.Add(new() {Id=id,EnvelopeId=envelope.Id,Kind=WorkKind.Email,AvailableAt=now,PayloadJson=JsonSerializer.Serialize(new {emailId=id})});
        await db.SaveChangesAsync(ct);
        // Preserve the established sender-review promise: unused links stop at
        // admission even if a later definite delivery failure prevents new mail.
        await db.AuthTokens.Where(x=>x.EnvelopeId==envelope.Id && x.PartyId==party.Id && x.PartyType==PartyType.Signer &&
            x.Purpose==TokenPurpose.SignerAccess && x.UsedAt==null && x.ExpiresAt>now).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,now),ct);
        await audit.AppendAsync(envelope.Id,CanonicalResendEvidence.Event,envelope.SenderEmail,ip,ua,ct,CanonicalResendEvidence.Canonical(reservation));
        await audit.AppendAsync(envelope.Id,InvitationSuccessorProtection.Event,envelope.SenderEmail,ip,ua,ct,InvitationSuccessorProtection.Canonical(scope));
        if(!await ValidateLockedAsync(envelope,scope,ct))return InvitationResendOutcome.Unavailable;
        await signals().PutHintAsync(id,now,ct);return InvitationResendOutcome.Queued;
    }
    public async Task<bool> ValidateLockedAsync(Envelope envelope,InvitationSuccessorScope scope,CancellationToken ct)
    {
        options.Validate();if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Canonical resend policy requires the envelope transaction.");
        if(!Enabled || scope.Reason!=Reason || scope.EnvelopeId!=envelope.Id || scope.SenderEmail!=envelope.SenderEmail ||
            scope.Deadline<=time.GetUtcNow() || envelope.Status!=EnvelopeStatus.Sent || envelope.ExpiresAt<=time.GetUtcNow())return false;
        var a=await CanonicalResendEvidence.FindAsync(db,scope.Id,envelope.Id,ct)??throw CanonicalResendEvidence.Invalid();
        if(CanonicalResendEvidence.Scope(a)!=scope)throw CanonicalResendEvidence.Invalid();
        await CheckSavedAsync(a,ct);
        var current=await CurrentLockedAsync(envelope,scope.SignerId,ct);
        if(current is null || current.Value.Party.Epoch!=scope.Contact || current.Value.Party.Email!=scope.Recipient ||
            current.Value.History.Latest.Id!=scope.Id || current.Value.Context.Identity.DocumentId!=scope.DocumentId ||
            current.Value.Context.Identity.DocumentHash!=scope.DocumentSha256 || current.Value.Context.Identity.DisclosureHash!=scope.DisclosureSha256 ||
            await db.Suppressions.AnyAsync(x=>x.Email==scope.Recipient,ct))return false;
        var retention=await DocumentRetentionAccess.ReadAsync(db,envelope,ct,pilotBounds);
        if(retention<a.Request.CounterUntil)return false;DocumentRetentionAccess.Check(retention,time);
        return await new InvitationResendReservations(db,legacy,protection,options,time).WithinAsync(a.Request,true,ct);
    }
    private async Task CheckSavedAsync(CanonicalResendAdmission a,CancellationToken ct)
    {
        var p=a.Request;var row=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==p.Id,ct)??throw CanonicalResendEvidence.Invalid();
        var item=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==p.Id,ct)??throw CanonicalResendEvidence.Invalid();
        if(protection.Read(row).Scope!=CanonicalResendEvidence.Scope(a) || item.EnvelopeId!=p.EnvelopeId || item.Kind!=WorkKind.Email ||
            item.PayloadJson!=JsonSerializer.Serialize(new {emailId=p.Id}))throw CanonicalResendEvidence.Invalid();
    }
    private async Task<(SignerContactParty Party,SignerReadContext Context,VerifiedInvitationLineage History)?> CurrentLockedAsync(Envelope envelope,Guid signer,CancellationToken ct)
    {
        var contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(envelope,ct);
        var party=contacts.Current.SingleOrDefault(x=>x.Id==signer);if(party is null)return null;
        var context=await access.GetEligibleLockedAsync(envelope.Id,signer,ct);if(context is null)return null;
        var history=await lineage.ReadLockedAsync(envelope,signer,contacts,ct)??throw CanonicalResendEvidence.Invalid();
        if(history.Latest.Contact!=party.Epoch || history.Latest.Recipient!=party.Email || context.Identity.Email!=party.Email ||
            history.Latest.DocumentId!=context.Identity.DocumentId || history.Latest.DocumentSha256!=context.Identity.DocumentHash ||
            history.Latest.DisclosureSha256!=context.Identity.DisclosureHash)throw CanonicalResendEvidence.Invalid();
        return(party,context,history);
    }
}

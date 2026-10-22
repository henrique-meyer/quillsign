using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public enum EmailPilotDispatchRoute { Ordinary, VerifiedPilot, VerifiedCloseout, RefusedKnown }
public sealed record EmailPilotDispatchDecision(EmailPilotWorkScope? Scope,WorkResult? Refusal)
{
    public EmailPilotDispatchRoute Route=>Refusal is not null?EmailPilotDispatchRoute.RefusedKnown:
        Scope?.IsCloseout==true?EmailPilotDispatchRoute.VerifiedCloseout:Scope is not null?EmailPilotDispatchRoute.VerifiedPilot:EmailPilotDispatchRoute.Ordinary;
}

// Installed only with the complete optional pilot runtime. The persisted cohort
// check stays active even after pilot disable/config rotation or public enable.
public sealed class EmailPilotDispatch(QuillSignDbContext db,EmailOptions options,Func<EmailPilotWorkAuthority> authority,
    Func<WorkLease,OutgoingEmail,CancellationToken,Task<EmailDelivery>> pilotSend,IEmailSender ordinary)
{
    public async Task<EmailPilotDispatchDecision> DecideAsync(WorkLease lease,CancellationToken ct)
    {
        // Classification by immutable identity precedes mutable association.
        // Known but unavailable private work can never become ordinary mail.
        try {
            if(await EmailPilotCloseout.RecognizesWorkAsync(db,lease.Id,ct)) {
                var selected=authority().Closeout is {} get?await get().ReadWorkAsync(lease,ct):null;
                return selected is null?new(null,new(WorkOutcome.Failed,"closeout-delivery-unavailable")):new(new(selected),null);
            }
        }catch(Exception error)when(error is InvalidDataException or InvalidOperationException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or ArgumentException)
        {return new(null,new(WorkOutcome.Failed,"closeout-delivery-unavailable"));}
        var envelope=await db.WorkItems.AsNoTracking().Where(x=>x.Id==lease.Id).Select(x=>x.EnvelopeId).SingleOrDefaultAsync(ct);
        var enrolled=envelope is Guid id && await db.EmailPilotEnrollments.AsNoTracking().AnyAsync(x=>x.SubjectEnvelopeId==id,ct);
        if(!enrolled)return new(null,options.Enabled ? null : new(WorkOutcome.Retry,"delivery-disabled"));
        var scope=await authority().ReadAsync(lease,ct);
        return scope is null ? new(null,new(WorkOutcome.Failed,"pilot-delivery-unavailable")) : new(scope,null);
    }

    public async Task<EmailDelivery> SendAsync(WorkLease lease,OutgoingEmail message,CancellationToken ct)
    {
        // Reacquire after committed token/payload changes; the sender independently
        // reserves and rechecks the exact prepared bytes before provider access.
        var decision=await DecideAsync(lease,ct);
        if(decision.Refusal is not null)throw new EmailDisabledException();
        return decision.Scope is null ? await ordinary.SendAsync(message,ct) : await pilotSend(lease,message,ct);
    }

    internal async Task<EmailPilotCloseout.AliasFact?> ReadAliasLockedAsync(QuillSignDbContext context,WorkLease lease,string recipient,CancellationToken ct=default)
    {
        if(authority().Closeout is {} closeout)return await closeout().ReadAliasLockedAsync(context,lease,recipient,ct);
        if(await EmailPilotCloseout.RecognizesWorkAsync(context,lease.Id,ct))throw EmailPilotProtection.Invalid();
        return null;
    }

    internal static DateTimeOffset Clamp(EmailPilotDispatchDecision? decision,DateTimeOffset expiry)=>
        decision?.Scope is {} scope && scope.RunExpiresAt<expiry ? scope.RunExpiresAt : expiry;
}

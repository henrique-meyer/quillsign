using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public sealed record EmailPilotOperatorEnvelope(EmailPilotScenario Scenario, EnvelopeStatus Status);
public sealed record EmailPilotOperatorStatus(DateTimeOffset ExpiresAt, EmailPilotBudget Budget,
    IReadOnlyList<EmailPilotOperatorEnvelope> Envelopes, bool Expired);

public sealed partial class EmailPilotLedger
{
    // A read cannot start or renew a run. Do not expose the private manifest to
    // the page, and authenticate protected evidence before reporting counters.
    internal async Task<EmailPilotOperatorStatus?> OperatorStatusAsync(string capability,CancellationToken ct)
    {
        if(!Enabled)return null;
        var hash=EmailPilotCanonical.Capability(capability);var db=database();await Open(db,ct);
        var run=await Manifest(db,RunId,false,ct);
        if(run is null)return null;
        if(!MatchesCapability(run,hash))throw EmailPilotProtection.Invalid();
        var enrolled=await Enrollments(db,run,ct);var saved=new List<EmailPilotOperatorEnvelope>();
        foreach(var item in enrolled.OrderBy(x=>x.Scenario)) {
            var parent=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==item.SubjectEnvelopeId,ct);
            if(parent is null || !parent.IsDemo || parent.SenderEmail!=run.Mailboxes.Sender)throw EmailPilotProtection.Invalid();
            saved.Add(new(item.Scenario,parent.Status));
        }
        var budget=Budget(await Reservations(db,run,ct));
        if(!Enabled || run.RunId!=RunId || run.Mailboxes!=options.Mailboxes)throw EmailPilotProtection.Invalid();
        return new(run.ExpiresAt,budget,saved,run.ExpiresAt<=Now);
    }
}

// Every backend remains lazy until an authenticated explicit action. The
// deterministic delayed cleanup must be durable before admitting any email.
public sealed class EmailPilotOperator(EmailPilotOperatorBrowser browser,Func<EmailPilotLedger> ledger,
    Func<EmailPilotSecretJobs> cleanup,Func<EmailPilotAdmission> envelopes,Func<EmailPilotLookupAdmission> lookups,
    Func<EmailPilotSimulatorAdmission> simulators)
{
    private void Demand(EmailPilotOperatorSession session)
    {if(!browser.Live(session))throw new EmailDisabledException();}
    private async Task<bool> Prepare(EmailPilotOperatorSession session,CancellationToken ct)
    {
        Demand(session);var manifest=await ledger().CreateAsync(session.Capability,ct);Demand(session);
        if(manifest.RunId!=session.RunId)throw EmailPilotProtection.Invalid();
        var result=await cleanup().PrepareAsync(manifest,ct);Demand(session);
        return result.WakeupPublished;
    }
    public async Task<EmailPilotOperatorStatus?> ReadAsync(EmailPilotOperatorSession session,CancellationToken ct=default)
    {Demand(session);var result=await ledger().OperatorStatusAsync(session.Capability,ct);Demand(session);return result;}
    public async Task<EmailPilotOperatorNotice> EnvelopeAsync(EmailPilotOperatorSession session,EmailPilotScenario scenario,
        string? ip,string? userAgent,CancellationToken ct=default)
    {
        Demand(session);if(!Enum.IsDefined(scenario))return EmailPilotOperatorNotice.Unavailable;
        if(!await Prepare(session,ct))return EmailPilotOperatorNotice.WakePending;
        var result=await envelopes().RequestAsync(session.Capability,scenario,ip,userAgent,ct);Demand(session);
        return result is null?EmailPilotOperatorNotice.Unavailable:result.WakeupPublished?EmailPilotOperatorNotice.EnvelopeSaved:EmailPilotOperatorNotice.WakePending;
    }
    public async Task<EmailPilotOperatorNotice> LookupAsync(EmailPilotOperatorSession session,string? ip,CancellationToken ct=default)
    {
        Demand(session);if(ip is null)return EmailPilotOperatorNotice.Unavailable;
        if(!await Prepare(session,ct))return EmailPilotOperatorNotice.WakePending;
        var result=await lookups().RequestAsync(session.Capability,ip,ct);Demand(session);
        return result is null?EmailPilotOperatorNotice.Unavailable:result.WakeupPublished?EmailPilotOperatorNotice.LookupSaved:EmailPilotOperatorNotice.WakePending;
    }
    public async Task<EmailPilotOperatorNotice> SimulatorAsync(EmailPilotOperatorSession session,EmailPilotSimulatorKind kind,CancellationToken ct=default)
    {
        Demand(session);if(!Enum.IsDefined(kind))return EmailPilotOperatorNotice.Unavailable;
        if(!await Prepare(session,ct))return EmailPilotOperatorNotice.WakePending;
        var result=await simulators().RequestAsync(session.Capability,kind,ct);Demand(session);
        return result is null?EmailPilotOperatorNotice.Unavailable:result.WakeupPublished?EmailPilotOperatorNotice.SimulatorSaved:EmailPilotOperatorNotice.WakePending;
    }
}

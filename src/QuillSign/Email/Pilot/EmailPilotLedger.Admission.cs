using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotLedger
{
    internal async Task<EmailPilotAdmissionResult?> AdmitAsync(string capability,
        Func<QuillSignDbContext,EmailPilotManifest,IReadOnlyList<EmailPilotEnrollment>,Func<Guid,EmailPilotAdmissionScope>,
            Action<EmailPilotEnrollment>,Task<EmailPilotAdmissionResult?>> prepare, CancellationToken ct)
    {
        if (!Enabled) return null;
        var id=RunId;var hash=EmailPilotCanonical.Capability(capability);var db=database();
        await Open(db,ct);await using var transaction=await db.Database.BeginTransactionAsync(ct);await Lock(db,id,ct);
        var run=await Manifest(db,id,true,ct);
        if(run is null || !MatchesCapability(run,hash))return null;
        var enrolled=await Enrollments(db,run,ct);
        var result=await prepare(db,run,enrolled,
            envelopeId=>new(db,envelopeId,run.Mailboxes.Sender,()=>EnsureLive(run)),
            value=> {
                if(value.RunId!=id || enrolled.Count>=3 || enrolled.Any(x=>x.Scenario==value.Scenario) || value.Verification is null)
                    throw EmailPilotProtection.Invalid();
                db.EmailPilotEnrollments.Add(new(){RunId=id,SubjectEnvelopeId=value.SubjectEnvelopeId,Scenario=value.Scenario,
                    EnrolledAt=value.EnrolledAt,ProtectedBinding=protection().Protect(id,"enrollment",value)});
            });
        if(result is null)return null;
        await db.SaveChangesAsync(ct);EnsureLive(run);await transaction.CommitAsync(ct);
        // The caller still has no transport authority; a later work gate must
        // recheck the deadline and source before any provider/credential access.
        return result;
    }
}

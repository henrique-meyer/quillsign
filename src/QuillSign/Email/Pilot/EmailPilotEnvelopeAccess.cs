using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

// Identity evidence only. This is neither a browser proof nor a provider permit.
// Known but denied enrollment must never become ordinary email authority.
public sealed class EmailPilotEnvelopeCohort
{
    internal EmailPilotEnvelopeCohort(Guid envelopeId, Guid? runId, EmailPilotManifest? manifest = null,
        EmailPilotEnrollment? enrollment = null, bool allowed = false, bool envelopeExists = true)
    { EnvelopeId=envelopeId; RunId=runId; Manifest=manifest; Enrollment=enrollment; Allowed=allowed; EnvelopeExists=envelopeExists; }
    public Guid EnvelopeId {get;}
    public bool EnvelopeExists {get;}
    public Guid? RunId {get;}
    public bool IsEnrolled=>RunId is not null;
    public bool Allowed {get;}
    public DateTimeOffset? RunExpiresAt=>Manifest?.ExpiresAt;
    public EmailPilotScenario? Scenario=>Enrollment?.Scenario;
    internal EmailPilotManifest? Manifest {get;}
    internal EmailPilotEnrollment? Enrollment {get;}
    internal EmailPilotEnvelopeCohort Denied()=>new(EnvelopeId,RunId,Manifest,Enrollment,envelopeExists:EnvelopeExists);
}

public sealed class EmailPilotEnvelopeAccess(Func<QuillSignDbContext> database, Func<EmailPilotLedger> ledger,
    Func<EmailPayloadProtection> payloads, EmailPilotAdmissionOptions admission, WorkOptions work)
{
    public async Task<EmailPilotEnvelopeCohort> ReadAsync(Guid envelopeId,CancellationToken ct=default)
    {
        var db=database();
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())
            throw new InvalidOperationException("Standalone pilot reads require a clean context without an existing transaction.");
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var result=await ReadLockedAsync(new(){Id=envelopeId},ct);
        await transaction.CommitAsync(ct);
        return result.Allowed && !ledger().EnvelopeCohortLive(result.Manifest!,admission,work) ? result.Denied() : result;
    }
    // The caller already owns an envelope transaction. Do not open an isolated
    // ledger/reservation transaction or acquire the run lock beneath this lock.
    public Task<EmailPilotEnvelopeCohort> ReadLockedAsync(Envelope envelope,CancellationToken ct=default)
        =>ledger().ReadEnvelopeCohortLockedAsync(database(),envelope.Id,payloads,admission,work,ct);

    public async Task<EmailPilotEnvelopeCohort> RequireSendRosterLockedAsync(Envelope envelope,CancellationToken ct=default)
    {
        var cohort=await ReadLockedAsync(envelope,ct);
        if(!cohort.IsEnrolled)return cohort;
        if(!cohort.Allowed || cohort.Manifest is not {} manifest || cohort.Scenario is not {} scenario)throw new EmailDisabledException();
        var db=database();
        var current=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelope.Id,ct);
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).OrderBy(x=>x.Order).Take(4).ToArrayAsync(ct);
        var recipients=await db.Recipients.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).Take(3).ToArrayAsync(ct);
        var count=scenario==EmailPilotScenario.Completion?2:1;
        if(current.SenderVerifiedAt is null || signers.Length!=count || signers[0].Order!=1 || signers[0].Email!=manifest.Mailboxes.FirstSigner ||
            count==2 && (signers[1].Order!=2 || signers[1].Email!=manifest.Mailboxes.SecondSigner) ||
            recipients.Length!=(count==2?1:0) || recipients.Any(x=>x.Email!=manifest.Mailboxes.Recipient) ||
            await db.SignerContactRevisions.AnyAsync(x=>x.EnvelopeId==envelope.Id,ct) ||
            !ledger().EnvelopeCohortLive(manifest,admission,work))throw new EmailDisabledException();
        return cohort;
    }
}

public sealed partial class EmailPilotLedger
{
    internal async Task<EmailPilotEnvelopeCohort> ReadEnvelopeCohortLockedAsync(QuillSignDbContext db,Guid envelopeId,
        Func<EmailPayloadProtection> payloads,EmailPilotAdmissionOptions admission,WorkOptions work,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Pilot envelope access requires its parent transaction.");
        var parent=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={envelopeId}")
            .AsNoTracking().SingleOrDefaultAsync(ct);
        // Lookup persists even with disabled options, replaced RunId or missing
        // secrets, so an old cohort cannot fall through to ordinary authority.
        var marker=await db.EmailPilotEnrollments.AsNoTracking().Where(x=>x.SubjectEnvelopeId==envelopeId)
            .Select(x=>new {x.RunId}).SingleOrDefaultAsync(ct);
        if(marker is null)return new(envelopeId,null,envelopeExists:parent is not null);
        EmailPilotManifest? run=null; EmailPilotEnrollment? saved=null;
        try {
            run=await Manifest(db,marker.RunId,false,ct,configured:false);
            if(run is null)return new(envelopeId,marker.RunId,envelopeExists:parent is not null);
            saved=(await Enrollments(db,run,ct)).SingleOrDefault(x=>x.SubjectEnvelopeId==envelopeId);
            if(parent is null || !Enum.IsDefined(parent.Status) || saved?.Verification is null || !EnvelopeCohortLive(run,admission,work))
                return new(envelopeId,marker.RunId,run,saved,envelopeExists:parent is not null);
            await EmailPilotAdmission.ReadSourceAsync(db,run,saved,payloads,ct);
            if(!EnvelopeCohortLive(run,admission,work))
                return new(envelopeId,marker.RunId,run,saved);
            return new(envelopeId,marker.RunId,run,saved,true);
        }
        catch(Exception error)when(error is InvalidDataException or CryptographicException or JsonException or ArgumentException)
        { return new(envelopeId,marker.RunId,run,saved,envelopeExists:parent is not null); }
    }
    internal bool EnvelopeCohortLive(EmailPilotManifest run,EmailPilotAdmissionOptions admission,WorkOptions work)=>
        Enabled && work.Enabled && Guid.TryParseExact(options.RunId,"N",out var configuredRun) && configuredRun==run.RunId && options.Mailboxes==run.Mailboxes &&
        run.ExpiresAt>Now && EmailPilotCanonical.Hash(admission.CapabilitySha256) &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(admission.CapabilitySha256),Convert.FromHexString(run.CapabilitySha256));
}

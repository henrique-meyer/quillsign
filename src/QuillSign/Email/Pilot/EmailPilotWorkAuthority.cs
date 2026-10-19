using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

// A server-only verified snapshot, never a provider call permit or browser proof.
// Every later reservation/transport boundary must re-read its current lease/run.
// Reacquire after legitimate handler token/payload binding; stale snapshots do
// not survive that change and reacquiring never extends the run or lease.
public sealed class EmailPilotWorkScope
{
    internal EmailPilotWorkScope(EmailPilotManifest run,EmailPilotEnrollment enrollment,WorkLease lease,string sourceHash,
        string? emailRecipient)
    {RunId=run.RunId;EnvelopeId=enrollment.SubjectEnvelopeId;Until=run.ExpiresAt<lease.Until?run.ExpiresAt:lease.Until;
        Lease=lease;SourceHash=sourceHash;Mailboxes=run.Mailboxes;EmailRecipient=emailRecipient;}
    public Guid RunId {get;}
    public Guid EnvelopeId {get;}
    public DateTimeOffset Until {get;}
    internal WorkLease Lease {get;}
    internal string SourceHash {get;}
    private EmailPilotMailboxes Mailboxes {get;}
    private string? EmailRecipient {get;}
    public bool AllowsTimestamp=>Lease.Kind==WorkKind.Sealing;
    public EmailPilotRole MailRole(string recipient)
    {
        if(Lease.Kind!=WorkKind.Email || recipient!=EmailRecipient)return EmailPilotRole.None;
        foreach(var role in new[]{EmailPilotRole.Sender,EmailPilotRole.FirstSigner,EmailPilotRole.SecondSigner,EmailPilotRole.Recipient})
            if(Mailboxes.Address(role)==recipient)return role;
        return EmailPilotRole.None;
    }
}

public sealed class EmailPilotWorkAuthority(EmailPilotOptions options,EmailOptions email,WorkOptions work,EmailPilotAdmissionOptions admission,Func<EmailPilotLedger> getLedger,
    Func<QuillSignDbContext> database,Func<EmailPayloadProtection> getPayloadProtection,TimeProvider time)
{
    public async Task<EmailPilotWorkScope?> ReadAsync(WorkLease lease,CancellationToken ct=default)
    {
        if(!options.Enabled || email.Enabled || !work.Enabled || !EmailPilotCanonical.Hash(admission.CapabilitySha256) || !Shape(lease))return null;
        var db=database();
        // Read one nominated row only. No discovery/polling or caller envelope ID.
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
        if(row?.EnvelopeId is not Guid envelopeId || !Owned(row,lease))return null;
        try
        {
            var scope=await getLedger().ReadScopeAsync<EmailPilotWorkScope>(envelopeId,async(context,run,saved)=>{
                if(!ReferenceEquals(context,db))throw EmailPilotProtection.Invalid();
                if(!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(admission.CapabilitySha256),Convert.FromHexString(run.CapabilitySha256)))return null;
                await EmailPilotAdmission.ReadSourceAsync(context,run,saved,getPayloadProtection,ct);
                var current=await context.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
                if(current is null || current.EnvelopeId!=envelopeId || !Owned(current,lease) || current.PayloadJson.Length>16384)return null;
                var envelope=await context.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelopeId,ct);
                // Contact correction/reminder features stay off for this baseline
                // pilot. Do not authorize original contacts after an epoch change.
                if(await context.SignerContactRevisions.AnyAsync(x=>x.EnvelopeId==envelopeId,ct))return null;
                var signers=await context.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId).OrderBy(x=>x.Order).Take(4).ToArrayAsync(ct);
                var recipients=await context.Recipients.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId).OrderBy(x=>x.Id).Take(3).ToArrayAsync(ct);
                EmailOutbox? outbox=null;
                if(lease.Kind==WorkKind.Email)
                {
                    outbox=await context.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
                    if(outbox is null || outbox.EnvelopeId!=envelopeId || outbox.Status!=EmailStatus.Queued || outbox.PayloadJson.Length>16384 ||
                        outbox.To!=EmailAddress.Normalize(outbox.To) || !ApprovedRecipient(run.Mailboxes,outbox.To))return null;
                }
                var verification=lease.Kind==WorkKind.Email && lease.Id==saved.Verification!.WorkId;
                if(verification)
                {
                    if(outbox!.Template!="sender-verification" || outbox.To!=run.Mailboxes.Sender || envelope.Status!=EnvelopeStatus.Draft ||
                        envelope.SenderVerifiedAt is not null || signers.Length!=0 || recipients.Length!=0)return null;
                }
                else
                {
                    var count=saved.Scenario==EmailPilotScenario.Completion?2:1;
                    if(envelope.SenderVerifiedAt is null || signers.Length!=count || signers[0].Order!=1 || signers[0].Email!=run.Mailboxes.FirstSigner ||
                        count==2 && (signers[1].Order!=2 || signers[1].Email!=run.Mailboxes.SecondSigner) ||
                        recipients.Length!=(count==2?1:0) || recipients.Any(x=>x.Email!=run.Mailboxes.Recipient))return null;
                    if(outbox is not null && !AllowedMail(outbox,envelope,signers,recipients,saved.Scenario))return null;
                    if(lease.Kind==WorkKind.Sealing && (saved.Scenario!=EmailPilotScenario.Completion || lease.Id!=CompletionJobs.WorkId(envelopeId) ||
                        envelope.Status is not (EnvelopeStatus.Sent or EnvelopeStatus.Completed) || signers.Any(x=>x.Status!=SignerStatus.Signed)))return null;
                    if(lease.Kind==WorkKind.Sealing && !await CompletionSource(context,envelopeId,lease,ct))return null;
                }
                var hash=Convert.ToHexStringLower(EmailPilotCanonical.Hash(new {run.RunId,saved.SubjectEnvelopeId,saved.Scenario,
                    saved.Verification,Work=current.PayloadJson,Email=outbox?.PayloadJson,Recipient=outbox?.To,Template=outbox?.Template,
                    envelope.CurrentCopyVersion,envelope.CurrentFinishId,envelope.SentPdfBlob,envelope.SentPdfSha256,envelope.ErsdSha256,
                    Signers=signers.Select(x=>new{x.Id,x.Order,x.Email}).ToArray(),Recipients=recipients.Select(x=>new{x.Id,x.Email}).ToArray()}));
                return new(run,saved,lease,hash,outbox?.To);
            },ct);
            return scope is not null && Shape(lease) && scope.Until>Now ? scope : null;
        }
        catch(Exception e)when(e is InvalidDataException or CryptographicException or JsonException or ArgumentException){return null;}
    }

    public async Task<bool> StillCurrentAsync(EmailPilotWorkScope scope,CancellationToken ct=default)
    {
        if(scope is null || scope.Until<=Now)return false;
        var current=await ReadAsync(scope.Lease,ct);
        return current is not null && current.RunId==scope.RunId && current.EnvelopeId==scope.EnvelopeId && current.Until==scope.Until &&
            current.SourceHash==scope.SourceHash;
    }

    private DateTimeOffset Now=>time.GetUtcNow().ToUniversalTime();
    private async Task<bool> CompletionSource(QuillSignDbContext db,Guid id,WorkLease lease,CancellationToken ct)
    {
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(envelope is null || row is null || !Owned(row,lease) || row.PayloadJson.Length>2048)return false;
        var payload=JsonSerializer.Deserialize<CompletionWorkPayload>(row.PayloadJson);
        if(payload is null || payload.Version!=CompletionJobs.Version || payload.FinishId==Guid.Empty || payload.CopyVersion!=2 ||
            !EmailPilotCanonical.Hash(payload.CheckpointSha256) || !EmailPilotCanonical.Hash(payload.DisclosureSha256))return false;
        var source=await new SignerCheckpointState(db,time).CurrentAsync(envelope,ct);
        if(source is null || source.FinishId!=payload.FinishId || source.Version!=payload.CopyVersion ||
            Convert.ToHexStringLower(source.Sha256)!=payload.CheckpointSha256 || envelope.ErsdSha256 is not {Length:32} ||
            Convert.ToHexStringLower(envelope.ErsdSha256)!=payload.DisclosureSha256)return false;
        if(!Owned(row,lease))return false;
        await transaction.CommitAsync(ct);return true;
    }
    private bool Shape(WorkLease lease)=>lease is not null && lease.Id!=Guid.Empty && lease.Owner!=Guid.Empty && lease.Attempt>=1 &&
        lease.Until.Offset==TimeSpan.Zero && lease.Until>Now && lease.Kind is WorkKind.Email or WorkKind.Sealing;
    private bool Owned(WorkItem row,WorkLease lease)=>row.Kind==lease.Kind && row.Status==WorkStatus.Leased && row.LeaseOwner==lease.Owner &&
        row.Attempts==lease.Attempt && row.LeaseExpiresAt==lease.Until && row.LeaseExpiresAt>Now && row.AvailableAt<=Now;
    private static bool ApprovedRecipient(EmailPilotMailboxes m,string address)=>address==m.Sender || address==m.FirstSigner || address==m.SecondSigner || address==m.Recipient;
    private static bool AllowedMail(EmailOutbox row,Envelope envelope,Signer[] signers,Recipient[] recipients,EmailPilotScenario scenario)=>row.Template switch {
        "signer-invitation" or InvitationResendProtection.Template=>envelope.Status==EnvelopeStatus.Sent && signers.Any(x=>x.Email==row.To),
        "signer-declined"=>scenario==EmailPilotScenario.Decline && envelope.Status==EnvelopeStatus.Declined && row.To==envelope.SenderEmail,
        CompletionNotificationJobs.Template=>scenario==EmailPilotScenario.Completion && envelope.Status==EnvelopeStatus.Completed && IsParty(row.To,envelope,signers,recipients),
        VoidNotificationJobs.Template=>scenario==EmailPilotScenario.Void && envelope.Status==EnvelopeStatus.Voided && IsParty(row.To,envelope,signers,recipients),
        _=>false
    };
    private static bool IsParty(string address,Envelope e,Signer[] signers,Recipient[] recipients)=>address==e.SenderEmail ||
        signers.Any(x=>x.Email==address) || recipients.Any(x=>x.Email==address);
}

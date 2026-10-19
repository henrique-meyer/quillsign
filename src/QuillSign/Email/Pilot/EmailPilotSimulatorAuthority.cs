using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

// Separate from envelope/application authority. No public constructor and no
// ability to turn an arbitrary recipient or nullable envelope into a permit.
public sealed class EmailPilotSimulatorScope
{
    public Guid RunId { get; }
    public WorkLease Lease { get; }
    public EmailPilotSimulatorKind Kind { get; }
    public DateTimeOffset RunExpiresAt { get; }
    public DateTimeOffset Until => Lease.Until < RunExpiresAt ? Lease.Until : RunExpiresAt;
    internal string SourceHash { get; }
    internal string CapabilityHash { get; }
    internal DateTimeOffset AdmittedAt { get; }
    internal EmailPilotSimulatorScope(EmailPilotManifest run,WorkLease lease,EmailPilotSimulatorPayload payload,string source)
    {RunId=run.RunId;Lease=lease;Kind=payload.Kind;RunExpiresAt=run.ExpiresAt;SourceHash=source;CapabilityHash=run.CapabilitySha256;AdmittedAt=payload.CreatedAt;}
}

public sealed class EmailPilotSimulatorAuthority(EmailPilotOptions options, EmailOptions email, WorkOptions work,
    EmailPilotAdmissionOptions admission, Func<EmailPilotLedger> ledger, TimeProvider time)
{
    public Task<EmailPilotSimulatorScope?> ReadAsync(WorkLease lease,CancellationToken ct=default)=>Read(lease,null,ct);
    internal Task<EmailPilotSimulatorScope?> ReadLockedAsync(WorkLease lease,QuillSignDbContext db,CancellationToken ct)=>Read(lease,db,ct);
    public async Task<bool> StillCurrentAsync(EmailPilotSimulatorScope scope,CancellationToken ct=default)
    {
        var current=await ReadAsync(scope.Lease,ct);
        return current is not null && current.RunId==scope.RunId && current.Kind==scope.Kind && current.RunExpiresAt==scope.RunExpiresAt && current.SourceHash==scope.SourceHash;
    }
    private async Task<EmailPilotSimulatorScope?> Read(WorkLease lease,QuillSignDbContext? locked,CancellationToken ct)
    {
        if(!options.Enabled || email.Enabled || !work.Enabled || !EmailPilotCanonical.Hash(admission.CapabilitySha256) ||
            lease is null || lease.Id==Guid.Empty || lease.Owner==Guid.Empty || lease.Kind!=WorkKind.Email || lease.Attempt<1 ||
            lease.Until.Offset!=TimeSpan.Zero || lease.Until<=time.GetUtcNow())return null;
        try {
            var result=await ledger().ReadSimulatorAsync<EmailPilotSimulatorScope>(async(db,run,protection)=> {
                if(run.CapabilitySha256!=admission.CapabilitySha256)return null;
                var item=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
                var row=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
                if(item is null || row is null || !Owned(item,lease,time.GetUtcNow()) || row.Status!=EmailStatus.Queued ||
                    row.Provider is not null || row.ProviderMessageId is not null || row.Attempts>lease.Attempt)return null;
                var payload=EmailPilotSimulator.Read(protection,run,item,row);
                if(payload.CreatedAt>time.GetUtcNow() || await db.Suppressions.AsNoTracking().AnyAsync(x=>x.Email==row.To,ct))return null;
                var hash=Convert.ToHexStringLower(EmailPilotCanonical.Hash(new{item.Id,item.PayloadJson,Email=row.PayloadJson,row.To,row.Template,row.AttachmentsJson}));
                return new(run,lease,payload,hash);
            },locked,ct);
            return options.Enabled && !email.Enabled && work.Enabled && result?.Until>time.GetUtcNow() &&
                admission.CapabilitySha256==result.CapabilityHash ? result : null;
        }catch(Exception e)when(e is InvalidDataException or CryptographicException or ArgumentException){return null;}
    }
    internal static bool Owned(WorkItem row,WorkLease lease,DateTimeOffset at)=>row.Id==lease.Id && row.EnvelopeId is null && row.Kind==WorkKind.Email &&
        row.Status==WorkStatus.Leased && row.LeaseOwner==lease.Owner && row.LeaseExpiresAt==lease.Until && row.LeaseExpiresAt>at &&
        row.Attempts==lease.Attempt && row.AvailableAt<=at;
}

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Storage;

// Separate from user identities and ordinary document read/write capabilities.
// This authorizes a bounded storage pass, never deletion of SQL evidence.
public sealed class DemoPurgeAuthority
{
    public const string Version="demo-purge-storage-v1";
    public Guid EnvelopeId {get;}
    public string PolicySha256 {get;}
    public DateTimeOffset DeleteAfter {get;}
    private readonly TimeProvider time;
    private readonly DateTimeOffset expires;
    private DemoPurgeAuthority(DocumentRetentionSnapshot policy,TimeProvider time,DateTimeOffset leaseUntil)
    {
        EnvelopeId=policy.EnvelopeId;PolicySha256=UploadRetention.Digest(policy);DeleteAfter=policy.DeleteAfter;
        this.time=time;expires=new[]{leaseUntil,time.GetUtcNow().AddMinutes(2)}.Min();
    }
    private DemoPurgeAuthority(DemoPurgeRecovery.VerifiedScope scope)
    {
        scope.Demand(default);EnvelopeId=scope.EnvelopeId;PolicySha256=scope.PolicySha256;DeleteAfter=scope.DeleteAfter;
        time=scope.Time;expires=scope.Until;
    }
    // Only authenticated marker readback under its finite storage lease creates this internal scope.
    internal static DemoPurgeAuthority Recovery(DemoPurgeRecovery.VerifiedScope scope)=>new(scope);
    // A scheduling description is not authority. Issuance verifies it against saved evidence.
    public static string Payload(DocumentRetentionSnapshot policy)=>JsonSerializer.Serialize(new {
        version=Version,envelopeId=policy.EnvelopeId,retentionSha256=UploadRetention.Digest(policy),deleteAfter=policy.DeleteAfter});

    public static async Task<DemoPurgeAuthority> AuthorizeLockedAsync(QuillSignDbContext db,WorkLease lease,TimeProvider time,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();
        if(db.Database.CurrentTransaction is null || lease.Kind!=WorkKind.Purge || lease.Id==Guid.Empty || lease.Owner==Guid.Empty ||
            lease.Attempt<1 || lease.Until<=time.GetUtcNow())throw Invalid();
        var located=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
        if(located?.EnvelopeId is not Guid id || id==Guid.Empty)throw Invalid();
        // Match established parent-before-work lock order. The first lookup grants nothing.
        var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        var work=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(envelope is null || !envelope.IsDemo || work?.EnvelopeId!=id || work.Kind!=WorkKind.Purge || work.Status!=WorkStatus.Leased ||
            work.LeaseOwner!=lease.Owner || work.Attempts!=lease.Attempt || work.LeaseExpiresAt!=lease.Until || work.AvailableAt>time.GetUtcNow())throw Invalid();
        var policy=await new UploadRetention(db,new(),time).ReadAsync(envelope,ct);
        if(policy is null || work.PayloadJson!=Payload(policy) || time.GetUtcNow()<policy.DeleteAfter || lease.Until<=time.GetUtcNow())throw Invalid();
        return new(policy,time,lease.Until);
    }
    internal void Demand(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if(time.GetUtcNow()<DeleteAfter || time.GetUtcNow()>=expires)throw Invalid();
    }
    internal DateTimeOffset Now=>time.GetUtcNow();
    private static UnauthorizedAccessException Invalid()=>new("A current verified demo purge storage scope is required.");
}

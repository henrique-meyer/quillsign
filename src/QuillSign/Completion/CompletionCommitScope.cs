using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Completion;

// Scoped worker state, never a user capability. Explicit internal preparations remain usable
// independently; a bound worker must still own its exact lease at every durable write.
public sealed class CompletionCommitScope(QuillSignDbContext db,TimeProvider time)
{
    private WorkLease? lease; private Guid envelopeId; private string? payload;
    internal void Bind(WorkLease value,Guid envelope,string exactPayload)
    {
        if(lease is not null || value.Kind!=WorkKind.Sealing || envelope==Guid.Empty)throw new CompletionLeaseUnavailableException();
        lease=value; envelopeId=envelope; payload=exactPayload;
    }
    internal void Clear() {lease=null; envelopeId=Guid.Empty; payload=null;}
    internal async Task CheckLockedAsync(Guid envelope,CancellationToken ct)
    {
        if(lease is null)return;
        if(db.Database.CurrentTransaction is null || envelope!=envelopeId)throw new CompletionLeaseUnavailableException();
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(row is null || row.EnvelopeId!=envelopeId || row.Kind!=WorkKind.Sealing || row.PayloadJson!=payload || row.Status!=WorkStatus.Leased ||
            row.LeaseOwner!=lease.Owner || row.Attempts!=lease.Attempt || row.LeaseExpiresAt!=lease.Until || lease.Until<=time.GetUtcNow())throw new CompletionLeaseUnavailableException();
    }
}
internal sealed class CompletionLeaseUnavailableException() : Exception("Completion work lease is no longer owned.");

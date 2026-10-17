using System.Data;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Storage;

// Internal worker dependency, deliberately unregistered until the coordinator exists.
// Success describes private SQL removal, never completion of physical storage purge.
public sealed class DemoPurgeSql(QuillSignDbContext db,DemoPurgeRecovery recovery,TimeProvider time)
{
    public async Task<bool> RemoveAsync(WorkLease lease,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges() || lease.Kind!=WorkKind.Purge ||
            lease.Id==Guid.Empty || lease.Owner==Guid.Empty || lease.Attempt<1 || lease.Until<=time.GetUtcNow())throw Invalid();
        var located=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct)??throw Invalid();
        var binding=Parse(located.PayloadJson);
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var parent=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={binding.Id}")
            .AsNoTracking().SingleOrDefaultAsync(ct);
        var work=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}")
            .AsNoTracking().SingleOrDefaultAsync(ct);
        if(work is null || work.Kind!=WorkKind.Purge || work.Status!=WorkStatus.Leased || work.LeaseOwner!=lease.Owner ||
            work.Attempts!=lease.Attempt || work.LeaseExpiresAt!=lease.Until || work.AvailableAt>time.GetUtcNow() ||
            work.PayloadJson!=located.PayloadJson || lease.Until<=time.GetUtcNow())throw Invalid();
        if(parent is not null)
        {
            if(work.EnvelopeId!=binding.Id)throw Invalid();
            var authority=await DemoPurgeAuthority.AuthorizeLockedAsync(db,lease,time,ct);
            if(authority.EnvelopeId!=binding.Id || authority.PolicySha256!=binding.Digest || authority.DeleteAfter!=binding.Deadline)throw Invalid();
            await recovery.RememberAsync(authority,ct);
            authority.Demand(ct);
        }
        else
        {
            if(work.EnvelopeId is not null)throw Invalid();
            await recovery.VerifyRememberedAsync(binding.Id,binding.Digest,binding.Deadline,ct);
        }
        ct.ThrowIfCancellationRequested();
        await using var command=((SqlConnection)db.Database.GetDbConnection()).CreateCommand();
        command.Transaction=(SqlTransaction)transaction.GetDbTransaction();
        command.CommandType=CommandType.StoredProcedure;command.CommandText="dbo.RemoveExpiredDemoPrivateRecords";
        command.Parameters.Add(new SqlParameter("@EnvelopeId",SqlDbType.UniqueIdentifier){Value=binding.Id});
        command.Parameters.Add(new SqlParameter("@WorkId",SqlDbType.UniqueIdentifier){Value=lease.Id});
        command.Parameters.Add(new SqlParameter("@Owner",SqlDbType.UniqueIdentifier){Value=lease.Owner});
        command.Parameters.Add(new SqlParameter("@Attempt",SqlDbType.Int){Value=lease.Attempt});
        command.Parameters.Add(new SqlParameter("@Until",SqlDbType.DateTimeOffset){Value=lease.Until});
        command.Parameters.Add(new SqlParameter("@PolicySha256",SqlDbType.NVarChar,64){Value=binding.Digest});
        command.Parameters.Add(new SqlParameter("@DeleteAfter",SqlDbType.DateTimeOffset){Value=binding.Deadline});
        var removed=Convert.ToBoolean(await command.ExecuteScalarAsync(ct));
        if(lease.Until<=time.GetUtcNow())throw Invalid();
        await transaction.CommitAsync(ct);
        db.ChangeTracker.Clear();
        return removed;
    }
    private sealed record Binding(Guid Id,string Digest,DateTimeOffset Deadline);
    private static Binding Parse(string json)
    {
        if(json.Length>1024)throw Invalid();
        try
        {
            using var document=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=4});var p=document.RootElement;
            var id=p.GetProperty("envelopeId").GetGuid();var digest=p.GetProperty("retentionSha256").GetString();
            var deadline=p.GetProperty("deleteAfter").GetDateTimeOffset();
            if(p.GetProperty("version").GetString()!=DemoPurgeAuthority.Version || id==Guid.Empty || digest is not {Length:64} ||
                !digest.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f') || deadline.Offset!=TimeSpan.Zero ||
                deadline.Ticks%TimeSpan.TicksPerSecond!=0 || json!=DemoPurgeAuthority.Payload(id,digest,deadline))throw Invalid();
            return new(id,digest,deadline);
        }
        catch(Exception error) when(error is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {throw new UnauthorizedAccessException("A current verified demo SQL cleanup scope is required.",error);}
    }
    private static UnauthorizedAccessException Invalid()=>new("A current verified demo SQL cleanup scope is required.");
}

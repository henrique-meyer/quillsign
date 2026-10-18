using System.Data;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;

namespace QuillSign.Work;

// Only the lookup mail records bound to the current Purge lease are in scope.
// It neither resolves private payload keys nor obtains document/blob authority.
public sealed class LookupContactCleanup(QuillSignDbContext db, Func<IWorkSignals> signals, TimeProvider time)
{
    public async Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken ct)
    {
        var remaining = lease.Until - time.GetUtcNow() - TimeSpan.FromSeconds(1);
        if (remaining <= TimeSpan.Zero) return new(WorkOutcome.Retry, "lookup-cleanup-lease-unavailable");
        using var budget = new CancellationTokenSource(remaining < TimeSpan.FromSeconds(50) ? remaining : TimeSpan.FromSeconds(50), time);
        using var active = CancellationTokenSource.CreateLinkedTokenSource(ct, budget.Token);
        try { await RemoveAsync(lease, active.Token); return new(WorkOutcome.Completed); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new(WorkOutcome.Retry, "lookup-cleanup-pending"); }
        catch (Exception e) when (e is SqlException or Azure.RequestFailedException or IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException or TimeoutException) {
            return new(WorkOutcome.Retry, "lookup-cleanup-unavailable");
        }
    }
    public async Task<bool> RemoveAsync(WorkLease lease, CancellationToken ct = default)
    {
        if (lease.Kind != WorkKind.Purge || lease.Id == Guid.Empty || lease.Until <= time.GetUtcNow() || db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())
            throw new UnauthorizedAccessException("A clean, current lookup cleanup lease is required.");
        bool removed; LookupContactRetention.Binding binding;
        try {
            await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
            await using (var tx = await db.Database.BeginTransactionAsync(ct)) {
                await LookupDeliveryRules.LockAsync(db, ct);
                var row = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct)
                    ?? throw new UnauthorizedAccessException("The lookup cleanup scope is unavailable.");
                binding = LookupContactRetention.ReadPayload(row.PayloadJson);
                if (lease.Id != LookupContactRetention.WorkId(binding.RequestId) || row.EnvelopeId is not null || row.Kind != WorkKind.Purge || row.Status != WorkStatus.Leased ||
                    row.LeaseOwner != lease.Owner || row.Attempts != lease.Attempt || row.LeaseExpiresAt != lease.Until || row.AvailableAt > time.GetUtcNow() || binding.DeleteAfter > time.GetUtcNow())
                    throw new UnauthorizedAccessException("The lookup cleanup scope is unavailable.");
                await using var command = db.Database.GetDbConnection().CreateCommand();
                command.Transaction = tx.GetDbTransaction(); command.CommandText = "dbo.RemoveExpiredLookupContacts"; command.CommandType = CommandType.StoredProcedure;
                foreach (var (name, value, type) in new (string, object, SqlDbType)[] {
                    ("@RequestId", binding.RequestId, SqlDbType.UniqueIdentifier), ("@WorkId", lease.Id, SqlDbType.UniqueIdentifier), ("@Owner", lease.Owner, SqlDbType.UniqueIdentifier),
                    ("@Attempt", lease.Attempt, SqlDbType.Int), ("@Until", lease.Until, SqlDbType.DateTimeOffset),
                    ("@PolicySha256", binding.Sha256, SqlDbType.NVarChar), ("@DeleteAfter", binding.DeleteAfter, SqlDbType.DateTimeOffset) }) {
                    var p = new SqlParameter(name, type) { Value = value }; if (type == SqlDbType.NVarChar) p.Size = 64; command.Parameters.Add(p);
                }
                removed = Convert.ToBoolean(await command.ExecuteScalarAsync(ct));
                if (lease.Until <= time.GetUtcNow()) throw new UnauthorizedAccessException("The lookup cleanup lease expired before commit.");
                await tx.CommitAsync(ct);
            }
        } finally { db.ChangeTracker.Clear(); }
        // The terminal technical email-work tombstone also drains a delayed wake.
        // A lost removal acknowledgement is safe; storage-only recovery can retry it.
        try { await signals().RemoveHintAsync(binding.RequestId, ct); }
        catch (Exception e) when (e is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { }
        return removed;
    }
}

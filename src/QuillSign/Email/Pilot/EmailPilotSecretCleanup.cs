using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed class EmailPilotSecretCleanup(QuillSignDbContext db, TimeProvider time)
{
    public async Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken ct)
    {
        var remaining = lease.Until - time.GetUtcNow() - TimeSpan.FromSeconds(1);
        if (remaining <= TimeSpan.Zero) return new(WorkOutcome.Retry, "pilot-secret-cleanup-lease-unavailable");
        using var budget = new CancellationTokenSource(remaining < TimeSpan.FromSeconds(50) ? remaining : TimeSpan.FromSeconds(50), time);
        using var active = CancellationTokenSource.CreateLinkedTokenSource(ct, budget.Token);
        try { await RemoveAsync(lease, active.Token); return new(WorkOutcome.Completed); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new(WorkOutcome.Retry, "pilot-secret-cleanup-pending"); }
        catch (Exception e) when (e is SqlException or IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException or TimeoutException) {
            return new(WorkOutcome.Retry, "pilot-secret-cleanup-unavailable");
        }
    }
    public async Task<bool> RemoveAsync(WorkLease lease, CancellationToken ct = default)
    {
        if (lease.Kind != WorkKind.Purge || lease.Id == Guid.Empty || lease.Owner == Guid.Empty || lease.Until <= time.GetUtcNow() ||
            db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()) throw new UnauthorizedAccessException("A clean current pilot cleanup lease is required.");
        try {
            await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
            // Read only enough to choose the lock. Re-read and validate under run-before-work locks.
            var initial = await db.WorkItems.AsNoTracking().Where(x => x.Id == lease.Id).Select(x => x.PayloadJson).SingleOrDefaultAsync(ct)
                ?? throw EmailPilotSecretJobs.Invalid();
            var b = EmailPilotSecretJobs.ReadPayload(initial);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await EmailPilotSecretJobs.LockAsync(db, b.RunId, ct);
            var row = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct)
                ?? throw EmailPilotSecretJobs.Invalid();
            EmailPilotSecretJobs.CheckWork(row, b);
            if (row.Status != WorkStatus.Leased || row.LeaseOwner != lease.Owner || row.Attempts != lease.Attempt || row.LeaseExpiresAt != lease.Until ||
                lease.Until <= time.GetUtcNow() || row.AvailableAt > time.GetUtcNow() || b.DeleteAfter > time.GetUtcNow()) throw new UnauthorizedAccessException("The pilot cleanup lease is unavailable.");
            await EmailPilotSecretJobs.CheckRunAsync(db, b, ct);
            var existed = await db.EmailPilotSecrets.AnyAsync(x => x.RunId == b.RunId, ct);
            if (lease.Until <= time.GetUtcNow()) throw new UnauthorizedAccessException("The pilot cleanup lease expired before execution.");
            await db.Database.ExecuteSqlInterpolatedAsync($"EXEC dbo.RemoveExpiredEmailPilotSecrets @RunId={b.RunId}", ct);
            if (await db.EmailPilotSecrets.AnyAsync(x => x.RunId == b.RunId, ct)) throw new InvalidOperationException("Pilot secret retention is not yet due in database UTC.");
            if (lease.Until <= time.GetUtcNow() || b.DeleteAfter > time.GetUtcNow()) throw new UnauthorizedAccessException("The pilot cleanup lease expired before commit.");
            await tx.CommitAsync(ct); return existed;
        } finally { db.ChangeTracker.Clear(); }
    }
}

public static class EmailPilotSecretConfiguration
{
    // Explicit composition only. No key-ring/provider dependency or automatic startup activation.
    public static IServiceCollection AddEmailPilotSecretCleanup(this IServiceCollection services)
    {
        services.AddScoped<EmailPilotSecretJobs>(); services.AddScoped<EmailPilotSecretCleanup>();
        services.AddScoped<Func<EmailPilotSecretCleanup>>(sp => () => sp.GetRequiredService<EmailPilotSecretCleanup>());
        return services;
    }
}

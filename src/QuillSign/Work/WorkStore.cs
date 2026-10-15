using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Work;

public sealed record WorkLease(Guid Id, Guid Owner, WorkKind Kind, int Attempt, DateTimeOffset Until);
public sealed record WorkClaim(WorkLease? Lease, DateTimeOffset? RetryAt, bool Terminal);
public enum WorkOutcome { Completed, Retry, Failed, Ambiguous }
public sealed record WorkResult(WorkOutcome Outcome, string? Code = null);

public interface IWorkHandler
{
    WorkKind Kind { get; }
    Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken cancellationToken);
}

public sealed class WorkStore(QuillSignDbContext db, WorkOptions options, TimeProvider time)
{
    public async Task<WorkClaim> ClaimAsync(Guid id, CancellationToken cancellationToken)
    {
        db.ChangeTracker.Clear(); // Each claim reads current state, including repeat CLI/test calls.
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(cancellationToken), cancellationToken);
        var now = time.GetUtcNow();
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        // UPDLOCK/HOLDLOCK also disables snapshot reads for this key. An insert which
        // persisted its hint but has not committed must settle before we remove it.
        var row = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}")
            .SingleOrDefaultAsync(cancellationToken);
        if (row is null || row.Status is WorkStatus.Completed or WorkStatus.Failed)
            return new(null, null, true);
        if (row.AvailableAt > now) return new(null, row.AvailableAt, false);
        if (row.Status == WorkStatus.Leased && row.LeaseExpiresAt > now) return new(null, row.LeaseExpiresAt, false);
        if (row.Kind == WorkKind.Email)
        {
            var email = await db.EmailOutbox.SingleAsync(x => x.Id == id, cancellationToken);
            if (email.SubmissionStartedAt is not null || email.Status != EmailStatus.Queued)
            {
                row.Status = email.Status is EmailStatus.Sent or EmailStatus.Bounced or EmailStatus.Complained ? WorkStatus.Completed : WorkStatus.Failed;
                row.LastError = email.SubmissionStartedAt is not null && email.Status == EmailStatus.Queued ? "submission-ambiguous" : email.LastError;
                if (email.Status == EmailStatus.Queued) { email.Status = EmailStatus.Failed; email.LastError = row.LastError; }
                row.LeaseOwner = null; row.LeaseExpiresAt = null;
                await db.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return new(null, null, true);
            }
        }
        if (row.Attempts >= options.MaximumAttempts)
        {
            row.Status = WorkStatus.Failed; row.LastError = "attempts-exhausted";
            row.LeaseOwner = null; row.LeaseExpiresAt = null;
            if (row.Kind == WorkKind.Email)
                await db.EmailOutbox.Where(x => x.Id == id && x.Status == EmailStatus.Queued)
                    .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, EmailStatus.Failed).SetProperty(x => x.LastError, "attempts-exhausted"), cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(null, null, true);
        }
        row.Status = WorkStatus.Leased;
        row.Attempts++;
        row.LeaseOwner = Guid.NewGuid();
        row.LeaseExpiresAt = now.AddSeconds(options.LeaseSeconds);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(new(row.Id, row.LeaseOwner.Value, row.Kind, row.Attempts, row.LeaseExpiresAt.Value), null, false);
    }

    public static TimeSpan Backoff(int attempt) => TimeSpan.FromSeconds(Math.Min(900, 15 * Math.Pow(2, Math.Clamp(attempt - 1, 0, 10))));

    public async Task<DateTimeOffset?> FinishAsync(WorkLease lease, WorkResult result, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var retry = result.Outcome == WorkOutcome.Retry && lease.Attempt < options.MaximumAttempts;
        var status = retry ? WorkStatus.Queued : result.Outcome == WorkOutcome.Completed ? WorkStatus.Completed : WorkStatus.Failed;
        var at = retry ? now + Backoff(lease.Attempt) : now;
        var code = result.Outcome == WorkOutcome.Retry && !retry ? "attempts-exhausted" : result.Code;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var changed = await db.WorkItems.Where(x => x.Id == lease.Id && x.Status == WorkStatus.Leased && x.LeaseOwner == lease.Owner && x.LeaseExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, status).SetProperty(x => x.AvailableAt, at)
                .SetProperty(x => x.LastError, code).SetProperty(x => x.LeaseOwner, (Guid?)null).SetProperty(x => x.LeaseExpiresAt, (DateTimeOffset?)null), cancellationToken);
        if (changed != 1) throw new InvalidOperationException("Work lease is no longer owned.");
        if (lease.Kind == WorkKind.Email && status == WorkStatus.Failed)
            await db.EmailOutbox.Where(x => x.Id == lease.Id && x.Status == EmailStatus.Queued)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, EmailStatus.Failed).SetProperty(x => x.LastError, code), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return retry ? at : null;
    }
}

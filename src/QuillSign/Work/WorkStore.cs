using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using QuillSign.Data;
using QuillSign.Lifecycle;

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
    private readonly IProductionWorkAdmission? admission;
    internal WorkStore(QuillSignDbContext db, WorkOptions options, TimeProvider time, IProductionWorkAdmission admission)
        : this(db, options, time) => this.admission = admission;

    public async Task<WorkClaim> ClaimAsync(Guid id, CancellationToken cancellationToken)
    {
        db.ChangeTracker.Clear(); // Each claim reads current state, including repeat CLI/test calls.
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(cancellationToken), cancellationToken);
        var now = time.GetUtcNow();
        Guid? expectedRecord = null; WorkKind? expectedKind = null; string? expectedRow = null; var expectedAttempt = 0; var owner = Guid.NewGuid();
        if (admission is not null)
        {
            // Read-only preflight before taking the worker row lock. Holding that
            // lock while draining another operation could deadlock preservation.
            var candidate = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
            if (candidate is null || candidate.Status is WorkStatus.Completed or WorkStatus.Failed) return new(null, null, true);
            if (candidate.AvailableAt > now) return new(null, candidate.AvailableAt, false);
            if (candidate.Status == WorkStatus.Leased && candidate.LeaseExpiresAt > now) return new(null, candidate.LeaseExpiresAt, false);
            expectedRecord = candidate.EnvelopeId; expectedKind = candidate.Kind;
            expectedRow = JsonSerializer.Serialize(candidate);
            expectedAttempt = candidate.Attempts == int.MaxValue ? int.MaxValue : candidate.Attempts + 1;
            try { await admission.ReserveAsync(id, expectedRecord, candidate.Kind, owner, expectedAttempt, cancellationToken); }
            catch (ProductionWorkBlockedException) { return new(null, time.GetUtcNow().AddMinutes(15), false); }
            now = time.GetUtcNow();
        }
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        if (admission is not null)
        {
            // Match inventory/hold lock ordering: parent, then work. Demand uses
            // this same transaction rather than waiting on its own parent lock.
            _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {expectedRecord}")
                .AsNoTracking().SingleOrDefaultAsync(cancellationToken) ?? throw new ProductionWorkBlockedException();
            await admission.DemandLockedAsync(db, id, expectedRecord, expectedKind!.Value, owner, expectedAttempt, true, cancellationToken);
            now = time.GetUtcNow();
        }
        // UPDLOCK/HOLDLOCK also disables snapshot reads for this key. An insert which
        // persisted its hint but has not committed must settle before we remove it.
        var row = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}")
            .SingleOrDefaultAsync(cancellationToken);
        if (admission is not null)
        {
            // A changed/missing candidate is not proof that our reservation had
            // no effect. Keep it pending for explicit reconciliation.
            if (row is null || JsonSerializer.Serialize(row) != expectedRow || row.EnvelopeId != expectedRecord || row.Kind != expectedKind || row.Status is WorkStatus.Completed or WorkStatus.Failed ||
                row.AvailableAt > now || row.Status == WorkStatus.Leased && row.LeaseExpiresAt > now)
                throw new ProductionWorkBlockedException();
        }
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
        if (row.Kind!=WorkKind.Purge && row.Attempts >= options.MaximumAttempts)
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
        row.Attempts=row.Kind==WorkKind.Purge && row.Attempts==int.MaxValue ? int.MaxValue : row.Attempts+1;
        row.LeaseOwner = owner;
        row.LeaseExpiresAt = now.AddSeconds(options.LeaseSeconds);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(new(row.Id, row.LeaseOwner.Value, row.Kind, row.Attempts, row.LeaseExpiresAt.Value), null, false);
    }

    public static TimeSpan Backoff(int attempt) => TimeSpan.FromSeconds(Math.Min(900, 15 * Math.Pow(2, Math.Clamp(attempt - 1, 0, 10))));

    public async Task<DateTimeOffset?> FinishAsync(WorkLease lease, WorkResult result, CancellationToken cancellationToken)
    {
        Guid? recordId = null;
        if (admission is not null)
        {
            recordId = await db.WorkItems.AsNoTracking().Where(x => x.Id == lease.Id).Select(x => x.EnvelopeId).SingleAsync(cancellationToken);
            if (result.Outcome != WorkOutcome.Completed)
                await admission.DemandAsync(lease.Id, recordId, lease.Kind, lease.Owner, lease.Attempt, cancellationToken);
        }
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        if (admission is not null)
        {
            _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {recordId}")
                .AsNoTracking().SingleOrDefaultAsync(cancellationToken) ?? throw new ProductionWorkBlockedException();
            if (result.Outcome == WorkOutcome.Completed)
                await admission.DemandHandlerOutcomeLockedAsync(db, lease, recordId, cancellationToken);
            else await admission.DemandLockedAsync(db, lease.Id, recordId, lease.Kind, lease.Owner, lease.Attempt, false, cancellationToken);
        }
        var now = time.GetUtcNow();
        var retry = result.Outcome == WorkOutcome.Retry && (lease.Kind==WorkKind.Purge || lease.Attempt < options.MaximumAttempts);
        var status = retry ? WorkStatus.Queued : result.Outcome == WorkOutcome.Completed ? WorkStatus.Completed : WorkStatus.Failed;
        var at = retry ? now + Backoff(lease.Attempt) : now;
        var code = result.Outcome == WorkOutcome.Retry && !retry ? "attempts-exhausted" : result.Code;
        var changed = await db.WorkItems.Where(x => x.Id == lease.Id && x.Kind == lease.Kind && x.Attempts == lease.Attempt &&
                x.Status == WorkStatus.Leased && x.LeaseOwner == lease.Owner && x.LeaseExpiresAt == lease.Until && x.LeaseExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, status).SetProperty(x => x.AvailableAt, at)
                .SetProperty(x => x.LastError, code).SetProperty(x => x.LeaseOwner, (Guid?)null).SetProperty(x => x.LeaseExpiresAt, (DateTimeOffset?)null), cancellationToken);
        if (changed != 1) throw new InvalidOperationException("Work lease is no longer owned.");
        if (lease.Kind == WorkKind.Email && status == WorkStatus.Failed)
            await db.EmailOutbox.Where(x => x.Id == lease.Id && x.Status == EmailStatus.Queued)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, EmailStatus.Failed).SetProperty(x => x.LastError, code), cancellationToken);
        if (admission is not null && result.Outcome == WorkOutcome.Completed)
        {
            await admission.PrepareOutcomeLockedAsync(db, lease, recordId, cancellationToken);
            if (lease.Until <= time.GetUtcNow()) throw new InvalidOperationException("Work lease is no longer owned.");
        }
        await transaction.CommitAsync(cancellationToken);
        if (admission is not null && result.Outcome == WorkOutcome.Completed)
            await admission.CompleteAsync(lease, recordId, cancellationToken);
        return retry ? at : null;
    }

    // Explicit readback after a lost Finish acknowledgement. It performs no
    // handler/provider execution and never obtains a new lease or extends one.
    internal Task ReconcileCompletedAsync(WorkLease lease, Guid recordId, CancellationToken ct = default)
        => admission?.CompleteAsync(lease, recordId, ct) ?? throw new InvalidOperationException("Record admission is not configured.");
}

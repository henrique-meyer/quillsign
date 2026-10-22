using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Work;

public sealed record WorkLease(Guid Id, Guid Owner, WorkKind Kind, int Attempt, DateTimeOffset Until);
public sealed record WorkClaim(WorkLease? Lease, DateTimeOffset? RetryAt, bool Terminal,bool PrivateHandoff=false,bool PrivateRefused=false);
public enum WorkOutcome { Completed, Retry, Failed, Ambiguous }
public sealed record WorkResult(WorkOutcome Outcome, string? Code = null);

public interface IWorkHandler
{
    WorkKind Kind { get; }
    Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken cancellationToken);
}

public sealed class WorkStore(QuillSignDbContext db, WorkOptions options, TimeProvider time, Email.Pilot.EmailPilotCloseout? closeout=null)
{
    internal IProductionDeletionWorkAdmission? DeletionAdmission {get;init;}
    private readonly IProductionWorkAdmission? admission;
    internal WorkStore(QuillSignDbContext db, WorkOptions options, TimeProvider time, IProductionWorkAdmission admission, Email.Pilot.EmailPilotCloseout? closeout=null)
        : this(db, options, time, closeout) => this.admission = admission;

    public async Task<WorkClaim> ClaimAsync(Guid id, CancellationToken cancellationToken)
    {
        db.ChangeTracker.Clear(); // Each claim reads current state, including repeat CLI/test calls.
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(cancellationToken), cancellationToken);
        var selectedKind=await db.WorkItems.AsNoTracking().Where(x=>x.Id==id).Select(x=>(WorkKind?)x.Kind).SingleOrDefaultAsync(cancellationToken);
        if(selectedKind==WorkKind.ProductionPurge)return await Deletion().ClaimAsync(db,id,cancellationToken);
        if(closeout?.HandoffHost==true&&await ReadPrivateHandoffAsync(id,cancellationToken) is {} handoff)return handoff;
        Email.Pilot.EmailPilotCloseout.NullLookupFact? nullLookup=null;
        if(admission is not null&&closeout is not null&&selectedKind==WorkKind.Email&&(await db.WorkItems.AsNoTracking().AnyAsync(x=>x.Id==id&&x.EnvelopeId==null,cancellationToken)||await db.EmailPilotCloseoutOperations.AsNoTracking().AnyAsync(x=>x.WorkId==id&&x.Kind==0&&x.Step==(int)Email.Pilot.EmailPilotCloseoutStep.Lookup,cancellationToken)))
            nullLookup=await closeout.ReadNullLookupAsync(id,null,cancellationToken);
        var effectiveAdmission=nullLookup is null?admission:null;
        var now = time.GetUtcNow();
        Guid? expectedRecord = null; WorkKind? expectedKind = null; string? expectedRow = null; var expectedAttempt = 0; var owner = Guid.NewGuid();
        DateTimeOffset? originalCompletionMailUntil=null;
        if (effectiveAdmission is not null)
        {
            // Read-only preflight before taking the worker row lock. Holding that
            // lock while draining another operation could deadlock preservation.
            var candidate = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
            if (candidate is null)
            {
                // A wakeup may precede its transaction's commit. Snapshot absence
                // cannot discard it. Release this key-only probe before acquiring
                // any record reservation or parent lock (parent -> work ordering).
                await using var probe = await db.Database.BeginTransactionAsync(cancellationToken);
                candidate = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}")
                    .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
                await probe.RollbackAsync(cancellationToken);
            }
            if(candidate?.Kind==WorkKind.ProductionPurge)return await Deletion().ClaimAsync(db,id,cancellationToken);
            if (candidate is null || candidate.Status is WorkStatus.Completed or WorkStatus.Failed) return new(null, null, true);
            if (candidate.AvailableAt > now) return new(null, candidate.AvailableAt, false);
            if (candidate.Status == WorkStatus.Leased && candidate.LeaseExpiresAt > now) return new(null, candidate.LeaseExpiresAt, false);
            expectedRecord = candidate.EnvelopeId; expectedKind = candidate.Kind;
            expectedRow = JsonSerializer.Serialize(candidate);
            expectedAttempt = candidate.Attempts == int.MaxValue ? int.MaxValue : candidate.Attempts + 1;
            try {
                originalCompletionMailUntil=await effectiveAdmission.ReserveCompletionMailAsync(id,expectedRecord,candidate.Kind,owner,expectedAttempt,
                    time.GetUtcNow().AddSeconds(options.LeaseSeconds),cancellationToken);
                if(originalCompletionMailUntil is null)
                    await effectiveAdmission.ReserveAsync(id, expectedRecord, candidate.Kind, owner, expectedAttempt, cancellationToken);
            }
            catch (ProductionWorkBlockedException) { return new(null, time.GetUtcNow().AddMinutes(15), false); }
            now = time.GetUtcNow();
        }
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        if (effectiveAdmission is not null)
        {
            // Match inventory/hold lock ordering: parent, then work. Demand uses
            // this same transaction rather than waiting on its own parent lock.
            _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {expectedRecord}")
                .AsNoTracking().SingleOrDefaultAsync(cancellationToken) ?? throw new ProductionWorkBlockedException();
            await effectiveAdmission.DemandLockedAsync(db, id, expectedRecord, expectedKind!.Value, owner, expectedAttempt, true, cancellationToken);
            now = time.GetUtcNow();
        }
        // UPDLOCK/HOLDLOCK also disables snapshot reads for this key. An insert which
        // persisted its hint but has not committed must settle before we remove it.
        var row = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}")
            .SingleOrDefaultAsync(cancellationToken);
        // A kind change after the read-only routing probe cannot enter ordinary
        // retry/lease mutation while this unrelated parent transaction is held.
        if(row?.Kind==WorkKind.ProductionPurge)throw new InvalidOperationException("Production deletion requires its dedicated work effectiveAdmission.");
        if (effectiveAdmission is not null)
        {
            // A changed/missing candidate is not proof that our reservation had
            // no effect. Keep it pending for explicit reconciliation.
            if (row is null || JsonSerializer.Serialize(row) != expectedRow || row.EnvelopeId != expectedRecord || row.Kind != expectedKind || row.Status is WorkStatus.Completed or WorkStatus.Failed ||
                row.AvailableAt > now || row.Status == WorkStatus.Leased && row.LeaseExpiresAt > now)
                throw new ProductionWorkBlockedException();
        }
        if (row is null || row.Status is WorkStatus.Completed or WorkStatus.Failed)
            return new(null, null, true);
        if(nullLookup is not null) {
            var current=await closeout!.ReadNullLookupLockedAsync(db,id,null,cancellationToken)??throw new ProductionWorkBlockedException();
            if(current.Configuration!=nullLookup.Configuration||current.RecordId!=nullLookup.RecordId)throw new ProductionWorkBlockedException();
            current.DemandLocked(db);await admission!.DemandCloseoutDemoLockedAsync(db,current.RecordId,cancellationToken);
        }
        if(closeout is not null&&closeout.HandoffHost) {
            try {
                if(await Email.Pilot.EmailPilotCloseout.RecognizesWorkAsync(db,row.Id,cancellationToken))return await closeout.HandoffLockedAsync(db,row.Id,cancellationToken)?new(null,null,false,true):new(null,null,false,false,true);
                await closeout.DemandClaimLockedAsync(db,row,cancellationToken);
            }catch(Exception e)when(e is InvalidDataException or InvalidOperationException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or ArgumentException){return new(null,null,false,false,true);}
        }
        else if(closeout is not null)await closeout.DemandClaimLockedAsync(db,row,cancellationToken);
        else if(await Email.Pilot.EmailPilotCloseout.RecognizesWorkAsync(db,row.Id,cancellationToken))
            throw new InvalidDataException("Known closeout work requires its dedicated effectiveAdmission.");
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
        ProductionWorkCompletionClaim? completionClaim=null;
        if(effectiveAdmission is not null&&row.Kind==WorkKind.Sealing)
        {
            var expectedClaim=JsonSerializer.Deserialize<WorkItem>(JsonSerializer.Serialize(row))??throw new ProductionWorkBlockedException();
            expectedClaim.Status=WorkStatus.Leased;expectedClaim.Attempts=row.Attempts+1;expectedClaim.LeaseOwner=owner;
            expectedClaim.LeaseExpiresAt=now.AddSeconds(options.LeaseSeconds);
            completionClaim=await effectiveAdmission.BeginCompletionClaimLockedAsync(db,expectedClaim,cancellationToken);
        }
        row.Status = WorkStatus.Leased;
        row.Attempts=row.Kind==WorkKind.Purge && row.Attempts==int.MaxValue ? int.MaxValue : row.Attempts+1;
        row.LeaseOwner = owner;
        if(originalCompletionMailUntil<=now)throw new ProductionWorkBlockedException();
        row.LeaseExpiresAt = originalCompletionMailUntil??now.AddSeconds(options.LeaseSeconds);
        if(closeout?.PassHost==true){if(!closeout.CanSend)throw new InvalidDataException("Private dispatch effectiveAdmission expired.");row.LeaseExpiresAt=new[]{row.LeaseExpiresAt.Value,closeout.HostOptions.Until}.Min();}
        await db.SaveChangesAsync(cancellationToken);
        if(completionClaim is not null)await effectiveAdmission!.PrepareCompletionClaimExpectedLockedAsync(db,completionClaim,cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        if(completionClaim is not null)
        {
            await transaction.DisposeAsync();
            await effectiveAdmission!.AcknowledgeCompletionClaimAsync(completionClaim,cancellationToken);
        }
        return new(new(row.Id, row.LeaseOwner.Value, row.Kind, row.Attempts, row.LeaseExpiresAt.Value), null, false);
    }

    public static TimeSpan Backoff(int attempt) => TimeSpan.FromSeconds(Math.Min(900, 15 * Math.Pow(2, Math.Clamp(attempt - 1, 0, 10))));

    public async Task<DateTimeOffset?> FinishAsync(WorkLease lease, WorkResult result, CancellationToken cancellationToken)
    {
        if(lease.Kind==WorkKind.ProductionPurge)return await Deletion().FinishAsync(db,lease,result,cancellationToken);
        var nullLookup=admission is not null&&closeout is not null&&lease.Kind==WorkKind.Email&&(await db.WorkItems.AsNoTracking().AnyAsync(x=>x.Id==lease.Id&&x.EnvelopeId==null,cancellationToken)||await db.EmailPilotCloseoutOperations.AsNoTracking().AnyAsync(x=>x.WorkId==lease.Id&&x.Kind==0&&x.Step==(int)Email.Pilot.EmailPilotCloseoutStep.Lookup,cancellationToken))
            ?await closeout.ReadNullLookupAsync(lease.Id,lease,cancellationToken):null;
        var effectiveAdmission=nullLookup is null?admission:null;
        Guid? recordId = null;
        if (effectiveAdmission is not null)
        {
            recordId = await db.WorkItems.AsNoTracking().Where(x => x.Id == lease.Id).Select(x => x.EnvelopeId).SingleAsync(cancellationToken);
            if (result.Outcome != WorkOutcome.Completed)
                await effectiveAdmission.DemandAsync(lease.Id, recordId, lease.Kind, lease.Owner, lease.Attempt, cancellationToken);
        }
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        if(nullLookup is not null) {
            var current=await closeout!.ReadNullLookupLockedAsync(db,lease.Id,lease,cancellationToken)??throw new ProductionWorkBlockedException();
            if(current.Configuration!=nullLookup.Configuration||current.RecordId!=nullLookup.RecordId)throw new ProductionWorkBlockedException();
            current.DemandLocked(db);await admission!.DemandCloseoutDemoLockedAsync(db,current.RecordId,cancellationToken);
            if(result.Outcome==WorkOutcome.Completed&&!await db.EmailOutbox.AnyAsync(x=>x.Id==lease.Id&&x.Status==EmailStatus.Sent&&x.Attempts==1&&x.SubmissionStartedAt!=null,cancellationToken))throw new ProductionWorkBlockedException();
        }
        if (effectiveAdmission is not null)
        {
            _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {recordId}")
                .AsNoTracking().SingleOrDefaultAsync(cancellationToken) ?? throw new ProductionWorkBlockedException();
            if (result.Outcome == WorkOutcome.Completed)
                await effectiveAdmission.DemandHandlerOutcomeLockedAsync(db, lease, recordId, cancellationToken);
            else await effectiveAdmission.DemandLockedAsync(db, lease.Id, recordId, lease.Kind, lease.Owner, lease.Attempt, false, cancellationToken);
        }
        var now = time.GetUtcNow();
        var retry = result.Outcome == WorkOutcome.Retry && (lease.Kind==WorkKind.Purge || lease.Attempt < options.MaximumAttempts);
        var status = retry ? WorkStatus.Queued : result.Outcome == WorkOutcome.Completed ? WorkStatus.Completed : WorkStatus.Failed;
        var at = retry ? now + Backoff(lease.Attempt) : now;
        var code = result.Outcome == WorkOutcome.Retry && !retry ? "attempts-exhausted" : result.Code;
        if(effectiveAdmission is not null&&lease.Kind==WorkKind.Sealing&&result.Outcome==WorkOutcome.Completed)
        {
            var original=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,cancellationToken);
            var completed=JsonSerializer.Deserialize<WorkItem>(JsonSerializer.Serialize(original))??throw new ProductionWorkBlockedException();
            completed.Status=status;completed.AvailableAt=at;completed.LastError=code;completed.LeaseOwner=null;completed.LeaseExpiresAt=null;
            await effectiveAdmission.PrepareCompletionFinishLockedAsync(db,lease,recordId,completed,cancellationToken);
        }
        var changed = await db.WorkItems.Where(x => x.Id == lease.Id && x.Kind == lease.Kind && x.Attempts == lease.Attempt &&
                x.Status == WorkStatus.Leased && x.LeaseOwner == lease.Owner && x.LeaseExpiresAt == lease.Until && x.LeaseExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, status).SetProperty(x => x.AvailableAt, at)
                .SetProperty(x => x.LastError, code).SetProperty(x => x.LeaseOwner, (Guid?)null).SetProperty(x => x.LeaseExpiresAt, (DateTimeOffset?)null), cancellationToken);
        if (changed != 1) throw new InvalidOperationException("Work lease is no longer owned.");
        if (lease.Kind == WorkKind.Email && status == WorkStatus.Failed)
            await db.EmailOutbox.Where(x => x.Id == lease.Id && x.Status == EmailStatus.Queued)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, EmailStatus.Failed).SetProperty(x => x.LastError, code), cancellationToken);
        if (effectiveAdmission is not null && result.Outcome == WorkOutcome.Completed)
        {
            await effectiveAdmission.PrepareOutcomeLockedAsync(db, lease, recordId, cancellationToken);
            if (lease.Until <= time.GetUtcNow()) throw new InvalidOperationException("Work lease is no longer owned.");
        }
        await transaction.CommitAsync(cancellationToken);
        if (effectiveAdmission is not null && result.Outcome == WorkOutcome.Completed)
            await effectiveAdmission.CompleteAsync(lease, recordId, cancellationToken);
        return retry ? at : null;
    }

    // Explicit readback after a lost Finish acknowledgement. It performs no
    // handler/provider execution and never obtains a new lease or extends one.
    internal Task ReconcileCompletedAsync(WorkLease lease, Guid recordId, CancellationToken ct = default)
        =>lease.Kind==WorkKind.ProductionPurge?Deletion().ReconcileCompletedAsync(lease,recordId,ct):
            admission?.CompleteAsync(lease, recordId, ct) ?? throw new InvalidOperationException("Record admission is not configured.");
    private async Task<WorkClaim?> ReadPrivateHandoffAsync(Guid id,CancellationToken ct)
    {
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(row?.Kind==WorkKind.ProductionPurge)throw new InvalidOperationException("Production deletion requires its dedicated work admission.");
        if(row is null||row.Status is WorkStatus.Completed or WorkStatus.Failed)return null;
        try {
            if(!await Email.Pilot.EmailPilotCloseout.RecognizesWorkAsync(db,id,ct))return null;
            return await closeout!.HandoffLockedAsync(db,id,ct)?new(null,null,false,true):new(null,null,false,false,true);
        }catch(Exception error)when(error is InvalidDataException or InvalidOperationException or System.Security.Cryptography.CryptographicException or JsonException or ArgumentException){return new(null,null,false,false,true);}
    }
    private IProductionDeletionWorkAdmission Deletion()=>DeletionAdmission??throw new InvalidOperationException("Production deletion work admission is not configured.");
}

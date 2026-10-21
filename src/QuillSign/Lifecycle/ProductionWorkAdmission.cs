using System.Security.Cryptography;
using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

internal interface IProductionWorkAdmission
{
    Task ReserveAsync(Guid workId, Guid? recordId, WorkKind kind, Guid owner, int attempt, CancellationToken ct);
    Task DemandAsync(Guid workId, Guid? recordId, WorkKind kind, Guid owner, int attempt, CancellationToken ct);
    Task DemandLockedAsync(QuillSignDbContext db, Guid workId, Guid? recordId, WorkKind kind, Guid owner, int attempt, bool starting, CancellationToken ct);
    Task CompleteAsync(WorkLease lease, Guid? recordId, CancellationToken ct);
    Task PrepareOutcomeLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct);
    Task PrepareHandlerOutcomeLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct);
    Task DemandHandlerOutcomeLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct);
    Task<EmailOutbox?> ReadDispatchAsync(QuillSignDbContext db, WorkLease lease, CancellationToken ct);
}

internal sealed class ProductionWorkBlockedException : Exception
{
    internal ProductionWorkBlockedException(Exception? inner = null) : base("Record work is unavailable pending reconciliation.", inner) { }
}

// Internal opt-in composition only. No DI registration until every mutation and
// global worker boundary is covered. Ordinary demo work uses its original rules.
internal sealed class ProductionWorkAdmission(Func<QuillSignDbContext> open, ProductionRecordOperationAdmission admission)
    : IProductionWorkAdmission
{
    public Task ReserveAsync(Guid workId, Guid? recordId, WorkKind kind, Guid owner, int attempt, CancellationToken ct)
        => Guard(async () =>
        {
            if (await Demo(recordId, ct)) return;
            // Admit only handlers whose provider/receipt checkpoint is actually
            // installed. A later Finish refusal cannot undo an unsupported send.
            await using var db = open();
            _ = await SupportedMail(db, workId, recordId, kind, ct);
            _ = await admission.BeginAsync(recordId!.Value, owner, Kind(kind), Reference(workId, attempt), ct);
        });

    public Task DemandAsync(Guid workId, Guid? recordId, WorkKind kind, Guid owner, int attempt, CancellationToken ct)
        => Guard(async () =>
        {
            if (await Demo(recordId, ct)) return;
            var scope = await admission.ResumeAsync(recordId!.Value, owner, Kind(kind), Reference(workId, attempt), ct);
            await admission.DemandAsync(scope, ct);
        });

    public Task CompleteAsync(WorkLease lease, Guid? recordId, CancellationToken ct)
        => Guard(async () =>
        {
            if (await Demo(recordId, ct)) return;
            var scope = await admission.ResumeAsync(recordId!.Value, lease.Owner, Kind(lease.Kind), Reference(lease.Id, lease.Attempt), ct);
            await using var db = open();
            var work = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == lease.Id, ct) ?? throw new ProductionWorkBlockedException();
            if (work.EnvelopeId != recordId || work.Kind != lease.Kind || work.Status != WorkStatus.Completed || work.Attempts != lease.Attempt ||
                work.LeaseOwner is not null || work.LeaseExpiresAt is not null) throw new ProductionWorkBlockedException();
            // This method is reached only after a completed handler and committed
            // Finish. Retry/failed/ambiguous outcomes deliberately retain the
            // reservation. No lease-expiry or listing absence settles a write.
            var hash = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
            { Version = "production-work-completed-v1", recordId, lease.Id, lease.Owner, lease.Kind, lease.Attempt, Work = work })));
            await admission.CompleteAsync(scope, hash, ct);
        });

    public Task DemandLockedAsync(QuillSignDbContext db, Guid workId, Guid? recordId, WorkKind kind, Guid owner, int attempt, bool starting, CancellationToken ct)
        => Guard(async () =>
        {
            if (await Demo(db, recordId, ct)) return;
            if (starting) _ = await SupportedMail(db, workId, recordId, kind, ct);
            var scope = await admission.ResumeLockedAsync(db, recordId!.Value, owner, Kind(kind), Reference(workId, attempt), ct);
            if (starting) await admission.DemandStartingLockedAsync(db, scope, ct);
        });

    public async Task<EmailOutbox?> ReadDispatchAsync(QuillSignDbContext db, WorkLease lease, CancellationToken ct)
    {
        EmailOutbox? result = null;
        await Guard(async () =>
        {
            var work = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == lease.Id, ct) ?? throw new ProductionWorkBlockedException();
            var recordId = work.EnvelopeId;
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={work.EnvelopeId}")
                .AsNoTracking().SingleOrDefaultAsync(ct) ?? throw new ProductionWorkBlockedException();
            work = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == lease.Id, ct) ?? throw new ProductionWorkBlockedException();
            if (work.EnvelopeId != recordId) throw new ProductionWorkBlockedException();
            if (await Demo(db, work.EnvelopeId, ct)) return;
            if (work.Kind != lease.Kind || work.Status != WorkStatus.Leased || work.LeaseOwner != lease.Owner ||
                work.LeaseExpiresAt != lease.Until || work.Attempts != lease.Attempt)
                throw new ProductionWorkBlockedException();
            result = await SupportedMail(db, lease.Id, work.EnvelopeId, lease.Kind, ct);
            _ = await admission.ResumeLockedAsync(db, work.EnvelopeId!.Value, lease.Owner, Kind(lease.Kind), Reference(lease.Id, lease.Attempt), ct);
            await tx.RollbackAsync(ct);
        });
        return result;
    }

    private static async Task<EmailOutbox> SupportedMail(QuillSignDbContext db, Guid workId, Guid? recordId, WorkKind kind, CancellationToken ct)
    {
        if (kind != WorkKind.Email) throw new ProductionWorkBlockedException();
        var mail = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == workId, ct);
        if (mail is null || mail.EnvelopeId != recordId || mail.Template is not ("sender-verification" or "signer-declined"))
            throw new ProductionWorkBlockedException();
        return mail;
    }

    public Task PrepareOutcomeLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct)
        => Guard(async () =>
        {
            if (await Demo(db, recordId, ct)) return;
            var scope = await admission.ResumeAsync(recordId!.Value, lease.Owner, Kind(lease.Kind), Reference(lease.Id, lease.Attempt), ct);
            await admission.PrepareOutcomeLockedAsync(db, scope, ct);
        });

    public Task PrepareHandlerOutcomeLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct)
        => Guard(async () =>
        {
            if (await Demo(db, recordId, ct)) return;
            var scope = await admission.ResumeLockedAsync(db, recordId!.Value, lease.Owner, Kind(lease.Kind), Reference(lease.Id, lease.Attempt), ct);
            await admission.PrepareHandlerOutcomeLockedAsync(db, scope, ct);
        });

    public Task DemandHandlerOutcomeLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct)
        => Guard(async () =>
        {
            if (await Demo(db, recordId, ct)) return;
            _ = await admission.ResumeHandlerLockedAsync(db, recordId!.Value, lease.Owner, Kind(lease.Kind), Reference(lease.Id, lease.Attempt), ct);
        });

    private async Task<bool> Demo(Guid? id, CancellationToken ct)
    {
        // Global jobs need their own explicit per-record boundary; they cannot
        // borrow a null owner to bypass a production admission gate.
        if (id is null || id == Guid.Empty) throw new ProductionWorkBlockedException();
        await using var db = open();
        return await Demo(db, id, ct);
    }
    private async Task<bool> Demo(QuillSignDbContext db, Guid? id, CancellationToken ct)
    {
        if (id is null || id == Guid.Empty) throw new ProductionWorkBlockedException();
        return await admission.IsUnenrolledDemoAsync(db, id.Value, ct);
    }
    private static string Kind(WorkKind kind) => Enum.IsDefined(kind) ? "work/" + ((int)kind).ToString(CultureInfo.InvariantCulture) : throw new ProductionWorkBlockedException();
    private static string Reference(Guid id, int attempt) => id != Guid.Empty && attempt > 0
        ? id.ToString("N") + "/attempt/" + attempt.ToString(CultureInfo.InvariantCulture) : throw new ProductionWorkBlockedException();
    private static async Task Guard(Func<Task> action)
    {
        try { await action(); }
        catch (Exception error) when (error is InvalidDataException or UnauthorizedAccessException or DocumentConflictException or
            IOException or HttpRequestException or Azure.RequestFailedException)
        { throw new ProductionWorkBlockedException(error); }
    }
}

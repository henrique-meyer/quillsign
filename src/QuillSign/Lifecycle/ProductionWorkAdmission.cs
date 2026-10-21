using System.Security.Cryptography;
using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Work;
using QuillSign.Signing;

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
    Task<bool> DemandCheckpointLockedAsync(QuillSignDbContext db,WorkLease lease,Guid recordId,CancellationToken ct);
    Task<EmailOutbox?> ReadDispatchAsync(QuillSignDbContext db, WorkLease lease, CancellationToken ct);
    Task<ProductionRecordDispatchPermit?> PrepareDispatchLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct);
    Task ConsumeDispatchLockedAsync(QuillSignDbContext db, ProductionRecordDispatchPermit permit, CancellationToken ct);
    Task DemandDispatchReceiptLockedAsync(QuillSignDbContext db, ProductionRecordDispatchPermit permit, CancellationToken ct);
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
            await SupportedWork(db, workId, recordId, kind, ct);
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
            if (starting) await SupportedWork(db, workId, recordId, kind, ct);
            var scope = await admission.ResumeLockedAsync(db, recordId!.Value, owner, Kind(kind), Reference(workId, attempt), ct);
            if (starting) await admission.DemandStartingLockedAsync(db, scope, ct);
        });

    public async Task<EmailOutbox?> ReadDispatchAsync(QuillSignDbContext db, WorkLease lease, CancellationToken ct)
    {
        EmailOutbox? result = null;
        await Guard(async () =>
        {
            if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()) throw new ProductionWorkBlockedException();
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

    public async Task<bool> DemandCheckpointLockedAsync(QuillSignDbContext db,WorkLease lease,Guid recordId,CancellationToken ct)
    {
        var production=false;
        await Guard(async()=>{
            if(await Demo(db,recordId,ct))return;
            await DemandInitialCheckpointAsync(db,lease.Id,recordId,ct,admission.Clock);
            await DemandLockedAsync(db,lease.Id,recordId,lease.Kind,lease.Owner,lease.Attempt,false,ct);production=true;
        });return production;
    }
    private async Task SupportedWork(QuillSignDbContext db,Guid workId,Guid? recordId,WorkKind kind,CancellationToken ct)
    {
        if(kind==WorkKind.Rendering){await DemandInitialCheckpointAsync(db,workId,recordId,ct,admission.Clock);return;}
        _=await SupportedMail(db,workId,recordId,kind,ct);
    }
    internal static async Task DemandInitialCheckpointAsync(QuillSignDbContext db,Guid workId,Guid? recordId,CancellationToken ct,TimeProvider? clock=null)
    {
        if(recordId is not {} id||id==Guid.Empty)throw new ProductionWorkBlockedException();
        // Reserve preflight owns a short read-only parent transaction. A worker
        // already holding the parent never opens another transaction/connection.
        if(db.Database.CurrentTransaction is null)
        {
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct)
                ??throw new ProductionWorkBlockedException();
            await DemandInitialCheckpointAsync(db,workId,id,ct,clock);await tx.RollbackAsync(ct);return;
        }
        // The optional clock supports old metadata-only test helpers. Every
        // actual admission and delivery supplies its original injected clock.
        clock??=TimeProvider.System;
        var work=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId,ct);
        var finish=await db.SignerFinishAcceptances.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId&&x.EnvelopeId==id,ct);
        var envelope=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        if(work is null||finish is null||envelope is null||work.Kind!=WorkKind.Rendering||work.EnvelopeId!=id||
            work.PayloadJson!=JsonSerializer.Serialize(new SignerCheckpointPayload(SignerCheckpointJobs.Version,workId))||
            envelope.Status!=EnvelopeStatus.Sent||signers.Length is <1 or >100||
            signers.Where((x,i)=>x.Order!=i+1).Any()||
            await db.SignerContactRevisions.AnyAsync(x=>x.EnvelopeId==id,ct)||
            await db.WorkItems.AnyAsync(x=>x.EnvelopeId==id&&x.Kind==WorkKind.Reminder,ct))throw new ProductionWorkBlockedException();
        var target=signers.SingleOrDefault(x=>x.Id==finish.SignerId)??throw new ProductionWorkBlockedException();
        var current=await new SignerCheckpointState(db,clock).CurrentAsync(envelope,ct)??throw new ProductionWorkBlockedException();
        if(signers.Take(target.Order-1).Any(x=>x.Status!=SignerStatus.Signed)||signers.Skip(target.Order).Any(x=>!Pending(x))||
            await db.SignerFinishAcceptances.CountAsync(x=>x.EnvelopeId==id,ct)!=target.Order)throw new ProductionWorkBlockedException();
        // The saved Send policy, rather than the mutable legacy draft array,
        // authorizes reminder work. This finite checkpoint admits only empty.
        if((await SenderSentStatus.ReadSentAsync(db,envelope,null,ct)).Reminders is not {} policy||!policy.Days.IsEmpty)
            throw new ProductionWorkBlockedException();
        var candidate=await db.SignerReviewCandidates.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==finish.ReviewCandidateId&&x.EnvelopeId==id,ct);
        if(candidate is null||!SignerFinish.MatchesCandidate(finish,candidate))throw new ProductionWorkBlockedException();
        if(finish.ProcessedAt is null)
        {
            if(current.Version!=target.Order-1||current.ObjectId!=finish.SourceObjectId||!SignerCheckpointState.Same(current.Sha256,finish.SourceSha256)||
                target.Status!=SignerStatus.Viewed||target.SignedAt is not null||finish.NextInvitationId is not null||
                await db.WorkItems.AnyAsync(x=>x.EnvelopeId==id&&x.Kind==WorkKind.Sealing,ct))
                throw new ProductionWorkBlockedException();
        }
        else
        {
            if(current.Version!=target.Order||current.FinishId!=finish.Id||target.Status!=SignerStatus.Signed||target.SignedAt!=finish.FinishedAt||
                target.SignedIp!=finish.Ip||target.SignedUa!=finish.UserAgent)
                throw new ProductionWorkBlockedException();
            if(target.Order==signers.Length)
            {
                if(finish.NextInvitationId is not null)throw new ProductionWorkBlockedException();
                await DemandQueuedCompletionAsync(db,envelope,finish,current,clock,ct);return;
            }
            if(await db.WorkItems.AnyAsync(x=>x.EnvelopeId==id&&x.Kind==WorkKind.Sealing,ct))throw new ProductionWorkBlockedException();
            if(finish.NextInvitationId is not {} next)
            {
                if(envelope.ExpiresAt is not {} expiry||finish.ProcessedAt<expiry)throw new ProductionWorkBlockedException();
                return;
            }
            var mail=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==next,ct);
            var nextWork=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==next,ct);
            if(mail is null||nextWork is null||mail.EnvelopeId!=id||mail.To!=signers[target.Order].Email||mail.Template!="signer-invitation"||mail.Status!=EmailStatus.Queued||
                mail.Attempts!=0||mail.SubmissionStartedAt is not null||mail.Provider is not null||mail.ProviderMessageId is not null||mail.AttachmentsJson!="[]"||
                nextWork.EnvelopeId!=id||nextWork.Kind!=WorkKind.Email||nextWork.Status!=WorkStatus.Queued||nextWork.Attempts!=0||nextWork.LeaseOwner is not null||nextWork.LeaseExpiresAt is not null||
                await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==id&&x.Purpose==TokenPurpose.SignerAccess&&x.PartyId==signers[target.Order].Id,ct))throw new ProductionWorkBlockedException();
        }
    }

    private static async Task DemandQueuedCompletionAsync(QuillSignDbContext db,Envelope envelope,SignerFinishAcceptance finish,SignerCurrentSource source,TimeProvider clock,CancellationToken ct)
    {
        var rows=await db.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id&&x.Kind==WorkKind.Sealing).Take(2).ToArrayAsync(ct);
        var expected=JsonSerializer.Serialize(new CompletionWorkPayload(CompletionJobs.Version,finish.Id,source.Version,
            Convert.ToHexStringLower(source.Sha256),Convert.ToHexStringLower(envelope.ErsdSha256!)));
        if(rows.Length!=1||rows[0].Id!=CompletionJobs.WorkId(envelope.Id)||rows[0].PayloadJson!=expected||rows[0].Status!=WorkStatus.Queued||
            rows[0].Attempts!=0||rows[0].LeaseOwner is not null||rows[0].LeaseExpiresAt is not null||rows[0].LastError is not null||
            rows[0].AvailableAt<finish.ProcessedAt||rows[0].AvailableAt>clock.GetUtcNow())throw new ProductionWorkBlockedException();
    }

    private async Task<EmailOutbox> SupportedMail(QuillSignDbContext db, Guid workId, Guid? recordId, WorkKind kind, CancellationToken ct)
    {
        if (kind != WorkKind.Email) throw new ProductionWorkBlockedException();
        var mail = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == workId, ct);
        if (mail is null || mail.EnvelopeId != recordId || mail.Template is not ("sender-verification" or "signer-declined" or "signer-invitation"))
            throw new ProductionWorkBlockedException();
        if (mail.Template == "signer-invitation") await DemandInitialInvitationAsync(db, mail, ct,admission.Clock);
        return mail;
    }

    internal static async Task<SignerCurrentSource> DemandInitialInvitationAsync(QuillSignDbContext db, EmailOutbox mail, CancellationToken ct,TimeProvider clock)
    {
        if (mail.EnvelopeId is not { } id || mail.Template != "signer-invitation" || mail.Status != EmailStatus.Queued ||
            mail.Attempts != 0 || mail.SubmissionStartedAt is not null || mail.Provider is not null || mail.ProviderMessageId is not null ||
            mail.AttachmentsJson != "[]" || mail.LastError is not null) throw new ProductionWorkBlockedException();
        if(db.Database.CurrentTransaction is null)
        {
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct)
                ??throw new ProductionWorkBlockedException();
            var result=await DemandInitialInvitationAsync(db,mail,ct,clock);await tx.RollbackAsync(ct);return result;
        }
        var source=await DemandInvitationPrefixLockedAsync(db,mail,clock,ct);
        var target=await db.Signers.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id&&x.Order==source.Version+1,ct);
        if(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==id&&x.Purpose==TokenPurpose.SignerAccess&&x.PartyId==target.Id,ct))throw new ProductionWorkBlockedException();
        return source;
    }

    internal static async Task<SignerCurrentSource> DemandInvitationPrefixLockedAsync(QuillSignDbContext db,EmailOutbox mail,TimeProvider clock,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null||mail.EnvelopeId is not {} id||mail.Template!="signer-invitation")throw new ProductionWorkBlockedException();
        var parent=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct)??throw new ProductionWorkBlockedException();
        if(parent.Status!=EnvelopeStatus.Sent||await db.SignerContactRevisions.AnyAsync(x=>x.EnvelopeId==id,ct))throw new ProductionWorkBlockedException();
        var sent=await SenderSentStatus.ReadSentAsync(db,parent,null,ct);
        var source=await new SignerCheckpointState(db,clock).CurrentAsync(parent,ct)??throw new ProductionWorkBlockedException();
        var signers = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == id).OrderBy(x => x.Order).Take(101).ToArrayAsync(ct);
        if(signers.Length is <1 or >100||source.Version>=signers.Length||signers.Where((x,i)=>x.Order!=i+1).Any()||
            signers.Take(source.Version).Any(x=>x.Status!=SignerStatus.Signed)||signers.Skip(source.Version).Any(x=>!Pending(x))||
            signers[source.Version].Email!=mail.To||await db.SignerFinishAcceptances.CountAsync(x=>x.EnvelopeId==id,ct)!=source.Version)
            throw new ProductionWorkBlockedException();
        var expected=source.FinishId is {} finishId
            ?(await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==finishId&&x.EnvelopeId==id,ct)).NextInvitationId
            :sent.InvitationWorkId;
        if(expected!=mail.Id)throw new ProductionWorkBlockedException();
        return source;
    }
    private static bool Pending(Signer signer)=>signer.Status==SignerStatus.Pending&&signer.ConsentAt is null&&signer.SignedAt is null&&signer.SignatureAdoptionId is null;

    public Task PrepareOutcomeLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct)
        => Guard(async () =>
        {
            if (await Demo(db, recordId, ct)) return;
            var scope = await admission.ResumeAsync(recordId!.Value, lease.Owner, Kind(lease.Kind), Reference(lease.Id, lease.Attempt), ct);
            await admission.PrepareOutcomeLockedAsync(db, scope, ct);
        });

    public async Task<ProductionRecordDispatchPermit?> PrepareDispatchLockedAsync(QuillSignDbContext db, WorkLease lease, Guid? recordId, CancellationToken ct)
    {
        ProductionRecordDispatchPermit? result = null;
        await Guard(async () => {
            if (await Demo(db, recordId, ct)) return;
            var scope = await admission.ResumeLockedAsync(db, recordId!.Value, lease.Owner, Kind(lease.Kind), Reference(lease.Id, lease.Attempt), ct);
            result = await admission.PrepareDispatchLockedAsync(db, scope, ct);
        }); return result;
    }

    public Task ConsumeDispatchLockedAsync(QuillSignDbContext db, ProductionRecordDispatchPermit permit, CancellationToken ct)
        => Guard(() => admission.ConsumeDispatchLockedAsync(db, permit, ct));

    public Task DemandDispatchReceiptLockedAsync(QuillSignDbContext db, ProductionRecordDispatchPermit permit, CancellationToken ct)
        => Guard(() => admission.DemandDispatchReceiptLockedAsync(db, permit, ct));

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

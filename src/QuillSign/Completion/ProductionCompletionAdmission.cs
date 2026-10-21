using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Sealing;
using QuillSign.Storage;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using System.Globalization;

namespace QuillSign.Completion;

// These identifiers are allocated before any nondeterministic seal operation.
// They are factual targets, never provider or worker authority by themselves.
internal sealed record CompletionSealTargets(Guid RowId,Guid SourceObjectId,Guid PdfObjectId);
internal sealed record CompletionOwnedSeal(CompletionSealOutput Row,SealedPdf Pdf,CompletionOwnedRowPlan Plan);
internal sealed record CompletionPublicationFiles(Guid ResultId,FinalStoredDocument Executed,FinalStoredDocument Certificate);
internal sealed record CompletionNotificationRosterMember(PartyType Type,Guid? Id,string? Name,string Email,int? Order);
internal sealed record CompletionPublicationTransition(CompletionPublicationIntent Intent,CompletionCandidateData Candidate,
    CompletionSealPair Pair,CompletionPublicationFiles Files,Envelope Before,Envelope Completed,
    CompletionPublicationResult Result,DateTimeOffset RecordedAt,IReadOnlyList<CompletionNotificationRosterMember> Notifications);

internal sealed class CompletionRecordedTime(DateTimeOffset at):TimeProvider
{
    public override DateTimeOffset GetUtcNow()=>at;
}

// Explicit composition only. Implementations must return authenticated codec/
// kernel facts from the real once-only provider boundary. A caller-authored row,
// JSON body, artifact hash or static storage principal is not that authority.
// Every call owns the caller's SAME parent transaction and original operation;
// none may begin another transaction, connection, worker or provider attempt.
internal interface IProductionCompletionEffects
{
    Task<CompletionOwnedRowPlan> CandidateLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,
        CompletionCandidate row,PreparedCompletionPacket packet,CancellationToken ct);
    Task<CompletionOwnedSeal> SealLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,
        CompletionCandidateData candidate,CompletionSealKind kind,CompletionSealTargets targets,byte[] source,
        CompletionSealData? executed,CancellationToken ct);
    Task<CompletionOwnedRowPlan> IntentLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,
        CompletionPublicationIntent row,CancellationToken ct);
    Task<CompletionPublicationFiles> PublicationLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,
        CompletionPublicationIntent intent,CompletionSealPair pair,DateTimeOffset recordedAt,DateTimeOffset? until,CancellationToken ct);
    Task<CompletionOwnedRowPlan> ResultLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,
        CompletionPublicationTransition transition,CancellationToken ct);
}

// One original Sealing reservation. Intermediate slots never become separate
// operations and the one final handler receipt follows committed ResultAck.
internal sealed class ProductionCompletionAdmission
{
    private readonly ProductionRecordOperationAdmission operations;
    private readonly IProductionCompletionEffects effects;
    internal ProductionCompletionAdmission(ProductionRecordOperationAdmission operations,IProductionCompletionEffects effects)
    {
        ArgumentNullException.ThrowIfNull(operations);ArgumentNullException.ThrowIfNull(effects);this.operations=operations;this.effects=effects;
    }
    internal bool Uses(ProductionRecordOperationAdmission value)=>ReferenceEquals(value,operations)&&effects is not null;

    internal async Task DemandQueuedLockedAsync(QuillSignDbContext db,Guid workId,Guid? recordId,CancellationToken ct)
    {
        if(recordId is not {} id||id==Guid.Empty)throw Invalid();
        if(db.Database.CurrentTransaction is null)
        {
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct)??throw Invalid();
            await DemandQueuedLockedAsync(db,workId,id,ct);await tx.RollbackAsync(ct);return;
        }
        var e=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct)??throw Invalid();
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId,ct)??throw Invalid();
        var clock=operations.Clock;
        if(e.Status!=EnvelopeStatus.Sent||row.Id!=CompletionJobs.WorkId(id)||row.EnvelopeId!=id||row.Kind!=WorkKind.Sealing||
            row.Status!=WorkStatus.Queued||row.Attempts!=0||row.LeaseOwner is not null||row.LeaseExpiresAt is not null||row.LastError is not null||row.AvailableAt>clock.GetUtcNow()||
            await db.SignerContactRevisions.AnyAsync(x=>x.EnvelopeId==id,ct)||await db.WorkItems.AnyAsync(x=>x.EnvelopeId==id&&x.Kind==WorkKind.Reminder,ct)||
            await db.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==id,ct)||await db.CompletionSealOutputs.AnyAsync(x=>x.EnvelopeId==id,ct)||
            await db.CompletionPublicationIntents.AnyAsync(x=>x.EnvelopeId==id,ct)||await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==id,ct))throw Invalid();
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        // Preserve the existing candidate codec bound and refuse it BEFORE any
        // admitted effect rather than writing an unreadable candidate.
        if(signers.Length is <1 or >CompletionCandidates.MaximumCopyVersion||signers.Where((x,i)=>x.Order!=i+1||x.Status!=SignerStatus.Signed).Any())throw Invalid();
        var current=await new SignerCheckpointState(db,clock).CurrentAsync(e,ct)??throw Invalid();
        var finish=await db.SignerFinishAcceptances.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==current.FinishId&&x.EnvelopeId==id,ct)??throw Invalid();
        if(current.Version!=signers.Length||finish.ProcessedAt is null||finish.NextInvitationId is not null||row.AvailableAt<finish.ProcessedAt||e.ErsdSha256 is not {Length:32}||
            row.PayloadJson!=JsonSerializer.Serialize(new CompletionWorkPayload(CompletionJobs.Version,finish.Id,current.Version,Convert.ToHexStringLower(current.Sha256),Convert.ToHexStringLower(e.ErsdSha256))))throw Invalid();
        if((await SenderSentStatus.ReadSentAsync(db,e,null,ct)).Reminders is not {} reminder||!reminder.Days.IsEmpty)throw Invalid();
        var retention=await ProductionRecordRetentionAccess.ReadLockedAsync(db,e,clock,ct);
        if(retention.Kind!=ProductionEnrollmentKind.Enrolled||retention.Stage!=ProductionRecordStage.Completing)throw Invalid();
    }

    internal async Task<bool> IsProductionLockedAsync(QuillSignDbContext db,Guid id,CancellationToken ct)
        =>!await operations.IsUnenrolledDemoAsync(db,id,ct);
    internal async Task<bool> HasHandlerOutcomeAsync(QuillSignDbContext db,WorkLease lease,Guid id,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())throw Invalid();
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var scope=await operations.ResumeCompletionLockedAsync(db,id,lease.Owner,Kind,Reference(lease),ct);
        var saved=await operations.TryDemandCompletionHandlerOutcomeLockedAsync(db,scope,ct);await tx.RollbackAsync(ct);return saved;
    }

    internal async Task<PublishedCompletion> RunAsync(QuillSignDbContext db,CompletionCandidates candidates,CompletionSealOutputs seals,
        CompletionPublication publication,WorkLease lease,Guid id,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges()||lease.Kind!=WorkKind.Sealing||
            !candidates.UsesContext(db)||!seals.UsesContext(db)||!publication.UsesContext(db))throw Invalid();
        publication.DemandAdmittedComposition();
        ProductionRecordOperation scope;HoldWitnessCompletionState saved;
        await using(var tx=await db.Database.BeginTransactionAsync(ct))
        {
            scope=await operations.ResumeCompletionLockedAsync(db,id,lease.Owner,Kind,Reference(lease),ct);
            saved=await operations.ReadCompletionRecoveryLockedAsync(db,scope,ct);await tx.RollbackAsync(ct);
        }
        if(saved.ClaimAcknowledged is null)await operations.AcknowledgeCompletionClaimAsync(scope,ct);
        foreach(var item in saved.Slots!.OrderBy(x=>x.Key).Where(x=>x.Value.Expected is not null&&x.Value.Acknowledged is null))
            await operations.AcknowledgeCompletionSlotAsync(scope,item.Key,ct);
        async Task Demand(CancellationToken token)=>await operations.DemandCompletionProgressLockedAsync(db,scope,token);
        async Task<T> Read<T>(Func<CancellationToken,Task<T>> read)
        {
            await using var tx=await db.Database.BeginTransactionAsync(ct);await Demand(ct);var value=await read(ct);await Demand(ct);await tx.RollbackAsync(ct);return value;
        }
        async Task Advance(CompletionSlot slot,Func<CancellationToken,Task<CompletionOwnedRowPlan>> prepare,
            Func<CompletionOwnedRowPlan,CancellationToken,Task> mutate)
        {
            var acknowledge=false;
            await using(var tx=await db.Database.BeginTransactionAsync(ct))
            {
                var state=await operations.ReadCompletionRecoveryLockedAsync(db,scope,ct);
                if(state.Slots?.GetValueOrDefault(slot) is {Acknowledged:not null}){await tx.RollbackAsync(ct);return;}
                if(state.Slots?.GetValueOrDefault(slot) is {Expected:not null}){acknowledge=true;await tx.RollbackAsync(ct);}
                else
                {
                    await Demand(ct);var owned=await prepare(ct);
                    // Semantic facts/targets were purpose-bound before mutation.
                    // The codec binds SQL-generated values only after validating
                    // their exact declared producer dependencies and remainder.
                    await mutate(owned,ct);
                    var permit=await operations.PrepareCompletionSqlLockedAsync(db,scope,owned,ct);
                    await operations.PrepareCompletionExpectedLockedAsync(db,permit,ct);
                    await tx.CommitAsync(ct);acknowledge=true;
                }
            }
            if(acknowledge)await operations.AcknowledgeCompletionSlotAsync(scope,slot,ct);
        }

        (CompletionCandidate Row,PreparedCompletionPacket Packet,CompletionMaterialization Source)? fresh=null;
        await Advance(CompletionSlot.Candidate,async token=>{
            fresh=await candidates.CreateLockedAsync(id,token)??throw Invalid();
            return await effects.CandidateLockedAsync(db,scope,fresh.Value.Row,fresh.Value.Packet,token);
        },(owned,token)=>candidates.InsertOwnedLockedAsync(fresh!.Value.Row,fresh.Value.Source,owned.RecordedAt,token));
        var candidate=await Read(token=>candidates.ReadLockedAsync(id,token))??throw Invalid();
        CompletionSealData? executed=null;
        foreach(var kind in new[]{CompletionSealKind.Executed,CompletionSealKind.Certificate})
        {
            var slot=kind==CompletionSealKind.Executed?CompletionSlot.ExecutedSeal:CompletionSlot.CertificateSeal;
            CompletionOwnedSeal? actual=null;byte[]? source=null;
            await Advance(slot,async token=>{
                source=seals.PrepareSource(candidate,kind,executed,token);
                var targets=new CompletionSealTargets(Guid.NewGuid(),kind==CompletionSealKind.Executed?candidate.PdfObjectId:Guid.NewGuid(),Guid.NewGuid());
                actual=await effects.SealLockedAsync(db,scope,candidate,kind,targets,source,executed,token);
                if(actual.Row.Id!=targets.RowId||actual.Row.SourceObjectId!=targets.SourceObjectId||actual.Row.PdfObjectId!=targets.PdfObjectId||actual.Row.Kind!=kind)throw Invalid();
                _=await seals.VerifyOwnedAsync(actual.Row,source,actual.Pdf.Bytes,candidate,executed,token);return actual.Plan;
            },(owned,token)=>seals.InsertOwnedLockedAsync(actual??throw Invalid(),source??throw Invalid(),candidate,executed,owned.RecordedAt,token));
            if(kind==CompletionSealKind.Executed)executed=await Read(token=>seals.ReadOwnedLockedAsync(candidate,kind,null,token))??throw Invalid();
        }
        var pair=await Read(token=>seals.ReadLockedAsync(id,token))??throw Invalid();
        CompletionPublicationIntent? freshIntent=null;
        await Advance(CompletionSlot.PublicationIntent,async token=>{
            freshIntent=await publication.CreateIntentLockedAsync(candidate,pair,token);
            return await effects.IntentLockedAsync(db,scope,freshIntent,token);
        },(owned,token)=>publication.InsertIntentLockedAsync(freshIntent??throw Invalid(),candidate,pair,owned.RecordedAt,token));
        var intent=await Read(token=>publication.ReadIntentLockedAsync(candidate,pair,token))??throw Invalid();
        CompletionPublicationTransition? transition=null;Guid[] notificationIds=[];
        await Advance(CompletionSlot.PublicationResult,async token=>{
            var at=await SelectPublicationTimeAsync(operations.Clock,Demand,token);CompletionRetentionBinding.CanPublish(intent,at);
            var files=await effects.PublicationLockedAsync(db,scope,intent,pair,at,CompletionRetentionBinding.RequiredUntil(intent,at),token);
            transition=await publication.CreateResultLockedAsync(intent,candidate,pair,files,at,token);
            return await effects.ResultLockedAsync(db,scope,transition,token);
        },async(owned,token)=>{
            if(transition is null||owned.RecordedAt!=transition.RecordedAt)throw Invalid();
            notificationIds=await publication.InsertResultLockedAsync(transition,async(workId,due,t)=>{
                if(due!=transition.RecordedAt||!transition.Notifications.Any(x=>CompletionNotificationJobs.Id(transition.Result.Id,x.Type,x.Id)==workId))throw Invalid();
                var work=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId,t);
                if(work is null||work.EnvelopeId!=id||work.Kind!=WorkKind.Email||work.Status!=WorkStatus.Queued||work.Attempts!=0||
                    work.LeaseOwner is not null||work.LeaseExpiresAt is not null||work.LastError is not null||work.AvailableAt!=due||
                    work.PayloadJson!=CompletionNotificationJobs.WorkJson(workId))throw Invalid();
                await operations.DemandCompletionMutationLockedAsync(db,scope,CompletionSlot.PublicationResult,t);
            },token);
        });
        var published=await Read(token=>publication.ReadLockedAsync(id,token))??throw Invalid();
        // LINEAR A: Result committed and acknowledged; final handler receipt is
        // a LATER read-only parent operation, never part of the result commit.
        await using(var tx=await db.Database.BeginTransactionAsync(ct))
        {
            await operations.PrepareCompletionHandlerOutcomeLockedAsync(db,scope,ct);await tx.RollbackAsync(ct);
        }
        await publication.PublishNotificationsAsync(notificationIds,ct);return published;
    }
    // Blob's retention header uses RFC1123 whole seconds. Select the original
    // producer UTC before opening the result slot; never round provider facts or
    // change an already frozen decision after a write/restart.
    internal static async Task<DateTimeOffset> SelectPublicationTimeAsync(TimeProvider clock,
        Func<CancellationToken,Task> demand,CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(clock);ArgumentNullException.ThrowIfNull(demand);
        ct.ThrowIfCancellationRequested();await demand(ct);ct.ThrowIfCancellationRequested();
        var now=clock.GetUtcNow();if(now.Offset!=TimeSpan.Zero)throw Invalid();
        var remainder=now.Ticks%TimeSpan.TicksPerSecond;var target=now;
        if(remainder!=0)
        {
            try{target=now.AddTicks(TimeSpan.TicksPerSecond-remainder);}
            catch(ArgumentOutOfRangeException){throw Invalid();}
            var wait=target-now;if(wait<=TimeSpan.Zero||wait>TimeSpan.FromSeconds(1))throw Invalid();
            // Task.Delay truncates sub-millisecond durations. Wait at least one
            // timer millisecond while retaining the exact selected UTC target.
            var timerWait=TimeSpan.FromMilliseconds(Math.Ceiling(wait.TotalMilliseconds));
            await Task.Delay(timerWait,clock,ct);
        }
        await demand(ct);ct.ThrowIfCancellationRequested();
        var observed=clock.GetUtcNow();if(observed.Offset!=TimeSpan.Zero||observed<target)throw Invalid();
        return target;
    }
    private static InvalidDataException Invalid()=>new("The admitted completion operation is unavailable pending exact reconciliation.");
    private static string Kind=>"work/"+((int)WorkKind.Sealing).ToString(CultureInfo.InvariantCulture);
    private static string Reference(WorkLease lease)=>lease.Id.ToString("N")+"/attempt/"+lease.Attempt.ToString(CultureInfo.InvariantCulture);
}

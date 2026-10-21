using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Lifecycle;
using QuillSign.Documents;

namespace QuillSign.Work;

public sealed record CompletionWorkPayload(string Version,Guid FinishId,int CopyVersion,string CheckpointSha256,string DisclosureSha256);
public sealed class CompletionJobs(QuillSignDbContext db,SignerCheckpointState state,Func<IWorkSignals> signals,WorkOptions options,TimeProvider time)
{
    internal ProductionRecordOperationAdmission? HoldAdmission {get;init;}
    public const string Version="completion-work-v1";
    internal static Guid WorkId(Guid envelope)=>new(SHA256.HashData(Encoding.ASCII.GetBytes(Version+":"+envelope.ToString("N"))).AsSpan(0,16));
    internal Task<Guid?> PrepareAsync(Guid id,CancellationToken ct,Func<Guid,DateTimeOffset,CancellationToken,Task>? demandHint=null)
        =>PrepareCoreAsync(id,ct,demandHint,null);
    private async Task<Guid?> PrepareCoreAsync(Guid id,CancellationToken ct,Func<Guid,DateTimeOffset,CancellationToken,Task>? demandHint,DateTimeOffset? originalDue)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A transaction is required.");
        if(!options.Enabled)throw new InvalidOperationException("Completion processing is disabled.");
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e is null || e.Status!=EnvelopeStatus.Sent)return null;
        var source=await state.CurrentAsync(e,ct); var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        if(source?.FinishId is not Guid finish || e.SenderVerifiedAt is null || e.ErsdSha256 is not {Length:32} || signers.Length is <1 or >100 ||
            signers.Any(x=>x.Status!=SignerStatus.Signed) || source.Version!=signers.Length)return null;
        var payload=JsonSerializer.Serialize(new CompletionWorkPayload(Version,finish,source.Version,Convert.ToHexStringLower(source.Sha256),Convert.ToHexStringLower(e.ErsdSha256)));
        var workId=WorkId(id); var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId,ct);
        if(row is not null)
        {
            if(row.EnvelopeId!=id || row.Kind!=WorkKind.Sealing || row.PayloadJson!=payload)throw new InvalidDataException("Invalid completion work scope.");
            if(row.Status is WorkStatus.Completed or WorkStatus.Failed)throw new InvalidOperationException("Terminal completion work requires explicit operator review.");
        }
        else
        {
            row=new WorkItem {Id=workId,EnvelopeId=id,Kind=WorkKind.Sealing,PayloadJson=payload,AvailableAt=originalDue??time.GetUtcNow()};
            db.WorkItems.Add(row); await db.SaveChangesAsync(ct);
        }
        var due=row.Status==WorkStatus.Leased && row.LeaseExpiresAt is DateTimeOffset until ? until : row.AvailableAt;
        if(demandHint is not null)await demandHint(workId,due,ct);
        await signals().PutHintAsync(workId,due,ct);
        if(demandHint is not null)await demandHint(workId,due,ct);
        return workId;
    }
    // Explicit recovery only: no recurring database discovery and no terminal/live lease reset.
    public async Task<Guid?> ResumeAsync(Guid envelopeId,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(envelopeId==Guid.Empty)return null;
        if(HoldAdmission is not null)
        {
            ProductionSignerMutationAdmission.DemandStandalone(db);
            try{return await ResumeAdmittedAsync(envelopeId,ct);}catch{db.ChangeTracker.Clear();throw;}
        }
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct); Guid? id;
        await using(var transaction=await db.Database.BeginTransactionAsync(ct)) {id=await PrepareAsync(envelopeId,ct); await transaction.CommitAsync(ct);}
        if(id is Guid workId)await PublishAsync(workId,ct); return id;
    }
    private async Task<Guid?> ResumeAdmittedAsync(Guid id,CancellationToken ct)
    {
        if(!options.Enabled)throw new InvalidOperationException("Completion processing is disabled.");
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}")
            .AsNoTracking().SingleOrDefaultAsync(ct);if(envelope is null)return null;
        if(await HoldAdmission!.IsUnenrolledDemoAsync(db,id,ct))
        {
            var demo=await PrepareAsync(id,ct);await transaction.CommitAsync(ct);await transaction.DisposeAsync();
            if(demo is {} demoWork)await PublishAsync(demoWork,ct);return demo;
        }
        var retained=await ProductionRecordRetentionAccess.ReadLockedAsync(db,envelope,time,ct);
        var source=await state.CurrentAsync(envelope,ct);
        if(retained.Kind!=ProductionEnrollmentKind.Enrolled||retained.Stage!=ProductionRecordStage.Completing||
            envelope.Status!=EnvelopeStatus.Sent||envelope.SenderVerifiedAt is null||envelope.ErsdSha256 is not {Length:32}||source?.FinishId is not {} finishId||
            await db.Signers.AnyAsync(x=>x.EnvelopeId==id&&x.Status!=SignerStatus.Signed,ct))throw new InvalidDataException("The original completion preparation is unavailable.");
        var finish=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==finishId&&x.EnvelopeId==id,ct);
        if(finish.ProcessedAt is not {} originalAt||originalAt>time.GetUtcNow()||finish.NextInvitationId is not null||finish.FinishedAt>originalAt||
            envelope.ExpiresAt is {} expires&&(finish.FinishedAt>=expires||finish.ReviewExpiresAt>expires))throw new InvalidDataException("The original completion clock is unavailable.");
        var workId=WorkId(id);var payload=JsonSerializer.Serialize(new CompletionWorkPayload(Version,finishId,source.Version,
            Convert.ToHexStringLower(source.Sha256),Convert.ToHexStringLower(envelope.ErsdSha256)));
        var existing=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId,ct);
        if(existing is not null)
        {
            // Historical exact metadata only: no hint, publication, replacement
            // or new operation. Sealing remains outside this closed composition.
            DemandQueued(existing,id,payload);if(existing.AvailableAt<originalAt)throw new InvalidDataException("The original completion schedule changed.");
            DocumentRetentionAccess.Check(retained.Deadline,time);
            await transaction.CommitAsync(ct);return workId;
        }
        // An old SQL restore which lost previously witnessed work fails Begin's
        // full baseline. Absence itself never authorizes this distinct repair.
        var operation=await HoldAdmission.BeginLockedAsync(db,id,Guid.NewGuid(),"checkpoint/completion-repair",finishId.ToString("N"),ct);
        var prepared=await PrepareCoreAsync(id,ct,async (job,due,token)=>{
            if(job!=workId||due!=originalAt)throw new InvalidDataException("The original completion job changed.");
            await HoldAdmission.DemandLockedAsync(db,operation,token);
            var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==workId,token);DemandQueued(row,id,payload);
            if(row.AvailableAt!=originalAt||finish.ProcessedAt!=originalAt||originalAt>time.GetUtcNow())throw new InvalidDataException("The original completion job changed.");
            DocumentRetentionAccess.Check(retained.Deadline,time);
        },originalAt);
        if(prepared!=workId)throw new InvalidDataException("The completion preparation is unavailable.");
        await HoldAdmission.PrepareOutcomeLockedAsync(db,operation,ct);DocumentRetentionAccess.Check(retained.Deadline,time);
        if(originalAt>time.GetUtcNow())throw new InvalidDataException("The original completion clock is unavailable.");
        await transaction.CommitAsync(ct);await transaction.DisposeAsync();
        await HoldAdmission.CompleteAsync(operation,Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{
            Version="production-completion-repair-v1",id,operation.OperationId,workId,payload,originalAt}))),ct);
        await PublishAsync(workId,ct);return workId;
    }
    private void DemandQueued(WorkItem row,Guid id,string payload)
    {
        if(row.EnvelopeId!=id||row.Kind!=WorkKind.Sealing||row.PayloadJson!=payload||row.Status!=WorkStatus.Queued||row.Attempts!=0||
            row.LeaseOwner is not null||row.LeaseExpiresAt is not null||row.LastError is not null||row.AvailableAt>time.GetUtcNow())
            throw new InvalidDataException("The queued completion work could not be verified.");
    }
    internal async Task PublishAsync(Guid id,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Commit before publishing completion work.");
        try {await signals().PublishAsync(id,TimeSpan.Zero,ct);}
        catch(Exception e) when(e is Azure.RequestFailedException or IOException or OperationCanceledException or HttpRequestException) { /* durable hint recovers */ }
    }
}

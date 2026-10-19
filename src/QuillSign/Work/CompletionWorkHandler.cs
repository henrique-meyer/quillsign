using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email.Pilot;
using QuillSign.Sealing;
using QuillSign.Signing;

namespace QuillSign.Work;

public sealed class CompletionPipeline(CompletionCandidates candidates,CompletionSealOutputs seals,CompletionPublication publication)
{
    internal async Task<PublishedCompletion?> RunAsync(Guid id,CancellationToken ct,CompletionTimestampWork? timestampWork=null)
    {
        var completed=await publication.ReadAsync(id,ct); if(completed is not null)return completed;
        if(await candidates.PrepareAsync(id,ct) is null || await seals.PrepareAsync(id,ct,timestampWork) is null)return null;
        return await publication.PublishAsync(id,ct);
    }
}

// Completion providers/storage resolve only for an actual Sealing delivery, after scope checks.
public sealed class CompletionWorkHandler(QuillSignDbContext db,SignerCheckpointState state,CompletionCommitScope scope,
    Func<CompletionPipeline> pipeline,TimeProvider time,PilotTimestampBoundary? timestamps=null) : IWorkHandler
{
    public WorkKind Kind=>WorkKind.Sealing;
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        if(lease.Kind!=Kind)return new(WorkOutcome.Failed,"invalid-completion-scope");
        try
        {
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
            if(row?.EnvelopeId is not Guid id || lease.Id!=CompletionJobs.WorkId(id) || row.Kind!=Kind || row.PayloadJson.Length>2048)return new(WorkOutcome.Failed,"invalid-completion-scope");
            var payload=JsonSerializer.Deserialize<CompletionWorkPayload>(row.PayloadJson);
            if(payload is null || payload.Version!=CompletionJobs.Version || payload.FinishId==Guid.Empty || payload.CopyVersion is <1 or >100 ||
                !Hash(payload.CheckpointSha256) || !Hash(payload.DisclosureSha256))return new(WorkOutcome.Failed,"invalid-completion-payload");
            scope.Bind(lease,id,row.PayloadJson);
            await using(var transaction=await db.Database.BeginTransactionAsync(ct))
            {
                var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
                await scope.CheckLockedAsync(id,ct);
                if(envelope is null || envelope.Status is not (EnvelopeStatus.Sent or EnvelopeStatus.Completed))return new(WorkOutcome.Failed,"completion-not-current");
                var current=await state.CurrentAsync(envelope,ct);
                if(current is null || current.FinishId!=payload.FinishId || current.Version!=payload.CopyVersion || Convert.ToHexStringLower(current.Sha256)!=payload.CheckpointSha256 ||
                    envelope.ErsdSha256 is not {Length:32} || Convert.ToHexStringLower(envelope.ErsdSha256)!=payload.DisclosureSha256 ||
                    await db.Signers.AnyAsync(x=>x.EnvelopeId==id && x.Status!=SignerStatus.Signed,ct))return new(WorkOutcome.Failed,"completion-source-unavailable");
                await transaction.CommitAsync(ct);
            }
            CompletionTimestampWork? timestampWork=null;
            if(timestamps is not null)timestampWork=await timestamps.ReadCompletionAsync(lease,id,row.PayloadJson,ct);
            else if(await db.EmailPilotEnrollments.AsNoTracking().AnyAsync(x=>x.SubjectEnvelopeId==id,ct))
                return new(WorkOutcome.Failed,"pilot-completion-unavailable");
            var remaining=lease.Until-time.GetUtcNow()-TimeSpan.FromSeconds(1); if(remaining<=TimeSpan.Zero)throw new CompletionLeaseUnavailableException();
            using var deadline=new CancellationTokenSource(remaining,time); using var linked=CancellationTokenSource.CreateLinkedTokenSource(ct,deadline.Token);
            return await pipeline().RunAsync(id,linked.Token,timestampWork) is null ? new(WorkOutcome.Failed,"completion-evidence-unavailable") : new(WorkOutcome.Completed);
        }
        catch(PilotTimestampDeniedException) {return new(WorkOutcome.Failed,"pilot-completion-unavailable");}
        catch(CompletionLeaseUnavailableException) {return new(WorkOutcome.Retry,"completion-lease-unavailable");}
        catch(Exception e) when(e is IOException or Azure.RequestFailedException or HttpRequestException or SealUnavailableException or CompletionPublicationUnavailableException or InvalidOperationException or DocumentConflictException)
        {return new(WorkOutcome.Retry,"completion-dependency-unavailable");}
        catch(Exception e) when(e is InvalidDataException or JsonException or DocumentRejectedException or SignatureImageRejectedException)
        {return new(WorkOutcome.Failed,"completion-integrity-unavailable");}
        finally {scope.Clear();}
    }
    private static bool Hash(string? value)=>value is {Length:64} && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

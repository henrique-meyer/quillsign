using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Work;

public sealed record SignerCheckpointPayload(string Version,Guid FinishId);
public sealed class SignerCheckpointJobs(QuillSignDbContext db,Func<IWorkSignals> signals,WorkOptions options,TimeProvider time)
{
    public const string Version="signer-checkpoint-v1";
    internal async Task<bool> PrepareAsync(SignerFinishAcceptance finish,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A transaction is required.");
        if(!options.Enabled)throw new InvalidOperationException("Checkpoint processing is disabled.");
        var payload=JsonSerializer.Serialize(new SignerCheckpointPayload(Version,finish.Id));
        var existing=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==finish.Id,ct);
        if(existing is not null)
        {
            if(existing.EnvelopeId!=finish.EnvelopeId || existing.Kind!=WorkKind.Rendering || existing.PayloadJson!=payload)
                throw new InvalidDataException("Invalid checkpoint work scope.");
            return false;
        }
        var row=new WorkItem { Id=finish.Id,EnvelopeId=finish.EnvelopeId,Kind=WorkKind.Rendering,PayloadJson=payload,AvailableAt=time.GetUtcNow() };
        db.WorkItems.Add(row); await db.SaveChangesAsync(ct); await signals().PutHintAsync(row.Id,row.AvailableAt,ct); return true;
    }
    internal async Task PublishAsync(Guid id,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Commit before publishing.");
        try { await signals().PublishAsync(id,TimeSpan.Zero,ct); }
        catch(Exception e) when(e is Azure.RequestFailedException or IOException or OperationCanceledException or HttpRequestException) { /* durable hint recovers */ }
    }
}

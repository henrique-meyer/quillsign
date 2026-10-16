using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Work;

public sealed record CompletionWorkPayload(string Version,Guid FinishId,int CopyVersion,string CheckpointSha256,string DisclosureSha256);
public sealed class CompletionJobs(QuillSignDbContext db,SignerCheckpointState state,Func<IWorkSignals> signals,WorkOptions options,TimeProvider time)
{
    public const string Version="completion-work-v1";
    internal static Guid WorkId(Guid envelope)=>new(SHA256.HashData(Encoding.ASCII.GetBytes(Version+":"+envelope.ToString("N"))).AsSpan(0,16));
    internal async Task<Guid?> PrepareAsync(Guid id,CancellationToken ct)
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
            row=new WorkItem {Id=workId,EnvelopeId=id,Kind=WorkKind.Sealing,PayloadJson=payload,AvailableAt=time.GetUtcNow()};
            db.WorkItems.Add(row); await db.SaveChangesAsync(ct);
        }
        await signals().PutHintAsync(workId,row.Status==WorkStatus.Leased && row.LeaseExpiresAt is DateTimeOffset until ? until : row.AvailableAt,ct);
        return workId;
    }
    // Explicit recovery only: no recurring database discovery and no terminal/live lease reset.
    public async Task<Guid?> ResumeAsync(Guid envelopeId,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(envelopeId==Guid.Empty)return null;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct); Guid? id;
        await using(var transaction=await db.Database.BeginTransactionAsync(ct)) {id=await PrepareAsync(envelopeId,ct); await transaction.CommitAsync(ct);}
        if(id is Guid workId)await PublishAsync(workId,ct); return id;
    }
    internal async Task PublishAsync(Guid id,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Commit before publishing completion work.");
        try {await signals().PublishAsync(id,TimeSpan.Zero,ct);}
        catch(Exception e) when(e is Azure.RequestFailedException or IOException or OperationCanceledException or HttpRequestException) { /* durable hint recovers */ }
    }
}

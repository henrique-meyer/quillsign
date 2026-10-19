using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Work;

public sealed class DemoPurgeJobs(QuillSignDbContext db,Func<IWorkSignals> signals,WorkOptions options,TimeProvider time)
{
    internal static Guid WorkId(Guid envelope)=>new(SHA256.HashData(Encoding.ASCII.GetBytes("demo-purge-work-v1:"+envelope.ToString("N"))).AsSpan(0,16));
    private static bool Matches(WorkItem row,DocumentRetentionSnapshot policy)=>row.Id==WorkId(policy.EnvelopeId) &&
        row.EnvelopeId==policy.EnvelopeId && row.Kind==WorkKind.Purge && row.PayloadJson==DemoPurgeAuthority.Payload(policy) &&
        row.AvailableAt>=policy.DeleteAfter && row.Attempts>=0 && Enum.IsDefined(row.Status) &&
        (row.Status==WorkStatus.Leased ? row.LeaseOwner is Guid owner && owner!=Guid.Empty && row.LeaseExpiresAt>row.AvailableAt :
            row.LeaseOwner is null && row.LeaseExpiresAt is null);
    internal static async Task<bool> IsPreparedLockedAsync(QuillSignDbContext db,DocumentRetentionSnapshot policy,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Verify purge scheduling under the parent transaction.");
        var id=WorkId(policy.EnvelopeId);
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(row is null)return false;if(!Matches(row,policy))throw Invalid();
        return row.Status is WorkStatus.Queued or WorkStatus.Leased;
    }
    internal async Task<Guid> PrepareLockedAsync(Guid envelopeId,bool allowCreate,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Purge preparation requires the upload transaction.");
        if(!options.Enabled)throw new DocumentRejectedException("This demo's document retention service is not ready.");
        var parent=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={envelopeId}").AsNoTracking().SingleOrDefaultAsync(ct)??throw Invalid();
        var policy=await new UploadRetention(db,new(),time).ReadAsync(parent,ct)??throw Invalid();
        var id=WorkId(envelopeId);
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(row is null)
        {
            if(!allowCreate)throw new DocumentRejectedException("This demo document needs its existing retention service restored before it can be replaced.");
            if(await db.WorkItems.AnyAsync(x=>x.EnvelopeId==envelopeId && x.Kind==WorkKind.Purge,ct))throw Invalid();
            row=new(){Id=id,EnvelopeId=envelopeId,Kind=WorkKind.Purge,PayloadJson=DemoPurgeAuthority.Payload(policy),AvailableAt=policy.DeleteAfter};
            db.WorkItems.Add(row);await db.SaveChangesAsync(ct);
        }
        else
        {
            if(!Matches(row,policy))throw Invalid();
            if(row.Status==WorkStatus.Failed)
            {
                // Only explicit trusted resume can recover an old exhausted/unsupported
                // verified purge job. Email attempts and ambiguous submissions are untouched.
                if(!allowCreate || row.LastError is not("attempts-exhausted" or "unsupported-work-kind"))throw Invalid();
                await db.WorkItems.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,WorkStatus.Queued)
                    .SetProperty(x=>x.LeaseOwner,(Guid?)null).SetProperty(x=>x.LeaseExpiresAt,(DateTimeOffset?)null)
                    .SetProperty(x=>x.LastError,(string?)null),ct);
                row.Status=WorkStatus.Queued;row.LeaseOwner=null;row.LeaseExpiresAt=null;
            }
            if(row.Status==WorkStatus.Completed)throw Invalid();
        }
        await signals().PutHintAsync(id,row.Status==WorkStatus.Leased && row.LeaseExpiresAt>row.AvailableAt ? row.LeaseExpiresAt.Value : row.AvailableAt,ct);
        return id;
    }
    public async Task<Guid?> ResumeAsync(Guid envelopeId,CancellationToken ct=default)
    {
        if(envelopeId==Guid.Empty)return null;
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Purge resume needs a clean standalone unit of work.");
        Guid id;DateTimeOffset due;
        try
        {
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            await using(var tx=await db.Database.BeginTransactionAsync(ct))
            {
                var parent=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={envelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
                if(parent is null)return null;
                var policy=await new UploadRetention(db,new(),time).ReadAsync(parent,ct);
                if(policy is null)return null;due=policy.DeleteAfter;
                id=await PrepareLockedAsync(envelopeId,true,ct);await tx.CommitAsync(ct);
            }
            await PublishAsync(id,due,ct);return id;
        }
        finally{db.ChangeTracker.Clear();}
    }
    internal async Task PublishAsync(Guid id,DateTimeOffset due,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Commit before publishing purge work.");
        try{await signals().PublishAsync(id,TimeSpan.FromSeconds(Math.Clamp((due-time.GetUtcNow()).TotalSeconds,0,7*24*60*60)),ct);}
        catch(Exception error) when(error is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException){ /* durable hint recovers */ }
    }
    private static InvalidDataException Invalid()=>new("The saved demo purge schedule could not be verified.");
}

// Lazy dependencies keep empty deliveries and unrelated work free of key-ring I/O.
public sealed class DemoPurgeHandler(QuillSignDbContext db,Func<DemoPurgeSql> sql,Func<DemoPurgeRecovery> recovery,TimeProvider time,Func<LookupContactCleanup>? lookupCleanup=null,Func<QuillSign.Email.Pilot.EmailPilotSecretCleanup>? pilotCleanup=null):IWorkHandler
{
    public WorkKind Kind=>WorkKind.Purge;
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        if(lease.Kind!=Kind || lease.Id==Guid.Empty)return new(WorkOutcome.Failed,"invalid-purge-scope");
        DemoPurgeSql.Binding binding;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
        if(row is null || row.Kind!=Kind)return new(WorkOutcome.Failed,"invalid-purge-scope");
        if(QuillSign.Email.Pilot.EmailPilotSecretJobs.IsPayload(row.PayloadJson))return pilotCleanup is null
            ? new(WorkOutcome.Retry,"pilot-secret-cleanup-unavailable") : await pilotCleanup().ExecuteAsync(lease,ct);
        if(LookupContactRetention.IsPayload(row.PayloadJson))return lookupCleanup is null
            ? new(WorkOutcome.Retry,"lookup-cleanup-unavailable") : await lookupCleanup().ExecuteAsync(lease,ct);
        try{binding=DemoPurgeSql.ReadPayload(row.PayloadJson);if(lease.Id!=DemoPurgeJobs.WorkId(binding.Id))return new(WorkOutcome.Failed,"invalid-purge-scope");}
        catch(UnauthorizedAccessException){return new(WorkOutcome.Failed,"invalid-purge-payload");}
        var remaining=lease.Until-time.GetUtcNow()-TimeSpan.FromSeconds(1);
        if(remaining<=TimeSpan.Zero)return new(WorkOutcome.Retry,"purge-lease-unavailable");
        using var budget=new CancellationTokenSource(remaining<TimeSpan.FromSeconds(55) ? remaining : TimeSpan.FromSeconds(55),time);
        using var active=CancellationTokenSource.CreateLinkedTokenSource(ct,budget.Token);
        try
        {
            _=await sql().RemoveAsync(lease,active.Token);
            var batch=await recovery().RecoverEnvelopeAsync(binding.Id,active.Token);
            return batch is null || !batch.ReachedEnd || batch.Protected>0 || batch.Changed>0
                ? new(WorkOutcome.Retry,"purge-storage-pending") : new(WorkOutcome.Completed);
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){return new(WorkOutcome.Retry,"purge-pass-pending");}
        catch(Exception error) when(error is SqlException or Azure.RequestFailedException or IOException or InvalidDataException or
            HttpRequestException or TimeoutException or CryptographicException or UnauthorizedAccessException or InvalidOperationException)
        {return new(WorkOutcome.Retry,"purge-dependency-unavailable");}
    }
}

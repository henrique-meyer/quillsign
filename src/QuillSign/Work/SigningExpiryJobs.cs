using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;

namespace QuillSign.Work;

public sealed record SigningExpiryPayload(string Version,Guid EnvelopeId,DateTimeOffset SentAt,DateTimeOffset Deadline,
    string SentObjectId,string SentSha256,string SourceSha256,string DisclosureSha256);

// Trusted preparation/resume only. Send will join preparation in a later slice.
public sealed class SigningExpiryJobs(QuillSignDbContext db,SignerCheckpointState state,Func<IWorkSignals> signals,WorkOptions options,TimeProvider time)
{
    public const string Version="signing-expiry-work-v1";
    internal static Guid WorkId(Guid envelope)=>new(SHA256.HashData(Encoding.ASCII.GetBytes(Version+":"+envelope.ToString("N"))).AsSpan(0,16));
    internal static string Bind(Envelope e)
    {
        if(e.Id==Guid.Empty || e.SentAt is not {} sent || e.ExpiresAt is not {} deadline || deadline<=sent ||
            !Guid.TryParseExact(e.SentPdfBlob,"N",out var blob) || blob==Guid.Empty || e.SentPdfSha256 is not {Length:32} ||
            e.PdfSha256 is not {Length:32} || e.ErsdSha256 is not {Length:32})throw Invalid();
        return JsonSerializer.Serialize(new SigningExpiryPayload(Version,e.Id,sent.ToUniversalTime(),deadline.ToUniversalTime(),e.SentPdfBlob,
            Convert.ToHexStringLower(e.SentPdfSha256),Convert.ToHexStringLower(e.PdfSha256),Convert.ToHexStringLower(e.ErsdSha256)));
    }
    internal static bool Matches(Envelope e,WorkItem row)=>row.Id==WorkId(e.Id) && row.Kind==WorkKind.Expiry && row.EnvelopeId==e.Id &&
        row.PayloadJson==Bind(e) && Enum.IsDefined(row.Status) && row.AvailableAt>=e.ExpiresAt && row.Attempts>=0;

    internal async Task<Guid?> PrepareAsync(Guid envelopeId,CancellationToken ct,Func<Guid,DateTimeOffset,CancellationToken,Task>? demandHint=null)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Expiry preparation requires its parent's transaction.");
        if(!options.Enabled)throw new InvalidOperationException("Expiry processing is disabled.");
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={envelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e is null || e.Status is not (EnvelopeStatus.Sent or EnvelopeStatus.Expired) || e.ExpiresAt is null)return null;
        var payload=Bind(e);var id=WorkId(e.Id);
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(row is null)
        {
            if(e.Status!=EnvelopeStatus.Sent) {_=await new SenderVoidState(db,state,time).SourceLockedAsync(e,ct);return null;}
            row=new WorkItem {Id=id,EnvelopeId=e.Id,Kind=WorkKind.Expiry,PayloadJson=payload,AvailableAt=e.ExpiresAt.Value.ToUniversalTime()};
            db.WorkItems.Add(row);await db.SaveChangesAsync(ct);
        }
        else
        {
            if(!Matches(e,row) || row.Attempts>options.MaximumAttempts)throw Invalid();
            if(row.Status==WorkStatus.Leased && (row.LeaseOwner is null || row.LeaseExpiresAt is null))throw Invalid();
        }
        // New Send evidence binds this row. Insert within the parent's transaction
        // before verifying that evidence; no hint or commit precedes verification.
        _=await new SenderVoidState(db,state,time).SourceLockedAsync(e,ct);
        if(row.Status==WorkStatus.Failed)throw new InvalidOperationException("Failed expiry work requires operator review; resume does not reset attempts.");
        if(row.Status==WorkStatus.Completed)return id;
        var due=row.Status==WorkStatus.Leased && row.LeaseExpiresAt>row.AvailableAt ? row.LeaseExpiresAt.Value : row.AvailableAt;
        if(demandHint is not null)await demandHint(id,due,ct);
        await signals().PutHintAsync(id,due,ct);
        if(demandHint is not null)await demandHint(id,due,ct);
        return id;
    }

    public async Task<Guid?> ResumeAsync(Guid envelopeId,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();if(envelopeId==Guid.Empty)return null;
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Expiry resume requires a clean standalone unit of work.");
        try
        {
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);Guid? id;
            await using(var tx=await db.Database.BeginTransactionAsync(ct)) {id=await PrepareAsync(envelopeId,ct);await tx.CommitAsync(ct);}
            if(id is Guid workId)
            {
                var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==workId,ct);
                if(row.Status is not (WorkStatus.Completed or WorkStatus.Failed))await PublishAsync(workId,row.AvailableAt,ct);
            }
            return id;
        }
        finally {db.ChangeTracker.Clear();}
    }

    internal async Task PublishAsync(Guid id,DateTimeOffset due,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Commit before publishing expiry work.");
        try {await signals().PublishAsync(id,TimeSpan.FromSeconds(Math.Clamp((due-time.GetUtcNow()).TotalSeconds,0,7*24*60*60)),ct);}
        catch(Exception error) when(error is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { /* durable hint recovers */ }
    }

    internal static InvalidDataException Invalid()=>new("Saved expiry work could not be verified.");
}

public sealed class SigningExpiryHandler(QuillSignDbContext db,SigningExpiry expiry) : IWorkHandler
{
    public WorkKind Kind=>WorkKind.Expiry;
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        try
        {
            if(lease.Kind!=Kind || lease.Id==Guid.Empty)return new(WorkOutcome.Failed,"invalid-expiry-scope");
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
            if(row?.EnvelopeId is not Guid envelopeId || row.Kind!=Kind || row.PayloadJson.Length>2048 || lease.Id!=SigningExpiryJobs.WorkId(envelopeId))
                return new(WorkOutcome.Failed,"invalid-expiry-scope");
            var result=await expiry.ExpireWorkAsync(envelopeId,lease,row.PayloadJson,ct);
            return result.Outcome is SigningExpiryOutcome.NotDue or SigningExpiryOutcome.AcceptedPending
                ? new(WorkOutcome.Retry,"expiry-waiting-for-deadline-or-checkpoint") : new(WorkOutcome.Completed);
        }
        catch(InvalidDataException) {return new(WorkOutcome.Failed,"expiry-evidence-unavailable");}
        catch(IOException) {return new(WorkOutcome.Retry,"expiry-commit-unconfirmed");}
    }
}

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Completion;

internal sealed record CompletionAccessPreparation(DownloadPublication Saved,PublishedCompletion Verified,DateTimeOffset Until);
internal sealed record CompletionAccessParty(PartyType Type,Guid? Id,string Email,byte[] Sha256);

public sealed class CompletionAccessState(QuillSignDbContext db,CompletionEvidenceCollector collector,Func<CompletionPublication> publication,TimeProvider time,Email.Pilot.EmailPilotReadBounds? pilotBounds=null)
{
    internal async Task<CompletionAccessPreparation?> PrepareLockedAsync(Guid id,Func<CancellationToken,Task> demand,Action clocks,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null || id==Guid.Empty)throw Invalid();
        var until=time.GetUtcNow().AddMinutes(2);
        using var restriction=CompletionReadRestriction.Enter(db,()=>{clocks();ct.ThrowIfCancellationRequested();if(until<=time.GetUtcNow())throw Invalid();});
        await demand(ct);
        var saved=await CompletionDownloadState.ReadAsync(db,id,time,ct);if(saved is null || saved.PurgeAfter<=time.GetUtcNow())return null;
        until=new[]{until,saved.PurgeAfter??DateTimeOffset.MaxValue}.Min();
        await demand(ct);
        var verified=await publication().ReadLockedAsync(id,ct);
        await demand(ct);
        if(verified is null || !saved.Matches(verified) || until<=time.GetUtcNow())throw Invalid();
        await RecheckLockedAsync(saved,ct);await demand(ct);
        return new(saved,verified,until);
    }
    internal async Task<CompletionAccessPreparation?> PrepareAsync(Guid id,CancellationToken ct)
    {
        if(id==Guid.Empty)return null;
        var saved=await CompletionDownloadState.ReadAsync(db,id,time,ct); if(saved is null || saved.PurgeAfter<=time.GetUtcNow())return null;
        var pilotEnd=pilotBounds is null?null:await pilotBounds.ReadAsync(new(){Id=id},ct);
        var verified=await publication().ReadAsync(id,ct); if(verified is null || !saved.Matches(verified))throw Invalid();
        await using var tx=await db.Database.BeginTransactionAsync(ct); await RecheckLockedAsync(saved,ct); await Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,tx,ct);
        return new(saved,verified,new[]{time.GetUtcNow().AddMinutes(2),saved.PurgeAfter??DateTimeOffset.MaxValue,pilotEnd??DateTimeOffset.MaxValue}.Min());
    }
    internal async Task RecheckLockedAsync(DownloadPublication saved,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Readonly completion scope requires its parent transaction.");
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={saved.EnvelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e is null || e.Status!=EnvelopeStatus.Completed || e.PurgeAfter<=time.GetUtcNow())throw Invalid();
        if(pilotBounds is not null)await pilotBounds.ReadAsync(e,ct);
        var current=await CompletionDownloadState.ReadAsync(db,saved.EnvelopeId,time,ct);
        if(current is null || current.Id!=saved.Id || !Same(current.Recipe,saved.Recipe) || !current.Revision.AsSpan().SequenceEqual(saved.Revision) ||
            !Same(DownloadPublication.Reference(current.Executed),DownloadPublication.Reference(saved.Executed)) ||
            !Same(DownloadPublication.Reference(current.Certificate),DownloadPublication.Reference(saved.Certificate)))throw Invalid();
        await CompletionDownloadState.RecheckSourceAsync(collector,saved,ct);
        if(saved.PurgeAfter<=time.GetUtcNow())throw Invalid();
    }
    internal async Task<CompletionAccessParty?> PartyLockedAsync(DownloadPublication saved,PartyType type,Guid? id,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Frozen parties require a verified parent transaction.");
        if(type is not (PartyType.Sender or PartyType.Signer or PartyType.Recipient) || (type==PartyType.Sender ? id is not null : id is null || id==Guid.Empty))return null;
        string email; string? name; int? order=null;
        if(type==PartyType.Sender) {var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==saved.EnvelopeId,ct); email=e.SenderEmail; name=e.SenderName;}
        else if(type==PartyType.Signer) {
            var s=await db.Signers.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==saved.EnvelopeId && x.Id==id,ct);
            if(s is null)return null; email=s.Email; name=s.FullName; order=s.Order;
        } else {
            var r=await db.Recipients.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==saved.EnvelopeId && x.Id==id,ct);
            if(r is null)return null; email=r.Email; name=r.Name;
        }
        // Keep each issued party scope pinned to its original publication revision.
        return PartyProjection(saved,type,id,email,name,order);
    }
    internal static CompletionAccessParty PartyProjection(DownloadPublication saved,PartyType type,Guid? id,string email,string? name,int? order)
        =>PartyProjection(saved.EnvelopeId,saved.Id,saved.Revision,type,id,email,name,order);
    internal static CompletionAccessParty PartyProjection(Guid envelopeId,Guid publicationId,byte[] revision,PartyType type,Guid? id,string email,string? name,int? order)
        =>new(type,id,email,SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {version=CompletionAccessProtection.Version,
            EnvelopeId=envelopeId,publicationId,publicationRevision=revision,type,id,name,email,order})));
    private static bool Same(byte[]? a,byte[]? b)=>CompletionEvidenceValidation.Same(a,b);
    internal static InvalidDataException Invalid()=>new("Completed retrieval evidence could not be verified.");
}

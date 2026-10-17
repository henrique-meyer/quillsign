using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Sender;

namespace QuillSign.Signing;

public enum SigningExpiryOutcome { Expired,AlreadyExpired,Missing,NotDue,Closed,AcceptedPending,AllSigned }
public sealed record SigningExpiryResult(SigningExpiryOutcome Outcome,DateTimeOffset? ExpiredAt=null);
public sealed record SigningExpiryBatch(int Examined,int Expired,int AlreadyExpired,int Skipped,int Failed,string? NextCursor);

// Trusted finite maintenance only. No public action, queue timer, email or storage authority.
public sealed class SigningExpiry(QuillSignDbContext db,SignerCheckpointState checkpoints,AuditWriter audit,TimeProvider time)
{
    private sealed record Evidence(string Version,string BeforeVersion,DateTimeOffset Deadline,DateTimeOffset ExpiredAt,string SourceSha256);
    private sealed record Roster(Guid Id,int Order,string FullName,string Email,string? Role);
    public async Task<SigningExpiryResult> ExpireAsync(Guid id,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();OwnUnitOfWork();if(id==Guid.Empty)return new(SigningExpiryOutcome.Missing);
        try {
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
            if(e is null)return new(SigningExpiryOutcome.Missing);
            if(e.Status is not (EnvelopeStatus.Sent or EnvelopeStatus.Expired))return new(SigningExpiryOutcome.Closed);
            if(e.ExpiresAt is not DateTimeOffset deadline || deadline>time.GetUtcNow())return new(SigningExpiryOutcome.NotDue);
            if(e.SentAt is null || deadline<=e.SentAt || e.PurgeAfter<=time.GetUtcNow())throw Invalid();
            var events=await Chain(id,ct);
            var source=await new SenderVoidState(db,checkpoints,time).SourceLockedAsync(e,ct);
            var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
            if(signers.Length is <1 or >100 || signers.Where((s,i)=>s.Order!=i+1 || !Enum.IsDefined(s.Status) || s.Status==SignerStatus.Declined).Any())throw Invalid();
            var binding=Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
                e.Id,e.PublicId,e.SenderEmail,e.SenderVerifiedAt,e.Title,e.Message,e.SentAt,e.ExpiresAt,e.SentPdfBlob,e.SentPdfSha256,e.PdfSha256,
                e.ErsdVersion,e.ErsdSha256,e.CurrentFinishId,e.CurrentCopyVersion,source,
                roster=signers.Select(s=>new Roster(s.Id,s.Order,s.FullName,s.Email,s.Role))
            })));
            var existing=events.Where(x=>x.Event=="expired").ToArray();
            if(e.Status==EnvelopeStatus.Expired) {
                if(existing.Length!=1)throw Invalid();var row=existing[0];if(row.DataJson.Length>4096)throw Invalid();Evidence? saved;
                try {saved=JsonSerializer.Deserialize<Evidence>(row.DataJson,new JsonSerializerOptions {MaxDepth=4});}catch(JsonException) {throw Invalid();}
                if(saved is null || saved.Version!="signing-expiry-v1" || !Version(saved.BeforeVersion) || saved.Deadline.Offset!=TimeSpan.Zero || saved.Deadline!=deadline.ToUniversalTime() ||
                    saved.ExpiredAt.Offset!=TimeSpan.Zero || saved.ExpiredAt<saved.Deadline || row.At<saved.ExpiredAt || row.ActorType!=PartyType.System ||
                    row.ActorId is not null || row.ActorEmail is not null || row.Ip is not null || row.UserAgent is not null ||
                    row.DataJson!=JsonSerializer.Serialize(saved with {SourceSha256=binding}))throw Invalid();
                await tx.CommitAsync(ct);return new(SigningExpiryOutcome.AlreadyExpired,saved.ExpiredAt);
            }
            if(existing.Length!=0 || events.Length>=512)throw Invalid();
            if(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==id && x.ProcessedAt==null,ct))return new(SigningExpiryOutcome.AcceptedPending);
            if(signers.All(x=>x.Status==SignerStatus.Signed))return new(SigningExpiryOutcome.AllSigned);
            var at=time.GetUtcNow().ToUniversalTime();if(deadline>at)return new(SigningExpiryOutcome.NotDue);if(at<events[^1].At)throw Invalid();
            var changed=await db.Envelopes.Where(x=>x.Id==id && x.Status==EnvelopeStatus.Sent && x.RowVersion==e.RowVersion)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Expired),ct);
            if(changed!=1)throw Invalid();
            // Used tokens remain historical evidence. Status closes all edit/session checks.
            await db.AuthTokens.Where(x=>x.EnvelopeId==id && x.Purpose==TokenPurpose.SignerAccess && x.UsedAt==null && x.ExpiresAt>at)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,at),ct);
            await audit.AppendAsync(id,"expired",null,null,null,ct,JsonSerializer.Serialize(new Evidence("signing-expiry-v1",Convert.ToBase64String(e.RowVersion),deadline.ToUniversalTime(),at,binding)),PartyType.System);
            var recorded=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id && x.Event=="expired",ct);
            if(recorded.At<at || recorded.At>time.GetUtcNow())throw Invalid();
            // An unknown acknowledgement never claims success. A fresh explicit operation
            // verifies saved status/evidence and cannot append a second expiration.
            await tx.CommitAsync(ct);return new(SigningExpiryOutcome.Expired,at);
        } finally {db.ChangeTracker.Clear();}
    }

    public async Task<SigningExpiryBatch> RunBatchAsync(int maximum=32,string? cursor=null,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();OwnUnitOfWork();if(maximum is <1 or >64)throw new ArgumentOutOfRangeException(nameof(maximum));
        var after=ParseCursor(cursor);var now=time.GetUtcNow();
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        var query=db.Envelopes.AsNoTracking().Where(x=>x.Status==EnvelopeStatus.Sent && x.ExpiresAt!=null && x.ExpiresAt<=now && (x.PurgeAfter==null || x.PurgeAfter>now));
        if(after is { } key)query=query.Where(x=>x.ExpiresAt>key.At || x.ExpiresAt==key.At && x.Id.CompareTo(key.Id)>0);
        var rows=await query.OrderBy(x=>x.ExpiresAt).ThenBy(x=>x.Id).Select(x=>new {x.Id,x.ExpiresAt}).Take(maximum+1).ToArrayAsync(ct);
        var selected=rows.Take(maximum).ToArray();var expired=0;var already=0;var skipped=0;var failed=0;
        foreach(var row in selected) {
            ct.ThrowIfCancellationRequested();
            try {var result=await ExpireAsync(row.Id,ct);if(result.Outcome==SigningExpiryOutcome.Expired)expired++;else if(result.Outcome==SigningExpiryOutcome.AlreadyExpired)already++;else skipped++;}
            catch(Exception error) when(error is InvalidDataException or DbUpdateException or IOException) {failed++;}
        }
        var last=selected.LastOrDefault();var next=rows.Length>maximum && last is not null ? Cursor(last.ExpiresAt!.Value,last.Id) : null;
        return new(selected.Length,expired,already,skipped,failed,next);
    }
    private async Task<AuditEvent[]> Chain(Guid id,CancellationToken ct)
    {
        var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={id}").SingleAsync(ct);
        if(size>16*1024*1024)throw Invalid();
        var rows=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Sequence).Take(513).ToArrayAsync(ct);
        if(rows.Length is <1 or >512)throw Invalid();byte[]? previous=null;DateTimeOffset? previousAt=null;
        for(var i=0;i<rows.Length;i++) {var row=rows[i];
            if(row.Sequence!=i+1 || row.At>time.GetUtcNow() || previousAt>row.At ||
                (previous is null ? row.PrevHash is not null : !SignerCheckpointState.Same(previous,row.PrevHash)) || !SignerCheckpointState.Same(row.Hash,AuditHash.Compute(row)))throw Invalid();
            previous=row.Hash;previousAt=row.At;
        }
        return rows;
    }
    private void OwnUnitOfWork() {if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Signing expiry requires a clean standalone unit of work.");}
    private static bool Version(string? value) {if(value is not {Length:12})return false;try {return Convert.FromBase64String(value) is {Length:8} bytes && Convert.ToBase64String(bytes)==value;}catch(FormatException) {return false;}}
    private static string Cursor(DateTimeOffset at,Guid id)=>at.UtcTicks.ToString(CultureInfo.InvariantCulture)+"."+id.ToString("N");
    private static (DateTimeOffset At,Guid Id)? ParseCursor(string? value) {
        if(value is null)return null;if(value.Length>64)throw new ArgumentException("Invalid expiry continuation.",nameof(value));var parts=value.Split('.');
        if(parts.Length!=2 || !long.TryParse(parts[0],NumberStyles.None,CultureInfo.InvariantCulture,out var ticks) || ticks<0 || ticks>DateTimeOffset.MaxValue.Ticks ||
            !Guid.TryParseExact(parts[1],"N",out var id) || id==Guid.Empty)throw new ArgumentException("Invalid expiry continuation.",nameof(value));
        var at=new DateTimeOffset(ticks,TimeSpan.Zero);if(Cursor(at,id)!=value)throw new ArgumentException("Invalid expiry continuation.",nameof(value));return (at,id);
    }
    private static InvalidDataException Invalid()=>new("The signing expiry evidence could not be verified.");
}

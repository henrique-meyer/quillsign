using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Sender;

public static class SenderVoidStatement
{
    public const string Version="sender-void-v1";
    public const string Text="I want to void this signing request and stop further signing. Records of earlier actions will be retained.";
    public static string Sha256=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Text)));
}

public enum SenderVoidOutcome { Voided,AlreadyVoided,InvalidContext,InvalidConfirmation,Conflict,Closed }
public sealed record SenderVoidRecord(string PublicId,DateTimeOffset VoidedAt,string? Reason);
public sealed record SenderVoidResult(SenderVoidOutcome Outcome,SenderVoidRecord? Action=null);

// Internal application operation; no HTTP endpoint or notification producer. The caller
// supplies the original named sender ticket's expiry, never an expiry from a form.
public sealed class SenderVoid(QuillSignDbContext db,SignerCheckpointState checkpoints,AuditWriter audit,TimeProvider time)
{
    private const string EvidenceVersion="sender-void-evidence-v1";
    private sealed record Evidence(string Version,string ReviewedVersion,string StatementVersion,string Statement,string StatementSha256,
        DateTimeOffset VoidedAt,string? Reason,string SentSha256,string DisclosureSha256,Guid SourceObjectId,string SourceSha256,int CopyVersion,Guid? FinishId);

    public async Task<SenderVoidResult> VoidAsync(ClaimsPrincipal sender,string publicId,DateTimeOffset senderTicketExpiresAt,
        byte[]? reviewedVersion,bool confirmed,string? statementVersion,string? reason,string? ip,string? userAgent,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Sender void requires a clean standalone unit of work.");
        var identity=SendDraftWorkflow.Identity(sender,publicId);
        if(identity is null || !Guid.TryParseExact(publicId,"N",out var parsed) || parsed==Guid.Empty || senderTicketExpiresAt<=time.GetUtcNow())return new(SenderVoidOutcome.InvalidContext);
        if(reviewedVersion is not {Length:8})return new(SenderVoidOutcome.Conflict);
        if(!confirmed || statementVersion!=SenderVoidStatement.Version || !Reason(reason,out var normalized))return new(SenderVoidOutcome.InvalidConfirmation);
        // Copy caller-owned mutable input before the first await.
        var version=Convert.ToBase64String(reviewedVersion.ToArray());
        db.ChangeTracker.Clear();
        try {var result=await Core(identity.Value.Id,identity.Value.Email,publicId,senderTicketExpiresAt,version,normalized,ip,userAgent,ct);db.ChangeTracker.Clear();return result;}
        catch {db.ChangeTracker.Clear();throw;}
    }

    private async Task<SenderVoidResult> Core(Guid id,string email,string publicId,DateTimeOffset until,string version,string? reason,string? ip,string? ua,CancellationToken ct)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(envelope is null || envelope.PublicId!=publicId || envelope.SenderEmail!=email || envelope.SenderVerifiedAt is null || until<=time.GetUtcNow())return new(SenderVoidOutcome.InvalidContext);
        if(envelope.Status==EnvelopeStatus.Voided) {
            var recorded=await Recorded(envelope,version,reason,ct);if(recorded is null)return new(SenderVoidOutcome.Conflict);
            if(until<=time.GetUtcNow())return new(SenderVoidOutcome.InvalidContext);
            await tx.CommitAsync(ct);return new(SenderVoidOutcome.AlreadyVoided,recorded);
        }
        if(envelope.Status!=EnvelopeStatus.Sent || envelope.ExpiresAt<=time.GetUtcNow())return new(SenderVoidOutcome.Closed);
        if(Convert.ToBase64String(envelope.RowVersion)!=version)return new(SenderVoidOutcome.Conflict);
        var source=await Source(envelope,ct);
        if(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==id && x.Event=="voided",ct))throw Invalid();
        var at=time.GetUtcNow();if(until<=at)return new(SenderVoidOutcome.InvalidContext);
        if(envelope.ExpiresAt<=at)return new(SenderVoidOutcome.Closed);
        var changed=await db.Envelopes.Where(x=>x.Id==id && x.Status==EnvelopeStatus.Sent && x.RowVersion==envelope.RowVersion)
            .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided),ct);
        if(changed!=1)return new(SenderVoidOutcome.Conflict);
        await audit.AppendAsync(id,"voided",email,ip,ua,ct,JsonSerializer.Serialize(Bind(envelope,source,version,reason,at)),PartyType.Sender);
        envelope.Status=EnvelopeStatus.Voided;
        var result=await Recorded(envelope,version,reason,ct)??throw Invalid();
        if(until<=time.GetUtcNow())return new(SenderVoidOutcome.InvalidContext);
        if(envelope.ExpiresAt<=time.GetUtcNow())return new(SenderVoidOutcome.Closed);
        // A lost acknowledgement propagates. A later explicit saved-state read/repeat
        // can verify the existing action; it cannot create a second void record.
        await tx.CommitAsync(ct);return new(SenderVoidOutcome.Voided,result);
    }

    private async Task<SignerCurrentSource> Source(Envelope e,CancellationToken ct)
    {
        if(e.SentAt is null || e.SentAt>time.GetUtcNow() || e.SenderVerifiedAt is null || e.SenderVerifiedAt>e.SentAt || e.CompletedAt is not null || e.FinalBlob is not null || e.CertificateBlob is not null)throw Invalid();
        _=await SenderSentStatus.ReadSentAsync(db,e,null,ct);
        var source=await checkpoints.CurrentAsync(e,ct)??throw Invalid();
        var pending=await db.SignerFinishAcceptances.AsNoTracking().Where(x=>x.EnvelopeId==e.Id && x.ProcessedAt==null).Take(2).ToArrayAsync(ct);
        if(pending.Length>1)throw Invalid();
        foreach(var finish in pending) {
            var signer=await db.Signers.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==finish.SignerId && x.EnvelopeId==e.Id,ct);
            if(signer is null || signer.Order!=source.Version+1 || signer.Status!=SignerStatus.Viewed || signer.SignedAt is not null ||
                finish.SourceObjectId!=source.ObjectId || !SignerCheckpointState.Same(finish.SourceSha256,source.Sha256) ||
                await checkpoints.AcceptanceAsync(finish,signer,ct) is null)throw Invalid();
        }
        return source;
    }
    private async Task<SenderVoidRecord?> Recorded(Envelope envelope,string version,string? reason,CancellationToken ct)
    {
        var source=await Source(envelope,ct);
        var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={envelope.Id} AND [Event]='voided'").SingleAsync(ct);
        if(size>16384)throw Invalid();
        var rows=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Event=="voided").Take(2).ToArrayAsync(ct);
        if(rows.Length!=1)throw Invalid();var row=rows[0];Evidence? saved;
        try {saved=JsonSerializer.Deserialize<Evidence>(row.DataJson,new JsonSerializerOptions {MaxDepth=8});}
        catch(Exception error) when(error is JsonException or ArgumentException) {throw Invalid();}
        if(saved is null || row.ActorType!=PartyType.Sender || row.ActorId is not null || row.ActorEmail!=envelope.SenderEmail ||
            !CryptographicOperations.FixedTimeEquals(row.Hash,AuditHash.Compute(row)) || saved.VoidedAt.Offset!=TimeSpan.Zero ||
            saved.VoidedAt<envelope.SentAt || envelope.ExpiresAt<=saved.VoidedAt || row.At<saved.VoidedAt || row.At>time.GetUtcNow() || row.Sequence<2 || row.PrevHash is not {Length:32})throw Invalid();
        var previous=await db.AuditEvents.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==envelope.Id && x.Sequence==row.Sequence-1,ct);
        if(previous is null || previous.At>row.At || !CryptographicOperations.FixedTimeEquals(previous.Hash,row.PrevHash) ||
            !CryptographicOperations.FixedTimeEquals(previous.Hash,AuditHash.Compute(previous)))throw Invalid();
        if(saved.ReviewedVersion!=version || saved.Reason!=reason)return null;
        if(row.DataJson!=JsonSerializer.Serialize(Bind(envelope,source,version,reason,saved.VoidedAt)))throw Invalid();
        return new(envelope.PublicId,saved.VoidedAt,reason);
    }
    private static Evidence Bind(Envelope e,SignerCurrentSource source,string version,string? reason,DateTimeOffset at)=>new(EvidenceVersion,version,
        SenderVoidStatement.Version,SenderVoidStatement.Text,SenderVoidStatement.Sha256,at,reason,SignerCheckpointState.Hex(e.SentPdfSha256!),
        SignerCheckpointState.Hex(e.ErsdSha256!),source.ObjectId,SignerCheckpointState.Hex(source.Sha256),source.Version,source.FinishId);
    private static bool Reason(string? input,out string? value)
    {
        value=null;if(input is null)return true;
        if(input.Length>512 || input.Any(c=>char.IsControl(c) && c is not ('\r' or '\n' or '\t')))return false;
        try {value=input.Replace("\r\n","\n").Replace('\r','\n').Trim().Normalize(NormalizationForm.FormC);}
        catch(ArgumentException) {return false;}
        if(value.Length>512)return false;if(value.Length==0)value=null;return true;
    }
    private static InvalidDataException Invalid()=>new("Saved sender void evidence could not be verified.");
}

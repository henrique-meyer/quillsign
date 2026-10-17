using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Documents;

namespace QuillSign.Sender;

public sealed record SenderVoidPreview(string PublicId,string Title,EnvelopeStatus Status,string Version,DateTimeOffset SentAt,
    bool CanVoid,IReadOnlyList<SenderSignerProgress> Signers,SenderVoidRecord? Action);

// Keep the existing QUILS-53 canonical JSON layout and version unchanged.
internal sealed record SenderVoidEvidence(string Version,string ReviewedVersion,string StatementVersion,string Statement,string StatementSha256,
    DateTimeOffset VoidedAt,string? Reason,string SentSha256,string DisclosureSha256,Guid SourceObjectId,string SourceSha256,int CopyVersion,Guid? FinishId);
internal sealed record SenderVoidScope(Envelope Envelope,SignerCurrentSource Source,AuditEvent Audit,SenderVoidEvidence Evidence)
{
    internal SenderVoidRecord Action=>new(Envelope.PublicId,Evidence.VoidedAt,Evidence.Reason);
}

// Metadata verification shared by the original sender action and trusted notification
// work. Internal reads require the parent transaction; they grant no user authority.
public sealed class SenderVoidState(QuillSignDbContext db,SignerCheckpointState checkpoints,TimeProvider time)
{
    public async Task<SenderVoidPreview?> PreviewAsync(ClaimsPrincipal sender,string publicId,DateTimeOffset ticketExpiresAt,CancellationToken ct=default)
    {
        var identity=SendDraftWorkflow.Identity(sender,publicId);
        if(identity is null || !Guid.TryParseExact(publicId,"N",out var parsed) || parsed==Guid.Empty || ticketExpiresAt<=time.GetUtcNow())return null;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);await using var tx=await db.Database.BeginTransactionAsync(ct);
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={identity.Value.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e is null || e.PublicId!=publicId || e.SenderEmail!=identity.Value.Email || e.SenderVerifiedAt is null || e.Status==EnvelopeStatus.Draft)return null;
        var deadline=await SenderPreparationRetention.ReadAsync(db,e,time,ct);
        if(!Enum.IsDefined(e.Status) || e.SentAt is null || e.SentAt>time.GetUtcNow())throw Invalid();
        _=await SenderSentStatus.ReadSentAsync(db,e,null,ct);SenderVoidRecord? action=null;
        if(e.Status==EnvelopeStatus.Voided)action=(await ReadLockedAsync(e.Id,ct)??throw Invalid()).Action;
        else if(e.Status==EnvelopeStatus.Sent) {
            _=await SourceLockedAsync(e,ct);
            if(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided",ct))throw Invalid();
        } else if(await checkpoints.CurrentAsync(e,ct) is null)throw Invalid();
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==e.Id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        if(signers.Length is <1 or >100)throw Invalid();
        var pending=await db.SignerFinishAcceptances.AsNoTracking().Where(x=>x.EnvelopeId==e.Id && x.ProcessedAt==null).Select(x=>x.SignerId).Take(2).ToArrayAsync(ct);
        if(pending.Length>1)throw Invalid();
        var live=e.Status==EnvelopeStatus.Sent && (e.ExpiresAt is null || e.ExpiresAt>time.GetUtcNow());
        string Progress(Signer signer) {
            if(signer.Status==SignerStatus.Signed)return "Signed";
            if(pending.Contains(signer.Id)) {
                if(live)return "Finish accepted; copy processing";
                return e.Status==EnvelopeStatus.Voided ? "Finish accepted before void" : "Finish accepted; request closed";
            }
            return signer.ConsentAt is not null ? "Consent recorded; not signed" : "Not signed";
        }
        var progress=signers.Select(x=>new SenderSignerProgress(x.Order,x.FullName,x.Email,x.Role,Progress(x),x.SignedAt)).ToArray();
        if(ticketExpiresAt<=time.GetUtcNow())return null;
        DocumentRetentionAccess.Check(deadline,time);
        await tx.CommitAsync(ct);DocumentRetentionAccess.Check(deadline,time);if(ticketExpiresAt<=time.GetUtcNow())return null;
        return new(e.PublicId,e.Title!,e.Status,Convert.ToBase64String(e.RowVersion),e.SentAt.Value,
            live,progress,action);
    }

    internal async Task<SignerCurrentSource> SourceLockedAsync(Envelope e,CancellationToken ct)
    {
        RequireTransaction();
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

    internal async Task<SenderVoidScope?> ReadLockedAsync(Guid id,CancellationToken ct)
    {
        RequireTransaction();
        // Reload the actual post-transition revision; callers may hold a pre-void DTO.
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e?.Status!=EnvelopeStatus.Voided)return null;var source=await SourceLockedAsync(e,ct);
        var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={id} AND [Event]='voided'").SingleAsync(ct);
        if(size>16384)throw Invalid();
        var rows=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==id && x.Event=="voided").Take(2).ToArrayAsync(ct);
        if(rows.Length!=1)throw Invalid();var row=rows[0];SenderVoidEvidence? saved;
        try {saved=JsonSerializer.Deserialize<SenderVoidEvidence>(row.DataJson,new JsonSerializerOptions {MaxDepth=8});}
        catch(Exception error) when(error is JsonException or ArgumentException) {throw Invalid();}
        if(saved is null || row.ActorType!=PartyType.Sender || row.ActorId is not null || row.ActorEmail!=e.SenderEmail ||
            !CryptographicOperations.FixedTimeEquals(row.Hash,AuditHash.Compute(row)) || saved.VoidedAt.Offset!=TimeSpan.Zero ||
            saved.VoidedAt<e.SentAt || e.ExpiresAt<=saved.VoidedAt || row.At<saved.VoidedAt || row.At>time.GetUtcNow() || row.Sequence<2 || row.PrevHash is not {Length:32} ||
            !Reason(saved.Reason,out var normalized) || normalized!=saved.Reason || !Version(saved.ReviewedVersion))throw Invalid();
        var previous=await db.AuditEvents.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==id && x.Sequence==row.Sequence-1,ct);
        if(previous is null || previous.At>row.At || !CryptographicOperations.FixedTimeEquals(previous.Hash,row.PrevHash) ||
            !CryptographicOperations.FixedTimeEquals(previous.Hash,AuditHash.Compute(previous)) ||
            row.DataJson!=JsonSerializer.Serialize(Bind(e,source,saved.ReviewedVersion,saved.Reason,saved.VoidedAt)))throw Invalid();
        return new(e,source,row,saved);
    }

    internal static SenderVoidEvidence Bind(Envelope e,SignerCurrentSource source,string version,string? reason,DateTimeOffset at)=>new("sender-void-evidence-v1",version,
        SenderVoidStatement.Version,SenderVoidStatement.Text,SenderVoidStatement.Sha256,at,reason,SignerCheckpointState.Hex(e.SentPdfSha256!),
        SignerCheckpointState.Hex(e.ErsdSha256!),source.ObjectId,SignerCheckpointState.Hex(source.Sha256),source.Version,source.FinishId);
    internal static bool Reason(string? input,out string? value)
    {
        value=null;if(input is null)return true;
        if(input.Length>512 || input.Any(c=>char.IsControl(c) && c is not ('\r' or '\n' or '\t')))return false;
        try {value=input.Replace("\r\n","\n").Replace('\r','\n').Trim().Normalize(NormalizationForm.FormC);}
        catch(ArgumentException) {return false;}
        if(value.Length>512)return false;if(value.Length==0)value=null;return true;
    }
    private static bool Version(string value) {
        try {return Convert.FromBase64String(value) is {Length:8} bytes && Convert.ToBase64String(bytes)==value;}
        catch(ArgumentException) {return false;}catch(FormatException) {return false;}
    }
    private void RequireTransaction() {if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Void state requires its parent's transaction.");}
    internal static InvalidDataException Invalid()=>new("Saved sender void evidence could not be verified.");
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Signing;

public sealed record SignerCurrentSource(Guid ObjectId,byte[] Sha256,int Version,Guid? FinishId);

// Metadata/evidence verification only; callers own the envelope transaction lock.
public sealed class SignerCheckpointState(QuillSignDbContext db,TimeProvider time)
{
    public async Task<SignerCurrentSource?> CurrentAsync(Envelope envelope,CancellationToken ct)
    {
        RequireTransaction();
        if(!Guid.TryParseExact(envelope.SentPdfBlob,"N",out var original) || original==Guid.Empty || envelope.SentPdfSha256 is not { Length:32 })return null;
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        if(signers.Length is <1 or >100)return null;
        var signed=signers.TakeWhile(x=>x.Status==SignerStatus.Signed).ToArray();
        if(signers.Skip(signed.Length).Any(x=>x.Status==SignerStatus.Signed))return null;
        var finishes=await db.SignerFinishAcceptances.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.ProcessedAt!=null).Take(101).ToArrayAsync(ct);
        if(finishes.Length!=signed.Length || envelope.CurrentCopyVersion!=signed.Length)return null;
        if(signed.Length==0)return envelope.CurrentFinishId is null ? new(original,envelope.SentPdfSha256,0,null) : null;
        var ids=finishes.Select(x=>x.ReviewCandidateId).ToArray();
        var candidates=await db.SignerReviewCandidates.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && ids.Contains(x.Id)).ToDictionaryAsync(x=>x.Id,ct);
        var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Event=="signer_completed").Take(101).ToArrayAsync(ct);
        if(events.Length!=signed.Length)return null;
        var objectId=original; var hash=envelope.SentPdfSha256; Guid? latest=null;
        foreach(var signer in signed)
        {
            var f=finishes.SingleOrDefault(x=>x.SignerId==signer.Id);
            if(f is null || !candidates.TryGetValue(f.ReviewCandidateId,out var p) || !SignerFinish.MatchesCandidate(f,p) ||
                f.ProcessedAt>time.GetUtcNow() || signer.SignedAt!=f.FinishedAt || signer.SignedIp!=f.Ip || signer.SignedUa!=f.UserAgent ||
                f.SourceObjectId!=objectId || !Same(f.SourceSha256,hash) || !Same(f.DisclosureSha256,envelope.ErsdSha256) ||
                p.RendererVersion!=SignerPdfRenderer.Version || p.SnapshotVersion!=SignerReviewCandidates.SnapshotVersion ||
                !PublishedEvidence(events,f,signer) || !await SignerReviewCandidates.PreparationEvidence(db,p,signer.Email,ct) ||
                !await SignerFinish.AcceptanceEvidence(db,f,signer.Email,ct))return null;
            objectId=f.PdfObjectId; hash=f.PdfSha256; latest=f.Id;
        }
        return latest==envelope.CurrentFinishId ? new(objectId,hash,signed.Length,latest) : null;
    }
    internal async Task<SignaturePreview?> AcceptanceAsync(SignerFinishAcceptance f,Signer signer,CancellationToken ct)
    {
        RequireTransaction();
        var p=await db.SignerReviewCandidates.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==f.ReviewCandidateId && x.EnvelopeId==f.EnvelopeId && x.SignerId==f.SignerId,ct);
        if(p is null || f.FinishedAt>time.GetUtcNow() || !SignerFinish.MatchesCandidate(f,p) || signer.Id!=f.SignerId || signer.EnvelopeId!=f.EnvelopeId ||
            signer.ConsentAt is null || signer.ConsentAt>f.FinishedAt || !await SignerReviewCandidates.PreparationEvidence(db,p,signer.Email,ct) ||
            !await SignerFinish.AcceptanceEvidence(db,f,signer.Email,ct))return null;
        var fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==f.EnvelopeId && x.SignerId==f.SignerId).OrderBy(x=>x.Id).Take(201).ToArrayAsync(ct);
        if(fields.Length is <1 or >200 || JsonSerializer.Serialize(fields)!=f.FieldsJson ||
            fields.Any(x=>x.Type==FieldType.DateSigned ? x.Value!=f.ProspectiveDate.ToString("yyyy-MM-dd",System.Globalization.CultureInfo.InvariantCulture) || x.FilledAt!=f.FinishedAt || x.FilledBy!=PartyType.Signer : x.Required && !SignerFields.Item(x,signer).Filled) ||
            !fields.Any(x=>x.Type==FieldType.Signature && SignerFields.Item(x,signer).Filled))return null;
        var preview=await db.SignaturePreviews.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==f.AdoptionId && x.EnvelopeId==f.EnvelopeId && x.SignerId==f.SignerId,ct);
        if(preview?.UsedAt is null || preview.UsedAt>f.FinishedAt || preview.DocumentId!=f.SourceObjectId || !Same(preview.DocumentSha256,f.SourceSha256) ||
            !Same(preview.DisclosureSha256,f.DisclosureSha256) || preview.NormalizationVersion!=SignaturePng.Version || preview.AdoptionVersion!=SignatureAdoptionStatement.Version ||
            !SignatureAdoption.MatchesRevision(preview,signer))return null;
        var events=await db.AuditEvents.FromSqlInterpolated($"SELECT * FROM [AuditEvents] WHERE JSON_VALUE([DataJson], '$.adoptionId') = {preview.Id.ToString("D")}")
            .AsNoTracking().Where(x=>x.EnvelopeId==f.EnvelopeId && x.Event=="signature_adopted" && x.ActorType==PartyType.Signer && x.ActorId==f.SignerId && x.ActorEmail==signer.Email).ToArrayAsync(ct);
        return events.Length==1 && Same(events[0].Hash,AuditHash.Compute(events[0])) &&
            SignatureAdoption.MatchesAdoptionEvidence(events[0].DataJson,preview,Hex(f.SourceSha256),Hex(f.DisclosureSha256)) ? preview : null;
    }
    internal static string PublishedJson(SignerFinishAcceptance f)=>JsonSerializer.Serialize(new { finishId=f.Id,candidateId=f.ReviewCandidateId,
        sourceObjectId=f.SourceObjectId,checkpointObjectId=f.PdfObjectId,source_sha256=Hex(f.SourceSha256),checkpoint_sha256=Hex(f.PdfSha256),
        disclosure_sha256=Hex(f.DisclosureSha256),snapshot_sha256=Hex(f.SnapshotSha256),recipe_sha256=Hex(f.RecipeSha256),fields_sha256=Hex(f.FieldsSha256),
        f.AdoptionId,f.FinishedAt,f.ProcessedAt,f.NextInvitationId,serverEvidence="accepted_exact_review_published_as_checkpoint" });
    internal static bool PublishedEvidence(AuditEvent[] events,SignerFinishAcceptance f,Signer signer)
    {
        var owned=events.Where(x=>x.ActorId==f.SignerId).ToArray();
        return f.ProcessedAt is not null && owned.Length==1 && owned[0].EnvelopeId==f.EnvelopeId && owned[0].Event=="signer_completed" &&
            owned[0].ActorType==PartyType.Signer && owned[0].ActorEmail==signer.Email && Same(owned[0].Hash,AuditHash.Compute(owned[0])) && owned[0].DataJson==PublishedJson(f);
    }
    internal static bool Same(byte[]? a,byte[]? b)=>a is { Length:32 } && b is { Length:32 } && CryptographicOperations.FixedTimeEquals(a,b);
    internal static string Hex(byte[] value)=>Convert.ToHexStringLower(value);
    private void RequireTransaction() { if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A transaction is required."); }
}

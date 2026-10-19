using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Signing;

public static class SignerFinishStatement
{
    public const string Version="signer-finish-v1";
    public const string Text="By selecting Finish, I intend to sign this document electronically using the signature and initials I applied, and I confirm I reviewed this document and my saved entries.";
    public static byte[] Sha256=>SHA256.HashData(Encoding.UTF8.GetBytes(Text));
}
public enum SignerFinishOutcome { Accepted,AlreadyAccepted,InvalidIntent,InvalidContext,InvalidReview }
public sealed record SignerFinishAccepted(Guid Id,Guid ReviewCandidateId,string PdfSha256,DateTimeOffset FinishedAt,DateOnly DateSigned,bool ProcessingPending);
public sealed record SignerFinishResult(SignerFinishOutcome Outcome,SignerFinishAccepted? Acceptance=null);

// Acceptance freezes entries; a subsequent checkpoint worker owns Signed/progression.
public sealed class SignerFinish(QuillSignDbContext db,SignerAccess access,SignerReviewCandidates reviews,
    SignerReviewProtection protection,AuditWriter audit,TimeProvider time,SignerCheckpointJobs jobs)
{
    public const string SnapshotVersion="signer-finish-snapshot-v1";
    public async Task<SignerFinishResult> AcceptAsync(ClaimsPrincipal principal,string publicId,string? receipt,bool affirm,string? statementVersion,
        string? ip=null,string? ua=null,CancellationToken ct=default)
    {
        if(!affirm || statementVersion!=SignerFinishStatement.Version)return new(SignerFinishOutcome.InvalidIntent);
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var context=await access.GetLockedContextAsync(principal,publicId,ct,finishConfirmation:true);
        if(context?.ConsentAt is null)return new(SignerFinishOutcome.InvalidContext);
        var token=protection.ReadAccepted(receipt,context.Identity); if(token is null)return new(SignerFinishOutcome.InvalidReview);
        var existing=await db.SignerFinishAcceptances.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==context.Identity.EnvelopeId && x.SignerId==context.Identity.SignerId,ct);
        if(existing is not null)
        {
            var candidate=await db.SignerReviewCandidates.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==existing.ReviewCandidateId,ct);
            if(candidate is null || existing.FinishedAt>time.GetUtcNow() || existing.AdoptionId!=context.SignatureAdoptionId || !SignerReviewCandidates.TokenMatches(candidate,token) || !Matches(existing,candidate,context.Identity) ||
                !await reviews.Evidence(candidate,context.Identity,ct) || !await Evidence(existing,context.Identity,ct))return new(SignerFinishOutcome.InvalidReview);
            var state=new SignerCheckpointState(db,time); var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==existing.EnvelopeId,ct);
            var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==existing.SignerId && x.EnvelopeId==existing.EnvelopeId,ct);
            if(await state.CurrentAsync(envelope,ct) is null || await state.AcceptanceAsync(existing,signer,ct) is null)return new(SignerFinishOutcome.InvalidReview);
            _=await reviews.ReadPdf(candidate,context.Identity,ct);
            if((await access.GetLockedContextAsync(principal,publicId,ct,finishConfirmation:true))?.ConsentAt is null)return new(SignerFinishOutcome.InvalidContext);
            var created=existing.ProcessedAt is null && await jobs.PrepareAsync(existing,ct);
            await access.CommitAsync(transaction,ct); await transaction.DisposeAsync();
            if(created)await jobs.PublishAsync(existing.Id,ct);
            return new(SignerFinishOutcome.AlreadyAccepted,Result(existing));
        }
        var review=await reviews.ReadLockedAsync(principal,publicId,receipt,ct); if(review is null)return new(SignerFinishOutcome.InvalidReview);
        if(!await reviews.VerifySourceLockedAsync(principal,publicId,ct))return new(SignerFinishOutcome.InvalidContext);
        var p=review.Candidate; var now=time.GetUtcNow();
        if(!Live(p,context.Identity,now))return new(SignerFinishOutcome.InvalidReview);
        if((await access.GetLockedContextAsync(principal,publicId,ct))?.ConsentAt is null)return new(SignerFinishOutcome.InvalidContext);
        // The review snapshot was verified before this server-only Date Signed update.
        await db.Fields.Where(x=>x.EnvelopeId==p.EnvelopeId && x.SignerId==p.SignerId && x.Type==FieldType.DateSigned)
            .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Value,p.ProspectiveDate.ToString("yyyy-MM-dd",CultureInfo.InvariantCulture))
                .SetProperty(x=>x.FilledAt,now).SetProperty(x=>x.FilledBy,PartyType.Signer),ct);
        var fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==p.EnvelopeId && x.SignerId==p.SignerId).OrderBy(x=>x.Id).Take(201).ToArrayAsync(ct);
        if(fields.Length is <1 or >200)throw new InvalidDataException("Invalid Finish field snapshot.");
        var json=JsonSerializer.Serialize(fields); if(json.Length>8*1024*1024)throw new InvalidDataException("Finish field snapshot exceeds its limit.");
        var accepted=new SignerFinishAcceptance { EnvelopeId=p.EnvelopeId,SignerId=p.SignerId,ReviewCandidateId=p.Id,AdoptionId=p.AdoptionId,
            SourceObjectId=p.SourceObjectId,PdfObjectId=p.PdfObjectId,PdfLength=p.PdfLength,SourceSha256=p.SourceSha256,DisclosureSha256=p.DisclosureSha256,
            SessionSha256=p.SessionSha256,SnapshotSha256=p.SnapshotSha256,PdfSha256=p.PdfSha256,RecipeSha256=p.RecipeSha256,
            FieldsJson=json,FieldsSha256=SHA256.HashData(Encoding.UTF8.GetBytes(json)),SnapshotVersion=SnapshotVersion,
            StatementVersion=SignerFinishStatement.Version,Statement=SignerFinishStatement.Text,StatementSha256=SignerFinishStatement.Sha256,
            ProspectiveDate=p.ProspectiveDate,ReviewPreparedAt=p.PreparedAt,ReviewExpiresAt=p.ExpiresAt,FinishedAt=now,
            Ip=Limit(ip,45),UserAgent=Limit(ua,2048) };
        var consumed=await db.SignerReviewCandidates.Where(x=>x.Id==p.Id && x.RowVersion==p.RowVersion && x.UsedAt==null && x.SupersededAt==null)
            .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.UsedAt,now),ct);
        if(consumed!=1)return new(SignerFinishOutcome.InvalidReview);
        db.SignerFinishAcceptances.Add(accepted); await db.SaveChangesAsync(ct);
        await audit.AppendAsync(p.EnvelopeId,"signer_finish_accepted",context.Identity.Email,accepted.Ip,accepted.UserAgent,ct,
            EvidenceJson(accepted),PartyType.Signer,p.SignerId);
        if(!Live(p,context.Identity,time.GetUtcNow()))return new(SignerFinishOutcome.InvalidReview);
        if((await access.GetLockedContextAsync(principal,publicId,ct,finishConfirmation:true))?.ConsentAt is null)return new(SignerFinishOutcome.InvalidContext);
        if(!Live(p,context.Identity,time.GetUtcNow()))return new(SignerFinishOutcome.InvalidReview);
        await jobs.PrepareAsync(accepted,ct);
        if(!Live(p,context.Identity,time.GetUtcNow()))return new(SignerFinishOutcome.InvalidReview);
        if(!access.IsLive(context))return new(SignerFinishOutcome.InvalidContext);
        await access.CommitAsync(transaction,ct); await transaction.DisposeAsync(); await jobs.PublishAsync(accepted.Id,ct);
        return new(SignerFinishOutcome.Accepted,Result(accepted));
    }
    private static bool Live(SignerReviewCandidate p,VerifiedSigner identity,DateTimeOffset now)=>p.PreparedAt<=now && p.ExpiresAt>now &&
        identity.SessionExpiresAt>now && p.ProspectiveDate==DateOnly.FromDateTime(now.UtcDateTime);
    private static bool Matches(SignerFinishAcceptance f,SignerReviewCandidate p,VerifiedSigner identity)=>MatchesCandidate(f,p) &&
        f.EnvelopeId==identity.EnvelopeId && f.SignerId==identity.SignerId && f.SourceObjectId==identity.DocumentId &&
        Same(f.SourceSha256,Convert.FromHexString(identity.DocumentHash)) && Same(f.DisclosureSha256,Convert.FromHexString(identity.DisclosureHash));
    internal static bool MatchesCandidate(SignerFinishAcceptance f,SignerReviewCandidate p)=>f.ReviewCandidateId==p.Id &&
        p.EnvelopeId==f.EnvelopeId && p.SignerId==f.SignerId && f.AdoptionId==p.AdoptionId && f.SourceObjectId==p.SourceObjectId &&
        f.PdfObjectId==p.PdfObjectId && f.PdfLength==p.PdfLength && f.ReviewPreparedAt==p.PreparedAt && f.ReviewExpiresAt==p.ExpiresAt &&
        f.ProspectiveDate==p.ProspectiveDate && p.UsedAt==f.FinishedAt && p.SupersededAt is null && f.FinishedAt>=p.PreparedAt && f.FinishedAt<p.ExpiresAt &&
        f.ProspectiveDate==DateOnly.FromDateTime(f.FinishedAt.UtcDateTime) && f.SnapshotVersion==SnapshotVersion && f.StatementVersion==SignerFinishStatement.Version && f.Statement==SignerFinishStatement.Text &&
        Same(f.SourceSha256,p.SourceSha256) && Same(f.DisclosureSha256,p.DisclosureSha256) && Same(f.SessionSha256,p.SessionSha256) &&
        Same(f.SnapshotSha256,p.SnapshotSha256) && Same(f.PdfSha256,p.PdfSha256) && Same(f.RecipeSha256,p.RecipeSha256) &&
        Same(f.FieldsSha256,SHA256.HashData(Encoding.UTF8.GetBytes(f.FieldsJson))) && Same(f.StatementSha256,SignerFinishStatement.Sha256);
    private async Task<bool> Evidence(SignerFinishAcceptance f,VerifiedSigner identity,CancellationToken ct)
        =>await AcceptanceEvidence(db,f,identity.Email,ct);
    internal static async Task<bool> AcceptanceEvidence(QuillSignDbContext db,SignerFinishAcceptance f,string email,CancellationToken ct)
    {
        var events=await db.AuditEvents.FromSqlInterpolated($"SELECT * FROM [AuditEvents] WHERE JSON_VALUE([DataJson], '$.finishId') = {f.Id.ToString("D")}")
            .AsNoTracking().Where(x=>x.EnvelopeId==f.EnvelopeId && x.Event=="signer_finish_accepted" && x.ActorType==PartyType.Signer && x.ActorId==f.SignerId && x.ActorEmail==email).ToArrayAsync(ct);
        return events.Length==1 && Same(events[0].Hash,AuditHash.Compute(events[0])) && events[0].Ip==f.Ip && events[0].UserAgent==f.UserAgent && events[0].DataJson==EvidenceJson(f);
    }
    private static string EvidenceJson(SignerFinishAcceptance f)=>JsonSerializer.Serialize(new { finishId=f.Id,candidateId=f.ReviewCandidateId,
        f.AdoptionId,f.SourceObjectId,f.PdfObjectId,f.PdfLength,sourceSha256=Hex(f.SourceSha256),disclosureSha256=Hex(f.DisclosureSha256),
        sessionSha256=Hex(f.SessionSha256),snapshotSha256=Hex(f.SnapshotSha256),pdfSha256=Hex(f.PdfSha256),recipeSha256=Hex(f.RecipeSha256),
        fieldsSha256=Hex(f.FieldsSha256),statementSha256=Hex(f.StatementSha256),f.SnapshotVersion,f.StatementVersion,f.Statement,f.ProspectiveDate,
        f.ReviewPreparedAt,f.ReviewExpiresAt,f.FinishedAt,affirm=true,serverEvidence="exact_review_accepted_checkpoint_publication_pending" });
    internal static SignerFinishAccepted Result(SignerFinishAcceptance f)=>new(f.Id,f.ReviewCandidateId,Hex(f.PdfSha256),f.FinishedAt,f.ProspectiveDate,f.ProcessedAt is null);
    private static bool Same(byte[] a,byte[] b)=>a.Length==32 && CryptographicOperations.FixedTimeEquals(a,b);
    private static string Hex(byte[] b)=>Convert.ToHexStringLower(b);
    private static string? Limit(string? value,int length)=>value is not null && value.Length>length ? value[..length] : value;
}

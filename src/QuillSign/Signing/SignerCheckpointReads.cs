using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Signing;

public sealed record SignerOwnCheckpoint(SignerFinishAccepted Acceptance,byte[] Pdf)
{
    internal DateTimeOffset? RetentionDeadline {get;init;}
}
public sealed class SignerCheckpointReads(QuillSignDbContext db,SignerAccess access,SignerCheckpointState state,SignerCheckpointBlobs blobs,
    SignerReviewProtection protection,TimeProvider time)
{
    public async Task<SignerFinishAccepted?> ConfirmAsync(ClaimsPrincipal principal,string publicId,string? receipt,CancellationToken ct=default)
        =>(await GetAsync(principal,publicId,receipt,false,ct))?.Acceptance;
    internal Task<SignerOwnCheckpoint?> ConfirmScopeAsync(ClaimsPrincipal principal,string publicId,string? receipt,CancellationToken ct)
        =>GetAsync(principal,publicId,receipt,false,ct);
    public Task<SignerOwnCheckpoint?> ReadAsync(ClaimsPrincipal principal,string publicId,string? receipt,CancellationToken ct=default)
        =>GetAsync(principal,publicId,receipt,true,ct);
    private async Task<SignerOwnCheckpoint?> GetAsync(ClaimsPrincipal principal,string publicId,string? receipt,bool published,CancellationToken ct)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct); await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var context=await access.GetLockedContextAsync(principal,publicId,ct,finishConfirmation:true); if(context?.ConsentAt is null)return null;
        var token=protection.ReadAccepted(receipt,context.Identity); if(token is null)return null;
        var f=await db.SignerFinishAcceptances.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==context.Identity.EnvelopeId && x.SignerId==context.Identity.SignerId,ct);
        if(f is null || published && f.ProcessedAt is null)return null;
        var p=await db.SignerReviewCandidates.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==f.ReviewCandidateId,ct);
        if(p is null || !SignerReviewCandidates.TokenMatches(p,token))return null;
        var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==f.EnvelopeId,ct);
        if(await state.CurrentAsync(envelope,ct) is null)return null;
        var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==f.SignerId && x.EnvelopeId==f.EnvelopeId,ct);
        var adoption=await state.AcceptanceAsync(f,signer,ct); if(adoption is null)return null;
        var bytes=await blobs.PdfAsync(f,false,ct); await blobs.AssetsAsync(f,adoption,ct);
        if((await access.GetLockedContextAsync(principal,publicId,ct,finishConfirmation:true))?.ConsentAt is null || context.Identity.SessionExpiresAt<=time.GetUtcNow())return null;
        await access.CommitAsync(transaction,ct);DocumentRetentionAccess.Check(context.RetentionDeadline,time);
        if(context.Identity.SessionExpiresAt<=time.GetUtcNow())return null;
        return new(SignerFinish.Result(f),bytes){RetentionDeadline=context.RetentionDeadline};
    }
}

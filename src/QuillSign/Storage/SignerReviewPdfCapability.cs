using System.Security.Claims;
using QuillSign.Signing;

namespace QuillSign.Storage;

// In-process authority for a single new review PDF. Claims/cookies cannot reproduce it.
internal sealed class SignerReviewPdfCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity=new([],"QuillSign.InternalReviewPdf");
    private readonly DocumentBlob target; private readonly AssetOperation operation;
    private readonly DateTimeOffset expires; private readonly TimeProvider time;
    private SignerReviewPdfCapability(DocumentBlob target,AssetOperation operation,DateTimeOffset expires,TimeProvider time)
    { this.target=target; this.operation=operation; this.expires=expires; this.time=time; AddIdentity(identity); }
    internal static ClaimsPrincipal Create(VerifiedSigner signer,DocumentBlob target,AssetOperation operation,TimeProvider time)
    {
        if(signer.SignerId==Guid.Empty || target.EnvelopeId!=signer.EnvelopeId || target.ObjectId==Guid.Empty || target.ObjectId==signer.DocumentId || target.Kind!=DocumentBlobKind.Normalized || !Enum.IsDefined(operation))
            throw new UnauthorizedAccessException("Invalid signer review PDF scope.");
        var expires=time.GetUtcNow().AddMinutes(2); if(operation!=AssetOperation.Delete && signer.SessionExpiresAt<expires)expires=signer.SessionExpiresAt;
        return new SignerReviewPdfCapability(target,operation,expires,time);
    }
    internal void Demand(DocumentBlob blob,AssetOperation requested)
    {
        var identities=Identities.ToArray();
        if(identities.Length!=1 || !ReferenceEquals(identities[0],identity) || !identity.IsAuthenticated || target!=blob || operation!=requested || expires<=time.GetUtcNow())
            throw new UnauthorizedAccessException("This signer review PDF capability is not valid for this operation.");
    }
}

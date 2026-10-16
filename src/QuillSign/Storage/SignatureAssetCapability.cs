using System.Security.Claims;
using QuillSign.Signing;

namespace QuillSign.Storage;

internal enum AssetOperation { Read, Write, Delete }

// An in-process capability, never an authentication scheme or serialized cookie/claim.
// Copying its claims into a new principal does not copy this authority.
internal sealed class SignatureAssetCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity = new([], "QuillSign.InternalAsset");
    private readonly DocumentBlob target;
    private readonly AssetOperation operation;
    private readonly DateTimeOffset expires;
    private readonly TimeProvider time;
    private SignatureAssetCapability(DocumentBlob target,AssetOperation operation,DateTimeOffset expires,TimeProvider time)
    { this.target = target; this.operation = operation; this.expires = expires; this.time = time; AddIdentity(identity); }

    internal static ClaimsPrincipal Create(VerifiedSigner signer,DocumentBlob target,AssetOperation operation,TimeProvider time)
    {
        if (signer.SignerId == Guid.Empty || target.EnvelopeId != signer.EnvelopeId || target.ObjectId == Guid.Empty ||
            target.ObjectId == signer.DocumentId || target.Kind is not (DocumentBlobKind.Signature or DocumentBlobKind.Initials))
            throw new UnauthorizedAccessException("Invalid signature asset scope.");
        var expires = time.GetUtcNow().AddMinutes(2);
        if (operation != AssetOperation.Delete && signer.SessionExpiresAt < expires) expires = signer.SessionExpiresAt;
        return new SignatureAssetCapability(target,operation,expires,time);
    }
    internal void Demand(DocumentBlob blob,AssetOperation requested)
    {
        var identities = Identities.ToArray();
        if (identities.Length != 1 || !ReferenceEquals(identities[0],identity) || !identity.IsAuthenticated ||
            target != blob || operation != requested || expires <= time.GetUtcNow())
            throw new UnauthorizedAccessException("This signature asset capability is not valid for this operation.");
    }
}

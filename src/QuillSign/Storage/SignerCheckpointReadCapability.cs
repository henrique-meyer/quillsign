using System.Security.Claims;
using QuillSign.Data;

namespace QuillSign.Storage;

// Worker/accepted-read authority, independent of an expired editable signer session.
internal sealed class SignerCheckpointReadCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity=new([],"QuillSign.InternalCheckpointRead");
    private readonly DocumentBlob target; private readonly DateTimeOffset expires; private readonly TimeProvider time;
    private SignerCheckpointReadCapability(DocumentBlob target,TimeProvider time)
    { this.target=target; this.time=time; expires=time.GetUtcNow().AddMinutes(2); AddIdentity(identity); }
    internal static ClaimsPrincipal Create(SignerFinishAcceptance finish,DocumentBlob target,TimeProvider time,SignaturePreview? assets=null)
    {
        var pdf=target.Kind==DocumentBlobKind.Normalized && (target.ObjectId==finish.SourceObjectId || target.ObjectId==finish.PdfObjectId);
        var asset=assets is not null && assets.Id==finish.AdoptionId && assets.EnvelopeId==finish.EnvelopeId && assets.SignerId==finish.SignerId &&
            (target.Kind==DocumentBlobKind.Signature && target.ObjectId==assets.SignatureObjectId || target.Kind==DocumentBlobKind.Initials && target.ObjectId==assets.InitialsObjectId);
        if(finish.Id==Guid.Empty || finish.SignerId==Guid.Empty || target.EnvelopeId!=finish.EnvelopeId || target.EnvelopeId==Guid.Empty || target.ObjectId==Guid.Empty || !(pdf || asset))
            throw new UnauthorizedAccessException("Invalid checkpoint read scope.");
        return new SignerCheckpointReadCapability(target,time);
    }
    internal void Demand(DocumentBlob blob)
    {
        var identities=Identities.ToArray();
        if(identities.Length!=1 || !ReferenceEquals(identities[0],identity) || !identity.IsAuthenticated || target!=blob || expires<=time.GetUtcNow())
            throw new UnauthorizedAccessException("This checkpoint read capability is no longer valid for this object.");
    }
}

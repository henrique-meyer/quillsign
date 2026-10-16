using System.Security.Claims;

namespace QuillSign.Storage;

// In-process authority for one unsigned completion object and one operation; never a cookie.
internal sealed class CompletionCandidateCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity=new([],"QuillSign.InternalCompletionCandidate");
    private readonly DocumentBlob target; private readonly AssetOperation operation;
    private readonly TimeProvider time; private readonly DateTimeOffset expires;
    private CompletionCandidateCapability(DocumentBlob target,AssetOperation operation,TimeProvider time)
    {this.target=target; this.operation=operation; this.time=time; expires=time.GetUtcNow().AddMinutes(2); AddIdentity(identity);}
    internal static ClaimsPrincipal Create(DocumentBlob target,AssetOperation operation,TimeProvider time)
    {
        if(target.EnvelopeId==Guid.Empty || target.ObjectId==Guid.Empty || target.Kind!=DocumentBlobKind.CompletionCandidate || !Enum.IsDefined(operation))
            throw new UnauthorizedAccessException("Invalid completion candidate scope.");
        return new CompletionCandidateCapability(target,operation,time);
    }
    internal void Demand(DocumentBlob blob,AssetOperation requested)
    {
        var identities=Identities.ToArray();
        if(identities.Length!=1 || !ReferenceEquals(identities[0],identity) || !identity.IsAuthenticated || target!=blob || operation!=requested)
            throw new UnauthorizedAccessException("Invalid completion candidate scope.");
        if(expires<=time.GetUtcNow())throw new IOException("Completion candidate scope expired.");
    }
}

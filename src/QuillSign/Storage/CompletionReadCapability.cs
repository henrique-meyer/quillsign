using System.Security.Claims;

namespace QuillSign.Storage;

// Created only by the internal collector after frozen-state verification. Never a cookie identity.
internal sealed class CompletionReadCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity=new([],"QuillSign.InternalCompletionRead");
    private readonly DocumentBlob target; private readonly TimeProvider time; private readonly DateTimeOffset expires;
    private CompletionReadCapability(DocumentBlob target,TimeProvider time)
    {this.target=target; this.time=time; expires=time.GetUtcNow().AddMinutes(2); AddIdentity(identity);}
    internal static ClaimsPrincipal Create(DocumentBlob target,TimeProvider time)
    {
        if(target.EnvelopeId==Guid.Empty || target.ObjectId==Guid.Empty || target.Kind is not (DocumentBlobKind.Original or DocumentBlobKind.Normalized))
            throw new UnauthorizedAccessException("Invalid completion source scope.");
        return new CompletionReadCapability(target,time);
    }
    internal void Demand(DocumentBlob blob)
    {
        var identities=Identities.ToArray();
        if(identities.Length!=1 || !ReferenceEquals(identities[0],identity) || !identity.IsAuthenticated || target!=blob)
            throw new UnauthorizedAccessException("Invalid completion source scope.");
        if(expires<=time.GetUtcNow())throw new IOException("Completion source read expired.");
    }
}

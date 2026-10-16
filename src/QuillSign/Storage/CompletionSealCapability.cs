using System.Security.Claims;

namespace QuillSign.Storage;

// Exact private completion-stage object and operation; cannot become public session authority.
internal sealed class CompletionSealCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity=new([],"QuillSign.InternalCompletionSeal");
    private readonly DocumentBlob target; private readonly AssetOperation operation;
    private readonly TimeProvider time; private readonly DateTimeOffset expires;
    private CompletionSealCapability(DocumentBlob target,AssetOperation operation,TimeProvider time)
    {this.target=target; this.operation=operation; this.time=time; expires=time.GetUtcNow().AddMinutes(2); AddIdentity(identity);}
    internal static bool IsKind(DocumentBlobKind kind)=>kind is DocumentBlobKind.CompletionExecutedSeal or DocumentBlobKind.CompletionCertificateSource or DocumentBlobKind.CompletionCertificateSeal;
    internal static ClaimsPrincipal Create(DocumentBlob target,AssetOperation operation,TimeProvider time)
    {
        if(target.EnvelopeId==Guid.Empty || target.ObjectId==Guid.Empty || !IsKind(target.Kind) || !Enum.IsDefined(operation))
            throw new UnauthorizedAccessException("Invalid completion seal scope.");
        return new CompletionSealCapability(target,operation,time);
    }
    internal void Demand(DocumentBlob blob,AssetOperation requested)
    {
        var identities=Identities.ToArray();
        if(identities.Length!=1 || !ReferenceEquals(identities[0],identity) || !identity.IsAuthenticated || target!=blob || operation!=requested)
            throw new UnauthorizedAccessException("Invalid completion seal scope.");
        if(expires<=time.GetUtcNow())throw new IOException("Completion seal scope expired.");
    }
}

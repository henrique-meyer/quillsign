using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

namespace QuillSign.Storage;

// No delete operation and no public identity fallback. Only verified internal publication/read code creates this.
internal sealed class CompletionFinalCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity=new([],"QuillSign.InternalCompletionFinal");
    private readonly FinalDocument target; private readonly long length; private readonly byte[] sha256;
    private readonly DateTimeOffset? requiredUntil; private readonly byte[]? reference;
    private readonly TimeProvider time; private readonly DateTimeOffset expires;
    internal bool DevelopmentWriteOnce {get;}
    internal bool ExactDeadline {get;}
    internal DateTimeOffset? ExactUntil=>ExactDeadline ? requiredUntil : null;
    private CompletionFinalCapability(FinalDocument target,long length,byte[] sha256,DateTimeOffset? requiredUntil,
        bool development,FinalStoredDocument? reference,TimeProvider time,bool exact=false)
    {
        if(target.EnvelopeId==Guid.Empty || target.ObjectId==Guid.Empty || !Enum.IsDefined(target.Kind) || length is <16 or >64*1024*1024 || sha256 is not {Length:32})
            throw new UnauthorizedAccessException("Invalid final document scope.");
        if(exact && (requiredUntil is not DateTimeOffset until || until.Offset!=TimeSpan.Zero || until.Ticks%TimeSpan.TicksPerSecond!=0 ||
            reference is not null && (reference.Protection==FinalProtection.LegalHold || reference.Protection==FinalProtection.LockedTime && reference.ProtectedUntil!=until)))
            throw new UnauthorizedAccessException("Invalid fixed final-retention scope.");
        this.target=target; this.length=length; this.sha256=sha256.ToArray(); this.requiredUntil=requiredUntil;
        this.reference=reference is null ? null : Digest(reference); DevelopmentWriteOnce=development;
        this.time=time;ExactDeadline=exact; expires=time.GetUtcNow().AddMinutes(2);
        if(exact && reference is null && requiredUntil is DateTimeOffset cutoff && cutoff<expires)expires=cutoff;
        AddIdentity(identity);
    }
    internal static ClaimsPrincipal Write(FinalDocument target,long length,byte[] hash,DateTimeOffset? requiredUntil,bool development,TimeProvider time)
        =>new CompletionFinalCapability(target,length,hash,requiredUntil,development,null,time);
    internal static ClaimsPrincipal Read(FinalStoredDocument reference,TimeProvider time)
        =>new CompletionFinalCapability(reference.Document,reference.Length,reference.Sha256,null,
            reference.Protection==FinalProtection.DevelopmentWriteOnce,reference,time);
    internal static ClaimsPrincipal WriteFixed(FinalDocument target,long length,byte[] hash,DateTimeOffset until,bool development,TimeProvider time)
        =>new CompletionFinalCapability(target,length,hash,until,development,null,time,true);
    internal static ClaimsPrincipal ReadFixed(FinalStoredDocument reference,DateTimeOffset until,TimeProvider time)
        =>new CompletionFinalCapability(reference.Document,reference.Length,reference.Sha256,until,
            reference.Protection==FinalProtection.DevelopmentWriteOnce,reference,time,true);
    internal static CompletionFinalCapability DemandWrite(ClaimsPrincipal principal,FinalDocument target,long length,byte[] hash,DateTimeOffset? until)
    {
        if(principal is not CompletionFinalCapability cap || cap.reference is not null || cap.target!=target || cap.length!=length ||
            !Same(cap.sha256,hash) || cap.requiredUntil!=until)throw new UnauthorizedAccessException("Invalid final document write scope.");
        cap.IdentityScope(); return cap;
    }
    internal static CompletionFinalCapability DemandRead(ClaimsPrincipal principal,FinalStoredDocument stored)
    {
        if(principal is not CompletionFinalCapability cap || cap.reference is null || !Same(cap.reference,Digest(stored)))
            throw new UnauthorizedAccessException("Invalid final document read scope.");
        cap.IdentityScope(); return cap;
    }
    internal void ValidateLifetime()=>IdentityScope();
    private void IdentityScope()
    {
        var identities=Identities.ToArray();
        if(identities.Length!=1 || !ReferenceEquals(identities[0],identity) || !identity.IsAuthenticated)throw new UnauthorizedAccessException("Invalid final document identity.");
        if(expires<=time.GetUtcNow())throw new IOException("Final document scope expired.");
    }
    private static byte[] Digest(FinalStoredDocument value)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value));
    private static bool Same(byte[]? a,byte[]? b)=>a is {Length:32} && b is {Length:32} && CryptographicOperations.FixedTimeEquals(a,b);
}

using System.Security.Claims;

namespace QuillSign.Storage;

public enum FinalDocumentKind { Executed,Certificate }
public enum FinalProtection { LockedTime,LegalHold,DevelopmentWriteOnce }
public readonly record struct FinalDocument(Guid EnvelopeId,FinalDocumentKind Kind,Guid ObjectId);
public sealed record FinalStoredDocument(FinalDocument Document,long Length,byte[] Sha256,string VersionId,string ETag,
    FinalProtection Protection,DateTimeOffset? ProtectedUntil,DateTimeOffset CreatedAt);

public interface ICompletionFinalStore
{
    Task<FinalStoredDocument> WriteAsync(ClaimsPrincipal authority,FinalDocument target,Stream source,long length,byte[] sha256,
        DateTimeOffset? requiredUntil,CancellationToken ct=default);
    Task ReadAsync(ClaimsPrincipal authority,FinalStoredDocument stored,Stream destination,CancellationToken ct=default);
}

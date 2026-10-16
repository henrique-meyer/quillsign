using System.Security.Claims;
using QuillSign.Signing;

namespace QuillSign.Storage;

public enum DocumentBlobKind { Original, Normalized, Preview, Signature, Initials, CompletionCandidate, CompletionExecutedSeal, CompletionCertificateSource, CompletionCertificateSeal }

// References contain no filenames, URLs, or caller-controlled path fragments.
public readonly record struct DocumentBlob(Guid EnvelopeId, DocumentBlobKind Kind, Guid ObjectId);

public interface IBlobStore
{
    Task WriteAsync(ClaimsPrincipal sender, DocumentBlob blob, Stream source, long length,
        CancellationToken cancellationToken = default);
    Task<long> CopyToAsync(ClaimsPrincipal sender, DocumentBlob blob, Stream destination,
        CancellationToken cancellationToken = default);
    Task DeleteAsync(ClaimsPrincipal sender, DocumentBlob blob, CancellationToken cancellationToken = default);
}

public static class EnvelopeStorageAuthorization
{
    // QUILS-15 issues this identity only after verification in a protected sender session.
    // Business rules (draft state, document selection, etc.) belong to the calling workflow.
    public const string SenderScheme = "QuillSign.Sender";
    public const string EnvelopeClaim = "quillsign:envelope";

    public static void DemandRead(ClaimsPrincipal principal,DocumentBlob blob)
    {
        if(principal is CompletionSealCapability seal) {seal.Demand(blob,AssetOperation.Read); return;}
        if(CompletionSealCapability.IsKind(blob.Kind))throw new UnauthorizedAccessException("An internal completion seal capability is required.");
        if(principal is CompletionCandidateCapability candidate) {candidate.Demand(blob,AssetOperation.Read); return;}
        if(blob.Kind==DocumentBlobKind.CompletionCandidate)throw new UnauthorizedAccessException("An internal completion candidate capability is required.");
        if (principal is SignatureAssetCapability capability) { capability.Demand(blob,AssetOperation.Read); return; }
        if (principal is SignerReviewPdfCapability review) { review.Demand(blob,AssetOperation.Read); return; }
        if (principal is SignerCheckpointReadCapability checkpoint) { checkpoint.Demand(blob); return; }
        if (principal is CompletionReadCapability completion) { completion.Demand(blob); return; }
        if (principal.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType == SignerAccessConfiguration.Scheme))
        {
            var signer = SignerAccessConfiguration.ReadIdentity(principal,DateTimeOffset.UtcNow);
            if (signer is not null && blob.Kind == DocumentBlobKind.Normalized && blob.EnvelopeId == signer.EnvelopeId && blob.ObjectId == signer.DocumentId) return;
            throw new UnauthorizedAccessException("A current signer session for this frozen document is required.");
        }
        Demand(principal,blob);
    }

    public static void Demand(ClaimsPrincipal sender, DocumentBlob blob)
        => DemandMutation(sender,blob,AssetOperation.Write);

    public static void DemandDelete(ClaimsPrincipal principal,DocumentBlob blob)
        => DemandMutation(principal,blob,AssetOperation.Delete);

    private static void DemandMutation(ClaimsPrincipal sender,DocumentBlob blob,AssetOperation operation)
    {
        if(sender is CompletionSealCapability seal) {seal.Demand(blob,operation); return;}
        if(CompletionSealCapability.IsKind(blob.Kind))throw new UnauthorizedAccessException("An internal completion seal capability is required.");
        if(sender is CompletionCandidateCapability candidate) {candidate.Demand(blob,operation); return;}
        if(blob.Kind==DocumentBlobKind.CompletionCandidate)throw new UnauthorizedAccessException("An internal completion candidate capability is required.");
        if(sender is CompletionReadCapability or SignerCheckpointReadCapability)
            throw new UnauthorizedAccessException("This internal read capability cannot mutate documents.");
        if (sender is SignatureAssetCapability capability) { capability.Demand(blob,operation); return; }
        if (sender is SignerReviewPdfCapability review) { review.Demand(blob,operation); return; }
        var identities = sender.Identities.Where(i => i.IsAuthenticated).ToArray();
        if (identities.Length != 1 || identities[0].AuthenticationType != SenderScheme)
            throw new UnauthorizedAccessException("A verified sender session for this envelope is required.");
        var claims = identities.SelectMany(i => i.FindAll(EnvelopeClaim)).ToArray();
        if (blob.EnvelopeId == Guid.Empty || claims.Length != 1 ||
            !Guid.TryParse(claims[0].Value, out var authorized) || authorized != blob.EnvelopeId)
            throw new UnauthorizedAccessException("A verified sender session for this envelope is required.");
        if (blob.ObjectId == Guid.Empty || !Enum.IsDefined(blob.Kind))
            throw new ArgumentException("Invalid document reference.", nameof(blob));
    }
}

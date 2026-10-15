using System.Security.Claims;

namespace QuillSign.Storage;

public enum DocumentBlobKind { Original, Normalized, Preview }

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

    public static void Demand(ClaimsPrincipal sender, DocumentBlob blob)
    {
        var identities = sender.Identities.Where(i => i.IsAuthenticated && i.AuthenticationType == SenderScheme);
        var claims = identities.SelectMany(i => i.FindAll(EnvelopeClaim)).ToArray();
        if (blob.EnvelopeId == Guid.Empty || claims.Length != 1 ||
            !Guid.TryParse(claims[0].Value, out var authorized) || authorized != blob.EnvelopeId)
            throw new UnauthorizedAccessException("A verified sender session for this envelope is required.");
        if (blob.ObjectId == Guid.Empty || !Enum.IsDefined(blob.Kind))
            throw new ArgumentException("Invalid document reference.", nameof(blob));
    }
}

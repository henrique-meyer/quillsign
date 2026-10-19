using System.Security.Cryptography;
using System.Text;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed record EmailPilotLookupAdmissionResult(Guid RequestId, bool Recovered, bool WakeupPublished);

internal sealed record EmailPilotLookupRequestBinding(string Version, Guid RunId, Guid RequestId, Guid SubjectEnvelopeId,
    Guid PublicationId, string PublicationRecipeSha256, string RequestSha256, string WorkSha256, string RetentionSha256,
    DateTimeOffset RequestedAt, DateTimeOffset ExpiresAt);
internal sealed record EmailPilotLookupTokenBinding(string Version, Guid Id, Guid RunId, Guid RequestId, int Attempt,
    string TokenSha256, string IssuedRevision, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);

// Server-only typed authority. Null-envelope lookup work never becomes an
// EmailPilotWorkScope or ordinary envelope-send authority.
internal sealed class EmailPilotLookupWorkScope(EmailPilotLookupRequestBinding request, EmailPilotManifest manifest,
    WorkLease lease, DownloadPublication publication, string sourceSha256, DateTimeOffset until)
{
    internal EmailPilotLookupRequestBinding Request { get; } = request;
    internal EmailPilotManifest Manifest { get; } = manifest;
    internal WorkLease Lease { get; } = lease;
    internal DownloadPublication Publication { get; } = publication;
    internal string SourceSha256 { get; } = sourceSha256;
    internal DateTimeOffset Until { get; } = until;
}

internal sealed record EmailPilotLookupTokenScope(bool IsPilot, bool Allowed,
    EmailPilotLookupRequestBinding? Request = null, EmailPilotManifest? Manifest = null);

internal static class EmailPilotLookupRules
{
    internal const string Version = "operator-pilot-lookup-2026-10-19.1";
    internal static Guid RequestId(Guid run) => new(SHA256.HashData(Encoding.ASCII.GetBytes(Version + ":request:" + run.ToString("N"))).AsSpan(0, 16));
    internal static string OriginalRequestSha256(LookupMailPayload request) => Convert.ToHexStringLower(EmailPilotCanonical.Hash(request with { Issued = null }));
    internal static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    internal static bool Revision(string value)
    {
        try { return value is { Length: 12 } && Convert.FromBase64String(value) is { Length: 8 } bytes && Convert.ToBase64String(bytes) == value; }
        catch (FormatException) { return false; }
    }
    internal static EmailPilotLookupRequestBinding Binding(EmailPilotLookupRequestRecord row) => new(Version, row.RunId,
        row.RequestId, row.SubjectEnvelopeId, row.PublicationId, Convert.ToHexStringLower(row.PublicationRecipeSha256),
        Convert.ToHexStringLower(row.RequestSha256), Convert.ToHexStringLower(row.WorkSha256), Convert.ToHexStringLower(row.RetentionSha256), row.RequestedAt, row.ExpiresAt);
    internal static EmailPilotLookupTokenBinding Binding(EmailPilotLookupTokenRecord row) => new(Version, row.Id, row.RunId,
        row.RequestId, row.Attempt, Convert.ToHexStringLower(row.TokenSha256), row.IssuedRevision, row.IssuedAt, row.ExpiresAt);
    internal static bool Shape(EmailPilotLookupRequestBinding value) => value.Version == Version && value.RunId != Guid.Empty &&
        value.RequestId == RequestId(value.RunId) && value.SubjectEnvelopeId != Guid.Empty && value.PublicationId != Guid.Empty &&
        new[] { value.PublicationRecipeSha256, value.RequestSha256, value.WorkSha256, value.RetentionSha256 }.All(EmailPilotCanonical.Hash) &&
        value.RequestedAt.Offset == TimeSpan.Zero && value.ExpiresAt.Offset == TimeSpan.Zero && value.ExpiresAt > value.RequestedAt &&
        value.ExpiresAt <= value.RequestedAt.AddMinutes(60);
    internal static bool Shape(EmailPilotLookupTokenBinding value) => value.Version == Version && value.Id != Guid.Empty && value.RunId != Guid.Empty &&
        value.RequestId == RequestId(value.RunId) && value.Attempt is >= 1 and <= 10 && EmailPilotCanonical.Hash(value.TokenSha256) && Revision(value.IssuedRevision) &&
        value.IssuedAt.Offset == TimeSpan.Zero && value.ExpiresAt.Offset == TimeSpan.Zero && value.ExpiresAt > value.IssuedAt && value.ExpiresAt <= value.IssuedAt.AddMinutes(60);
}

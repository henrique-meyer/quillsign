using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Email;
using QuillSign.Work;

namespace QuillSign.Sender;

internal sealed record SignerContactCorrectionConfirmation(Guid Id, Guid EnvelopeId, string PublicId, string SenderEmail,
    DateTimeOffset TicketExpiresAt, DateTimeOffset PreparedAt, DateTimeOffset ExpiresAt, string Title,
    string StatementVersion, string StatementSha256, SignerContactCorrectionReview Review);

// Carries an exact review in the private POST body. Only the correction service
// can admit the server-generated command; this proof never renews a session.
public sealed class SignerContactCorrectionBrowser(IDataProtectionProvider keys, TimeProvider time)
{
    internal const int MaximumProofLength = 16384;
    private readonly IDataProtector protector = keys.CreateProtector("QuillSign.SenderContactCorrection.Review.v1");
    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 8, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };

    internal string Create(ClaimsPrincipal sender, string publicId, DateTimeOffset until, SignerContactCorrectionPreview preview)
    {
        var identity = SendDraftWorkflow.Identity(sender, publicId) ?? throw new InvalidOperationException("Missing sender scope.");
        var now = time.GetUtcNow().ToUniversalTime(); until = until.ToUniversalTime();
        var expires = new[] { now.AddMinutes(10), until, InvitationResendProtection.DayEnd(now) }.Min();
        if (expires <= now || preview.Blocked is not null || !Text(preview.Title) || !Review(preview.Review))
            throw new InvalidOperationException("Contact correction review is unavailable.");
        var result = protector.Protect(JsonSerializer.Serialize(new SignerContactCorrectionConfirmation(Guid.NewGuid(), identity.Id,
            publicId, identity.Email, until, now, expires, preview.Title, SignerContactCorrectionStatement.Version,
            SignerContactCorrectionStatement.Sha256, preview.Review), Json));
        if (result.Length > MaximumProofLength) throw new InvalidOperationException("Contact correction review is unavailable.");
        return result;
    }

    internal SignerContactCorrectionConfirmation? Read(string? value, ClaimsPrincipal sender, string publicId, DateTimeOffset until)
    {
        var identity = SendDraftWorkflow.Identity(sender, publicId);
        if (identity is null || value is not { Length: > 0 and <= MaximumProofLength }) return null;
        try
        {
            var p = JsonSerializer.Deserialize<SignerContactCorrectionConfirmation>(protector.Unprotect(value), Json);
            var now = time.GetUtcNow();
            if (p is null || p.Id == Guid.Empty || p.EnvelopeId != identity.Value.Id || p.PublicId != publicId ||
                p.SenderEmail != identity.Value.Email || p.TicketExpiresAt != until.ToUniversalTime() || p.TicketExpiresAt.Offset != TimeSpan.Zero ||
                p.PreparedAt.Offset != TimeSpan.Zero || p.ExpiresAt.Offset != TimeSpan.Zero || p.PreparedAt > now ||
                p.ExpiresAt <= now || p.ExpiresAt <= p.PreparedAt || p.ExpiresAt > p.PreparedAt.AddMinutes(10) ||
                p.ExpiresAt > p.TicketExpiresAt || p.ExpiresAt > InvitationResendProtection.DayEnd(p.PreparedAt) || !Text(p.Title) ||
                p.StatementVersion != SignerContactCorrectionStatement.Version || p.StatementSha256 != SignerContactCorrectionStatement.Sha256 ||
                !Review(p.Review)) return null;
            return p;
        }
        catch (Exception e) when (e is CryptographicException or JsonException or ArgumentException or FormatException) { return null; }
    }

    private static bool Review(SignerContactCorrectionReview? r) => r is not null && r.SignerId != Guid.Empty && r.DocumentId != Guid.Empty &&
        Text(r.Name) && Address(r.OldEmail) && Address(r.NewEmail) && r.OldEmail != r.NewEmail &&
        InvitationResendProtection.RowVersion(r.Version) && InvitationResendProtection.RowVersion(r.SignerVersion) &&
        InvitationResendProtection.Hash(r.DocumentSha256) && InvitationResendProtection.Hash(r.DisclosureSha256) &&
        (r.ContactRevisionNumber == 0 ? r.ContactRevisionId == Guid.Empty : r.ContactRevisionNumber is > 0 and <= 100 && r.ContactRevisionId != Guid.Empty);
    private static bool Text(string? value) => value is { Length: > 0 and <= 512 } && !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    private static bool Address(string? value)
    {
        if (value is not { Length: > 0 and <= 254 }) return false;
        try { return EmailAddress.Normalize(value) == value; } catch (ArgumentException) { return false; }
    }
}

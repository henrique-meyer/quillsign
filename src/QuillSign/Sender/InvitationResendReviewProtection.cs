using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Work;

namespace QuillSign.Sender;

internal sealed record InvitationResendConfirmation(Guid Id, Guid EnvelopeId, string PublicId, string SenderEmail,
    DateTimeOffset TicketExpiresAt, DateTimeOffset PreparedAt, DateTimeOffset ExpiresAt, string Title, InvitationResendReview Review);

// Browser proof only: no invitation token or caller-supplied command authority.
public sealed class InvitationResendReviewProtection(IDataProtectionProvider keys, TimeProvider time)
{
    private readonly IDataProtector protector = keys.CreateProtector("QuillSign.SenderInvitationResend.Review.v1");
    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 8 };
    internal string Create(ClaimsPrincipal sender, string publicId, DateTimeOffset until, InvitationResendPreview preview)
    {
        var identity = SendDraftWorkflow.Identity(sender, publicId) ?? throw new InvalidOperationException("Missing sender scope.");
        var now = time.GetUtcNow(); until = until.ToUniversalTime();
        var expires = new[] { now.AddMinutes(10), until, InvitationResendProtection.DayEnd(now) }.Min();
        if (expires <= now || preview.Blocked is not null) throw new InvalidOperationException("Resend review is unavailable.");
        return protector.Protect(JsonSerializer.Serialize(new InvitationResendConfirmation(Guid.NewGuid(), identity.Id, publicId, identity.Email,
            until, now, expires, preview.Title, preview.Review), Json));
    }
    internal InvitationResendConfirmation? Read(string? value, ClaimsPrincipal sender, string publicId, DateTimeOffset until)
    {
        var identity = SendDraftWorkflow.Identity(sender, publicId);
        if (identity is null || value is not { Length: > 0 and <= 8192 }) return null;
        try {
            var p = JsonSerializer.Deserialize<InvitationResendConfirmation>(protector.Unprotect(value), Json);
            var now = time.GetUtcNow();
            if (p is null || p.Id == Guid.Empty || p.EnvelopeId != identity.Value.Id || p.PublicId != publicId || p.SenderEmail != identity.Value.Email ||
                p.TicketExpiresAt != until.ToUniversalTime() || p.PreparedAt.Offset != TimeSpan.Zero || p.ExpiresAt.Offset != TimeSpan.Zero ||
                p.PreparedAt > now || p.ExpiresAt <= now || p.ExpiresAt <= p.PreparedAt || p.ExpiresAt > p.PreparedAt.AddMinutes(10) ||
                p.ExpiresAt > p.TicketExpiresAt || p.ExpiresAt > InvitationResendProtection.DayEnd(p.PreparedAt) ||
                p.Title is not { Length: > 0 and <= 512 } || p.Review is not { } r || r.SignerId == Guid.Empty || r.DocumentId == Guid.Empty ||
                r.Name is not { Length: > 0 and <= 512 } || r.Email is not { Length: > 0 and <= 254 } ||
                !InvitationResendProtection.RowVersion(r.Version) || !InvitationResendProtection.Hash(r.DocumentSha256) || !InvitationResendProtection.Hash(r.DisclosureSha256)) return null;
            return p;
        } catch (Exception e) when (e is CryptographicException or JsonException or ArgumentException or FormatException) { return null; }
    }
}

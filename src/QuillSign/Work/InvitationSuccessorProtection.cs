using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Signing;

namespace QuillSign.Work;

public enum InvitationSuccessorReason { ManualResend, Reminder, ContactCorrection }
public sealed record InvitationSuccessorScope(string Version, Guid Id, Guid EnvelopeId, Guid SignerId,
    Guid PreviousId, SignerContactEpoch Contact, InvitationSuccessorReason Reason, string Recipient,
    string SenderEmail, Guid DocumentId, string DocumentSha256, string DisclosureSha256,
    string AuthorizationSha256, DateTimeOffset AdmittedAt, DateTimeOffset Deadline);
public sealed record InvitationSuccessorToken(Guid Id, string Sha256, DateTimeOffset ExpiresAt);
public sealed record InvitationSuccessorMail(InvitationSuccessorScope Scope, InvitationSuccessorToken? Issued = null);

// Integrity format for future supported producers. Reading or protecting a
// payload grants no authority to correct contacts, submit mail or replace links.
// Producers must verify the exact reason's deliberate/system admission evidence
// and the full current contact/invitation chain under the envelope lock.
public sealed class InvitationSuccessorProtection(IDataProtectionProvider provider)
{
    public const string Version = "invitation-successor-v1";
    public const string Template = "signer-invitation-successor";
    public const string Event = "invitation_successor_admitted";
    private const int MaximumJsonLength = 12000;
    private readonly IDataProtector protector = provider.CreateProtector("QuillSign.InvitationSuccessor.Payload.v1");
    private static readonly JsonSerializerOptions Json = new() {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, MaxDepth = 5,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static string Canonical(InvitationSuccessorScope scope)
    {
        Validate(scope);
        return JsonSerializer.Serialize(scope, Json);
    }
    public static string Digest(InvitationSuccessorScope scope) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(scope))));
    public string Protect(InvitationSuccessorMail mail)
    {
        ValidateMail(mail);
        return JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(JsonSerializer.Serialize(mail, Json))));
    }
    public InvitationSuccessorMail Read(EmailOutbox row)
    {
        if (row is null || row.Template != Template || row.AttachmentsJson != "[]" || row.PayloadJson is not { Length: > 0 and <= MaximumJsonLength } ||
            !Enum.IsDefined(row.Status) || row.Attempts < 0 || row.AvailableAt.Offset != TimeSpan.Zero) throw Invalid();
        InvitationSuccessorMail mail;
        try {
            mail = JsonSerializer.Deserialize<InvitationSuccessorMail>(protector.Unprotect(
                JsonSerializer.Deserialize<ProtectedWorkPayload>(row.PayloadJson)?.Protected ?? throw Invalid()), Json) ?? throw Invalid();
        }
        catch (JsonException) { throw Invalid(); }
        ValidateMail(mail); var p = mail.Scope;
        if (p.Id != row.Id || p.EnvelopeId != row.EnvelopeId || p.Recipient != row.To || p.AdmittedAt != row.AvailableAt ||
            (row.SubmissionStartedAt is null) != (mail.Issued is null) || row.SubmissionStartedAt < p.AdmittedAt || row.SubmissionStartedAt >= p.Deadline ||
            row.SubmissionStartedAt is { } intent && (intent.Offset != TimeSpan.Zero || row.Attempts < 1 || intent >= mail.Issued!.ExpiresAt))
            throw Invalid();
        return mail;
    }

    public static InvitationSuccessorScope ReadEvidence(AuditEvent row)
    {
        if (row is null || row.Event != Event || row.ActorId is not null || row.Sequence < 1 || row.At.Offset != TimeSpan.Zero ||
            row.DataJson is not { Length: > 0 and <= MaximumJsonLength } || row.Hash is not { Length: 32 } ||
            row.PrevHash is not null and not { Length: 32 } || !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(row), row.Hash)) throw Invalid();
        InvitationSuccessorScope scope;
        try { scope = JsonSerializer.Deserialize<InvitationSuccessorScope>(row.DataJson, Json) ?? throw Invalid(); }
        catch (JsonException) { throw Invalid(); }
        Validate(scope);
        var system = scope.Reason == InvitationSuccessorReason.Reminder;
        if (row.DataJson != Canonical(scope) || row.EnvelopeId != scope.EnvelopeId || row.At < scope.AdmittedAt || row.At >= scope.Deadline ||
            row.ActorType != (system ? PartyType.System : PartyType.Sender) || row.ActorEmail != (system ? null : scope.SenderEmail)) throw Invalid();
        return scope;
    }

    private static void ValidateMail(InvitationSuccessorMail? mail)
    {
        if (mail is null) throw Invalid(); Validate(mail.Scope);
        if (mail.Issued is { } token && (token.Id == Guid.Empty || !Hash(token.Sha256) || token.ExpiresAt.Offset != TimeSpan.Zero ||
            token.ExpiresAt <= mail.Scope.AdmittedAt || token.ExpiresAt > mail.Scope.AdmittedAt.AddDays(7))) throw Invalid();
    }
    private static void Validate(InvitationSuccessorScope? p)
    {
        if (p is null || p.Version != Version || p.Id == Guid.Empty || p.EnvelopeId == Guid.Empty || p.SignerId == Guid.Empty ||
            p.PreviousId == Guid.Empty || p.Id == p.PreviousId || p.DocumentId == Guid.Empty || !Enum.IsDefined(p.Reason) ||
            p.Contact is null || p.Contact.Number is < 0 or > SignerContactHistory.MaximumCorrections ||
            (p.Contact.Number == 0) != (p.Contact.RevisionId == Guid.Empty) ||
            p.Reason == InvitationSuccessorReason.ContactCorrection && p.Contact.Number == 0 ||
            !Address(p.Recipient) || !Address(p.SenderEmail) || !Hash(p.DocumentSha256) || !Hash(p.DisclosureSha256) || !Hash(p.AuthorizationSha256) ||
            p.AdmittedAt.Offset != TimeSpan.Zero || p.Deadline.Offset != TimeSpan.Zero || p.Deadline <= p.AdmittedAt ||
            p.AdmittedAt > DateTimeOffset.MaxValue.AddDays(-7) || p.Deadline > DayEnd(p.AdmittedAt)) throw Invalid();
    }
    private static DateTimeOffset DayEnd(DateTimeOffset at) => new DateTimeOffset(at.UtcDateTime.Date, TimeSpan.Zero).AddDays(1);
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Address(string value) { try { return EmailAddress.Normalize(value) == value; } catch (ArgumentException) { return false; } }
    public static InvalidDataException Invalid() => new("The saved invitation successor could not be verified.");
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public sealed class EmailPilotOptions
{
    public bool Enabled { get; set; }
    public string RunId { get; set; } = "";
    public EmailPilotMailboxes Mailboxes { get; set; } = new("", "", "", "");
    public EmailPilotBudget Allowance { get; set; } = EmailPilotLimits.Maximum;
    public void Validate()
    {
        if (!Enabled) return;
        if (!Guid.TryParseExact(RunId, "N", out var id) || id == Guid.Empty || Mailboxes is null || !Mailboxes.Valid() || !EmailPilotLimits.Valid(Allowance))
            throw new InvalidOperationException("Configure one explicit pilot run and four distinct normalized mailbox roles.");
    }
}

public sealed record EmailPilotMailboxes(string Sender, string FirstSigner, string SecondSigner, string Recipient)
{
    public string? Address(EmailPilotRole role) => role switch {
        EmailPilotRole.Sender => Sender, EmailPilotRole.FirstSigner => FirstSigner,
        EmailPilotRole.SecondSigner => SecondSigner, EmailPilotRole.Recipient => Recipient, _ => null
    };
    public bool Valid()
    {
        var values = new[] { Sender, FirstSigner, SecondSigner, Recipient };
        try { return values.Distinct(StringComparer.Ordinal).Count() == 4 && values.All(x => x is { Length: > 0 and <= 254 } && EmailAddress.Normalize(x) == x); }
        catch (ArgumentException) { return false; }
    }
}

public static class EmailPilotLimits
{
    public const int ApplicationAttempts = 20, SimulatorAttempts = 10, TimestampAttempts = 4;
    public const int MessageBytes = 1024 * 1024, AggregateBytes = 30 * MessageBytes;
    public const string Version = "operator-pilot-2026-10-18.1";
    // Configuration binding may populate init-only record properties through reflection.
    // Give every options/legacy profile its own value, never a shared mutable default.
    public static EmailPilotBudget Maximum => new(ApplicationAttempts,SimulatorAttempts,TimestampAttempts,AggregateBytes);
    internal static bool Valid(EmailPilotBudget? value) => value is not null &&
        value.ApplicationAttempts is >=0 and <=ApplicationAttempts && value.SimulatorAttempts is >=0 and <=SimulatorAttempts &&
        value.TimestampAttempts is >=0 and <=TimestampAttempts && value.EncodedBytes is >=0 and <=AggregateBytes;
}

public sealed record EmailPilotManifest(string Version, Guid RunId, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt,
    string CapabilitySha256, EmailPilotMailboxes Mailboxes)
{
    // Omitting null preserves the exact canonical bytes/hashes of legacy manifests.
    // A legacy manifest has the original hard allowance, never a new lower profile.
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public EmailPilotBudget? Allowance { get; init; }
    internal EmailPilotBudget EffectiveAllowance => Allowance ?? EmailPilotLimits.Maximum;
}
public sealed record EmailPilotEnrollment(Guid RunId, Guid SubjectEnvelopeId, EmailPilotScenario Scenario, DateTimeOffset EnrolledAt,
    EmailPilotVerificationBinding? Verification = null);
public sealed record EmailPilotVerificationBinding(Guid WorkId, string DraftSha256, string EmailPayloadSha256, string WorkPayloadSha256);
public sealed record EmailPilotAttempt(Guid Id, Guid RunId, Guid? SubjectEnvelopeId, Guid OperationId,
    EmailPilotAttemptKind Kind, EmailPilotRole Role, int EncodedBytes, string RequestSha256, DateTimeOffset ReservedAt);
public sealed record EmailPilotReservation(Guid Id, Guid? SubjectEnvelopeId, Guid OperationId,
    EmailPilotAttemptKind Kind, EmailPilotRole Role, int EncodedBytes, string RequestSha256);
public enum EmailPilotReservationOutcome { Reserved, AlreadyConsumed, Refused }
public sealed record EmailPilotBudget(int ApplicationAttempts, int SimulatorAttempts, int TimestampAttempts, long EncodedBytes);

internal static class EmailPilotCanonical
{
    internal static byte[] Hash<T>(T value) => SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value));
    internal static byte[] Capability(string value)
    {
        if (value is not { Length: 43 } || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new ArgumentException("A random bounded pilot capability is required.");
        return SHA256.HashData(Encoding.ASCII.GetBytes(value));
    }
    internal static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

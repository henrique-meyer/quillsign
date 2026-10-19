namespace QuillSign.Data;

// Operational tombstones contain random identifiers and authenticated digests.
// The separately expiring secret row holds the encrypted mailbox manifest.
public sealed class EmailPilotRunRecord
{
    public Guid Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public byte[] ManifestSha256 { get; set; } = [];
    public byte[] CapabilitySha256 { get; set; } = [];
}

public sealed class EmailPilotSecretRecord
{
    public Guid RunId { get; set; }
    public string ProtectedManifest { get; set; } = "";
    public DateTimeOffset DeleteAfter { get; set; }
}

public enum EmailPilotScenario { Completion = 1, Void = 2, Decline = 3 }
public enum EmailPilotAttemptKind { Application, Simulator, Timestamp }
public enum EmailPilotRole { None, Sender, FirstSigner, SecondSigner, Recipient, Simulator }

public sealed class EmailPilotEnrollmentRecord
{
    public Guid SubjectEnvelopeId { get; set; }
    public Guid RunId { get; set; }
    public EmailPilotScenario Scenario { get; set; }
    public DateTimeOffset EnrolledAt { get; set; }
    public string ProtectedBinding { get; set; } = "";
}

public sealed class EmailPilotReservationRecord
{
    public Guid Id { get; set; }
    public Guid RunId { get; set; }
    public Guid? SubjectEnvelopeId { get; set; }
    public Guid OperationId { get; set; }
    public EmailPilotAttemptKind Kind { get; set; }
    public EmailPilotRole Role { get; set; }
    public int EncodedBytes { get; set; }
    public byte[] RequestSha256 { get; set; } = [];
    public DateTimeOffset ReservedAt { get; set; }
    public string ProtectedReceipt { get; set; } = "";
}

namespace QuillSign.Data;

// Nonpersonal operational tombstones. Mailbox/contact data stays in the existing
// expiring run manifest and normal protected lookup outbox only.
public sealed class EmailPilotLookupRequestRecord
{
    public Guid RunId { get; set; }
    public Guid RequestId { get; set; }
    public Guid SubjectEnvelopeId { get; set; }
    public Guid PublicationId { get; set; }
    public byte[] PublicationRecipeSha256 { get; set; } = [];
    public byte[] RequestSha256 { get; set; } = [];
    public byte[] WorkSha256 { get; set; } = [];
    public byte[] RetentionSha256 { get; set; } = [];
    public DateTimeOffset RequestedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public string ProtectedBinding { get; set; } = "";
}

public sealed class EmailPilotLookupTokenRecord
{
    public Guid Id { get; set; }
    public Guid RunId { get; set; }
    public Guid RequestId { get; set; }
    public int Attempt { get; set; }
    public byte[] TokenSha256 { get; set; } = [];
    public string IssuedRevision { get; set; } = "";
    public DateTimeOffset IssuedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public string ProtectedBinding { get; set; } = "";
}

namespace QuillSign.Data;

// Append-only evidence. No navigation property is added to Signer or Envelope:
// their historical serialized completion/Finish bindings must remain unchanged.
public sealed class SignerContactRevisionRecord
{
    public Guid Id { get; set; }
    public Guid EnvelopeId { get; set; }
    public Guid SignerId { get; set; }
    public int Number { get; set; }
    public Guid? PreviousRevisionId { get; set; }
    public DateTimeOffset ChangedAt { get; set; }
    public string EvidenceJson { get; set; } = "";
    public string RetirementJson { get; set; } = "";
}

public sealed class SignerContactSession
{
    public Guid SessionId { get; set; }
    public Guid EnvelopeId { get; set; }
    public Guid SignerId { get; set; }
    public Guid RevisionId { get; set; }
    public byte[] SessionSha256 { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

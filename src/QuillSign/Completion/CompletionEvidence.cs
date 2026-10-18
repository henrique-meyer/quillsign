namespace QuillSign.Completion;

// Internal rendering inputs, never public request DTOs. The completion workflow must derive
// these from verified persisted evidence. The renderer takes private copies before use.
public sealed record CompletionDocument(Guid Id,string Name,int Pages,byte[] OriginalSha256,byte[] ConvertedSha256,
    byte[] SentSha256,byte[] CurrentSha256);
public sealed record CompletionSender(string? Name,string Email,DateTimeOffset VerifiedAt);
public sealed record CompletionMark(byte[] Png,byte[] Sha256,string NormalizationVersion);
public sealed record CompletionSigner(Guid Id,int Order,string Name,string Email,string? Role,
    DateTimeOffset EmailVerifiedAt,DateTimeOffset ViewedAt,DateTimeOffset ConsentedAt,DateTimeOffset FinishedAt,DateTimeOffset CheckpointAt,
    string DisclosureVersion,byte[] DisclosureSha256,byte[] CheckpointSha256,string? Ip,string? UserAgent,
    Guid? AdoptionId,CompletionMark? Signature,CompletionMark? Initials);
public sealed record CompletionRecipient(string? Name,string Email);
public sealed record CompletionEvent(long Sequence,DateTimeOffset At,string Event,string ActorType,string? Actor,
    string? Ip,string? UserAgent,byte[] PreviousHash,byte[] Hash)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public CompletionContactCorrection? ContactCorrection {get;init;}
}
public sealed record CompletionContactCorrection(Guid SignerId,string Name,string OldEmail,string NewEmail,Guid RevisionId,int Number,string RetirementSha256);
public sealed record CompletionEvidence(Guid EnvelopeId,DateTimeOffset PreparedAt,bool Demo,bool Synthetic,
    CompletionDocument Document,CompletionSender Sender,string DisclosureVersion,byte[] DisclosureSha256,
    IReadOnlyList<CompletionSigner> Signers,IReadOnlyList<CompletionRecipient> Recipients,
    IReadOnlyList<CompletionEvent> Events,byte[] AuditAnchor);
public sealed record PreparedCompletionPacket(byte[] Bytes,byte[] Sha256,byte[] SourceSha256,byte[] EvidenceSha256,
    byte[] AppendixBytes,int DocumentPages,int CertificatePages,string RendererVersion);
public sealed record RenderedCompletionCertificate(byte[] Bytes,byte[] Sha256,byte[] EvidenceSha256,byte[] ExecutedSha256,
    int Pages,string RendererVersion);

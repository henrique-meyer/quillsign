namespace QuillSign.Data;

public enum EnvelopeStatus { Draft, Sent, Completed, Declined, Voided, Expired }
public enum SignerStatus { Pending, Notified, Viewed, Signed, Declined }
public enum SignatureMethod { Typed, Drawn, Uploaded }
public enum FieldType { Signature, Initials, FullName, DateSigned, Text, Checkbox, Date }
public enum FieldSource { Manual, Ai, AcroForm }
public enum PartyType { Sender, Signer, Recipient, System }
public enum TokenPurpose { SenderVerify, SenderStatus, SignerAccess, Lookup }
public enum EmailStatus { Queued, Sent, Failed, Bounced, Complained }
public enum WorkStatus { Queued, Leased, Completed, Failed }
public enum WorkKind { Conversion, Ai, Rendering, Sealing, Email, Purge }
public enum SuppressionReason { Bounce, Complaint, Unsubscribe, BlockedSender }

public interface IVersionedRecord { byte[] RowVersion { get; set; } }

public sealed class Envelope : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string PublicId { get; set; } = Guid.NewGuid().ToString("N");
    public EnvelopeStatus Status { get; set; }
    public string SenderEmail { get; set; } = "";
    public string? SenderName { get; set; }
    public DateTimeOffset? SenderVerifiedAt { get; set; }
    public string? Title { get; set; }
    public string? Message { get; set; }
    public string ReminderDaysJson { get; set; } = "[3,7]";
    public DateTimeOffset? ExpiresAt { get; set; }
    public string? ErsdVersion { get; set; }
    public string? ErsdText { get; set; }
    public byte[]? ErsdSha256 { get; set; }
    public DateTimeOffset? ExclusionsAckAt { get; set; }
    public string? OriginalBlob { get; set; }
    public byte[]? OriginalSha256 { get; set; }
    public string? OriginalMime { get; set; }
    public string? PdfBlob { get; set; }
    public byte[]? PdfSha256 { get; set; }
    public int? PageCount { get; set; }
    public string? PageSizesJson { get; set; }
    public DateTimeOffset? PreviewConfirmedAt { get; set; }
    public string? SentPdfBlob { get; set; }
    public byte[]? SentPdfSha256 { get; set; }
    public string? FinalBlob { get; set; }
    public byte[]? FinalSha256 { get; set; }
    public string? CertificateBlob { get; set; }
    public byte[]? CertificateSha256 { get; set; }
    public string? SealCertThumbprint { get; set; }
    public string? SealProvider { get; set; }
    public string? TsaUrl { get; set; }
    public string? AiRolesJson { get; set; }
    public string? AiModel { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? SentAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset? PurgeAfter { get; set; }
    public bool IsDemo { get; set; }
    public byte[] RowVersion { get; set; } = [];
}

public sealed class Signer : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EnvelopeId { get; set; }
    public int Order { get; set; } = 1;
    public string FullName { get; set; } = "";
    public string Email { get; set; } = "";
    public string? Role { get; set; }
    public string? Color { get; set; }
    public SignerStatus Status { get; set; }
    public DateTimeOffset? ConsentAt { get; set; }
    public string? ConsentIp { get; set; }
    public string? ConsentUa { get; set; }
    public DateTimeOffset? SignedAt { get; set; }
    public string? SignedIp { get; set; }
    public string? SignedUa { get; set; }
    public string? DeclineReason { get; set; }
    public string? SignatureImageBlob { get; set; }
    public string? InitialsImageBlob { get; set; }
    public SignatureMethod? SignatureMethod { get; set; }
    public Guid? SignatureAdoptionId { get; set; }
    public byte[]? SignatureImageSha256 { get; set; }
    public byte[]? InitialsImageSha256 { get; set; }
    public DateTimeOffset? SignatureAdoptedAt { get; set; }
    public string? SignatureTypedName { get; set; }
    public string? SignatureTypedInitials { get; set; }
    public string? SignatureNormalizationVersion { get; set; }
    public string? SignatureAdoptionVersion { get; set; }
    public byte[] RowVersion { get; set; } = [];
}

public sealed class SignaturePreview
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EnvelopeId { get; set; }
    public Guid SignerId { get; set; }
    public Guid DocumentId { get; set; }
    public Guid SignatureObjectId { get; set; }
    public Guid InitialsObjectId { get; set; }
    public byte[] SignatureSha256 { get; set; } = [];
    public byte[] InitialsSha256 { get; set; } = [];
    public byte[] DocumentSha256 { get; set; } = [];
    public byte[] DisclosureSha256 { get; set; } = [];
    public byte[] SessionSha256 { get; set; } = [];
    public byte[] BaselineSignerVersion { get; set; } = [];
    public int SignatureWidth { get; set; }
    public int SignatureHeight { get; set; }
    public int InitialsWidth { get; set; }
    public int InitialsHeight { get; set; }
    public SignatureMethod Method { get; set; }
    public string? TypedName { get; set; }
    public string? TypedInitials { get; set; }
    public string NormalizationVersion { get; set; } = "";
    public string AdoptionVersion { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

public sealed class SignerReviewCandidate : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EnvelopeId { get; set; }
    public Guid SignerId { get; set; }
    public Guid AdoptionId { get; set; }
    public Guid SourceObjectId { get; set; }
    public Guid PdfObjectId { get; set; }
    public long PdfLength { get; set; }
    public byte[] SourceSha256 { get; set; } = [];
    public byte[] DisclosureSha256 { get; set; } = [];
    public byte[] SessionSha256 { get; set; } = [];
    public byte[] SnapshotSha256 { get; set; } = [];
    public byte[] PdfSha256 { get; set; } = [];
    public byte[] RecipeSha256 { get; set; } = [];
    public string RendererVersion { get; set; } = "";
    public string SnapshotVersion { get; set; } = "";
    public DateOnly ProspectiveDate { get; set; }
    public DateTimeOffset PreparedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public DateTimeOffset? SupersededAt { get; set; }
    public byte[] RowVersion { get; set; } = [];
}

public sealed class SignerFinishAcceptance : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EnvelopeId { get; set; }
    public Guid SignerId { get; set; }
    public Guid ReviewCandidateId { get; set; }
    public Guid AdoptionId { get; set; }
    public Guid SourceObjectId { get; set; }
    public Guid PdfObjectId { get; set; }
    public long PdfLength { get; set; }
    public byte[] SourceSha256 { get; set; } = [];
    public byte[] DisclosureSha256 { get; set; } = [];
    public byte[] SessionSha256 { get; set; } = [];
    public byte[] SnapshotSha256 { get; set; } = [];
    public byte[] PdfSha256 { get; set; } = [];
    public byte[] RecipeSha256 { get; set; } = [];
    public byte[] FieldsSha256 { get; set; } = [];
    public byte[] StatementSha256 { get; set; } = [];
    public string FieldsJson { get; set; } = "";
    public string SnapshotVersion { get; set; } = "";
    public string StatementVersion { get; set; } = "";
    public string Statement { get; set; } = "";
    public DateOnly ProspectiveDate { get; set; }
    public DateTimeOffset ReviewPreparedAt { get; set; }
    public DateTimeOffset ReviewExpiresAt { get; set; }
    public DateTimeOffset FinishedAt { get; set; }
    public string? Ip { get; set; }
    public string? UserAgent { get; set; }
    public DateTimeOffset? ProcessedAt { get; set; }
    public byte[] RowVersion { get; set; } = [];
}

public sealed class Recipient : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EnvelopeId { get; set; }
    public string Name { get; set; } = "";
    public string Email { get; set; } = "";
    public byte[] RowVersion { get; set; } = [];
}

public sealed class DocumentField : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid EnvelopeId { get; set; }
    public Guid? SignerId { get; set; }
    public FieldType Type { get; set; }
    public int Page { get; set; } = 1;
    public decimal X { get; set; }
    public decimal Y { get; set; }
    public decimal Width { get; set; }
    public decimal Height { get; set; }
    public bool Required { get; set; }
    public string? Label { get; set; }
    public string? Placeholder { get; set; }
    public string? DateFormat { get; set; }
    public FieldSource Source { get; set; }
    public decimal? AiConfidence { get; set; }
    public string? Value { get; set; }
    public DateTimeOffset? FilledAt { get; set; }
    public PartyType? FilledBy { get; set; }
    public Guid? SignatureAdoptionId { get; set; }
    public byte[]? ImageSha256 { get; set; }
    public byte[] RowVersion { get; set; } = [];
}

public sealed class AuthToken : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public byte[] TokenSha256 { get; set; } = [];
    public TokenPurpose Purpose { get; set; }
    public Guid? EnvelopeId { get; set; }
    public PartyType PartyType { get; set; }
    public Guid? PartyId { get; set; }
    public string Email { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public string? Ip { get; set; }
    public byte[] RowVersion { get; set; } = [];
}

public sealed class AuditEvent
{
    public long Id { get; set; }
    public Guid EnvelopeId { get; set; }
    public long Sequence { get; set; }
    public DateTimeOffset At { get; set; }
    public PartyType ActorType { get; set; }
    public Guid? ActorId { get; set; }
    public string? ActorEmail { get; set; }
    public string Event { get; set; } = "";
    public string? Ip { get; set; }
    public string? UserAgent { get; set; }
    public string DataJson { get; set; } = "{}";
    public byte[]? PrevHash { get; set; }
    public byte[] Hash { get; set; } = [];
}

public sealed class EmailOutbox : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? EnvelopeId { get; set; }
    public string To { get; set; } = "";
    public string Template { get; set; } = "";
    // Dispatch code must protect sensitive payloads; auth-token records contain hashes only.
    public string PayloadJson { get; set; } = "{}";
    public string AttachmentsJson { get; set; } = "[]";
    public EmailStatus Status { get; set; }
    public string? Provider { get; set; }
    public string? ProviderMessageId { get; set; }
    public DateTimeOffset? SubmissionStartedAt { get; set; }
    public int Attempts { get; set; }
    public string? LastError { get; set; }
    public DateTimeOffset AvailableAt { get; set; } = DateTimeOffset.UtcNow;
    public Guid? LeaseOwner { get; set; }
    public DateTimeOffset? LeaseExpiresAt { get; set; }
    public byte[] RowVersion { get; set; } = [];
}

public sealed class WorkItem : IVersionedRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? EnvelopeId { get; set; }
    public WorkKind Kind { get; set; }
    public WorkStatus Status { get; set; }
    public string PayloadJson { get; set; } = "{}";
    public int Attempts { get; set; }
    public string? LastError { get; set; }
    public DateTimeOffset AvailableAt { get; set; } = DateTimeOffset.UtcNow;
    public Guid? LeaseOwner { get; set; }
    public DateTimeOffset? LeaseExpiresAt { get; set; }
    public byte[] RowVersion { get; set; } = [];
}

public sealed class Suppression : IVersionedRecord
{
    public string Email { get; set; } = "";
    public SuppressionReason Reason { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public byte[] RowVersion { get; set; } = [];
}

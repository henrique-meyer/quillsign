namespace QuillSign.Data;

// Insert-only records. The intent owns stable targets before any retained file is written.
public sealed class CompletionPublicationIntent : IVersionedRecord
{
    public Guid Id {get;set;}=Guid.NewGuid();
    public Guid EnvelopeId {get;set;}
    public Guid CandidateId {get;set;}
    public Guid ExecutedOutputId {get;set;}
    public Guid CertificateOutputId {get;set;}
    public Guid ExecutedObjectId {get;set;}=Guid.NewGuid();
    public Guid CertificateObjectId {get;set;}=Guid.NewGuid();
    public string BeforeEnvelopeJson {get;set;}="";
    public string StageBindingsJson {get;set;}="";
    public int RetentionDays {get;set;}
    public bool DevelopmentWriteOnce {get;set;}
    public DateTimeOffset PreparedAt {get;set;}
    public byte[] RecipeSha256 {get;set;}=[];
    public byte[] RowVersion {get;set;}=[];
}

public sealed class CompletionPublicationResult : IVersionedRecord
{
    public Guid Id {get;set;}=Guid.NewGuid();
    public Guid EnvelopeId {get;set;}
    public Guid IntentId {get;set;}
    public string FinalDocumentsJson {get;set;}="";
    public DateTimeOffset CompletedAt {get;set;}
    public byte[] AfterEnvelopeSha256 {get;set;}=[];
    public byte[] IntentRecipeSha256 {get;set;}=[];
    public byte[] RecipeSha256 {get;set;}=[];
    public long AuditSequence {get;set;}
    public byte[] RowVersion {get;set;}=[];
}

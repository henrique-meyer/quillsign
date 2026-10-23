namespace QuillSign.Data;

public sealed class EmailPilotCloseoutHeaderRecord
{
    public Guid Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset Until { get; set; }
    public DateTimeOffset DeleteAfter { get; set; }
    public byte[] CapabilitySha256 { get; set; } = [];
    public byte[] ManifestSha256 { get; set; } = [];
    public string? ProtectedManifest { get; set; }
}

public sealed class EmailPilotCloseoutOperationRecord
{
    public Guid Id { get; set; }
    public Guid CloseoutId { get; set; }
    public int Kind { get; set; }
    public int Step { get; set; }
    public Guid SubjectEnvelopeId { get; set; }
    public Guid WorkId { get; set; }
    public DateTimeOffset At { get; set; }
    public int EncodedBytes { get; set; }
    public byte[] RequestSha256 { get; set; } = [];
    public string ProtectedReceipt { get; set; } = "";
}

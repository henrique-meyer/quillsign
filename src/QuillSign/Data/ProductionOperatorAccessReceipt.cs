namespace QuillSign.Data;

// Private read-observability only; it never authorizes a lifecycle operation.
public sealed class ProductionOperatorAccessReceipt
{
    public Guid Id { get; set; }
    public DateTimeOffset At { get; set; }
    public byte[] PayloadSha256 { get; set; }=[];
    public string ProtectedReceipt { get; set; }="";
}

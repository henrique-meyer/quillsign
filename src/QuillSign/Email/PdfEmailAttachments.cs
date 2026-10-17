using System.Text;

namespace QuillSign.Email;

public sealed class EmailAttachmentLimitException() : ArgumentException("Email attachments or encoded message exceed the configured transport limit.");

public sealed class EmailAttachmentOptions
{
    public const long HardDecodedBytes=25L*1024*1024,HardMessageBytes=32L*1024*1024;
    public long MaximumDecodedBytes {get;set;}=20L*1024*1024;
    public long MaximumMessageBytes {get;set;}=HardMessageBytes;
    internal void Validate() {
        if(MaximumDecodedBytes is <1 or >HardDecodedBytes || MaximumMessageBytes is <1 or >HardMessageBytes)
            throw new InvalidOperationException("Configure bounded email attachment and encoded message sizes.");
    }
}

// Own the bytes once. Every reader is non-writable and cannot expose the backing buffer.
public sealed class PdfEmailAttachment
{
    public const string ContentType="application/pdf";
    private readonly byte[] bytes;
    public string FileName {get;}
    public int Length=>bytes.Length;
    public PdfEmailAttachment(string fileName,ReadOnlyMemory<byte> content)
    {
        if(fileName is not {Length:>=5 and <=120} || !char.IsLetterOrDigit(fileName[0]) || fileName!=fileName.Trim() ||
            !fileName.EndsWith(".pdf",StringComparison.OrdinalIgnoreCase) || fileName.Contains("..",StringComparison.Ordinal) ||
            !fileName.All(c=>char.IsLetterOrDigit(c) || c is ' ' or '-' or '_' or '.'))throw new ArgumentException("Use a safe bounded PDF attachment filename.");
        if(content.Length> EmailAttachmentOptions.HardDecodedBytes)throw new EmailAttachmentLimitException();
        if(!content.Span.StartsWith("%PDF-"u8))throw new ArgumentException("PDF attachment bytes are required.");
        FileName=fileName;bytes=content.ToArray();
    }
    public MemoryStream OpenRead()=>new(bytes,0,bytes.Length,writable:false,publiclyVisible:false);
    internal byte[] CopyBytes()=>bytes.ToArray();
}

internal static class PdfEmailAttachments
{
    internal static OutgoingEmail Snapshot(OutgoingEmail message,EmailAttachmentOptions limits,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();limits.Validate();
        var recipient=EmailAddress.Normalize(message.To);
        if(string.IsNullOrWhiteSpace(message.Subject) || message.Subject.Length>998 || message.Subject.Any(char.IsControl) || message.Text is null || message.Html is null)
            throw new ArgumentException("Invalid email content.");
        var input=message.Attachments??Array.Empty<PdfEmailAttachment>();
        if(input.Count>2)throw new EmailAttachmentLimitException();
        var files=new PdfEmailAttachment[input.Count];var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long decoded=0;
        // MIME Base64 wraps at 76 characters. Four times UTF-8 body bytes bounds
        // transfer encoding/line wrapping; reserve additional header/boundary space.
        long encoded=65536L+4L*(Encoding.UTF8.GetByteCount(message.Text)+(long)Encoding.UTF8.GetByteCount(message.Html));
        for(var i=0;i<files.Length;i++) {
            var file=input[i];if(file is null || !names.Add(file.FileName))throw new ArgumentException("Distinct PDF attachments are required.");
            files[i]=file;decoded+=file.Length;
            var base64=4L*((file.Length+2L)/3);
            encoded+=base64+2*((base64+75)/76)+4096L+8L*Encoding.UTF8.GetByteCount(file.FileName);
        }
        if(decoded>limits.MaximumDecodedBytes || encoded>limits.MaximumMessageBytes)throw new EmailAttachmentLimitException();
        return message with {To=recipient,Attachments=Array.AsReadOnly(files)};
    }
}

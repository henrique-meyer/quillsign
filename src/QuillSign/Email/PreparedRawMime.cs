using System.Security.Cryptography;
using System.Text;
using MimeKit;

namespace QuillSign.Email;

public sealed class RawMimeLimitException() : ArgumentException("The complete encoded email exceeds the one-MiB limit.");

// A serialized artifact, not authority to send. No transport or credential factory is involved.
public sealed class PreparedRawMime
{
    public const int MaximumBytes = 1024 * 1024;
    private readonly byte[] bytes;
    private readonly byte[] hash;
    public string Sender { get; }
    public string Recipient { get; }
    public Guid? EnvelopeId { get; }
    public string MessageId { get; }
    public int ByteCount => bytes.Length;
    public byte[] Sha256 => hash.ToArray();
    public MemoryStream OpenRead() => new(bytes, 0, bytes.Length, writable: false, publiclyVisible: false);

    private PreparedRawMime(byte[] owned, string sender, OutgoingEmail message, string messageId)
    {
        bytes = owned;
        hash = SHA256.HashData(owned);
        Sender = sender;
        Recipient = message.To;
        EnvelopeId = message.EnvelopeId;
        MessageId = messageId;
    }

    public static async Task<PreparedRawMime> PrepareAsync(OutgoingEmail message, string fromEmail, string fromName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(message);
        if (fromName is null || fromName.Length > 256 || fromName.Any(char.IsControl))
            throw new ArgumentException("A bounded sender display name is required.");
        ValidateText(fromName, message.Subject, message.Text, message.Html);
        var sender = EmailAddress.Normalize(fromEmail);
        // The ordinary contract owns attachment content already. Snapshot its mutable list
        // before any await; the exact serializer below, not this coarse estimate, sets the cap.
        var input = message.Attachments;
        var count = input?.Count ?? 0;
        if (count is < 0 or > 2) throw new EmailAttachmentLimitException();
        var files = new PdfEmailAttachment[count];
        for (var i = 0; i < files.Length; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { files[i] = input![i]; }
            catch (ArgumentOutOfRangeException) { throw new ArgumentException("The attachment list changed during preparation."); }
            catch (IndexOutOfRangeException) { throw new ArgumentException("The attachment list changed during preparation."); }
        }
        var snapshot = PdfEmailAttachments.Snapshot(message with { Attachments = Array.AsReadOnly(files) }, new()
        {
            MaximumDecodedBytes = MaximumBytes,
            MaximumMessageBytes = EmailAttachmentOptions.HardMessageBytes
        }, cancellationToken);
        var owned = new List<(string Name, byte[] Bytes)>();
        try
        {
            foreach (var file in snapshot.Attachments!)
            {
                cancellationToken.ThrowIfCancellationRequested();
                owned.Add((file.FileName, file.CopyBytes()));
            }
            using var mime = new MimeMessage
            {
                Subject = snapshot.Subject,
                MessageId = Guid.NewGuid().ToString("N") + "@quillsign.invalid",
                Date = DateTimeOffset.UtcNow
            };
            mime.From.Add(new MailboxAddress(fromName, sender));
            mime.To.Add(new MailboxAddress("", snapshot.To));
            if (snapshot.EnvelopeId is { } envelope)
                mime.Headers.Add("X-QuillSign-Envelope", envelope.ToString("N"));
            var body = new BodyBuilder { TextBody = snapshot.Text, HtmlBody = snapshot.Html };
            foreach (var file in owned)
            {
                var part = (MimePart)body.Attachments.Add(file.Name, file.Bytes, ContentType.Parse(PdfEmailAttachment.ContentType));
                part.ContentDisposition = new ContentDisposition(ContentDisposition.Attachment) { FileName = file.Name };
            }
            mime.Body = body.ToMessageBody();
            // Seven-bit complete MIME is independent of SMTPUTF8/8BITMIME capabilities.
            foreach (var part in mime.BodyParts.OfType<MimePart>()) part.ContentTransferEncoding = ContentEncoding.Base64;
            var format = FormatOptions.Default.Clone();
            format.NewLineFormat = NewLineFormat.Dos;
            format.EnsureNewLine = true;
            format.International = false;
            using var output = new BoundedOutput();
            await mime.WriteToAsync(format, output, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return new(output.CopyBytes(), sender, snapshot, mime.MessageId);
        }
        finally
        {
            foreach (var file in owned) Array.Clear(file.Bytes);
        }
    }

    private static void ValidateText(string fromName, string? subject, string? text, string? html)
    {
        if (subject is null || text is null || html is null || subject.Length > 998 ||
            text.Length > MaximumBytes || html.Length > MaximumBytes)
            throw new ArgumentException("Invalid or oversized email content.");
        try
        {
            var utf8 = new UTF8Encoding(false, true);
            _ = utf8.GetByteCount(fromName);
            _ = utf8.GetByteCount(subject);
            if (utf8.GetByteCount(text) + (long)utf8.GetByteCount(html) > MaximumBytes)
                throw new RawMimeLimitException();
        }
        catch (EncoderFallbackException) { throw new ArgumentException("Email content must contain valid Unicode."); }
    }

    private sealed class BoundedOutput : Stream
    {
        // Fixed capacity makes the allocation bound independent of serializer write sizes.
        private readonly MemoryStream output = new(MaximumBytes);
        public byte[] CopyBytes() => output.ToArray();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => output.CanWrite;
        public override long Length => output.Length;
        public override long Position { get => output.Position; set => throw new NotSupportedException(); }
        public override void Flush() => output.Flush();
        public override Task FlushAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length > MaximumBytes - output.Length) throw new RawMimeLimitException();
            output.Write(buffer);
        }
        public override void WriteByte(byte value)
        {
            if (output.Length == MaximumBytes) throw new RawMimeLimitException();
            output.WriteByte(value);
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Write(buffer, offset, count); return Task.CompletedTask;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested(); Write(buffer.Span); return ValueTask.CompletedTask;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (output.TryGetBuffer(out var data)) data.AsSpan().Clear();
                output.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}

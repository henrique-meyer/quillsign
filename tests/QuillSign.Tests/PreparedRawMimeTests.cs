using System.Collections;
using System.Security.Cryptography;
using System.Text;
using MimeKit;
using QuillSign.Email;

namespace QuillSign.Tests;

public sealed class PreparedRawMimeTests
{
    private const string Sender = "sender@example.invalid", Recipient = "recipient@example.invalid";
    private static readonly byte[] Pdf = "%PDF-1.7\nSynthetic transport-only NO AGREEMENT\n%%EOF"u8.ToArray();
    private static OutgoingEmail Message(string text = "Plain text", string html = "<p>HTML</p>") =>
        new(Recipient, "Synthetic NO AGREEMENT", text, html);
    private static Task<PreparedRawMime> Prepare(OutgoingEmail message, CancellationToken ct = default) =>
        PreparedRawMime.PrepareAsync(message, Sender, "QuillSign", ct);

    [Fact]
    public async Task Complete_seven_bit_MIME_round_trips_Unicode_alternatives_headers_and_exact_attachments()
    {
        var envelope = Guid.NewGuid();
        var message = new OutgoingEmail("Recipient@EXAMPLE.INVALID", "Assinatura – 日本語 🔏", "Olá 日本語 🔏\r\nNo agreement.",
            "<p>Olá 日本語 🔏</p>\r\n<p>No agreement.</p>", envelope,
            [new("résumé.pdf", Pdf), new("証明書.pdf", Pdf)]);
        var prepared = await PreparedRawMime.PrepareAsync(message, "Sender@EXAMPLE.INVALID", "Équipe 日本語 🔏");
        using var input = prepared.OpenRead();
        using var parsed = await MimeMessage.LoadAsync(input);
        Assert.Equal(message.Subject, parsed.Subject);
        Assert.Equal("Équipe 日本語 🔏", Assert.Single(parsed.From.Mailboxes).Name);
        Assert.Equal(Sender, Assert.Single(parsed.From.Mailboxes).Address);
        Assert.Equal(Recipient, Assert.Single(parsed.To.Mailboxes).Address);
        Assert.Equal(Lines(message.Text), Lines(parsed.TextBody));
        Assert.Equal(Lines(message.Html), Lines(parsed.HtmlBody));
        Assert.Equal(prepared.MessageId, parsed.MessageId);
        Assert.EndsWith("@quillsign.invalid", parsed.MessageId);
        Assert.Equal(envelope.ToString("N"), parsed.Headers["X-QuillSign-Envelope"]);
        Assert.Equal(TimeSpan.Zero, parsed.Date.Offset);
        Assert.Equal(envelope, prepared.EnvelopeId);
        Assert.Equal(Sender, prepared.Sender); Assert.Equal(Recipient, prepared.Recipient);
        Assert.IsType<Multipart>(parsed.Body);
        foreach (var (expected, entity) in message.Attachments!.Zip(parsed.Attachments))
        {
            var part = Assert.IsType<MimePart>(entity);
            Assert.Equal(expected.FileName, part.FileName);
            Assert.Equal(PdfEmailAttachment.ContentType, part.ContentType.MimeType);
            Assert.Equal(ContentDisposition.Attachment, part.ContentDisposition!.Disposition);
            Assert.Equal(ContentEncoding.Base64, part.ContentTransferEncoding);
            using var decoded = new MemoryStream(); await part.Content!.DecodeToAsync(decoded);
            Assert.Equal(Pdf, decoded.ToArray());
        }
        Assert.Equal(2, parsed.Attachments.Count());
        Assert.All(parsed.BodyParts.OfType<MimePart>(), part => Assert.Equal(ContentEncoding.Base64, part.ContentTransferEncoding));
        var bytes = input.ToArray(); Assert.Equal(bytes.Length, prepared.ByteCount);
        Assert.Equal(SHA256.HashData(bytes), prepared.Sha256);
        Assert.All(bytes, b => Assert.True(b < 128));
        var raw = Encoding.ASCII.GetString(bytes);
        Assert.Contains("MIME-Version: 1.0\r\n", raw);
        Assert.DoesNotMatch("(?<!\\r)\\n", raw);
        Assert.All(raw.Split("\r\n"), line => Assert.True(line.Length <= 998));
        Assert.EndsWith("\r\n", raw);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task No_attachment_messages_retain_both_alternatives_without_envelope_header(bool empty)
    {
        var message = empty ? Message("", "") : Message();
        var prepared = await Prepare(message); using var input = prepared.OpenRead();
        using var parsed = await MimeMessage.LoadAsync(input);
        Assert.Equal("multipart/alternative", parsed.Body!.ContentType.MimeType);
        Assert.Equal(2, Assert.IsType<MultipartAlternative>(parsed.Body).Count);
        Assert.Equal(message.Text, parsed.TextBody); Assert.Equal(message.Html, parsed.HtmlBody);
        Assert.Empty(parsed.Attachments); Assert.Null(parsed.Headers["X-QuillSign-Envelope"]);
        Assert.Null(prepared.EnvelopeId);
    }

    [Fact]
    public async Task Artifact_and_hash_own_bytes_and_every_reopened_stream_is_independent_and_read_only()
    {
        var original = Pdf.ToArray(); var files = new[] { new PdfEmailAttachment("executed.pdf", original) };
        var prepared = await Prepare(Message() with { Attachments = files });
        Array.Clear(original); files[0] = new("different.pdf", Pdf);
        var hash = prepared.Sha256; Array.Clear(hash);
        using var first = prepared.OpenRead(); var expected = first.ToArray(); first.Position = first.Length;
        var copy = first.ToArray(); Array.Clear(copy);
        Assert.False(first.CanWrite); Assert.False(first.TryGetBuffer(out _));
        Assert.Throws<UnauthorizedAccessException>(() => first.GetBuffer());
        Assert.Throws<NotSupportedException>(() => first.WriteByte(0));
        using var second = prepared.OpenRead(); Assert.Equal(0, second.Position);
        Assert.Equal(expected, second.ToArray()); Assert.Equal(SHA256.HashData(expected), prepared.Sha256);
        using var parsed = await MimeMessage.LoadAsync(second);
        var part = Assert.IsType<MimePart>(Assert.Single(parsed.Attachments));
        Assert.Equal("executed.pdf", part.FileName);
        using var bytes = new MemoryStream(); await part.Content!.DecodeToAsync(bytes); Assert.Equal(Pdf, bytes.ToArray());
        first.Dispose(); using var third = prepared.OpenRead(); Assert.Equal(expected, third.ToArray());
    }

    [Fact]
    public async Task Mutable_attachment_collection_is_snapshotted_before_encoding()
    {
        var first = new PdfEmailAttachment("first.pdf", Pdf);
        var second = new PdfEmailAttachment("second.pdf", Pdf);
        var files = new ChangingFiles(first, second, () => { });
        var prepared = await Prepare(Message() with { Attachments = files });
        Assert.Equal("replacement.pdf", files[0].FileName);
        using var input = prepared.OpenRead(); using var parsed = await MimeMessage.LoadAsync(input);
        Assert.Equal(new[] { "first.pdf", "second.pdf" }, parsed.Attachments.OfType<MimePart>().Select(x => x.FileName));
    }

    [Fact]
    public async Task Header_and_boundary_looking_body_content_remains_inside_its_encoded_alternative()
    {
        var text = "NO AGREEMENT\r\n\r\nBcc: other@example.invalid\r\nContent-Type: multipart/mixed; boundary=pretend\r\n--pretend\r\nPRIVATE-MARKER";
        var prepared = await Prepare(Message(text, "<p>" + text + "</p>"));
        using var input = prepared.OpenRead(); using var parsed = await MimeMessage.LoadAsync(input);
        Assert.Equal(Lines(text), Lines(parsed.TextBody)); Assert.Equal(Lines("<p>" + text + "</p>"), Lines(parsed.HtmlBody));
        Assert.Empty(parsed.Bcc); Assert.Single(parsed.To); Assert.Empty(parsed.Attachments);
        Assert.Equal(2, Assert.IsType<MultipartAlternative>(parsed.Body).Count);
    }

    [Fact]
    public async Task Mutable_count_is_observed_once_before_allocating_the_bounded_attachment_snapshot()
    {
        var input = new ChangingCount();
        var prepared = await Prepare(Message() with { Attachments = input });
        Assert.Equal(1, input.Reads);
        using var read = prepared.OpenRead(); using var parsed = await MimeMessage.LoadAsync(read);
        Assert.Equal(2, parsed.Attachments.Count());
    }

    [Theory]
    [InlineData("text")][InlineData("attachment")]
    public async Task Actual_encoded_overflow_is_rejected_even_when_decoded_inputs_fit_one_MiB(string mode)
    {
        var message = mode == "text" ? Message(new('a', 400_000), new('b', 400_000)) :
            Message() with { Attachments = [new("executed.pdf", LargePdf(780_000))] };
        var error = await Assert.ThrowsAsync<RawMimeLimitException>(() => Prepare(message));
        Assert.Null(error.InnerException); Assert.DoesNotContain("PRIVATE", error.Message);
    }

    [Fact]
    public async Task Complete_headers_count_toward_exact_one_MiB_and_one_more_header_byte_is_rejected()
    {
        var low = 0; var high = PreparedRawMime.MaximumBytes;
        PreparedRawMime? largest = null;
        while (low < high)
        {
            var middle = low + (high - low + 1) / 2;
            try { largest = await Prepare(Message(new('a', middle), "")); low = middle; }
            catch (RawMimeLimitException) { high = middle - 1; }
        }
        largest = await Prepare(Message(new('a', low), ""));
        var gap = PreparedRawMime.MaximumBytes - largest.ByteCount; Assert.InRange(gap, 0, 7);
        var exact = Message(new('a', low), "") with { Subject = Message().Subject + new string('x', gap) };
        var prepared = await Prepare(exact); Assert.Equal(PreparedRawMime.MaximumBytes, prepared.ByteCount);
        using var read = prepared.OpenRead(); Assert.Equal(prepared.ByteCount, read.Length);
        Assert.Equal(SHA256.HashData(read.ToArray()), prepared.Sha256);
        using var parsed = await MimeMessage.LoadAsync(read); Assert.Equal(exact.Text, parsed.TextBody);
        await Assert.ThrowsAsync<RawMimeLimitException>(() => Prepare(exact with { Subject = exact.Subject + "x" }));
    }

    [Theory]
    [InlineData("name")][InlineData("subject")][InlineData("to")][InlineData("from")]
    [InlineData("unicode-text")][InlineData("unicode-html")][InlineData("unicode-subject")][InlineData("unicode-name")]
    public async Task Invalid_header_or_Unicode_input_fails_without_reflecting_content(string mode)
    {
        var message = Message(); var name = "QuillSign"; var from = Sender;
        var injection = "PRIVATE-MARKER\r\nBcc: other@example.invalid"; var invalid = new string('\ud800', 1);
        switch (mode)
        {
            case "name": name = injection; break;
            case "subject": message = message with { Subject = injection }; break;
            case "to": message = message with { To = injection }; break;
            case "from": from = injection; break;
            case "unicode-text": message = message with { Text = invalid }; break;
            case "unicode-html": message = message with { Html = invalid }; break;
            case "unicode-subject": message = message with { Subject = invalid }; break;
            case "unicode-name": name = invalid; break;
        }
        var error = await Assert.ThrowsAsync<ArgumentException>(() => PreparedRawMime.PrepareAsync(message, from, name));
        Assert.DoesNotContain("PRIVATE-MARKER", error.Message); Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData("characters")][InlineData("utf8")][InlineData("attachment-sum")][InlineData("count")]
    public async Task Input_work_is_bounded_before_MIME_encoding(string mode)
    {
        var message = mode switch
        {
            "characters" => Message(new('a', PreparedRawMime.MaximumBytes + 1)),
            "utf8" => Message(new('日', 400_000)),
            "attachment-sum" => Message() with { Attachments = [new("first.pdf", LargePdf(600_000)), new("second.pdf", LargePdf(600_000))] },
            _ => Message() with { Attachments = [new("first.pdf", Pdf), new("second.pdf", Pdf), new("third.pdf", Pdf)] }
        };
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Prepare(message));
    }

    [Fact]
    public async Task Cancellation_before_validation_and_after_collection_snapshot_returns_no_artifact()
    {
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PreparedRawMime.PrepareAsync(null!, "invalid", "", canceled.Token));
        using var during = new CancellationTokenSource();
        var files = new ChangingFiles(new("first.pdf", Pdf), new("second.pdf", Pdf), during.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Prepare(Message() with { Attachments = files }, during.Token));
    }

    private static byte[] LargePdf(int length)
    {
        var bytes = new byte[length]; Pdf.CopyTo(bytes, 0); return bytes;
    }
    // MimeKit's text accessor uses the platform newline convention after decoding.
    // Serialized wire CRLF and exact decoded attachment bytes are asserted separately.
    private static string Lines(string? text) => Assert.IsType<string>(text).Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
    private sealed class ChangingFiles(PdfEmailAttachment first, PdfEmailAttachment second, Action change) : IReadOnlyList<PdfEmailAttachment>
    {
        private PdfEmailAttachment current = first;
        public int Count => 2;
        public PdfEmailAttachment this[int index]
        {
            get
            {
                if (index == 0) return current;
                if (index != 1) throw new ArgumentOutOfRangeException(nameof(index));
                current = new("replacement.pdf", Pdf); change(); return second;
            }
        }
        public IEnumerator<PdfEmailAttachment> GetEnumerator() { yield return this[0]; yield return this[1]; }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
    private sealed class ChangingCount : IReadOnlyList<PdfEmailAttachment>
    {
        public int Reads { get; private set; }
        public int Count => ++Reads == 1 ? 2 : 3;
        public PdfEmailAttachment this[int index] => index switch
        {
            0 => new("first.pdf", Pdf), 1 => new("second.pdf", Pdf), _ => throw new ArgumentOutOfRangeException(nameof(index))
        };
        public IEnumerator<PdfEmailAttachment> GetEnumerator() => throw new NotSupportedException();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

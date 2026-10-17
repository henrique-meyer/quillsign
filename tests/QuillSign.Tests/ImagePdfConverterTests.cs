using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class ImagePdfConverterTests
{
    [Theory]
    [InlineData(false, 1, 0, 1, 2, 3)]
    [InlineData(false, 2, 1, 0, 3, 2)]
    [InlineData(false, 3, 3, 2, 1, 0)]
    [InlineData(false, 4, 2, 3, 0, 1)]
    [InlineData(false, 5, 0, 2, 1, 3)]
    [InlineData(false, 6, 2, 0, 3, 1)]
    [InlineData(false, 7, 3, 1, 2, 0)]
    [InlineData(false, 8, 1, 3, 0, 2)]
    [InlineData(true, 1, 0, 1, 2, 3)]
    [InlineData(true, 2, 1, 0, 3, 2)]
    [InlineData(true, 3, 3, 2, 1, 0)]
    [InlineData(true, 4, 2, 3, 0, 1)]
    [InlineData(true, 5, 0, 2, 1, 3)]
    [InlineData(true, 6, 2, 0, 3, 1)]
    [InlineData(true, 7, 3, 1, 2, 0)]
    [InlineData(true, 8, 1, 3, 0, 2)]
    public async Task Actual_embedded_pixels_follow_every_orientation_without_cropping_stretching_or_metadata(bool jpeg, int orientation, int a, int b, int c, int d)
    {
        var bytes = jpeg ? WithExif(Jpeg(), orientation) : Png(orientation: orientation); var expected = bytes.ToArray(); using var source = new MemoryStream(bytes);
        using var converted = await Converter().ConvertAsync(source, bytes.Length); Assert.True(source.CanRead); Assert.Equal(jpeg ? "image/jpeg" : "image/png", converted.SourceMime);
        Assert.Equal(SHA256.HashData(expected), converted.OriginalSha256); using (var original = converted.OpenOriginal()) { using var copy = new MemoryStream(); await original.CopyToAsync(copy); Assert.Equal(expected, copy.ToArray()); }
        using var read = converted.OpenPdf(); Assert.Equal(converted.PdfSha256, await SHA256.HashDataAsync(read)); read.Position = 0;
        using var pdf = UglyToad.PdfPig.PdfDocument.Open(read); var page = pdf.GetPage(1); var image = Assert.Single(page.GetImages()); Assert.True(image.TryGetBytesAsMemory(out var pixels));
        Assert.Equal(orientation >= 5 ? 48 : 80, image.WidthInSamples); Assert.Equal(orientation >= 5 ? 80 : 48, image.HeightInSamples);
        Assert.Equal(image.WidthInSamples, converted.Width); Assert.Equal(image.HeightInSamples, converted.Height);
        Assert.InRange(image.BoundingBox.Left, 23.999, 768); Assert.InRange(image.BoundingBox.Bottom, 23.999, 768);
        Assert.InRange(image.BoundingBox.Right, 24, page.Width - 23.999); Assert.InRange(image.BoundingBox.Top, 24, page.Height - 23.999);
        Assert.InRange(Math.Abs(image.BoundingBox.Width / image.BoundingBox.Height - (double)converted.Width / converted.Height), 0, .00001);
        int[][] colors = [[220, 20, 40], [20, 160, 50], [30, 70, 210], [230, 180, 20]]; int[] corners = [a, b, c, d];
        for (var i = 0; i < 4; i++) { var x = i % 2 == 0 ? 4 : converted.Width - 5; var y = i < 2 ? 4 : converted.Height - 5; var at = (y * converted.Width + x) * 3; for (var channel = 0; channel < 3; channel++) Assert.InRange((int)pixels.Span[at + channel], colors[corners[i]][channel] - (jpeg ? 12 : 0), colors[corners[i]][channel] + (jpeg ? 12 : 0)); }
        Assert.Equal(converted.Width > converted.Height ? 792 : 612, Assert.Single(converted.Pages).Width);
        using var pdfBytes = converted.OpenPdf(); using var output = new MemoryStream(); await pdfBytes.CopyToAsync(output); Assert.DoesNotContain("PRIVATE-MARKER", Encoding.Latin1.GetString(output.ToArray()));
    }

    [Fact]
    public async Task Transparency_is_composited_over_white_and_owned_results_are_immutable()
    {
        var bytes = Png(alpha: true); var expected = bytes.ToArray(); using var source = new MemoryStream(bytes); var result = await Converter().ConvertAsync(source, bytes.Length);
        bytes[0] ^= 1; var hash = result.PdfSha256; hash[0] ^= 1; var pages = result.Pages; pages[0].MediaBox[0] = 123;
        Assert.NotEqual(hash, result.PdfSha256); Assert.Equal(0, result.Pages[0].MediaBox[0]); using var reader = result.OpenPdf(); Assert.False(reader.CanWrite);
        result.Dispose(); Assert.True(source.CanRead); Assert.Throws<ObjectDisposedException>(() => result.OpenPdf()); Assert.Throws<ObjectDisposedException>(() => result.OriginalSha256);
        using var pdf = UglyToad.PdfPig.PdfDocument.Open(reader); var image = Assert.Single(pdf.GetPage(1).GetImages()); Assert.True(image.TryGetBytesAsMemory(out var pixels));
        Assert.Equal(new byte[] { 137, 167, 207 }, pixels.Span[..3].ToArray()); Assert.Equal(new byte[] { 255, 255, 255 }, pixels.Span[3..6].ToArray()); Assert.Equal(137, pixels.Span[(48 * 80 - 1) * 3]);
    }

    [Fact]
    public async Task A_complete_progressive_JPEG_is_fully_decoded_and_normalized()
    {
        var bytes = Jpeg(progressive: true); using var source = new MemoryStream(bytes); using var result = await Converter().ConvertAsync(source, bytes.Length); Assert.Equal(80, result.Width); Assert.Equal(48, result.Height);
        using var pdf = UglyToad.PdfPig.PdfDocument.Open(result.OpenPdf()); var image = Assert.Single(pdf.GetPage(1).GetImages()); Assert.True(image.TryGetBytesAsMemory(out var pixels)); Assert.Equal(80 * 48 * 3, pixels.Length);
    }

    [Theory]
    [InlineData("crc")]
    [InlineData("trailing")]
    [InlineData("animation")]
    [InlineData("profile")]
    [InlineData("gamma")]
    [InlineData("large-side")]
    [InlineData("large-area")]
    [InlineData("expanded")]
    [InlineData("extra-zlib")]
    [InlineData("truncated-zlib")]
    [InlineData("interlaced")]
    [InlineData("sixteen-bit")]
    [InlineData("invalid-filter")]
    [InlineData("jpeg-trailing")]
    [InlineData("jpeg-truncated")]
    [InlineData("jpeg-entropy")]
    [InlineData("jpeg-profile")]
    [InlineData("jpeg-mpf")]
    [InlineData("jpeg-duplicate-exif")]
    [InlineData("jpeg-bad-exif")]
    [InlineData("gif")]
    [InlineData("svg")]
    [InlineData("random")]
    public async Task Unsupported_corrupt_ambiguous_and_expanding_images_return_no_PDF_or_private_details(string kind)
    {
        byte[] bytes;
        if (kind.StartsWith("jpeg"))
        {
            bytes = Jpeg(); if (kind == "jpeg-trailing") bytes = [.. bytes, 1]; if (kind == "jpeg-truncated") bytes = bytes[..^3];
            if (kind == "jpeg-entropy") { var scan = FindScan(bytes); bytes = [.. bytes[..(scan + 12)], 255, 217]; }
            if (kind == "jpeg-profile") bytes = Segment(bytes, 226, "ICC_PROFILE\0PRIVATE-MARKER"u8.ToArray()); if (kind == "jpeg-mpf") bytes = Segment(bytes, 226, "MPF\0PRIVATE-MARKER"u8.ToArray());
            if (kind == "jpeg-duplicate-exif") bytes = WithExif(WithExif(bytes, 1), 2); if (kind == "jpeg-bad-exif") bytes = WithExif(bytes, 9);
        }
        else bytes = kind switch
        {
            "trailing" => [.. Png(), 1],
            "animation" => Png(extra: ("acTL", new byte[8])),
            "profile" => Png(extra: ("iCCP", "PRIVATE-MARKER"u8.ToArray())),
            "gamma" => Png(extra: ("gAMA", new byte[] { 0, 1, 134, 160 })),
            "large-side" => Png(width: 12001, height: 1, raw: new byte[] { 0 }),
            "large-area" => Png(width: 4000, height: 4000, raw: new byte[] { 0 }),
            "expanded" => Png(width: 1, height: 1, raw: new byte[1024 * 1024]),
            "extra-zlib" => Png(extraZlib: true),
            "truncated-zlib" => Png(truncatedZlib: true),
            "interlaced" => Png(interlace: 1),
            "sixteen-bit" => Png(depth: 16),
            "invalid-filter" => Png(width: 1, height: 1, raw: new byte[] { 5, 1, 2, 3 }),
            "gif" => "GIF89aPRIVATE-MARKER"u8.ToArray(),
            "svg" => "<svg>PRIVATE-MARKER</svg>"u8.ToArray(),
            "random" => new byte[128],
            _ => Png()
        };
        if (kind == "crc") bytes[32] ^= 1; using var source = new MemoryStream(bytes); var error = await Assert.ThrowsAsync<DocumentRejectedException>(() => Converter().ConvertAsync(source, bytes.Length));
        Assert.True(source.CanRead); Assert.DoesNotContain("PRIVATE-MARKER", error.Message); Assert.Null(error.InnerException);
    }

    [Fact]
    public async Task Declared_actual_and_output_limits_and_caller_cancellation_preserve_ownership()
    {
        var bytes = Png(); using var input = new MemoryStream(bytes);
        await Assert.ThrowsAsync<DocumentRejectedException>(() => Converter().ConvertAsync(input, bytes.Length + 1)); Assert.True(input.CanRead); input.Position = 0;
        await Assert.ThrowsAsync<DocumentRejectedException>(() => Converter(1024).ConvertAsync(input, bytes.Length)); Assert.True(input.CanRead); input.Position = 0;
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Converter().ConvertAsync(input, bytes.Length, cancellation.Token)); Assert.Equal(0, input.Position);
        using var huge = new MemoryStream(new byte[2049]); await Assert.ThrowsAsync<DocumentRejectedException>(() => Converter(2048).ConvertAsync(huge, 1024)); Assert.True(huge.CanRead);
    }

    [Fact]
    public async Task A_waiting_conversion_can_cancel_without_reading_and_a_cancelled_reader_releases_admission()
    {
        using var firstCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10)); using var waiting = new WaitingStream(); var first = Converter().ConvertAsync(waiting, 100, firstCancellation.Token);
        await waiting.Started.Task.WaitAsync(TimeSpan.FromSeconds(5)); using var secondCancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50)); using var untouched = new MemoryStream(Png());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Converter().ConvertAsync(untouched, untouched.Length, secondCancellation.Token)); Assert.Equal(0, untouched.Position);
        firstCancellation.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first); Assert.True(waiting.CanRead); untouched.Position = 0; using var recovered = await Converter().ConvertAsync(untouched, untouched.Length); Assert.Single(recovered.Pages);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Grayscale_and_indexed_PNGs_decode_to_complete_RGB_pixels(bool indexed)
    {
        var bytes = Convert.FromBase64String(indexed ? "iVBORw0KGgoAAAANSUhEUgAAAFAAAAAwCAMAAACxOw3FAAADAFBMVEXcFCgUoDIeRtLmtBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACiXAfPAAAAS0lEQVR4nO3QoRGAQADEwDz03zMakZkTOLIFRARGZ0RB1UPFyhNvBd0ZsSqo6KHya29/DF6je0RB1UOFX+vhiB6qHir8Wg9Hnz98AGfPFoEnB72iAAAAAElFTkSuQmCC" : "iVBORw0KGgoAAAANSUhEUgAAAFAAAAAwCAAAAACjjqIrAAAAVUlEQVR4nO3VoQ0AMQxD0fRP1BE68o142CySQ6r6Y+uRgKxTvXZzRw1HQDt8Qgvox4AhBfRjwJAC+vEeuL7mMH/54isT0A6f0AL6MWBIAf0YMOpx8AcbOAGv9R8ZPwAAAABJRU5ErkJggg=="); using var input = new MemoryStream(bytes); using var result = await Converter().ConvertAsync(input, bytes.Length);
        using var pdf = UglyToad.PdfPig.PdfDocument.Open(result.OpenPdf()); var image = Assert.Single(pdf.GetPage(1).GetImages()); Assert.True(image.TryGetBytesAsMemory(out var pixels));
        Assert.Equal(new byte[] { indexed ? (byte)220 : (byte)64, indexed ? (byte)20 : (byte)64, indexed ? (byte)40 : (byte)64 }, pixels.Span[..3].ToArray());
        Assert.Equal(80 * 48 * 3, pixels.Length); Assert.Equal("image/png", result.SourceMime);
    }

    private static ImagePdfConverter Converter(long maximum = 10 * 1024 * 1024) { var options = new DocumentOptions { MaximumBytes = maximum }; return new(options, new(options)); }
    public static byte[] Png(int width = 80, int height = 48, int orientation = 1, bool alpha = false, byte[]? raw = null, (string Type, byte[] Bytes)? extra = null, bool extraZlib = false, bool truncatedZlib = false, int interlace = 0, int depth = 8)
    {
        if (raw is null)
        {
            raw = new byte[height * (1 + width * (alpha ? 4 : 3))]; int[][] colors = [[220, 20, 40], [20, 160, 50], [30, 70, 210], [230, 180, 20]];
            for (var y = 0; y < height; y++) for (var x = 0; x < width; x++) { var at = y * (1 + width * (alpha ? 4 : 3)) + 1 + x * (alpha ? 4 : 3); var color = colors[(y < height / 2 ? 0 : 2) + (x < width / 2 ? 0 : 1)]; for (var c = 0; c < 3; c++) raw[at + c] = (byte)(alpha ? new[] { 20, 80, 160 }[c] : color[c]); if (alpha) raw[at + 3] = x == 1 && y == 0 ? (byte)0 : (byte)128; }
        }
        using var output = new MemoryStream(); output.Write(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }); byte[] header = new byte[13]; BinaryPrimitives.WriteUInt32BigEndian(header, (uint)width); BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)height); header[8] = (byte)depth; header[9] = alpha ? (byte)6 : (byte)2; header[12] = (byte)interlace; Chunk(output, "IHDR", header); Chunk(output, "tEXt", "comment\0PRIVATE-MARKER"u8.ToArray());
        if (orientation != 1) Chunk(output, "eXIf", Tiff(orientation)); if (extra is { } e) Chunk(output, e.Type, e.Bytes);
        using var compressed = new MemoryStream(); using (var z = new ZLibStream(compressed, CompressionLevel.Optimal, true)) z.Write(raw); var encoded = compressed.ToArray(); if (extraZlib) encoded = [.. encoded, .. encoded]; if (truncatedZlib) encoded = encoded[..^2]; Chunk(output, "IDAT", encoded); Chunk(output, "IEND", []); return output.ToArray();
    }
    private static byte[] Tiff(int orientation)
    {
        byte[] bytes = new byte[26]; bytes[0] = bytes[1] = 73; BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), 42); BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), 8); BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8), 1); BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(10), 274); BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(12), 3); BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(14), 1); BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(18), (ushort)orientation); return bytes;
    }
    private static byte[] WithExif(byte[] bytes, int orientation) => Segment(bytes, 225, [.. "Exif\0\0"u8.ToArray(), .. Tiff(orientation)]);
    private static byte[] Segment(byte[] jpeg, int marker, byte[] data) { byte[] segment = new byte[data.Length + 4]; segment[0] = 255; segment[1] = (byte)marker; BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(2), (ushort)(data.Length + 2)); data.CopyTo(segment, 4); return [.. jpeg[..2], .. segment, .. jpeg[2..]]; }
    private static int FindScan(byte[] bytes) { for (var i = 2; i < bytes.Length - 1; i++) if (bytes[i] == 255 && bytes[i + 1] == 218) return i; throw new InvalidDataException(); }
    private static void Chunk(Stream output, string type, byte[] data)
    {
        byte[] name = Encoding.ASCII.GetBytes(type); Span<byte> length = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, (uint)data.Length); output.Write(length); output.Write(name); output.Write(data); uint crc = uint.MaxValue; foreach (var value in name.Concat(data)) { crc ^= value; for (var i = 0; i < 8; i++) crc = (crc & 1) != 0 ? 0xedb88320 ^ (crc >> 1) : crc >> 1; }
        BinaryPrimitives.WriteUInt32BigEndian(length, ~crc); output.Write(length);
    }
    public static byte[] Jpeg(bool progressive = false, int orientation = 1) { var bytes = Convert.FromBase64String(progressive ? "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAIBAQEBAQIBAQECAgICAgQDAgICAgUEBAMEBgUGBgYFBgYGBwkIBgcJBwYGCAsICQoKCgoKBggLDAsKDAkKCgr/2wBDAQICAgICAgUDAwUKBwYHCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgr/wgARCAAwAFADAREAAhEBAxEB/8QAFwABAQEBAAAAAAAAAAAAAAAAAAYIB//EABgBAQEBAQEAAAAAAAAAAAAAAAAJCAQG/9oADAMBAAIQAxAAAAHkfj9iAAWHDMEACP7qfAAWHDMEACP7qfAAWHDMEADn+2PeAAbOlrooADGNSs6gAbOlrooADGNSs6gAbOlrooAD/8QAFBABAAAAAAAAAAAAAAAAAAAAUP/aAAgBAQABBQJz/8QAFBEBAAAAAAAAAAAAAAAAAAAAUP/aAAgBAwEBPwFz/8QAFBEBAAAAAAAAAAAAAAAAAAAAUP/aAAgBAgEBPwFz/8QAFBABAAAAAAAAAAAAAAAAAAAAUP/aAAgBAQAGPwJz/8QAFBABAAAAAAAAAAAAAAAAAAAAUP/aAAgBAQABPyFz/9oADAMBAAIAAwAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//EABQRAQAAAAAAAAAAAAAAAAAAAFD/2gAIAQMBAT8Qc//EABQRAQAAAAAAAAAAAAAAAAAAAFD/2gAIAQIBAT8Qc//EABQQAQAAAAAAAAAAAAAAAAAAAFD/2gAIAQEAAT8Qc//Z" : "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAIBAQEBAQIBAQECAgICAgQDAgICAgUEBAMEBgUGBgYFBgYGBwkIBgcJBwYGCAsICQoKCgoKBggLDAsKDAkKCgr/2wBDAQICAgICAgUDAwUKBwYHCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgr/wAARCAAwAFADAREAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD5Hr8fP9iAoAKACgAoA9grwz/mDCgAoAKACgDx+vcP+nwKACgAoAKAPYK8M/5gwoAKACgAoA8fr3D/AKfAoAKACgAoA9grwz/mDCgAoAKACgD5/r/bA/eAoAKACgAoA/Zyv+Ws/wBFAoAKACgAoA/GOv8AqUP86woAKACgAoA/Zyv+Ws/0UCgAoAKACgD8Y6/6lD/OsKACgAoAKAP2cr/lrP8ARQKACgAoAKAP/9k="); return orientation == 1 ? bytes : WithExif(bytes, orientation); }
    private sealed class WaitingStream : Stream
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { Started.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, ct); return 0; }
        public override bool CanRead => true; public override bool CanWrite => false; public override bool CanSeek => false; public override long Length => 100; public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException(); public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

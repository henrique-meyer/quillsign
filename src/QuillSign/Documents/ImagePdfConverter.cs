using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using StbImageSharp;

namespace QuillSign.Documents;

public sealed class ImagePdfConversion : IDisposable
{
    private readonly object gate = new(); private byte[]? original, pdf; private readonly byte[] originalHash, pdfHash; private readonly PageGeometry[] pages;
    public string SourceMime { get; }
    public int Width { get; }
    public int Height { get; }
    public long OriginalLength { get; }
    public long PdfLength { get; }
    internal ImagePdfConversion(byte[] original, byte[] pdf, ImageHeaderValidation.Header header, IReadOnlyList<PageGeometry> pages)
    {
        this.original = original; this.pdf = pdf; originalHash = SHA256.HashData(original); pdfHash = SHA256.HashData(pdf); this.pages = pages.ToArray(); SourceMime = header.Mime;
        Width = header.Orientation >= 5 ? header.Height : header.Width; Height = header.Orientation >= 5 ? header.Width : header.Height; OriginalLength = original.Length; PdfLength = pdf.Length;
    }
    public byte[] OriginalSha256 { get { lock (gate) { Check(); return originalHash.ToArray(); } } }
    public byte[] PdfSha256 { get { lock (gate) { Check(); return pdfHash.ToArray(); } } }
    public IReadOnlyList<PageGeometry> Pages { get { lock (gate) { Check(); return pages.Select(x => x with { MediaBox = x.MediaBox.ToArray(), CropBox = x.CropBox.ToArray() }).ToArray(); } } }
    public Stream OpenOriginal() { lock (gate) { Check(); return new MemoryStream(original!.ToArray(), false); } }
    public Stream OpenPdf() { lock (gate) { Check(); return new MemoryStream(pdf!.ToArray(), false); } }
    private void Check() => ObjectDisposedException.ThrowIf(original is null, this);
    public void Dispose() { lock (gate) { if (original is null) return; Array.Clear(original); Array.Clear(pdf!); Array.Clear(originalHash); Array.Clear(pdfHash); original = pdf = null; } }
}

// Internal format conversion only; public upload stays PDF-only until intake integration.
public sealed class ImagePdfConverter(DocumentOptions options, PdfValidation validation)
{
    private static readonly SemaphoreSlim Admission = new(1, 1);
    public async Task<ImagePdfConversion> ConvertAsync(Stream input, long declaredLength, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(input); ct.ThrowIfCancellationRequested();
        if (options.MaximumBytes is < 1024 or > 64 * 1024 * 1024 || options.MaximumPages is < 1 or > 200) throw new InvalidOperationException("Configure supported document conversion limits.");
        if (declaredLength < 4 || declaredLength > options.MaximumBytes) throw ImageHeaderValidation.Rejected();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(15)); var token = timeout.Token;
        byte[]? original = null; byte[]? pixels = null; var entered = false; var transferred = false;
        try
        {
            await Admission.WaitAsync(token); entered = true; using (var copied = new MemoryStream())
            {
                var buffer = new byte[65536]; long total = 0; int count; while ((count = await input.ReadAsync(buffer, token)) != 0) { if ((total += count) > options.MaximumBytes) throw ImageHeaderValidation.Rejected(); await copied.WriteAsync(buffer.AsMemory(0, count), token); }
                if (total != declaredLength) throw ImageHeaderValidation.Rejected(); original = copied.ToArray();
            }
            var header = ImageHeaderValidation.Read(original, token); token.ThrowIfCancellationRequested();
            using (var infoStream = new MemoryStream(original, false)) { var info = ImageInfo.FromStream(infoStream); if (info is null || info.Value.Width != header.Width || info.Value.Height != header.Height || info.Value.BitsPerChannel != 8) throw ImageHeaderValidation.Rejected(); }
            var decoded = ImageResult.FromMemory(original, ColorComponents.RedGreenBlueAlpha); pixels = decoded.Data; token.ThrowIfCancellationRequested();
            if (decoded.Width != header.Width || decoded.Height != header.Height || pixels.LongLength != (long)header.Width * header.Height * 4) throw ImageHeaderValidation.Rejected();
            var width = header.Orientation >= 5 ? header.Height : header.Width; var height = header.Orientation >= 5 ? header.Width : header.Height;
            using var png = Encode(pixels, header, width, height, options.MaximumBytes, token); using var image = XImage.FromStream(png); using var document = new PdfDocument();
            document.Info.Creator = "QuillSign"; var page = document.AddPage(); page.Width = XUnit.FromPoint(width > height ? 792 : 612); page.Height = XUnit.FromPoint(width > height ? 612 : 792);
            using (var graphics = XGraphics.FromPdfPage(page))
            {
                var scale = Math.Min((page.Width.Point - 48) / width, (page.Height.Point - 48) / height); var w = width * scale; var h = height * scale;
                graphics.DrawImage(image, (page.Width.Point - w) / 2, (page.Height.Point - h) / 2, w, h);
            }
            using var rendered = new MemoryStream(); document.Save(new BoundedDocumentStream(rendered, options.MaximumBytes), false); token.ThrowIfCancellationRequested(); rendered.Position = 0;
            using var normalized = new MemoryStream(); var pages = validation.Rewrite(rendered, new BoundedDocumentStream(normalized, options.MaximumBytes)); token.ThrowIfCancellationRequested();
            var result = new ImagePdfConversion(original, normalized.ToArray(), header, pages); transferred = true; return result;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new DocumentRejectedException("This image took too long to convert. Export a PDF and try again."); }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException or IOException or OverflowException or IndexOutOfRangeException or NotSupportedException)
        { throw ImageHeaderValidation.Rejected(); }
        finally { if (pixels is not null) Array.Clear(pixels); if (!transferred && original is not null) Array.Clear(original); if (entered) Admission.Release(); }
    }

    private static MemoryStream Encode(byte[] pixels, ImageHeaderValidation.Header header, int width, int height, long maximum, CancellationToken ct)
    {
        using var compressed = new MemoryStream();
        using (var encoder = new ZLibStream(new BoundedDocumentStream(compressed, maximum - 57), CompressionLevel.Optimal, true))
        {
            var row = new byte[1 + width * 3]; for (var y = 0; y < height; y++)
            {
                ct.ThrowIfCancellationRequested(); for (var x = 0; x < width; x++)
                {
                    var (sx, sy) = header.Orientation switch
                    {
                        1 => (x, y),
                        2 => (header.Width - 1 - x, y),
                        3 => (header.Width - 1 - x, header.Height - 1 - y),
                        4 => (x, header.Height - 1 - y),
                        5 => (y, x),
                        6 => (y, header.Height - 1 - x),
                        7 => (header.Width - 1 - y, header.Height - 1 - x),
                        8 => (header.Width - 1 - y, x),
                        _ => throw ImageHeaderValidation.Rejected()
                    };
                    var at = (sy * header.Width + sx) * 4; var alpha = pixels[at + 3]; for (var c = 0; c < 3; c++) row[1 + x * 3 + c] = (byte)((pixels[at + c] * alpha + 255 * (255 - alpha) + 127) / 255);
                }
                encoder.Write(row);
            }
        }
        var output = new MemoryStream(); try
        {
            output.Write(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }); Span<byte> ihdr = stackalloc byte[13]; ihdr.Clear(); BinaryPrimitives.WriteUInt32BigEndian(ihdr, (uint)width); BinaryPrimitives.WriteUInt32BigEndian(ihdr[4..], (uint)height); ihdr[8] = 8; ihdr[9] = 2;
            Chunk(output, "IHDR"u8, ihdr); Chunk(output, "IDAT"u8, compressed.ToArray()); Chunk(output, "IEND"u8, []); output.Position = 0; return output;
        }
        catch { output.Dispose(); throw; }
    }
    private static void Chunk(Stream output, ReadOnlySpan<byte> type, ReadOnlySpan<byte> bytes)
    {
        Span<byte> number = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(number, (uint)bytes.Length); output.Write(number); output.Write(type); output.Write(bytes); BinaryPrimitives.WriteUInt32BigEndian(number, ImageHeaderValidation.Crc(type, bytes)); output.Write(number);
    }
}

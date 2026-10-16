using PdfSharp.Pdf;
using PdfSharp.Pdf.Advanced;
using PdfSharp.Pdf.IO;

namespace QuillSign.Documents;

public sealed class DocumentOptions
{
    public long MaximumBytes { get; set; } = 10 * 1024 * 1024;
    public int MaximumPages { get; set; } = 20;
}
public sealed class DocumentRejectedException(string message) : Exception(message);
public sealed class DocumentConflictException() : Exception("This draft changed. Reload it before trying again.");
public sealed record PageGeometry(double Width, double Height, int Rotation, double UserUnit, double[] MediaBox, double[] CropBox);

public sealed class PdfValidation(DocumentOptions options)
{
    public IReadOnlyList<PageGeometry> Rewrite(Stream input, Stream output)
    {
        if (input.Length < 16 || input.Length > options.MaximumBytes) throw new DocumentRejectedException("Choose a PDF within the upload size limit.");
        Span<byte> header = stackalloc byte[5];
        input.Position = 0; input.ReadExactly(header); input.Position = 0;
        if (!header.SequenceEqual("%PDF-"u8)) throw new DocumentRejectedException("Choose a valid PDF file.");
        input.Position = Math.Max(0, input.Length - 1024);
        var tail = new byte[input.Length - input.Position]; input.ReadExactly(tail); input.Position = 0;
        if (!System.Text.Encoding.ASCII.GetString(tail).TrimEnd(' ', '\t', '\r', '\n', '\f', '\0').EndsWith("%%EOF", StringComparison.Ordinal))
            throw new DocumentRejectedException("This PDF is incomplete. Export a new PDF and try again.");
        try
        {
            using var document = PdfReader.Open(input, PdfDocumentOpenMode.Modify, password => password.Abort = true);
            if (document is null || document.SecuritySettings.IsEncrypted) throw new DocumentRejectedException("Encrypted PDFs aren't supported. Upload an unencrypted copy.");
            if (document.PageCount < 1 || document.PageCount > options.MaximumPages) throw new DocumentRejectedException($"Choose a PDF with 1–{options.MaximumPages} pages.");
            Inspect(document);
            var pages = new List<PageGeometry>();
            foreach (var page in document.Pages)
            {
                var media = page.MediaBox;
                var crop = page.CropBoxReadOnly.IsZero ? media : page.CropBox;
                var left = Math.Max(media.X1, crop.X1); var bottom = Math.Max(media.Y1, crop.Y1);
                var right = Math.Min(media.X2, crop.X2); var top = Math.Min(media.Y2, crop.Y2);
                var unit = page.Elements.ContainsKey("/UserUnit") ? page.Elements.GetReal("/UserUnit") : 1;
                var rotation = (page.Rotate % 360 + 360) % 360;
                var width = (right - left) * unit; var height = (top - bottom) * unit;
                if (!(new[] { media.X1, media.Y1, media.X2, media.Y2, crop.X1, crop.Y1, crop.X2, crop.Y2 }).All(double.IsFinite) ||
                    !double.IsFinite(width) || !double.IsFinite(height) || !double.IsFinite(unit) ||
                    width is <= 0 or > 14400 || height is <= 0 or > 14400 || unit <= 0 || rotation % 90 != 0)
                    throw new DocumentRejectedException("This PDF has unsupported page dimensions or rotation.");
                page.Rotate = rotation;
                page.CropBox = new PdfRectangle(new PdfSharp.Drawing.XPoint(left, bottom), new PdfSharp.Drawing.XPoint(right, top));
                pages.Add(new(width, height, rotation, unit, [media.X1, media.Y1, media.X2, media.Y2], [left, bottom, right, top]));
            }
            document.Save(output, closeStream: false);
            return pages;
        }
        catch (DocumentRejectedException) { throw; }
        catch (Exception error) when (error is PdfReaderException or InvalidOperationException or ArgumentException or
            FormatException or IndexOutOfRangeException or NullReferenceException or OverflowException or NotImplementedException or InvalidDataException ||
            (error.GetType() == typeof(Exception) && error.TargetSite?.DeclaringType?.Assembly == typeof(PdfReader).Assembly))
        { throw new DocumentRejectedException("This PDF is malformed or unsupported. Export a new PDF and try again."); }
    }

    private static void Inspect(PdfDocument document)
    {
        var pending = new Stack<PdfItem>(document.Internals.GetAllObjects());
        pending.Push(document.Internals.Catalog);
        var visited = new HashSet<PdfItem>(ReferenceEqualityComparer.Instance);
        while (pending.TryPop(out var item))
        {
            if (!visited.Add(item)) continue;
            if (visited.Count > 50000) throw new DocumentRejectedException("This PDF is too complex. Export a simpler PDF and try again.");
            if (item is PdfReference reference) { pending.Push(reference.Value); continue; }
            if (item is PdfDictionary dictionary)
            {
                if (dictionary.Elements.ContainsKey("/XFA")) throw new DocumentRejectedException("XFA forms aren't supported. Export a regular PDF.");
                if (dictionary.Elements["/Type"] is PdfName { Value: "/Sig" } || dictionary.Elements.ContainsKey("/ByteRange") ||
                    (dictionary.Elements["/FT"] is PdfName { Value: "/Sig" } && dictionary.Elements["/V"] is not null and not PdfNull))
                    throw new DocumentRejectedException("Already-signed PDFs aren't supported. Upload an unsigned original.");
                foreach (var value in dictionary.Elements.Values) if (value is not null) pending.Push(value);
            }
            else if (item is PdfArray array) foreach (var value in array.Elements) pending.Push(value);
        }
    }
}

// A seekable file-backed stream with a hard bound on both writes and truncation.
public sealed class BoundedDocumentStream(Stream inner, long maximumBytes) : Stream
{
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => inner.CanSeek;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set { Check(value); inner.Position = value; } }
    private void Check(long end) { if (end < 0 || end > maximumBytes) throw new DocumentRejectedException("The PDF exceeds the upload size limit."); }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
    public override int Read(Span<byte> buffer) => inner.Read(buffer);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => inner.ReadAsync(buffer, ct);
    public override long Seek(long offset, SeekOrigin origin)
    {
        var end = checked(offset + (origin == SeekOrigin.Current ? Position : origin == SeekOrigin.End ? Length : 0));
        Check(end); return inner.Seek(offset, origin);
    }
    public override void SetLength(long value) { Check(value); inner.SetLength(value); }
    public override void Write(byte[] buffer, int offset, int count) { Check(checked(Position + count)); inner.Write(buffer, offset, count); }
    public override void Write(ReadOnlySpan<byte> buffer) { Check(checked(Position + buffer.Length)); inner.Write(buffer); }
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    { Check(checked(Position + buffer.Length)); return inner.WriteAsync(buffer, ct); }
}

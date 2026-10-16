using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using QuillSign.Signing;

namespace QuillSign.Documents;

public sealed record SenderPrefillField(Guid Id, Guid? SignerId, string Type, int Page, decimal X, decimal Y,
    decimal Width, decimal Height, string? Value);
public sealed record RenderedSenderPdf(byte[] Bytes, byte[] Sha256, byte[] SourceSha256);

// No authorization, persistence or send operation lives here. The future workflow must supply
// the current locked document/fields and commit immutable storage references and evidence itself.
public sealed class SenderPdfRenderer
{
    private const long MemoryByteCeiling = 64 * 1024 * 1024;
    // Bound concurrent PDFsharp work/font cache access and peak serialization allocation per process.
    private static readonly object RenderGate = new();
    private readonly long maximumBytes;
    private readonly int maximumPages;
    private readonly int maximumFields;
    public SenderPdfRenderer(long maximumBytes, int maximumPages, int maximumFields)
    {
        if (maximumBytes < 1 || maximumPages is < 1 or > 200 || maximumFields is < 1 or > 200)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        this.maximumBytes = Math.Min(maximumBytes, MemoryByteCeiling);
        this.maximumPages = maximumPages; this.maximumFields = maximumFields;
    }

    public RenderedSenderPdf Render(byte[] source, byte[] expectedSha256, IReadOnlyList<PageGeometry> expectedPages,
        IReadOnlyList<SenderPrefillField> senderFields)
    {
        if (source is null || source.LongLength < 16 || source.LongLength > maximumBytes || expectedSha256 is not { Length: 32 } ||
            expectedPages is null || expectedPages.Count is < 1 || expectedPages.Count > maximumPages ||
            senderFields is null || senderFields.Count > maximumFields)
            throw new DocumentRejectedException("The document or field count exceeds the rendering limits.");
        lock (RenderGate)
        {
            // Own a bounded copy so mutation of a caller's buffer cannot race the hash and parser.
            var ownedSource = source.ToArray(); var sourceHash = SHA256.HashData(ownedSource);
            if (!CryptographicOperations.FixedTimeEquals(sourceHash, expectedSha256)) throw new DocumentRejectedException("The source PDF changed.");
            var fields = senderFields.ToArray();
            var ids = new HashSet<Guid>();
            foreach (var field in fields)
            {
                if (field is null || field.Id == Guid.Empty || !ids.Add(field.Id) || field.SignerId is not null ||
                    field.Type is not ("Text" or "Checkbox" or "Date") || field.Page < 1 || field.Page > expectedPages.Count ||
                    !FieldGeometry.InBounds(field.X, field.Y, field.Width, field.Height))
                    throw new DocumentRejectedException("Use unique, unassigned text, checkbox or date fields entirely inside a page.");
                ValidateValue(field);
            }
            using var input = new MemoryStream(ownedSource, writable: false);
            using var normalized = new MemoryStream();
            // Reuse upload policy and derive geometry from actual bytes, never trust caller metadata.
            var actualPages = new PdfValidation(new DocumentOptions { MaximumBytes = maximumBytes, MaximumPages = maximumPages })
                .Rewrite(input, new BoundedDocumentStream(normalized, maximumBytes));
            if (!GeometryMatches(actualPages, expectedPages)) throw new DocumentRejectedException("The source PDF page information changed.");
            EmbeddedPdfFont.EnsureInitialized();
            normalized.Position = 0;
            using var document = PdfReader.Open(normalized, PdfDocumentOpenMode.Modify);
            for (var i = 0; i < document.PageCount; i++)
            {
                var onPage = fields.Where(f => f.Page == i + 1).ToArray(); if (onPage.Length == 0) continue;
                var page = document.Pages[i]; var geometry = actualPages[i]; var rotation = page.Rotate;
                var width = geometry.Rotation is 90 or 270 ? geometry.Height : geometry.Width;
                var height = geometry.Rotation is 90 or 270 ? geometry.Width : geometry.Height;
                page.Rotate = 0;
                try
                {
                    using var graphics = XGraphics.FromPdfPage(page, XGraphicsPdfPageOptions.Append);
                    graphics.MultiplyTransform(DisplayToGraphics(geometry));
                    foreach (var field in onPage)
                    {
                        var box = new XRect((double)field.X * width, (double)field.Y * height, (double)field.Width * width, (double)field.Height * height);
                        if (field.Type == "Checkbox") DrawCheckbox(graphics, field.Value == "true", box);
                        else DrawText(graphics, field.Value!, box);
                    }
                }
                finally { page.Rotate = rotation; }
            }
            using var output = new MemoryStream();
            document.Save(new BoundedDocumentStream(output, maximumBytes), closeStream: false);
            var bytes = output.ToArray();
            return new(bytes, SHA256.HashData(bytes), sourceHash);
        }
    }

    private static bool GeometryMatches(IReadOnlyList<PageGeometry> actual, IReadOnlyList<PageGeometry> expected) =>
        actual.Count == expected.Count && actual.Zip(expected).All(pair => pair.Second is not null &&
            pair.First.Rotation == pair.Second.Rotation && Near(pair.First.Width, pair.Second.Width) && Near(pair.First.Height, pair.Second.Height) &&
            Near(pair.First.UserUnit, pair.Second.UserUnit) && BoxMatches(pair.First.MediaBox, pair.Second.MediaBox) && BoxMatches(pair.First.CropBox, pair.Second.CropBox));
    private static bool Near(double actual, double expected) => double.IsFinite(expected) && Math.Abs(actual - expected) < .00001;
    private static bool BoxMatches(double[] actual, double[]? expected) => expected is { Length: 4 } && actual.Zip(expected).All(p => Near(p.First, p.Second));
    private static XMatrix DisplayToGraphics(PageGeometry p)
    {
        var b = p.CropBox; var h = p.MediaBox[3] - p.MediaBox[1]; var s = 1 / p.UserUnit;
        return p.Rotation switch
        {
            0 => new(s, 0, 0, s, b[0], h - b[3]),
            90 => new(0, -s, s, 0, b[0], h - b[1]),
            180 => new(-s, 0, 0, -s, b[2], h - b[1]),
            270 => new(0, s, -s, 0, b[2], h - b[3]),
            _ => throw new DocumentRejectedException("Unsupported page rotation.")
        };
    }
    private static string Normalize(string value)
    {
        try { return value.Replace("\r\n", "\n").Replace('\r', '\n').Normalize(NormalizationForm.FormC); }
        catch (ArgumentException) { throw new DocumentRejectedException("The sender field contains invalid Unicode text."); }
    }
    private static void ValidateValue(SenderPrefillField field)
    {
        var value = field.Value;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4000) throw new DocumentRejectedException("Fill or delete every sender field.");
        if (field.Type == "Checkbox")
        { if (value is not ("true" or "false")) throw new DocumentRejectedException("Use true or false for a checkbox."); return; }
        if (field.Type == "Date" && !DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
            throw new DocumentRejectedException("Use a valid YYYY-MM-DD date.");
        foreach (var rune in Normalize(value).EnumerateRunes())
        {
            if (rune.Value == '\n') continue;
            var allowed = rune.Value is >= 0x20 and <= 0x052f or >= 0x1e00 and <= 0x1fff or >= 0x2000 and <= 0x206f or >= 0x20a0 and <= 0x20cf;
            if (!allowed || Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.NonSpacingMark or
                UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark || !EmbeddedPdfFont.Supports(rune))
                throw new DocumentRejectedException($"This field contains unsupported text (U+{rune.Value:X4}). Use supported text before sending.");
        }
    }
    private static void DrawText(XGraphics graphics, string value, XRect box)
    {
        const double padding = 2; var lines = Normalize(value).Split('\n');
        if (box.Width <= 2 * padding || box.Height <= 2 * padding) throw new DocumentRejectedException("Enlarge the sender text field.");
        XFont? chosen = null;
        for (var size = 12d; size >= 8; size -= .25)
        {
            var candidate = new XFont(EmbeddedPdfFont.Family, size, XFontStyleEx.Regular, new XPdfFontOptions(PdfFontEncoding.Unicode));
            if (candidate.GetHeight() * lines.Length <= box.Height - 2 * padding &&
                lines.All(line => graphics.MeasureString(line, candidate).Width <= box.Width - 2 * padding)) { chosen = candidate; break; }
        }
        if (chosen is null) throw new DocumentRejectedException("The sender text does not fit at 8–12 points. Enlarge the field or add line breaks.");
        for (var i = 0; i < lines.Length; i++)
            if (lines[i].Length > 0) graphics.DrawString(lines[i], chosen, XBrushes.Black,
                new XRect(box.X + padding, box.Y + padding + i * chosen.GetHeight(), box.Width - 2 * padding, chosen.GetHeight()), XStringFormats.TopLeft);
    }
    private static void DrawCheckbox(XGraphics graphics, bool selected, XRect box)
    {
        var side = Math.Min(box.Width, box.Height);
        if (side < 8) throw new DocumentRejectedException("Enlarge the sender checkbox field.");
        var x = box.X + (box.Width - side) / 2; var y = box.Y + (box.Height - side) / 2;
        var pen = new XPen(XColors.Black, 1); graphics.DrawRectangle(pen, x + 1, y + 1, side - 2, side - 2);
        if (!selected) return;
        graphics.DrawLine(pen, x + .2 * side, y + .5 * side, x + .43 * side, y + .75 * side);
        graphics.DrawLine(pen, x + .43 * side, y + .75 * side, x + .83 * side, y + .2 * side);
    }
}

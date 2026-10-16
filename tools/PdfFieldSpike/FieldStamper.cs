using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using QuillSign.Documents;
using QuillSign.Signing;
using UglyToad.PdfPig.Fonts.TrueType;
using UglyToad.PdfPig.Fonts.TrueType.Parser;

namespace PdfFieldSpike;

internal enum StampKind { Text, FullName, Date, DateSigned, Checkbox, Signature, Initials }
internal sealed record Stamp(StampKind Kind, int Page, decimal X, decimal Y, decimal Width, decimal Height,
    string? Value = null, byte[]? Image = null);

// A feasibility prototype. No caller-supplied identity, consent, date or signature is trusted by a production API here.
internal sealed class FieldStamper
{
    private readonly TrueTypeFont font;
    public FieldStamper(byte[] fontBytes)
    {
        if (Convert.ToHexStringLower(SHA256.HashData(fontBytes)) != "76d04c18ea243f426b7de1f3ad208e927008f961dc5945e5aad352d0dfde8ee8")
            throw new InvalidDataException("Unexpected font bytes.");
        font = TrueTypeFontParser.Parse(new TrueTypeDataBytes(fontBytes));
        EmbeddedPdfFont.EnsureInitialized();
    }

    public byte[] Render(byte[] source, byte[] expectedHash, IReadOnlyList<PageGeometry> pages, IReadOnlyList<Stamp> fields,
        bool naiveTransform = false, bool fiducial = true)
    {
        if (expectedHash.Length != 32 || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(source), expectedHash))
            throw new InvalidDataException("Source document changed.");
        if (fields.Count > 200) throw new InvalidDataException("Too many fields.");
        foreach (var field in fields)
        {
            if (!Enum.IsDefined(field.Kind) || field.Page < 1 || field.Page > pages.Count ||
                !FieldGeometry.InBounds(field.X, field.Y, field.Width, field.Height)) throw new InvalidDataException("Invalid field geometry or type.");
            if (field.Kind is StampKind.Signature or StampKind.Initials) ValidateImage(field.Image);
            else ValidateValue(field);
        }
        using var input = new MemoryStream(source);
        using var document = PdfReader.Open(input, PdfDocumentOpenMode.Modify);
        if (document.PageCount != pages.Count) throw new InvalidDataException("Page metadata changed.");
        for (var i = 0; i < document.PageCount; i++)
        {
            var page = document.Pages[i]; var geometry = pages[i]; var originalRotation = page.Rotate;
            if (originalRotation != geometry.Rotation || !Matches(page.CropBox, geometry.CropBox) ||
                !Matches(page.MediaBox, geometry.MediaBox) ||
                (page.Elements.ContainsKey("/UserUnit") ? page.Elements.GetReal("/UserUnit") : 1) != geometry.UserUnit)
                throw new InvalidDataException("Page metadata changed.");
            var width = geometry.Rotation is 90 or 270 ? geometry.Height : geometry.Width;
            var height = geometry.Rotation is 90 or 270 ? geometry.Width : geometry.Height;
            // Keep existing content and page metadata. Draw through an explicit visible-page transform,
            // then restore /Rotate after closing the append graphics so text/images remain upright in viewers.
            page.Rotate = 0;
            try
            {
                using var graphics = XGraphics.FromPdfPage(page, XGraphicsPdfPageOptions.Append);
                if (!naiveTransform) graphics.MultiplyTransform(DisplayToGraphics(geometry));
                if (fiducial) graphics.DrawRectangle(new XSolidBrush(XColor.FromArgb(30, 120, 220)),
                    .05 * width, .05 * height, .25 * width, .12 * height);
                foreach (var field in fields.Where(x => x.Page == i + 1))
                {
                    var box = new XRect((double)field.X * width, (double)field.Y * height,
                        (double)field.Width * width, (double)field.Height * height);
                    if (field.Kind is StampKind.Signature or StampKind.Initials) DrawImage(graphics, field.Image!, box);
                    else if (field.Kind == StampKind.Checkbox) DrawCheckbox(graphics, field.Value == "true", box);
                    else DrawText(graphics, field.Value!, box);
                }
            }
            finally { page.Rotate = originalRotation; }
        }
        using var output = new MemoryStream(); document.Save(output, closeStream: false); return output.ToArray();
    }

    // Input coordinates and font sizes are physical PDF points in the visible rotated crop.
    // XGraphics itself uses a downward Y direction with an unrotated MediaBox-height reference.
    private static XMatrix DisplayToGraphics(PageGeometry p)
    {
        var b = p.CropBox; var mediaHeight = p.MediaBox[3] - p.MediaBox[1]; var s = 1 / p.UserUnit;
        return p.Rotation switch
        {
            0 => new(s, 0, 0, s, b[0], mediaHeight - b[3]),
            90 => new(0, -s, s, 0, b[0], mediaHeight - b[1]),
            180 => new(-s, 0, 0, -s, b[2], mediaHeight - b[1]),
            270 => new(0, s, -s, 0, b[2], mediaHeight - b[3]),
            _ => throw new InvalidDataException("Unsupported page rotation.")
        };
    }
    private static bool Matches(PdfRectangle actual, double[] expected) => expected.Length == 4 &&
        new[] { actual.X1, actual.Y1, actual.X2, actual.Y2 }.Zip(expected).All(x => Math.Abs(x.First - x.Second) < .00001);

    private void ValidateValue(Stamp field)
    {
        if (string.IsNullOrWhiteSpace(field.Value) || field.Value.Length > 4000) throw new InvalidDataException("Missing or oversized field value.");
        if (field.Kind == StampKind.Checkbox)
        { if (field.Value is not ("true" or "false")) throw new InvalidDataException("Invalid checkbox value."); return; }
        if (field.Kind is StampKind.Date or StampKind.DateSigned && !DateOnly.TryParseExact(field.Value, "yyyy-MM-dd",
            CultureInfo.InvariantCulture, DateTimeStyles.None, out _)) throw new InvalidDataException("Invalid date value.");
        foreach (var rune in Normalize(field.Value).EnumerateRunes())
        {
            if (rune.Value == '\n') continue;
            var allowed = rune.Value is >= 0x20 and <= 0x052f or >= 0x1e00 and <= 0x1fff or >= 0x2000 and <= 0x206f or >= 0x20a0 and <= 0x20cf;
            var category = Rune.GetUnicodeCategory(rune);
            if (!allowed || category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.NonSpacingMark or
                UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark ||
                font.TableRegister.CMapTable is null || !font.TableRegister.CMapTable.TryGetGlyphIndex(rune.Value, out var glyph) || glyph == 0)
                throw new InvalidDataException($"Unsupported glyph/script U+{rune.Value:X4}; a font/shaping strategy is required.");
        }
    }
    private static string Normalize(string value) => value.Replace("\r\n", "\n").Replace('\r', '\n').Normalize(NormalizationForm.FormC);

    private static void DrawText(XGraphics graphics, string value, XRect box)
    {
        const double padding = 2;
        var lines = Normalize(value).Split('\n');
        if (box.Width <= 2 * padding || box.Height <= 2 * padding) throw new InvalidDataException("Field is too small for readable text.");
        XFont? chosen = null;
        for (var size = 12d; size >= 8; size -= .25)
        {
            var candidate = new XFont(EmbeddedPdfFont.Family, size, XFontStyleEx.Regular, new XPdfFontOptions(PdfFontEncoding.Unicode));
            if (candidate.GetHeight() * lines.Length <= box.Height - 2 * padding &&
                lines.All(line => graphics.MeasureString(line, candidate).Width <= box.Width - 2 * padding)) { chosen = candidate; break; }
        }
        if (chosen is null) throw new InvalidDataException("Text does not fit at 8–12 points. Enlarge the field or add explicit line breaks.");
        for (var i = 0; i < lines.Length; i++)
            if (lines[i].Length > 0) graphics.DrawString(lines[i], chosen, XBrushes.Black,
                new XRect(box.X + padding, box.Y + padding + i * chosen.GetHeight(), box.Width - 2 * padding, chosen.GetHeight()), XStringFormats.TopLeft);
    }
    private static void DrawCheckbox(XGraphics graphics, bool selected, XRect box)
    {
        var side = Math.Min(box.Width, box.Height);
        if (side < 8) throw new InvalidDataException("Field is too small for a readable checkbox.");
        var x = box.X + (box.Width - side) / 2; var y = box.Y + (box.Height - side) / 2;
        var pen = new XPen(XColors.Black, 1);
        graphics.DrawRectangle(pen, x + 1, y + 1, side - 2, side - 2);
        if (selected)
        {
            graphics.DrawLine(pen, x + .2 * side, y + .5 * side, x + .43 * side, y + .75 * side);
            graphics.DrawLine(pen, x + .43 * side, y + .75 * side, x + .83 * side, y + .2 * side);
        }
    }
    private static void ValidateImage(byte[]? bytes)
    {
        if (bytes is null || bytes.Length is < 24 or > 262144 || !bytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
            throw new InvalidDataException("A bounded PNG signature image is required.");
        var width = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(16, 4));
        var height = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(20, 4));
        if (width is < 1 or > 2048 || height is < 1 or > 2048 || (long)width * height > 1_048_576)
            throw new InvalidDataException("Signature image dimensions are too large.");
    }
    private static void DrawImage(XGraphics graphics, byte[] bytes, XRect box)
    {
        if (Math.Min(box.Width, box.Height) < 8) throw new InvalidDataException("Field is too small for a readable image.");
        using var input = new MemoryStream(bytes, 0, bytes.Length, writable: false, publiclyVisible: true);
        using var image = XImage.FromStream(input);
        var scale = Math.Min(box.Width / image.PixelWidth, box.Height / image.PixelHeight);
        var width = image.PixelWidth * scale; var height = image.PixelHeight * scale;
        graphics.DrawImage(image, box.X + (box.Width - width) / 2, box.Y + (box.Height - height) / 2, width, height);
    }
}

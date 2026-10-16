using PdfSharp.Drawing;
using PdfSharp.Pdf;
using QuillSign.Documents;
using SkiaSharp;

namespace PdfFieldSpike;

internal sealed record PageCase(string Name, double Width, double Height, int Rotation = 0, double Left = 0,
    double Bottom = 0, double CropInset = 0, double UserUnit = 1);
internal static class Fixtures
{
    public static (byte[] Bytes, IReadOnlyList<PageGeometry> Pages) Create(PageCase spec)
    {
        using var document = new PdfDocument();
        document.Info.Title = "Synthetic field geometry: " + spec.Name;
        var page = document.AddPage();
        page.MediaBox = new PdfRectangle(new XPoint(spec.Left, spec.Bottom), new XPoint(spec.Left + spec.Width, spec.Bottom + spec.Height));
        page.CropBox = new PdfRectangle(new XPoint(spec.Left + spec.CropInset, spec.Bottom + spec.CropInset),
            new XPoint(spec.Left + spec.Width - spec.CropInset, spec.Bottom + spec.Height - spec.CropInset));
        page.Elements.SetReal("/UserUnit", spec.UserUnit);
        using (var graphics = XGraphics.FromPdfPage(page))
        {
            graphics.DrawRectangle(XBrushes.Red, spec.Left + spec.Width * .45, spec.Height - (spec.Bottom + spec.Height * .55),
                spec.Width * .08, spec.Height * .04);
            graphics.DrawString("BASE", new XFont("QuillFieldSpike", 10, XFontStyleEx.Regular, new XPdfFontOptions(PdfFontEncoding.Unicode)), XBrushes.White,
                new XRect(spec.Left + spec.Width * .45 + 2, spec.Height - (spec.Bottom + spec.Height * .55) + 2,
                    spec.Width * .08 - 4, spec.Height * .04 - 4), XStringFormats.TopLeft);
        }
        page.Rotate = spec.Rotation;
        using var original = new MemoryStream(); document.Save(original, closeStream: false); original.Position = 0;
        using var normalized = new MemoryStream();
        var pages = new PdfValidation(new DocumentOptions()).Rewrite(original, normalized);
        return (normalized.ToArray(), pages);
    }
    public static byte[] Mark(int width, int height)
    {
        using var bitmap = new SKBitmap(width, height);
        using (var canvas = new SKCanvas(bitmap))
        using (var paint = new SKPaint { Color = new SKColor(100, 30, 140), StrokeWidth = 4, IsAntialias = true, Style = SKPaintStyle.Stroke })
        using (var path = new SKPathBuilder())
        {
            canvas.Clear(SKColors.Transparent);
            path.MoveTo(width * .1f, height * .7f); path.LineTo(width * .3f, height * .2f);
            path.LineTo(width * .5f, height * .75f); path.LineTo(width * .8f, height * .3f); path.LineTo(width * .9f, height * .5f);
            using var shape = path.Detach();
            canvas.DrawPath(shape, paint);
        }
        using var image = SKImage.FromBitmap(bitmap); using var data = image.Encode(SKEncodedImageFormat.Png, 100); return data.ToArray();
    }
    public static Stamp[] Fields(byte[] signature, byte[] initials) =>
    [
        new(StampKind.Text, 1, .08m, .22m, .84m, .09m, "Synthetic field stamping"),
        new(StampKind.Text, 1, .08m, .35m, .84m, .10m, "Café déjà vu — Καλημέρα — Пример — € 123"),
        new(StampKind.FullName, 1, .08m, .50m, .4m, .08m, "Synthetic signer"),
        new(StampKind.DateSigned, 1, .52m, .50m, .4m, .08m, "2026-10-16"),
        new(StampKind.Date, 1, .08m, .63m, .35m, .08m, "2028-02-29"),
        new(StampKind.Checkbox, 1, .08m, .77m, .04m, .04m, "true"),
        new(StampKind.Checkbox, 1, .18m, .77m, .04m, .04m, "false"),
        new(StampKind.Signature, 1, .5m, .65m, .4m, .10m, Image: signature),
        new(StampKind.Initials, 1, .5m, .80m, .2m, .08m, Image: initials),
        new(StampKind.Text, 1, .08m, .89m, .84m, .08m, "Line one\nLine two")
    ];
}

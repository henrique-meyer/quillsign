using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Runtime.Versioning;
using PDFtoImage;
using PdfFieldSpike;
using QuillSign.Documents;
using QuillSign.Signing;
using SkiaSharp;
using PigDocument = UglyToad.PdfPig.PdfDocument;

[assembly: SupportedOSPlatform("Windows")]
[assembly: SupportedOSPlatform("Linux")]

if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("This harness is validated on Windows and Linux.");
var output = Path.GetFullPath(args.FirstOrDefault() ?? Path.Combine("artifacts", "pdf-fields"));
Directory.CreateDirectory(output);
var fontBytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "fonts", "LiberationSans-Regular.ttf"));
var stamper = new FieldStamper(fontBytes);
var signatureAsset = SignaturePng.Normalize(Fixtures.Mark(320,80)); var initialsAsset = SignaturePng.Normalize(Fixtures.Mark(160,80));
var signature = signatureAsset.Bytes; var initials = initialsAsset.Bytes;
File.WriteAllBytes(Path.Combine(output,"normalized-signature.png"),signature); File.WriteAllBytes(Path.Combine(output,"normalized-initials.png"),initials);
var fields = Fixtures.Fields(signature, initials);
PageCase[] cases =
[
    new("letter", 612, 792), new("a4", 595, 842), new("landscape", 792, 612),
    new("rotate-90", 612, 792, 90), new("rotate-180", 612, 792, 180), new("rotate-270", 612, 792, 270),
    new("crop-offset", 612, 792, Left: 15, Bottom: -20, CropInset: 30),
    new("rotate-90-crop", 612, 792, 90, Left: -30, Bottom: 25, CropInset: 40),
    new("rotate-270-crop-unit-2", 612, 792, 270, Left: 20, Bottom: -15, CropInset: 35, UserUnit: 2)
];
var results = new List<object>();
var productionResults = new List<object>();
foreach (var spec in cases)
{
    var source = Fixtures.Create(spec); var sourceHash = SHA256.HashData(source.Bytes);
    var bytes = stamper.Render(source.Bytes, sourceHash, source.Pages, fields);
    File.WriteAllBytes(Path.Combine(output, spec.Name + ".source.pdf"), source.Bytes);
    File.WriteAllBytes(Path.Combine(output, spec.Name + ".pdf"), bytes);
    var p = source.Pages[0]; var width = p.Rotation is 90 or 270 ? p.Height : p.Width; var height = p.Rotation is 90 or 270 ? p.Width : p.Height;
    // The explicit viewport is in physical points at 72 dpi; do not depend on native page-size APIs' UserUnit interpretation.
    var options = new RenderOptions(Dpi: 72, Width: (int)Math.Round(width), Height: (int)Math.Round(height));
    using var image = Conversion.ToImage(bytes, page: 0, options: options);
    using var original = Conversion.ToImage(source.Bytes, page: 0, options: options);
    using (var png = image.Encode(SKEncodedImageFormat.Png, 100)) File.WriteAllBytes(Path.Combine(output, spec.Name + ".png"), png.ToArray());
    var pixels = image.Pixels; var blue = Find(image, pixels, c => c.Red < 70 && c.Green is > 80 and < 170 && c.Blue > 180);
    Require(MatchesFiducial(blue, image.Width, image.Height), $"{spec.Name}: visible fiducial is misplaced: {JsonSerializer.Serialize(blue)} on {image.Width}x{image.Height}.");
    var redBefore = Find(original, original.Pixels, c => c.Red > 180 && c.Green < 70 && c.Blue < 70);
    var redAfter = Find(image, pixels, c => c.Red > 180 && c.Green < 70 && c.Blue < 70);
    Require(redBefore.Count > 0 && SameBounds(redBefore, redAfter, 1), spec.Name + ": original visible content changed.");
    var text = Find(image, pixels, Black, (.08, .22, .84, .09));
    Require(text.Count > 30 && text.Right - text.Left > 2 * (text.Bottom - text.Top), spec.Name + ": first text line is missing, clipped or not upright.");
    var checkedBox = Find(image, pixels, Black, CheckboxInterior(.08, image.Width, image.Height));
    var uncheckedBox = Find(image, pixels, Black, CheckboxInterior(.18, image.Width, image.Height));
    Require(checkedBox.Count > 5 && uncheckedBox.Count == 0, spec.Name + ": checkbox interiors aren't distinguishable.");
    var mark = Find(image, pixels, c => c.Red is > 65 and < 150 && c.Green < 80 && c.Blue is > 90 and < 190, (.5, .65, .4, .10));
    var initialMark = Find(image, pixels, c => c.Red is > 65 and < 150 && c.Green < 80 && c.Blue is > 90 and < 190, (.5, .80, .2, .08));
    Require(mark.Count > 20 && Math.Abs((double)(mark.Right - mark.Left + 1) / (mark.Bottom - mark.Top + 1) - 5.42) < .6,
        spec.Name + ": signature image lost its aspect ratio.");
    Require(initialMark.Count > 20 && Math.Abs((double)(initialMark.Right - initialMark.Left + 1) / (initialMark.Bottom - initialMark.Top + 1) - 2.75) < .5,
        spec.Name + ": initials image lost its aspect ratio.");
    using var parsed = PigDocument.Open(bytes);
    var extracted = Flatten(parsed.GetPage(1).Text);
    Require(extracted.Contains("BASE"), spec.Name + ": embedded original text was lost.");
    foreach (var field in fields.Where(x => x.Kind is not (StampKind.Signature or StampKind.Initials or StampKind.Checkbox)))
        Require(extracted.Contains(Flatten(field.Value!)), spec.Name + ": independent parser did not recover a complete field value.");
    Require(AllBlackInsideFields(image, pixels, fields), spec.Name + ": a text/checkbox pixel escaped its field bounds.");
    var nativeSize = Conversion.GetPageSizes(bytes).First();
    results.Add(new { spec.Name, spec.Rotation, spec.UserUnit, physicalWidth = width, physicalHeight = height,
        nativeReportedWidth = nativeSize.Width, nativeReportedHeight = nativeSize.Height, image.Width, image.Height,
        blue, text, checkedPixels = checkedBox.Count, uncheckedPixels = uncheckedBox.Count, mark, initialMark,
        sourceSha256 = Convert.ToHexStringLower(sourceHash), outputSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes = bytes.Length });
    Console.WriteLine($"PASS {spec.Name}: fiducial, original content, upright/complete text, checkbox states and image aspect ratios.");
    var senderStamps = fields.Where(f => f.Kind is StampKind.Text or StampKind.Date or StampKind.Checkbox).ToArray();
    var senderFields = senderStamps.Select(f => new SenderPrefillField(Guid.NewGuid(), null, f.Kind.ToString(), f.Page, f.X, f.Y, f.Width, f.Height, f.Value)).ToArray();
    var sender = new SenderPdfRenderer(25 * 1024 * 1024, 20, 200).Render(source.Bytes, sourceHash, source.Pages, senderFields);
    Require(sender.Sha256.SequenceEqual(SHA256.HashData(sender.Bytes)) && sender.SourceSha256.SequenceEqual(sourceHash), spec.Name + ": sender output hash mismatch.");
    File.WriteAllBytes(Path.Combine(output, spec.Name + ".sender.pdf"), sender.Bytes);
    using var senderImage = Conversion.ToImage(sender.Bytes, page: 0, options: options);
    using (var png = senderImage.Encode(SKEncodedImageFormat.Png, 100)) File.WriteAllBytes(Path.Combine(output, spec.Name + ".sender.png"), png.ToArray());
    var senderPixels = senderImage.Pixels;
    var senderRed = Find(senderImage, senderPixels, c => c.Red > 180 && c.Green < 70 && c.Blue < 70);
    var senderText = Find(senderImage, senderPixels, Black, (.08, .22, .84, .09));
    Require(SameBounds(redBefore, senderRed, 1), spec.Name + ": production renderer altered original content.");
    Require(senderText.Count > 30 && senderText.Right - senderText.Left > 2 * (senderText.Bottom - senderText.Top), spec.Name + ": production text is not upright.");
    Require(AllBlackInsideFields(senderImage, senderPixels, senderStamps), spec.Name + ": production text/checkbox escaped field bounds.");
    Require(Find(senderImage, senderPixels, Black, CheckboxInterior(.08, senderImage.Width, senderImage.Height)).Count > 5 &&
        Find(senderImage, senderPixels, Black, CheckboxInterior(.18, senderImage.Width, senderImage.Height)).Count == 0, spec.Name + ": production checkbox state is wrong.");
    Require(Find(senderImage, senderPixels, c => c.Red < 70 && c.Green is > 80 and < 170 && c.Blue > 180).Count == 0, spec.Name + ": production output contains a diagnostic fiducial.");
    using (var senderParsed = PigDocument.Open(sender.Bytes))
    {
        var senderExtracted = Flatten(senderParsed.GetPage(1).Text); Require(senderExtracted.Contains("BASE"), spec.Name + ": production original text lost.");
        foreach (var field in senderFields.Where(f => f.Type != "Checkbox")) Require(senderExtracted.Contains(Flatten(field.Value!)), spec.Name + ": production text lost.");
    }
    productionResults.Add(new { spec.Name, bytes = sender.Bytes.Length, sha256 = Convert.ToHexStringLower(sender.Sha256), senderText });
    Console.WriteLine($"PASS production sender renderer {spec.Name}: original content, upright/complete in-bounds text, checkbox states and output hashes.");
}

var basis = Fixtures.Create(cases[0]); var basisHash = SHA256.HashData(basis.Bytes); var first = fields[0]; var rejected = new List<string>();
void Reject(string name, Action action)
{
    try { action(); }
    catch (InvalidDataException) { rejected.Add(name); return; }
    throw new InvalidOperationException("Expected rejection: " + name);
}
foreach (var field in new[]
{
    first with { X = -.1m }, first with { Width = 0 }, first with { X = .9m, Width = .2m }, first with { Page = 2 },
    first with { Value = null }, first with { Value = " " }, first with { Value = new string('A', 4001) },
    first with { Value = new string('A', 150) }, first with { Width = .01m, Height = .01m },
    first with { Value = "漢字" }, first with { Value = "🙂" }, first with { Value = "مرحبا" }, first with { Value = "אבג" },
    first with { Value = "bad\0value" }, first with { Value = "tab\tvalue" },
    first with { Kind = StampKind.Date, Value = "2026-02-29" }, first with { Kind = StampKind.Checkbox, Value = "yes" },
    first with { Kind = StampKind.Signature, Image = null }, first with { Kind = StampKind.Signature, Image = [1, 2, 3] },
    first with { Kind = (StampKind)999 }
}) Reject("invalid-field-" + rejected.Count, () => stamper.Render(basis.Bytes, basisHash, basis.Pages, [field]));
Reject("changed-source", () => stamper.Render(basis.Bytes.Concat(new byte[] { 0 }).ToArray(), basisHash, basis.Pages, fields));
Reject("changed-page-metadata", () => stamper.Render(basis.Bytes, basisHash, [basis.Pages[0] with { Rotation = 90 }], fields));
Reject("field-count-limit", () => stamper.Render(basis.Bytes, basisHash, basis.Pages, Enumerable.Repeat(first, 201).ToList()));
var oversizedImage = signature.ToArray(); System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(oversizedImage.AsSpan(16, 4), 100_000);
Reject("oversized-image-dimensions", () => stamper.Render(basis.Bytes, basisHash, basis.Pages, [fields[7] with { Image = oversizedImage }]));
var changedFont = fontBytes.ToArray(); changedFont[100] ^= 1;
Reject("changed-font", () => new FieldStamper(changedFont));
// Canonically equivalent combining accents must render and extract as NFC rather than a missing combining glyph.
var nfc = stamper.Render(basis.Bytes, basisHash, basis.Pages, [first with { Value = "Cafe\u0301" }]);
using (var parsed = PigDocument.Open(nfc)) Require(Flatten(parsed.GetPage(1).Text).Contains("Café"), "NFC text was lost.");
var fitted = stamper.Render(basis.Bytes, basisHash, basis.Pages, [first with { Value = new string('A', 80) }]);
double fittedFontSize;
using (var parsed = PigDocument.Open(fitted))
{
    fittedFontSize = parsed.GetPage(1).Letters.Where(x => x.Value == "A").Min(x => x.FontSize);
    Require(fittedFontSize is >= 8 and < 12, "Adaptive text sizing wasn't independently observed.");
}

var rotated = Fixtures.Create(cases[7]); var naive = stamper.Render(rotated.Bytes, SHA256.HashData(rotated.Bytes), rotated.Pages, [], naiveTransform: true);
File.WriteAllBytes(Path.Combine(output, "naive-transform.pdf"), naive);
using (var image = Conversion.ToImage(naive, page: 0, options: new RenderOptions(Dpi: 72)))
    Require(!MatchesFiducial(Find(image, image.Pixels, c => c.Red < 70 && c.Green is > 80 and < 170 && c.Blue > 180), image.Width, image.Height),
        "The regression check failed to detect a deliberately naive transform.");

var report = new { pdfsharp = "6.2.4", pdftoimage = "5.4.0", pdfpig = "0.1.16", font = "Liberation Sans 2.1.5 / OFL-1.1",
    cases = results, productionCases = productionResults, rejected, canonicalAccent = true, fittedFontSize, naiveTransformDetected = true,
    signatureNormalization = new { signatureAsset.Version,signatureAsset.Width,signatureAsset.Height,
        sha256 = Convert.ToHexStringLower(signatureAsset.Sha256),initialsWidth = initialsAsset.Width,initialsHeight = initialsAsset.Height } };
File.WriteAllText(Path.Combine(output, "report.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"PASS {cases.Length} prototype and {productionResults.Count} production geometry cases, {rejected.Count} negative cases, NFC and naive-transform detection. Outputs: {output}");

static string Flatten(string value) => Regex.Replace(value.Normalize(NormalizationForm.FormC), @"\s+", "");
static bool Black(SKColor c) => c.Red < 65 && c.Green < 65 && c.Blue < 65;
static bool AllBlackInsideFields(SKBitmap image, SKColor[] pixels, IReadOnlyList<Stamp> fields)
{
    for (var i = 0; i < pixels.Length; i++)
    {
        if (!Black(pixels[i])) continue;
        var x = i % image.Width; var y = i / image.Width;
        if (!fields.Any(f => f.Kind is not (StampKind.Signature or StampKind.Initials) &&
            x >= (double)f.X * image.Width - 1 && y >= (double)f.Y * image.Height - 1 &&
            x <= (double)(f.X + f.Width) * image.Width + 1 && y <= (double)(f.Y + f.Height) * image.Height + 1)) return false;
    }
    return true;
}
static (double X, double Y, double Width, double Height) CheckboxInterior(double x, int width, int height)
{
    // Ignore outline antialiasing, which changes with fractional pixel alignment between adjacent fields.
    var side = Math.Min(.04 * width, .04 * height);
    return (x + (.04 * width - side) / 2 / width + 3d / width,
        .77 + (.04 * height - side) / 2 / height + 3d / height, (side - 6) / width, (side - 6) / height);
}
static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
static bool SameBounds(PixelBounds a, PixelBounds b, int tolerance) => b.Count > 0 && Math.Abs(a.Left - b.Left) <= tolerance &&
    Math.Abs(a.Top - b.Top) <= tolerance && Math.Abs(a.Right - b.Right) <= tolerance && Math.Abs(a.Bottom - b.Bottom) <= tolerance;
static bool MatchesFiducial(PixelBounds b, int w, int h) => b.Count > 0 && Math.Abs(b.Left - .05 * w) < 2.5 &&
    Math.Abs(b.Top - .05 * h) < 2.5 && Math.Abs(b.Right + 1 - .30 * w) < 2.5 && Math.Abs(b.Bottom + 1 - .17 * h) < 2.5;
static PixelBounds Find(SKBitmap image, SKColor[] pixels, Func<SKColor, bool> predicate,
    (double X, double Y, double Width, double Height)? region = null)
{
    var left = image.Width; var top = image.Height; var right = -1; var bottom = -1; var count = 0;
    var r = region ?? (0d, 0d, 1d, 1d);
    for (var y = Math.Max(0, (int)(r.Y * image.Height)); y < Math.Min(image.Height, (int)Math.Ceiling((r.Y + r.Height) * image.Height)); y++)
        for (var x = Math.Max(0, (int)(r.X * image.Width)); x < Math.Min(image.Width, (int)Math.Ceiling((r.X + r.Width) * image.Width)); x++)
            if (predicate(pixels[y * image.Width + x])) { left = Math.Min(left, x); top = Math.Min(top, y); right = Math.Max(right, x); bottom = Math.Max(bottom, y); count++; }
    return new(left, top, right, bottom, count);
}
internal sealed record PixelBounds(int Left, int Top, int Right, int Bottom, int Count);

using System.Security.Cryptography;
using System.Text;
using PdfSharp.Fonts;
using UglyToad.PdfPig.Fonts.TrueType;
using UglyToad.PdfPig.Fonts.TrueType.Parser;

namespace QuillSign.Documents;

internal static class EmbeddedPdfFont
{
    internal const string Family = "QuillSignDocument";
    internal const string Sha256 = "76d04c18ea243f426b7de1f3ad208e927008f961dc5945e5aad352d0dfde8ee8";
    private static readonly object Gate = new();
    private static bool initialized;
    private static readonly Lazy<FontData> Data = new(() =>
    {
        using var input = typeof(EmbeddedPdfFont).Assembly.GetManifestResourceStream("QuillSign.Fonts.LiberationSans-Regular.ttf")
            ?? throw new InvalidOperationException("The embedded document font is missing.");
        if (input.Length != 410712) throw new InvalidOperationException("The embedded document font has an unexpected size.");
        var bytes = new byte[410712]; input.ReadExactly(bytes);
        if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != Sha256) throw new InvalidOperationException("The embedded document font failed its integrity check.");
        return new(bytes, TrueTypeFontParser.Parse(new TrueTypeDataBytes(bytes)));
    });

    internal static void EnsureInitialized()
    {
        lock (Gate)
        {
            if (initialized) return;
            _ = Data.Value;
            if (GlobalFontSettings.FontResolver is not null)
                throw new InvalidOperationException("An unexpected PDF font resolver is already configured.");
            GlobalFontSettings.FontResolver = new Resolver();
            initialized = true;
        }
    }
    internal static bool Supports(Rune rune)
    {
        var cmap = Data.Value.Parsed.TableRegister.CMapTable;
        return cmap is not null && cmap.TryGetGlyphIndex(rune.Value, out var glyph) && glyph != 0;
    }
    private sealed record FontData(byte[] Bytes, TrueTypeFont Parsed);
    private sealed class Resolver : IFontResolver
    {
        public FontResolverInfo ResolveTypeface(string familyName, bool bold, bool italic) =>
            familyName == Family && !bold && !italic ? new("LiberationSans-Regular")
                : throw new InvalidOperationException("An unsupported document font was requested.");
        // PDFsharp treats the returned bytes as font data; no caller receives this array.
        public byte[] GetFont(string faceName) => faceName == "LiberationSans-Regular" ? Data.Value.Bytes
            : throw new InvalidOperationException("An unsupported document font face was requested.");
    }
}

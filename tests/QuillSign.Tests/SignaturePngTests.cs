using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using QuillSign.Signing;

namespace QuillSign.Tests;
public sealed class SignaturePngTests
{
    [Theory]
    [InlineData(2,0)][InlineData(2,1)][InlineData(2,2)][InlineData(2,3)][InlineData(2,4)]
    [InlineData(6,0)][InlineData(6,1)][InlineData(6,2)][InlineData(6,3)][InlineData(6,4)]
    public void RGB_and_RGBA_with_every_filter_preserve_pixels_crop_padding_and_stamping(int color,int filter)
    {
        var source = Make(color:color,filter:filter,split:3,metadata:true); var image = SignaturePng.Normalize(source);
        Assert.Equal(26,image.Width); Assert.Equal(22,image.Height); Assert.Equal(SignaturePng.Version,image.Version);
        Assert.Equal(new[] { "IHDR","IDAT","IEND" },Chunks(image.Bytes).Select(x => x.Type));
        Assert.Equal(SHA256.HashData(image.Bytes),image.Sha256);
        Assert.Equal(SignaturePng.Normalize(Make()).Bytes,image.Bytes);
        var originalPixels = StampAndDecode(source); var normalizedPixels = StampAndDecode(image.Bytes);
        Assert.Equal(64,originalPixels.Width); Assert.Equal(32,originalPixels.Height);
        Assert.Equal(26,normalizedPixels.Width); Assert.Equal(22,normalizedPixels.Height);
        for (var y = 0; y < 6; y++) for (var x = 0; x < 10; x++)
        {
            Assert.Equal(new byte[] { 20,80,160 },originalPixels.Rgb.AsSpan(((y + 10) * 64 + x + 20) * 3,3).ToArray());
            Assert.Equal(originalPixels.Rgb.AsSpan(((y + 10) * 64 + x + 20) * 3,3).ToArray(),normalizedPixels.Rgb.AsSpan(((y + 8) * 26 + x + 8) * 3,3).ToArray());
        }
        Assert.Equal(image.Bytes,SignaturePng.Normalize(image.Bytes).Bytes);
    }
    [Fact]
    public void Buffers_are_owned_and_metadata_does_not_survive()
    {
        var input = Make(metadata:true); var image = SignaturePng.Normalize(input); var expected = image.Bytes; var hash = image.Sha256;
        Array.Fill(input,(byte)0); var copy = image.Bytes; Array.Fill(copy,(byte)0); var hashCopy = image.Sha256; Array.Fill(hashCopy,(byte)0);
        Assert.Equal(expected,image.Bytes); Assert.Equal(hash,image.Sha256); Assert.DoesNotContain("private fixture note",Encoding.ASCII.GetString(image.Bytes));
    }
    [Theory]
    [InlineData("white")][InlineData("transparent")][InlineData("faint")]
    public void Blank_or_effectively_invisible_marks_are_rejected(string kind)
    {
        var pixels = new byte[64 * 32 * 4];
        for (var i = 0; i < pixels.Length; i += 4) { pixels[i] = pixels[i + 1] = pixels[i + 2] = kind == "white" ? (byte)255 : (byte)0; pixels[i + 3] = kind == "white" ? (byte)255 : kind == "faint" ? (byte)1 : (byte)0; }
        Assert.Throws<SignatureImageRejectedException>(() => SignaturePng.Normalize(Make(pixels:pixels)));
    }
    [Fact]
    public void Visible_alpha_color_and_faint_antialiasing_are_retained()
    {
        var pixels = Pixels(64,32,4); var faint = (10 * 64 + 18) * 4; pixels[faint] = pixels[faint + 1] = pixels[faint + 2] = 0; pixels[faint + 3] = 1;
        for (var y = 10; y < 16; y++) for (var x = 20; x < 30; x++) pixels[(y * 64 + x) * 4 + 3] = 128;
        var image = SignaturePng.Normalize(Make(pixels:pixels)); Assert.Equal(28,image.Width); Assert.Equal(22,image.Height);
        var decoded = UnfilteredOutput(image.Bytes); Assert.Equal((byte)1,decoded[(8 * 28 + 8) * 4 + 3]);
        Assert.Equal(new byte[] { 20,80,160,128 },decoded.AsSpan((8 * 28 + 10) * 4,4).ToArray());
    }
    [Fact]
    public void Full_size_ink_cannot_make_padding_exceed_dimension_limits()
    {
        var pixels = new byte[SignaturePng.MaximumWidth * SignaturePng.MaximumHeight * 4]; for (var i = 3; i < pixels.Length; i += 4) pixels[i] = 255;
        var image = SignaturePng.Normalize(Make(SignaturePng.MaximumWidth,SignaturePng.MaximumHeight,pixels:pixels));
        Assert.Equal(SignaturePng.MaximumWidth,image.Width); Assert.Equal(SignaturePng.MaximumHeight,image.Height); Assert.InRange(image.Bytes.Length,1,SignaturePng.MaximumBytes);
    }
    [Theory]
    [InlineData("magic")][InlineData("crc")][InlineData("truncated")][InlineData("trailing")][InlineData("length")]
    [InlineData("header-first")][InlineData("header-duplicate")][InlineData("no-data")][InlineData("empty-data")]
    [InlineData("no-end")][InlineData("bad-end")][InlineData("critical")][InlineData("reserved")][InlineData("split-data")][InlineData("chunk-cap")]
    [InlineData("PLTE")][InlineData("tRNS")][InlineData("acTL")][InlineData("fcTL")][InlineData("fdAT")]
    [InlineData("short-rows")][InlineData("extra-rows")][InlineData("filter")][InlineData("zlib-header")]
    [InlineData("zlib-crc")][InlineData("zlib-truncated")][InlineData("compressed-junk")][InlineData("compressed-concat")]
    public void Malformed_unsupported_or_ambiguous_streams_are_rejected(string kind)
    {
        var png = Make(); var parts = Chunks(png).ToList();
        switch (kind)
        {
            case "magic": png[0] = 0; break;
            case "crc": png[^1] ^= 1; break;
            case "truncated": png = png[..^1]; break;
            case "trailing": png = [..png,0]; break;
            case "length": BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(8),uint.MaxValue); break;
            case "header-first": parts.Insert(0,new("tEXt",[])); png = Rebuild(parts); break;
            case "header-duplicate": parts.Insert(1,parts[0]); png = Rebuild(parts); break;
            case "no-data": png = Rebuild(parts.Where(x => x.Type != "IDAT")); break;
            case "empty-data": parts[1] = new("IDAT",[]); png = Rebuild(parts); break;
            case "no-end": png = Rebuild(parts.Where(x => x.Type != "IEND")); break;
            case "bad-end": parts[^1] = new("IEND",[0]); png = Rebuild(parts); break;
            case "critical": parts.Insert(1,new("XYZA",[])); png = Rebuild(parts); break;
            case "reserved": parts.Insert(1,new("xyza",[])); png = Rebuild(parts); break;
            case "PLTE": case "tRNS": case "acTL": case "fcTL": case "fdAT": parts.Insert(1,new(kind,[])); png = Rebuild(parts); break;
            case "split-data": var data = parts[1].Data; parts.RemoveAt(1); parts.InsertRange(1,[new("IDAT",data[..4]),new("tEXt",[]),new("IDAT",data[4..])]); png = Rebuild(parts); break;
            case "chunk-cap": parts.InsertRange(1,Enumerable.Range(0,129).Select(_ => new Part("tEXt",[]))); png = Rebuild(parts); break;
            default:
                var raw = RawRows(64,32,4,0,Pixels(64,32,4)); var compressed = parts[1].Data;
                if (kind == "short-rows") compressed = Compress(raw[..^1]);
                if (kind == "extra-rows") compressed = Compress([..raw,0]);
                if (kind == "filter") { raw[0] = 5; compressed = Compress(raw); }
                if (kind == "zlib-header") compressed[0] = 0;
                if (kind == "zlib-crc") compressed[^1] ^= 1;
                if (kind == "zlib-truncated") compressed = compressed[..^4];
                if (kind == "compressed-junk") compressed = [..compressed,1,2,3,..compressed[^4..]];
                if (kind == "compressed-concat") compressed = [..compressed,..compressed];
                parts[1] = new("IDAT",compressed); png = Rebuild(parts); break;
        }
        Assert.Throws<SignatureImageRejectedException>(() => SignaturePng.Normalize(png));
    }
    [Theory]
    [InlineData("width-zero")][InlineData("width-cap")][InlineData("width-huge")]
    [InlineData("height-zero")][InlineData("height-cap")][InlineData("height-huge")]
    [InlineData("depth")][InlineData("gray")][InlineData("indexed")][InlineData("gray-alpha")]
    [InlineData("compression")][InlineData("filter-method")][InlineData("interlace")]
    public void Header_limits_are_checked_before_raster_allocation(string kind)
    {
        var parts = Chunks(Make()).ToList(); var data = parts[0].Data;
        if (kind.StartsWith("width")) BinaryPrimitives.WriteUInt32BigEndian(data,kind.EndsWith("zero") ? 0u : kind.EndsWith("huge") ? uint.MaxValue : 2049u);
        if (kind.StartsWith("height")) BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4),kind.EndsWith("zero") ? 0u : kind.EndsWith("huge") ? uint.MaxValue : 1025u);
        if (kind == "depth") data[8] = 16;
        if (kind is "gray" or "indexed" or "gray-alpha") data[9] = kind == "gray" ? (byte)0 : kind == "indexed" ? (byte)3 : (byte)4;
        if (kind == "compression") data[10] = 1; if (kind == "filter-method") data[11] = 1; if (kind == "interlace") data[12] = 1;
        Assert.Throws<SignatureImageRejectedException>(() => SignaturePng.Normalize(Rebuild(parts)));
    }
    [Fact]
    public void Encoded_and_expanded_bombs_and_complex_normalized_output_are_bounded()
    {
        Assert.Throws<SignatureImageRejectedException>(() => SignaturePng.Normalize(new byte[SignaturePng.MaximumBytes + 1]));
        var parts = Chunks(Make()).ToList(); BinaryPrimitives.WriteUInt32BigEndian(parts[0].Data,1); BinaryPrimitives.WriteUInt32BigEndian(parts[0].Data.AsSpan(4),1);
        parts[1] = new("IDAT",Compress(new byte[10 * 1024 * 1024])); Assert.Throws<SignatureImageRejectedException>(() => SignaturePng.Normalize(Rebuild(parts)));
        var random = new byte[640 * 256 * 3]; new Random(37).NextBytes(random); var complex = Make(640,256,color:2,pixels:random);
        Assert.InRange(complex.Length,1,SignaturePng.MaximumBytes); Assert.Throws<SignatureImageRejectedException>(() => SignaturePng.Normalize(complex));
    }
    private sealed record Part(string Type,byte[] Data);
    private static List<Part> Chunks(byte[] bytes)
    { var parts = new List<Part>(); for (var p = 8; p < bytes.Length;) { var n = (int)BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(p)); parts.Add(new(Encoding.ASCII.GetString(bytes,p + 4,4),bytes.AsSpan(p + 8,n).ToArray())); p += n + 12; } return parts; }
    private static byte[] Rebuild(IEnumerable<Part> parts)
    {
        using var output = new MemoryStream(); output.Write([137,80,78,71,13,10,26,10]);
        foreach (var part in parts)
        {
            var type = Encoding.ASCII.GetBytes(part.Type); var number = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(number,(uint)part.Data.Length); output.Write(number); output.Write(type); output.Write(part.Data);
            // Deliberately independent bitwise CRC, rather than the production lookup table.
            uint crc = uint.MaxValue; foreach (var value in type.Concat(part.Data)) { crc ^= value; for (var i = 0; i < 8; i++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320 : crc >> 1; }
            BinaryPrimitives.WriteUInt32BigEndian(number,~crc); output.Write(number);
        }
        return output.ToArray();
    }
    private static byte[] Make(int width = 64,int height = 32,int color = 6,int filter = 0,int split = 1,bool metadata = false,byte[]? pixels = null)
    {
        var channels = color == 2 ? 3 : 4; var header = new byte[13]; BinaryPrimitives.WriteUInt32BigEndian(header,(uint)width); BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4),(uint)height); header[8] = 8; header[9] = (byte)color;
        var parts = new List<Part> { new("IHDR",header) }; if (metadata) { parts.Add(new("tEXt",Encoding.UTF8.GetBytes("Note\0private fixture note"))); parts.Add(new("xYZA",[1,2,3])); }
        var compressed = Compress(RawRows(width,height,channels,filter,pixels ?? Pixels(width,height,channels)));
        for (var i = 0; i < split; i++) parts.Add(new("IDAT",compressed.AsSpan(i * compressed.Length / split,(i + 1) * compressed.Length / split - i * compressed.Length / split).ToArray()));
        parts.Add(new("IEND",[])); return Rebuild(parts);
    }
    private static byte[] Pixels(int width,int height,int channels)
    {
        var data = Enumerable.Repeat((byte)255,width * height * channels).ToArray();
        for (var y = 10; y < Math.Min(16,height); y++) for (var x = 20; x < Math.Min(30,width); x++) { var p = (y * width + x) * channels; data[p] = 20; data[p + 1] = 80; data[p + 2] = 160; }
        return data;
    }
    private static byte[] RawRows(int width,int height,int channels,int filter,byte[] pixels)
    {
        var stride = width * channels; var raw = new byte[(stride + 1) * height];
        for (var y = 0; y < height; y++)
        {
            raw[y * (stride + 1)] = (byte)filter;
            for (var i = 0; i < stride; i++)
            {
                var at = y * stride + i; var left = i < channels ? 0 : pixels[at - channels]; var up = y == 0 ? 0 : pixels[at - stride]; var corner = y == 0 || i < channels ? 0 : pixels[at - stride - channels];
                var paeth = 0;
                if (filter == 4) { var guess = left + up - corner; var candidates = new[] { left,up,corner }; paeth = candidates.OrderBy(c => Math.Abs(guess - c)).First(); }
                raw[y * (stride + 1) + 1 + i] = unchecked((byte)(pixels[at] - (filter switch { 0 => 0,1 => left,2 => up,3 => (left + up) >> 1,4 => paeth,_ => 0 })));
            }
        }
        return raw;
    }
    private static byte[] Compress(byte[] raw) { using var output = new MemoryStream(); using (var zlib = new ZLibStream(output,CompressionLevel.Optimal,true)) zlib.Write(raw); return output.ToArray(); }
    private static byte[] UnfilteredOutput(byte[] png)
    {
        var parts = Chunks(png); var w = (int)BinaryPrimitives.ReadUInt32BigEndian(parts[0].Data); var h = (int)BinaryPrimitives.ReadUInt32BigEndian(parts[0].Data.AsSpan(4));
        using var z = new ZLibStream(new MemoryStream(parts.Single(x => x.Type == "IDAT").Data),CompressionMode.Decompress); var pixels = new byte[w * h * 4];
        for (var y = 0; y < h; y++) { Assert.Equal(0,z.ReadByte()); z.ReadExactly(pixels.AsSpan(y * w * 4,w * 4)); } Assert.Equal(-1,z.ReadByte()); return pixels;
    }
    private static (int Width,int Height,byte[] Rgb) StampAndDecode(byte[] png)
    {
        using var input = new MemoryStream(png,0,png.Length,false,true); using var image = XImage.FromStream(input);
        using var pdf = new PdfDocument(); var page = pdf.AddPage(); using (var graphics = XGraphics.FromPdfPage(page)) graphics.DrawImage(image,20,20,200,100);
        using var output = new MemoryStream(); pdf.Save(output,false); using var inspected = UglyToad.PdfPig.PdfDocument.Open(output.ToArray()); var embedded = Assert.Single(inspected.GetPage(1).GetImages());
        Assert.True(embedded.TryGetBytesAsMemory(out var pixels)); Assert.Equal(embedded.WidthInSamples * embedded.HeightInSamples * 3,pixels.Length);
        return (embedded.WidthInSamples,embedded.HeightInSamples,pixels.ToArray());
    }
}

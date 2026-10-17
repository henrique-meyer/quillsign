using System.Buffers.Binary;
using System.IO.Compression;

namespace QuillSign.Documents;

// Validate format, dimensions and expansion before the general pixel decoder.
// Only ordinary static PNG and baseline/progressive 8-bit JPEG enter that decoder.
internal static class ImageHeaderValidation
{
    internal sealed record Header(int Width, int Height, int Orientation, string Mime);
    internal const long MaximumPixels = 12_000_000;
    private static readonly uint[] CrcTable = CreateCrcTable();
    internal static Header Read(byte[] bytes, CancellationToken ct)
    {
        Header header;
        if (bytes.Length >= 8 && bytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 })) header = Png(bytes, ct);
        else if (bytes.Length >= 4 && bytes[0] == 255 && bytes[1] == 216) header = Jpeg(bytes, ct);
        else throw Rejected();
        CheckDimensions(header.Width, header.Height); return header;
    }
    private static void CheckDimensions(int width, int height)
    { if (width is < 1 or > 12000 || height is < 1 or > 12000 || (long)width * height > MaximumPixels) throw Rejected(); }

    private static Header Png(byte[] bytes, CancellationToken ct)
    {
        var at = 8; var count = 0; var width = 0; var height = 0; var depth = 0; var color = 0; var orientation = 1;
        var hasData = false; var dataEnded = false; var palette = false; var transparency = false; var hasExif = false; var hasSrgb = false; var hasGamma = false; var hasChroma = false;
        using var compressed = new MemoryStream();
        while (at < bytes.Length)
        {
            ct.ThrowIfCancellationRequested(); if (++count > 4096 || bytes.Length - at < 12) throw Rejected();
            var length = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(at)); if (length > bytes.Length - at - 12) throw Rejected();
            var size = checked((int)length); var type = bytes.AsSpan(at + 4, 4); var data = bytes.AsSpan(at + 8, size);
            foreach (var c in type) if (c is not (>= 65 and <= 90) and not (>= 97 and <= 122)) throw Rejected();
            if (type[2] is < 65 or > 90 || Crc(type, data) != BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(at + 8 + size))) throw Rejected();
            if (count == 1 && !type.SequenceEqual("IHDR"u8)) throw Rejected();
            at += size + 12; if (hasData && !type.SequenceEqual("IDAT"u8)) dataEnded = true;
            if (type.SequenceEqual("IHDR"u8))
            {
                if (count != 1 || size != 13) throw Rejected(); width = checked((int)BinaryPrimitives.ReadUInt32BigEndian(data)); height = checked((int)BinaryPrimitives.ReadUInt32BigEndian(data[4..])); CheckDimensions(width, height);
                depth = data[8]; color = data[9]; if (color is not (0 or 2 or 3 or 4 or 6) || depth is not (1 or 2 or 4 or 8) || color is 2 or 4 or 6 && depth != 8 || data[10] != 0 || data[11] != 0 || data[12] != 0) throw Rejected();
            }
            else if (type.SequenceEqual("IDAT"u8)) { if (dataEnded || color == 3 && !palette) throw Rejected(); hasData = true; compressed.Write(data); }
            else if (type.SequenceEqual("IEND"u8))
            {
                if (!hasData || size != 0 || at != bytes.Length) throw Rejected();
                var channels = color switch { 0 or 3 => 1, 2 => 3, 4 => 2, 6 => 4, _ => throw Rejected() };
                ValidateZlib(compressed.ToArray(), checked((long)height * (1 + ((long)width * channels * depth + 7) / 8)), ct);
                return new(width, height, orientation, "image/png");
            }
            else if (type.SequenceEqual("PLTE"u8)) { if (palette || hasData || color is 0 or 4 || size is < 3 or > 768 || size % 3 != 0 || color == 3 && size / 3 > (1 << depth)) throw Rejected(); palette = true; }
            else if (type.SequenceEqual("tRNS"u8)) { if (transparency || hasData || color is 4 or 6 || color == 0 && size != 2 || color == 2 && size != 6 || color == 3 && (!palette || size is < 1 or > 256)) throw Rejected(); transparency = true; }
            else if (type.SequenceEqual("eXIf"u8)) { if (hasExif || hasData) throw Rejected(); hasExif = true; orientation = Exif(data); }
            else if (type.SequenceEqual("sRGB"u8)) { if (hasSrgb || hasData || size != 1 || data[0] > 3) throw Rejected(); hasSrgb = true; }
            else if (type.SequenceEqual("gAMA"u8)) { if (hasGamma || hasData || size != 4 || BinaryPrimitives.ReadUInt32BigEndian(data) != 45455) throw Rejected(); hasGamma = true; }
            else if (type.SequenceEqual("cHRM"u8))
            {
                if (hasChroma || hasData || size != 32) throw Rejected(); hasChroma = true; uint[] expected = [31270, 32900, 64000, 33000, 30000, 60000, 15000, 6000];
                for (var i = 0; i < 8; i++) if (BinaryPrimitives.ReadUInt32BigEndian(data[(i * 4)..]) != expected[i]) throw Rejected();
            }
            else if (type.SequenceEqual("acTL"u8) || type.SequenceEqual("fcTL"u8) || type.SequenceEqual("fdAT"u8) || type.SequenceEqual("iCCP"u8) || (type[0] & 32) == 0) throw Rejected();
            // Other ancillary metadata is CRC checked and never inflated or retained.
        }
        throw Rejected();
    }

    private static void ValidateZlib(byte[] compressed, long expected, CancellationToken ct)
    {
        if (compressed.Length < 6 || (compressed[0] & 15) != 8 || compressed[0] >> 4 > 7 || ((compressed[0] << 8) + compressed[1]) % 31 != 0 || (compressed[1] & 32) != 0) throw Rejected();
        using var source = new MemoryStream(compressed, false); using var exact = new SingleByteInput(source); using var inflater = new ZLibStream(exact, CompressionMode.Decompress, true);
        var buffer = new byte[8192]; long total = 0; uint a = 1, b = 0; int read;
        while ((read = inflater.Read(buffer)) != 0)
        {
            ct.ThrowIfCancellationRequested(); if ((total += read) > expected) throw Rejected();
            foreach (var value in buffer.AsSpan(0, read)) { a = (a + value) % 65521; b = (b + a) % 65521; }
        }
        if (total != expected || source.Position != source.Length || BinaryPrimitives.ReadUInt32BigEndian(compressed.AsSpan(compressed.Length - 4)) != (b << 16 | a)) throw Rejected();
    }

    private static Header Jpeg(byte[] bytes, CancellationToken ct)
    {
        var at = 2; var count = 0; var scans = 0; var width = 0; var height = 0; var orientation = 1; var hasExif = false;
        while (at < bytes.Length)
        {
            ct.ThrowIfCancellationRequested(); if (++count > 4096 || bytes[at++] != 255) throw Rejected(); while (at < bytes.Length && bytes[at] == 255) at++;
            if (at >= bytes.Length) throw Rejected(); var marker = bytes[at++];
            if (marker == 217) { if (at != bytes.Length || width == 0 || scans == 0) throw Rejected(); return new(width, height, orientation, "image/jpeg"); }
            if (marker is 0 or 1 or 216 or >= 208 and <= 215 || at + 2 > bytes.Length) throw Rejected(); var size = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(at));
            if (size < 2 || at + size > bytes.Length) throw Rejected(); var data = bytes.AsSpan(at + 2, size - 2); at += size;
            if (marker is >= 192 and <= 207 && marker is not (196 or 200 or 204))
            {
                if (marker is not (192 or 194) || width != 0 || data.Length < 6 || data[0] != 8 || data[5] is not (1 or 3) || data.Length != 6 + 3 * data[5]) throw Rejected();
                height = BinaryPrimitives.ReadUInt16BigEndian(data[1..]); width = BinaryPrimitives.ReadUInt16BigEndian(data[3..]); CheckDimensions(width, height);
            }
            if (marker == 225 && data.StartsWith("Exif\0\0"u8)) { if (hasExif) throw Rejected(); hasExif = true; orientation = Exif(data[6..]); }
            if (marker == 226 && (data.StartsWith("ICC_PROFILE\0"u8) || data.StartsWith("MPF\0"u8))) throw Rejected();
            if (marker == 218)
            {
                if (width == 0 || ++scans > 16) throw Rejected(); var found = false;
                while (at < bytes.Length)
                {
                    if ((at & 16383) == 0) ct.ThrowIfCancellationRequested(); if (bytes[at++] != 255) continue; var start = at - 1;
                    while (at < bytes.Length && bytes[at] == 255) at++; if (at >= bytes.Length) throw Rejected(); var code = bytes[at++];
                    if (code == 0 || code is >= 208 and <= 215) continue; at = start; found = true; break;
                }
                if (!found) throw Rejected();
            }
        }
        throw Rejected();
    }

    private static int Exif(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 8 or > 65535 || !(bytes[..2].SequenceEqual("II"u8) || bytes[..2].SequenceEqual("MM"u8))) throw Rejected(); var little = bytes[0] == 73;
        if (U16(bytes, 2, little) != 42) throw Rejected(); var offset = U32(bytes, 4, little); if (offset < 8 || offset + 2L > bytes.Length) throw Rejected(); var at = checked((int)offset); var count = U16(bytes, at, little);
        if (count > 256 || at + 2L + 12L * count + 4 > bytes.Length) throw Rejected(); var orientation = 1; var found = false;
        for (var i = 0; i < count; i++)
        {
            var entry = at + 2 + 12 * i; if (U16(bytes, entry, little) != 274) continue;
            if (found || U16(bytes, entry + 2, little) != 3 || U32(bytes, entry + 4, little) != 1) throw Rejected(); found = true; orientation = U16(bytes, entry + 8, little); if (orientation is < 1 or > 8) throw Rejected();
        }
        return orientation;
    }
    private static ushort U16(ReadOnlySpan<byte> bytes, int at, bool little) => little ? BinaryPrimitives.ReadUInt16LittleEndian(bytes[at..]) : BinaryPrimitives.ReadUInt16BigEndian(bytes[at..]);
    private static uint U32(ReadOnlySpan<byte> bytes, int at, bool little) => little ? BinaryPrimitives.ReadUInt32LittleEndian(bytes[at..]) : BinaryPrimitives.ReadUInt32BigEndian(bytes[at..]);
    internal static uint Crc(ReadOnlySpan<byte> type, ReadOnlySpan<byte> data) { uint value = uint.MaxValue; foreach (var b in type) value = CrcTable[(byte)(value ^ b)] ^ (value >> 8); foreach (var b in data) value = CrcTable[(byte)(value ^ b)] ^ (value >> 8); return ~value; }
    private static uint[] CreateCrcTable() { var result = new uint[256]; for (uint i = 0; i < 256; i++) { var value = i; for (var bit = 0; bit < 8; bit++) value = (value & 1) != 0 ? 0xedb88320 ^ (value >> 1) : value >> 1; result[i] = value; } return result; }
    internal static DocumentRejectedException Rejected() => new("Use a supported static PNG or JPEG within the image and PDF limits, or export the document to PDF.");
    private sealed class SingleByteInput(Stream source) : Stream
    {
        public override bool CanRead => true; public override bool CanWrite => false; public override bool CanSeek => false; public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => source.Read(buffer, offset, Math.Min(count, 1)); public override int Read(Span<byte> buffer) => source.Read(buffer[..Math.Min(buffer.Length, 1)]);
        public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

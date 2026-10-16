using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace QuillSign.Signing;

public sealed class SignatureImageRejectedException(string message) : Exception(message);
public sealed class NormalizedSignatureImage
{
    private readonly byte[] bytes,hash;
    internal NormalizedSignatureImage(byte[] encoded,int width,int height)
    { bytes = encoded.ToArray(); hash = SHA256.HashData(bytes); Width = width; Height = height; }
    public byte[] Bytes => bytes.ToArray();
    public byte[] Sha256 => hash.ToArray();
    public int Width { get; }
    public int Height { get; }
    public string Version => SignaturePng.Version;
}

// Strict browser-normalized PNG contract, not a general image-upload decoder.
// The later adoption flow must preview this exact normalized output before confirmation.
public static class SignaturePng
{
    public const string Version = "png-rgba-crop-v1";
    public const int MaximumBytes = 512 * 1024,MaximumWidth = 2048,MaximumHeight = 1024,Padding = 8;
    private static readonly byte[] Magic = [137,80,78,71,13,10,26,10];
    private static readonly uint[] CrcTable = CreateCrcTable();
    public static NormalizedSignatureImage Normalize(byte[] input)
    {
        if (input is null || input.Length is < 57 or > MaximumBytes) throw Rejected();
        var owned = input.ToArray();
        try
        {
            var (width,height,channels,compressed) = Parse(owned);
            var pixels = Decode(width,height,channels,compressed);
            var left = width; var right = -1; var top = height; var bottom = -1; var hasVisibleInk = false;
            for (var y = 0; y < height; y++) for (var x = 0; x < width; x++)
            {
                var offset = (y * width + x) * 4; var alpha = pixels[offset + 3];
                // Visibility against the white adoption preview, not biometric/identity evidence.
                var contrast = Math.Max(Math.Max(255 - pixels[offset],255 - pixels[offset + 1]),255 - pixels[offset + 2]) * alpha;
                hasVisibleInk |= contrast >= 8 * 255;
                if (contrast == 0) continue; // Retain even faint antialiasing around a visible mark.
                left = Math.Min(left,x); right = Math.Max(right,x); top = Math.Min(top,y); bottom = Math.Max(bottom,y);
            }
            if (!hasVisibleInk) throw new SignatureImageRejectedException("Draw or choose a visible mark before continuing.");
            var inkWidth = right - left + 1; var inkHeight = bottom - top + 1;
            var outputWidth = Math.Min(MaximumWidth,inkWidth + Padding * 2); var outputHeight = Math.Min(MaximumHeight,inkHeight + Padding * 2);
            var padX = (outputWidth - inkWidth) / 2; var padY = (outputHeight - inkHeight) / 2;
            using var compressedOutput = new MemoryStream();
            using (var bounded = new LimitedOutput(compressedOutput,MaximumBytes - 57))
            using (var encoder = new ZLibStream(bounded,CompressionLevel.Optimal,leaveOpen:true))
            {
                var row = new byte[outputWidth * 4 + 1];
                for (var y = 0; y < outputHeight; y++)
                {
                    Array.Clear(row);
                    if (y >= padY && y < padY + inkHeight)
                        pixels.AsSpan(((top + y - padY) * width + left) * 4,inkWidth * 4).CopyTo(row.AsSpan(1 + padX * 4));
                    encoder.Write(row);
                }
            }
            using var png = new MemoryStream(); png.Write(Magic);
            Span<byte> header = stackalloc byte[13]; header.Clear();
            BinaryPrimitives.WriteUInt32BigEndian(header,(uint)outputWidth); BinaryPrimitives.WriteUInt32BigEndian(header[4..],(uint)outputHeight);
            header[8] = 8; header[9] = 6;
            Chunk(png,"IHDR"u8,header); Chunk(png,"IDAT"u8,compressedOutput.ToArray()); Chunk(png,"IEND"u8,[]);
            return new(png.ToArray(),outputWidth,outputHeight);
        }
        catch (SignatureImageRejectedException) { throw; }
        catch (Exception e) when (e is InvalidDataException or EndOfStreamException or OverflowException or ArgumentException)
        { throw Rejected(); }
    }
    private static (int Width,int Height,int Channels,byte[] Compressed) Parse(byte[] bytes)
    {
        if (!bytes.AsSpan(0,8).SequenceEqual(Magic)) throw Rejected();
        var position = 8; var chunks = 0; var width = 0; var height = 0; var channels = 0;
        var hasHeader = false; var hasData = false; var dataEnded = false;
        using var compressed = new MemoryStream();
        while (position < bytes.Length)
        {
            if (++chunks > 128 || bytes.Length - position < 12) throw Rejected();
            var size = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(position));
            if (size > bytes.Length - position - 12) throw Rejected();
            var length = (int)size; var type = bytes.AsSpan(position + 4,4); var data = bytes.AsSpan(position + 8,length);
            foreach (var c in type) if (!(c is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z')) throw Rejected();
            if (type[2] is < (byte)'A' or > (byte)'Z' || Crc(type,data) != BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(position + 8 + length))) throw Rejected();
            var name = Encoding.ASCII.GetString(type); position += length + 12;
            if (!hasHeader && name != "IHDR") throw Rejected();
            if (hasData && name != "IDAT") dataEnded = true;
            switch (name)
            {
                case "IHDR":
                    if (hasHeader || length != 13) throw Rejected();
                    var w = BinaryPrimitives.ReadUInt32BigEndian(data); var h = BinaryPrimitives.ReadUInt32BigEndian(data[4..]);
                    if (w is < 1 or > MaximumWidth || h is < 1 or > MaximumHeight || data[8] != 8 || data[9] is not (2 or 6) || data[10] != 0 || data[11] != 0 || data[12] != 0) throw Rejected();
                    width = (int)w; height = (int)h; channels = data[9] == 2 ? 3 : 4; hasHeader = true; break;
                case "IDAT":
                    if (dataEnded) throw Rejected(); hasData = true; compressed.Write(data); break;
                case "IEND":
                    if (!hasData || length != 0 || position != bytes.Length) throw Rejected();
                    return (width,height,channels,compressed.ToArray());
                case "PLTE": case "tRNS": case "acTL": case "fcTL": case "fdAT": throw Rejected();
                default:
                    if (type[0] is >= (byte)'A' and <= (byte)'Z') throw Rejected();
                    // Opaque ancillary data is CRC-checked, never decompressed or retained.
                    break;
            }
        }
        throw Rejected();
    }
    private static byte[] Decode(int width,int height,int channels,byte[] compressed)
    {
        if (compressed.Length < 6 || (compressed[0] & 15) != 8 || (compressed[0] >> 4) > 7 ||
            ((compressed[0] << 8) + compressed[1]) % 31 != 0 || (compressed[1] & 32) != 0) throw Rejected();
        var stride = checked(width * channels); var pixels = new byte[checked(width * height * 4)];
        var row = new byte[stride]; var previous = new byte[stride]; uint adlerA = 1,adlerB = 0;
        void Adler(byte value) { adlerA = (adlerA + value) % 65521; adlerB = (adlerB + adlerA) % 65521; }
        using var source = new MemoryStream(compressed,false);
        // Prevent inflater read-ahead from hiding trailing compressed streams/junk.
        // Encoded input is capped at 512 KiB, bounding these single-byte reads.
        using var exact = new SingleByteInput(source); using var inflater = new ZLibStream(exact,CompressionMode.Decompress,leaveOpen:true);
        for (var y = 0; y < height; y++)
        {
            var filter = inflater.ReadByte(); if (filter is < 0 or > 4) throw Rejected(); Adler((byte)filter);
            inflater.ReadExactly(row); foreach (var value in row) Adler(value);
            for (var i = 0; i < stride; i++)
            {
                var a = i >= channels ? row[i - channels] : 0; var b = previous[i]; var c = i >= channels ? previous[i - channels] : 0;
                row[i] = unchecked((byte)(row[i] + (filter switch { 0 => 0,1 => a,2 => b,3 => (a + b) / 2,4 => Paeth(a,b,c),_ => 0 })));
            }
            for (var x = 0; x < width; x++)
            {
                var target = (y * width + x) * 4; row.AsSpan(x * channels,3).CopyTo(pixels.AsSpan(target,3));
                pixels[target + 3] = channels == 4 ? row[x * channels + 3] : (byte)255;
            }
            (row,previous) = (previous,row);
        }
        if (inflater.ReadByte() != -1 || source.Position != source.Length || BinaryPrimitives.ReadUInt32BigEndian(compressed.AsSpan(compressed.Length - 4)) != (adlerB << 16 | adlerA)) throw Rejected();
        return pixels;
    }
    private static int Paeth(int a,int b,int c)
    { var p = a + b - c; var da = Math.Abs(p - a); var db = Math.Abs(p - b); var dc = Math.Abs(p - c); return da <= db && da <= dc ? a : db <= dc ? b : c; }
    private static void Chunk(Stream output,ReadOnlySpan<byte> type,ReadOnlySpan<byte> data)
    {
        Span<byte> number = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(number,(uint)data.Length); output.Write(number); output.Write(type); output.Write(data);
        BinaryPrimitives.WriteUInt32BigEndian(number,Crc(type,data)); output.Write(number);
    }
    private static uint Crc(ReadOnlySpan<byte> type,ReadOnlySpan<byte> data)
    { uint crc = uint.MaxValue; foreach (var value in type) crc = CrcTable[(crc ^ value) & 255] ^ (crc >> 8); foreach (var value in data) crc = CrcTable[(crc ^ value) & 255] ^ (crc >> 8); return crc ^ uint.MaxValue; }
    private static uint[] CreateCrcTable()
    { var table = new uint[256]; for (uint i = 0; i < 256; i++) { var crc = i; for (var bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0 : 0xedb88320); table[i] = crc; } return table; }
    private static SignatureImageRejectedException Rejected() => new("Use a visible, static RGB/RGBA PNG within the signature image limits.");
    private sealed class SingleByteInput(Stream source) : Stream
    {
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => source.Length; public override long Position { get => source.Position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer,int offset,int count) => source.Read(buffer,offset,Math.Min(count,1));
        public override int Read(Span<byte> buffer) => source.Read(buffer[..Math.Min(buffer.Length,1)]);
        public override int ReadByte() => source.ReadByte(); public override void Flush() { }
        public override long Seek(long offset,SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer,int offset,int count) => throw new NotSupportedException();
    }
    private sealed class LimitedOutput(Stream output,int maximum) : Stream
    {
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => output.Length; public override long Position { get => output.Position; set => throw new NotSupportedException(); }
        public override void Write(byte[] buffer,int offset,int count) => Write(buffer.AsSpan(offset,count));
        public override void Write(ReadOnlySpan<byte> buffer) { if (output.Length + buffer.Length > maximum) throw Rejected(); output.Write(buffer); }
        public override void Flush() => output.Flush(); public override int Read(byte[] buffer,int offset,int count) => throw new NotSupportedException();
        public override long Seek(long offset,SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException();
    }
}

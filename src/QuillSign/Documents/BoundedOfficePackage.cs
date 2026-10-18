using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace QuillSign.Documents;

// Strict container/CRC/decompression primitives shared across separately gated Office families.
internal sealed class BoundedOfficePackage(byte[] original,Dictionary<string,byte[]> parts):IDisposable
{
    private byte[]? owned=original;
    internal Dictionary<string,byte[]> Parts {get;}=parts;
    internal byte[] DetachOriginal(){var result=owned??throw new ObjectDisposedException(nameof(BoundedOfficePackage));owned=null;return result;}
    public void Dispose(){foreach(var part in Parts.Values)Array.Clear(part);if(owned is not null)Array.Clear(owned);owned=null;}
    private const int MaximumEntries=2048,MaximumPart=16*1024*1024,MaximumXml=8*1024*1024,MaximumExpanded=64*1024*1024;
    private static readonly uint[] CrcTable=CreateCrcTable();
    internal static async Task<BoundedOfficePackage> ReadAsync(Stream input, long declaredLength, DocumentOptions limits, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested(); ArgumentNullException.ThrowIfNull(input);
        if (limits.MaximumBytes is < 1024 or > 64 * 1024 * 1024) throw new InvalidOperationException("Configure supported Office package input limits.");
        if (declaredLength < 4 || declaredLength > limits.MaximumBytes) throw Rejected();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(15)); var token = timeout.Token;
        byte[]? original = null; var transferred = false; var parts = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using (var copied = new MemoryStream()) { await Copy(input, copied, limits.MaximumBytes, token); if (copied.Length != declaredLength) throw Rejected(); original = copied.ToArray(); }
            InspectDirectory(original, token);
            using (var stream = new MemoryStream(original, false)) using (var archive = new ZipArchive(stream, ZipArchiveMode.Read, false, new UTF8Encoding(false, true)))
            {
                if (archive.Entries.Count is < 3 or > MaximumEntries) throw Rejected(); long expanded = 0; var names = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
                foreach (var entry in archive.Entries)
                {
                    token.ThrowIfCancellationRequested(); var directory = entry.FullName.EndsWith('/'); var name = Name(entry.FullName, directory);
                    if (entry.IsEncrypted || entry.Length < 0 || entry.Length > MaximumPart || entry.CompressedLength < 0 || (expanded += entry.Length) > MaximumExpanded ||
                        !names.TryAdd(name, directory) || ActivePart(name)) throw Rejected();
                    using var content = entry.Open(); using var bytes = new MemoryStream(); await Copy(content, bytes, Math.Min(entry.Length, MaximumPart), token);
                    var value = bytes.ToArray(); if (value.LongLength != entry.Length || Crc(value) != entry.Crc32) { Array.Clear(value); throw Rejected(); }
                    if (directory) { if (value.Length != 0) throw Rejected(); continue; }
                    parts[name] = value;
                }
                foreach (var name in names.Keys) { var at = name.LastIndexOf('/'); while (at >= 0) { if (names.TryGetValue(name[..at], out var parent) && !parent) throw Rejected(); at = name.LastIndexOf('/', at - 1); } }
            }
            token.ThrowIfCancellationRequested(); var result = new BoundedOfficePackage(original, parts); transferred = true; return result;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new DocumentRejectedException("This Office package is too complex to validate. Export a PDF and try again."); }
        catch (Exception e) when (e is InvalidDataException or XmlException or ArgumentException or NotSupportedException or OverflowException or IOException)
        { throw Rejected(); }
        finally { if (!transferred) { foreach (var part in parts.Values) Array.Clear(part); if (original is not null) Array.Clear(original); } }
    }

    private static void InspectDirectory(byte[] bytes, CancellationToken ct)
    {
        var data = bytes.AsSpan(); if (data.Length < 22 || U32(data, 0) != 0x04034b50) throw Rejected(); var end = -1;
        for (var at = data.Length - 22; at >= Math.Max(0, data.Length - 22 - ushort.MaxValue); at--)
            if (U32(data, at) == 0x06054b50 && at + 22 + U16(data, at + 20) == data.Length) { end = at; break; }
        if (end < 0 || U16(data, end + 4) != 0 || U16(data, end + 6) != 0 || U16(data, end + 8) != U16(data, end + 10) || U16(data, end + 10) is < 3 or > MaximumEntries) throw Rejected();
        var size = U32(data, end + 12); var start = U32(data, end + 16);
        if (size > 2 * 1024 * 1024 || (long)start + size != end) throw Rejected();
        var count = 0; var cursor = checked((int)start); var ranges = new List<(int Start, int End)>();
        while (cursor < end)
        {
            ct.ThrowIfCancellationRequested(); if (++count > MaximumEntries || cursor + 46 > end || U32(data, cursor) != 0x02014b50) throw Rejected();
            var flags = U16(data, cursor + 8); var method = U16(data, cursor + 10); var name = U16(data, cursor + 28); var extra = U16(data, cursor + 30); var comment = U16(data, cursor + 32);
            var next = checked(cursor + 46 + name + extra + comment); var attributes = U32(data, cursor + 38); var mode = (attributes >> 16) & 0xf000;
            if (next > end || name is 0 or > 2048 || (flags & ~0x080e) != 0 || method is not (0 or 8) || U16(data, cursor + 34) != 0 || mode is not (0 or 0x8000 or 0x4000)) throw Rejected();
            var directory = data[cursor + 46 + name - 1] == '/'; if (mode == 0x4000 && !directory || mode == 0x8000 && directory || (attributes & 0x10) != 0 && !directory) throw Rejected();
            var local = U32(data, cursor + 42); if (local > start || local + 30L > start) throw Rejected(); var offset = checked((int)local);
            if (U32(data, offset) != 0x04034b50 || U16(data, offset + 6) != flags || U16(data, offset + 8) != method || U16(data, offset + 26) != name) throw Rejected();
            // A different ZIP reader must not see an alternate name or size.
            _ = new UTF8Encoding(false, true).GetString(data.Slice(cursor + 46, name));
            InspectExtra(data.Slice(cursor + 46 + name, extra));
            InspectExtra(data.Slice(offset + 30 + name, U16(data, offset + 28)));
            var payload = checked(offset + 30 + name + U16(data, offset + 28)); var finish = checked((long)payload + U32(data, cursor + 20));
            if (finish > start || !data.Slice(offset + 30, name).SequenceEqual(data.Slice(cursor + 46, name))) throw Rejected();
            if ((flags & 8) == 0 && (U32(data, offset + 14) != U32(data, cursor + 16) || U32(data, offset + 18) != U32(data, cursor + 20) || U32(data, offset + 22) != U32(data, cursor + 24))) throw Rejected();
            if ((flags & 8) != 0)
            {
                var descriptor = checked((int)finish); if (descriptor + 12L > start) throw Rejected();
                if (U32(data, descriptor) == 0x08074b50) descriptor += 4;
                if (descriptor + 12L > start || U32(data, descriptor) != U32(data, cursor + 16) || U32(data, descriptor + 4) != U32(data, cursor + 20) || U32(data, descriptor + 8) != U32(data, cursor + 24)) throw Rejected();
                finish = descriptor + 12L;
            }
            ranges.Add((offset, checked((int)finish))); cursor = next;
        }
        if (cursor != end || count != U16(data, end + 10)) throw Rejected();
        var last = 0; foreach (var range in ranges.OrderBy(x => x.Start)) { if (range.Start != last) throw Rejected(); last = range.End; }
        if (last != start) throw Rejected();
    }

    private static void InspectExtra(ReadOnlySpan<byte> extra)
    {
        for (var at = 0; at < extra.Length;)
        {
            if (at + 4 > extra.Length) throw Rejected(); var kind = U16(extra, at); var length = U16(extra, at + 2); at += 4;
            // ZIP64 and alternate Unicode path records are outside the bounded
            // supported profile; they can override fields in other ZIP readers.
            if (kind is 0x0001 or 0x7075 || at + length > extra.Length) throw Rejected(); at += length;
        }
    }

    private static string Name(string name, bool directory)
    {
        if (name.Length is < 1 or > 512 || name.StartsWith('/') || name.Contains('\\') || name.Contains(':') || name.Contains('?') || name.Contains('#') || name.Contains('%')) throw Rejected();
        var decoded = Uri.UnescapeDataString(name).Normalize(NormalizationForm.FormC); if (decoded.Contains('%') || decoded.Contains('\\') || decoded.Contains(':') || decoded.Any(char.IsControl)) throw Rejected();
        var parts = (directory ? decoded[..^1] : decoded).Split('/'); if (parts.Any(x => x.Length == 0 || x is "." or ".." || x != x.Trim())) throw Rejected(); return string.Join('/', parts);
    }
    private static bool ActivePart(string value) => value.Contains("/embeddings/", StringComparison.OrdinalIgnoreCase) || value.StartsWith("embeddings/", StringComparison.OrdinalIgnoreCase) || value.Contains("activex", StringComparison.OrdinalIgnoreCase) || value.Split('/').Any(x => x.StartsWith("vba", StringComparison.OrdinalIgnoreCase)) || value.StartsWith("_xmlsignatures/", StringComparison.OrdinalIgnoreCase) || value.StartsWith("customUI/", StringComparison.OrdinalIgnoreCase);
    private static async Task Copy(Stream input, Stream output, long maximum, CancellationToken ct)
    {
        var buffer = new byte[65536]; long total = 0; int count; while ((count = await input.ReadAsync(buffer, ct)) != 0) { if ((total += count) > maximum) throw Rejected(); await output.WriteAsync(buffer.AsMemory(0, count), ct); }
    }
    private static ushort U16(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(at, 2));
    private static uint U32(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(at, 4));
    private static uint Crc(ReadOnlySpan<byte> bytes) { var crc = uint.MaxValue; foreach (var value in bytes) crc = CrcTable[(byte)(crc ^ value)] ^ (crc >> 8); return ~crc; }
    private static uint[] CreateCrcTable() { var table = new uint[256]; for (uint i = 0; i < table.Length; i++) { var value = i; for (var bit = 0; bit < 8; bit++) value = (value & 1) != 0 ? 0xedb88320 ^ (value >> 1) : value >> 1; table[i] = value; } return table; }
    internal static XDocument Xml(byte[] bytes, CancellationToken ct, ref int elements,int maximumElements=1_000_000)
    {
        if (bytes.Length > MaximumXml) throw Rejected(); using var input = new MemoryStream(bytes, false);
        using (var reader = XmlReader.Create(input, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumXml, IgnoreComments = true, CloseInput = false }))
            while (reader.Read()) { ct.ThrowIfCancellationRequested(); if (reader.Depth > 64 || reader.NodeType == XmlNodeType.ProcessingInstruction || reader.NodeType == XmlNodeType.Element && ++elements > maximumElements) throw Rejected(); }
        input.Position = 0; using var safe = XmlReader.Create(input, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumXml, IgnoreComments = true }); return XDocument.Load(safe);
    }
    private static DocumentRejectedException Rejected()=>new("This Office package is unsupported or malformed. Export a PDF and try again.");
}

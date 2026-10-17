using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace QuillSign.Documents;

public sealed class ValidatedDocx : IDisposable
{
    private readonly object gate = new(); private byte[]? bytes; private readonly byte[] hash;
    public long Length { get; }
    internal ValidatedDocx(byte[] bytes, byte[] hash) { this.bytes = bytes; this.hash = hash; Length = bytes.Length; }
    public byte[] OriginalSha256 { get { lock (gate) { ObjectDisposedException.ThrowIf(bytes is null, this); return hash.ToArray(); } } }
    public Stream OpenRead() { lock (gate) { ObjectDisposedException.ThrowIf(bytes is null, this); return new MemoryStream(bytes!.ToArray(), false); } }
    public void Dispose() { lock (gate) { if (bytes is null) return; Array.Clear(bytes); Array.Clear(hash); bytes = null; } }
}

// No filesystem extraction, external resolver, SQL or service request. The owned
// validated copy is independent of both the caller and subsequent read streams.
public sealed class DocxPackageValidation(DocumentOptions limits)
{
    private const int MaximumEntries = 2048, MaximumPart = 16 * 1024 * 1024, MaximumXml = 8 * 1024 * 1024, MaximumExpanded = 64 * 1024 * 1024;
    private const string ContentNamespace = "http://schemas.openxmlformats.org/package/2006/content-types", RelationshipNamespace = "http://schemas.openxmlformats.org/package/2006/relationships";
    private const string MainType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
    private static readonly string[] WordNamespaces = ["http://schemas.openxmlformats.org/wordprocessingml/2006/main", "http://purl.oclc.org/ooxml/wordprocessingml/main"];
    private static readonly HashSet<string> Fields = new("PAGE NUMPAGES SECTIONPAGES TOC SEQ REF PAGEREF NOTEREF STYLEREF DATE TIME CREATEDATE SAVEDATE PRINTDATE DOCPROPERTY DOCVARIABLE MERGEFIELD FORMTEXT FORMCHECKBOX FORMDROPDOWN SYMBOL INDEX TA TC XE IF".Split(' '), StringComparer.OrdinalIgnoreCase);
    private static readonly uint[] CrcTable = CreateCrcTable();

    public async Task<ValidatedDocx> ValidateAsync(Stream input, long declaredLength, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested(); ArgumentNullException.ThrowIfNull(input);
        if (limits.MaximumBytes is < 1024 or > 64 * 1024 * 1024) throw new InvalidOperationException("Configure supported DOCX input limits.");
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
            ValidateParts(parts, token); token.ThrowIfCancellationRequested(); var result = new ValidatedDocx(original, SHA256.HashData(original)); transferred = true; return result;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new DocumentRejectedException("This DOCX is too complex to validate. Export a PDF and try again."); }
        catch (Exception e) when (e is InvalidDataException or XmlException or ArgumentException or NotSupportedException or OverflowException or IOException)
        { throw Rejected(); }
        finally { foreach (var part in parts.Values) Array.Clear(part); if (!transferred && original is not null) Array.Clear(original); }
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

    private static void ValidateParts(Dictionary<string, byte[]> parts, CancellationToken ct)
    {
        if (!parts.TryGetValue("[Content_Types].xml", out var content)) throw Rejected(); var nodes = 0; var types = Xml(content, ct, ref nodes);
        if (types.Root?.Name != XName.Get("Types", ContentNamespace)) throw Rejected();
        var defaults = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var element in types.Root.Elements())
        {
            var type = (string?)element.Attribute("ContentType"); if (string.IsNullOrWhiteSpace(type) || ActiveType(type)) throw Rejected();
            if (element.Name == XName.Get("Default", ContentNamespace)) { var extension = (string?)element.Attribute("Extension"); if (string.IsNullOrWhiteSpace(extension) || extension.Any(c => !char.IsAsciiLetterOrDigit(c)) || !defaults.TryAdd(extension, type)) throw Rejected(); }
            else if (element.Name == XName.Get("Override", ContentNamespace)) { var part = (string?)element.Attribute("PartName"); if (part is null || !part.StartsWith('/') || !overrides.TryAdd(Name(part[1..], false), type)) throw Rejected(); }
            else throw Rejected();
        }
        if (!overrides.TryGetValue("word/document.xml", out var main) || main != MainType || overrides.Keys.Any(x => !parts.ContainsKey(x))) throw Rejected();
        var mainLinks = 0;
        foreach (var (name, bytes) in parts)
        {
            ct.ThrowIfCancellationRequested(); if (name.Equals("[Content_Types].xml", StringComparison.OrdinalIgnoreCase)) continue;
            var extension = name.Split('.').Last(); var type = overrides.GetValueOrDefault(name) ?? defaults.GetValueOrDefault(extension);
            if (type is null || ActiveType(type)) throw Rejected();
            if (extension.Equals("rels", StringComparison.OrdinalIgnoreCase) && type != "application/vnd.openxmlformats-package.relationships+xml") throw Rejected();
            if (extension.Equals("xml", StringComparison.OrdinalIgnoreCase) || extension.Equals("rels", StringComparison.OrdinalIgnoreCase) || type is "application/xml" or "text/xml" || type.EndsWith("+xml", StringComparison.OrdinalIgnoreCase))
            {
                var xml = Xml(bytes, ct, ref nodes);
                if (name.Equals("word/document.xml", StringComparison.OrdinalIgnoreCase) && (xml.Root?.Name.LocalName != "document" || !WordNamespaces.Contains(xml.Root.Name.NamespaceName) || xml.Root.Elements(xml.Root.Name.Namespace + "body").Count() != 1)) throw Rejected();
                FieldsAndResources(xml, ct);
                if (extension.Equals("rels", StringComparison.OrdinalIgnoreCase))
                {
                    if (xml.Root?.Name != XName.Get("Relationships", RelationshipNamespace)) throw Rejected(); var ids = new HashSet<string>(StringComparer.Ordinal); var owner = Owner(name);
                    if (owner.Length != 0 && !parts.ContainsKey(owner)) throw Rejected();
                    foreach (var relation in xml.Root.Elements())
                    {
                        ct.ThrowIfCancellationRequested(); var id = (string?)relation.Attribute("Id"); var target = (string?)relation.Attribute("Target"); var kind = (string?)relation.Attribute("Type"); var mode = (string?)relation.Attribute("TargetMode");
                        if (relation.Name != XName.Get("Relationship", RelationshipNamespace) || string.IsNullOrWhiteSpace(id) || !ids.Add(id) || string.IsNullOrWhiteSpace(target) || string.IsNullOrWhiteSpace(kind) || ActiveRelationship(kind)) throw Rejected();
                        if (string.Equals(mode, "External", StringComparison.OrdinalIgnoreCase)) { if (!kind.EndsWith("/hyperlink", StringComparison.Ordinal) || !Hyperlink(target)) throw Rejected(); continue; }
                        if (mode is not null && mode != "Internal") throw Rejected(); var resolved = Resolve(owner, target); if (!parts.ContainsKey(resolved)) throw Rejected();
                        if (kind.EndsWith("/officeDocument", StringComparison.Ordinal)) { if (owner.Length != 0 || resolved != "word/document.xml") throw Rejected(); mainLinks++; }
                    }
                }
            }
        }
        if (mainLinks != 1 || !parts.ContainsKey("_rels/.rels")) throw Rejected();
    }

    private static XDocument Xml(byte[] bytes, CancellationToken ct, ref int elements)
    {
        if (bytes.Length > MaximumXml) throw Rejected(); using var input = new MemoryStream(bytes, false);
        using (var reader = XmlReader.Create(input, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumXml, IgnoreComments = true, CloseInput = false }))
            while (reader.Read()) { ct.ThrowIfCancellationRequested(); if (reader.Depth > 64 || reader.NodeType == XmlNodeType.ProcessingInstruction || reader.NodeType == XmlNodeType.Element && ++elements > 1000000) throw Rejected(); }
        input.Position = 0; using var safe = XmlReader.Create(input, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumXml, IgnoreComments = true }); return XDocument.Load(safe);
    }
    private static void FieldsAndResources(XDocument document, CancellationToken ct)
    {
        var codes = new Stack<StringBuilder>();
        foreach (var element in document.Descendants())
        {
            ct.ThrowIfCancellationRequested();
            if (element.Name.NamespaceName == "http://www.w3.org/2000/svg" || element.Name.LocalName is "OLEObject" or "ocx") throw Rejected();
            if (element.Attributes().Any(a => a.Name.LocalName.Equals("href", StringComparison.OrdinalIgnoreCase) && !a.Value.StartsWith('#'))) throw Rejected();
            if (!WordNamespaces.Contains(element.Name.NamespaceName)) continue; var ns = element.Name.Namespace;
            if (element.Name.LocalName is "altChunk" or "object" or "control" or "subDoc") throw Rejected();
            if (element.Name.LocalName == "fldSimple") CheckField((string?)element.Attribute(ns + "instr") ?? "");
            if (element.Name.LocalName == "fldChar")
            {
                var kind = (string?)element.Attribute(ns + "fldCharType");
                if (kind == "begin") { if (codes.Count >= 32) throw Rejected(); codes.Push(new()); }
                else if (kind == "separate") { if (codes.Count == 0) throw Rejected(); CheckField(codes.Peek().ToString()); }
                else if (kind == "end") { if (codes.Count == 0) throw Rejected(); CheckField(codes.Pop().ToString()); }
            }
            if (element.Name.LocalName == "instrText") { if (codes.Count == 0) throw Rejected(); codes.Peek().Append(element.Value); }
        }
        if (codes.Count != 0) throw Rejected();
    }
    private static void CheckField(string value)
    {
        var command = new string(value.TrimStart().TakeWhile(char.IsAsciiLetter).ToArray());
        if (!Fields.Contains(command)) throw Rejected();
    }
    private static bool Hyperlink(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        (uri.Scheme is "http" or "https" && uri.UserInfo.Length == 0 || uri.Scheme == "mailto" && !value.Contains('?') && !value.Contains('#') && value[7..].Contains('@'));
    private static string Owner(string relationship)
    {
        if (relationship == "_rels/.rels") return ""; var marker = relationship.LastIndexOf("/_rels/", StringComparison.Ordinal);
        if (marker < 0 || !relationship.EndsWith(".rels", StringComparison.Ordinal)) throw Rejected(); return relationship[..marker] + "/" + relationship[(marker + 7)..^5];
    }
    private static string Resolve(string owner, string target)
    {
        var raw = target.Split('#')[0]; if (raw.Length == 0) return owner;
        if (raw.Contains('?') || raw.Contains(':') || raw.StartsWith("//", StringComparison.Ordinal)) throw Rejected();
        var stack = raw.StartsWith('/') ? new List<string>() : owner.Split('/').SkipLast(1).ToList();
        var decoded = Uri.UnescapeDataString(raw.TrimStart('/'));
        if (decoded.Contains('%') || decoded.Contains('\\') || decoded.Count(c => c == '/') != raw.TrimStart('/').Count(c => c == '/')) throw Rejected();
        foreach (var item in decoded.Split('/')) { if (item == ".") continue; if (item == "..") { if (stack.Count == 0) throw Rejected(); stack.RemoveAt(stack.Count - 1); } else stack.Add(item); }
        return Name(string.Join('/', stack), false);
    }
    private static string Name(string name, bool directory)
    {
        if (name.Length is < 1 or > 512 || name.StartsWith('/') || name.Contains('\\') || name.Contains(':') || name.Contains('?') || name.Contains('#') || name.Contains('%')) throw Rejected();
        var decoded = Uri.UnescapeDataString(name).Normalize(NormalizationForm.FormC); if (decoded.Contains('%') || decoded.Contains('\\') || decoded.Contains(':') || decoded.Any(char.IsControl)) throw Rejected();
        var parts = (directory ? decoded.TrimEnd('/') : decoded).Split('/'); if (parts.Any(x => x.Length == 0 || x is "." or ".." || x != x.Trim())) throw Rejected(); return string.Join('/', parts);
    }
    private static bool ActivePart(string value) => value.Contains("/embeddings/", StringComparison.OrdinalIgnoreCase) || value.StartsWith("embeddings/", StringComparison.OrdinalIgnoreCase) || value.Contains("activex", StringComparison.OrdinalIgnoreCase) || value.Split('/').Any(x => x.StartsWith("vba", StringComparison.OrdinalIgnoreCase)) || value.StartsWith("_xmlsignatures/", StringComparison.OrdinalIgnoreCase) || value.StartsWith("customUI/", StringComparison.OrdinalIgnoreCase);
    private static bool ActiveType(string value) => new[] { "macroenabled", "vba", "activex", "oleobject", "digital-signature", "executable", "javascript", "image/svg" }.Any(x => value.Contains(x, StringComparison.OrdinalIgnoreCase));
    private static bool ActiveRelationship(string value) => new[] { "/vbaProject", "/vbaData", "/oleObject", "/control", "/package", "/aFChunk", "/attachedTemplate", "/subDocument" }.Any(x => value.EndsWith(x, StringComparison.OrdinalIgnoreCase)) || value.Contains("/digital-signature", StringComparison.OrdinalIgnoreCase);
    private static async Task Copy(Stream input, Stream output, long maximum, CancellationToken ct)
    {
        var buffer = new byte[65536]; long total = 0; int count; while ((count = await input.ReadAsync(buffer, ct)) != 0) { if ((total += count) > maximum) throw Rejected(); await output.WriteAsync(buffer.AsMemory(0, count), ct); }
    }
    private static ushort U16(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(at, 2));
    private static uint U32(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(at, 4));
    private static uint Crc(ReadOnlySpan<byte> bytes) { var crc = uint.MaxValue; foreach (var value in bytes) crc = CrcTable[(byte)(crc ^ value)] ^ (crc >> 8); return ~crc; }
    private static uint[] CreateCrcTable() { var table = new uint[256]; for (uint i = 0; i < table.Length; i++) { var value = i; for (var bit = 0; bit < 8; bit++) value = (value & 1) != 0 ? 0xedb88320 ^ (value >> 1) : value >> 1; table[i] = value; } return table; }
    private static DocumentRejectedException Rejected() => new("This DOCX is unsupported or malformed. Export a PDF and try again.");
}

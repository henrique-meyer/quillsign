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
    private const string ContentNamespace = "http://schemas.openxmlformats.org/package/2006/content-types", RelationshipNamespace = "http://schemas.openxmlformats.org/package/2006/relationships";
    private const string MainType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
    private static readonly string[] WordNamespaces = ["http://schemas.openxmlformats.org/wordprocessingml/2006/main", "http://purl.oclc.org/ooxml/wordprocessingml/main"];
    private static readonly HashSet<string> Fields = new("PAGE NUMPAGES SECTIONPAGES TOC SEQ REF PAGEREF NOTEREF STYLEREF DATE TIME CREATEDATE SAVEDATE PRINTDATE DOCPROPERTY DOCVARIABLE MERGEFIELD FORMTEXT FORMCHECKBOX FORMDROPDOWN SYMBOL INDEX TA TC XE IF".Split(' '), StringComparer.OrdinalIgnoreCase);

    public async Task<ValidatedDocx> ValidateAsync(Stream input,long declaredLength,CancellationToken ct=default)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            using var package=await BoundedOfficePackage.ReadAsync(input,declaredLength,limits,timeout.Token);
            ValidateParts(package.Parts,timeout.Token);timeout.Token.ThrowIfCancellationRequested();
            var original=package.DetachOriginal();return new(original,SHA256.HashData(original));
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){throw Rejected();}
        catch(Exception e) when(e is DocumentRejectedException or InvalidDataException or XmlException or ArgumentException or NotSupportedException or OverflowException or IOException){throw Rejected();}
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

    private static XDocument Xml(byte[] bytes,CancellationToken ct,ref int elements)=>BoundedOfficePackage.Xml(bytes,ct,ref elements);
    private static void FieldsAndResources(XDocument document, CancellationToken ct)
    {
        var codes = new Stack<StringBuilder>();
        foreach (var element in document.Descendants())
        {
            ct.ThrowIfCancellationRequested();
            if (element.Name.NamespaceName == "http://www.w3.org/2000/svg" || element.Name.LocalName is "OLEObject" or "ocx") throw Rejected();
            if (element.Attributes().Any(a => (a.Name.LocalName.Equals("href", StringComparison.OrdinalIgnoreCase) ||
                a.Name.LocalName.Equals("src", StringComparison.OrdinalIgnoreCase) || a.Name.LocalName.Equals("codebase", StringComparison.OrdinalIgnoreCase) ||
                a.Name.LocalName.Equals("data", StringComparison.OrdinalIgnoreCase)) && !a.Value.StartsWith('#'))) throw Rejected();
            if (!WordNamespaces.Contains(element.Name.NamespaceName)) continue; var ns = element.Name.Namespace;
            if (element.Name.LocalName is "altChunk" or "object" or "control" or "subDoc" or "mailMerge" or "saveThroughXslt") throw Rejected();
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
        var parts = (directory ? decoded[..^1] : decoded).Split('/'); if (parts.Any(x => x.Length == 0 || x is "." or ".." || x != x.Trim())) throw Rejected(); return string.Join('/', parts);
    }
    private static bool ActivePart(string value) => value.Contains("/embeddings/", StringComparison.OrdinalIgnoreCase) || value.StartsWith("embeddings/", StringComparison.OrdinalIgnoreCase) || value.Contains("activex", StringComparison.OrdinalIgnoreCase) || value.Split('/').Any(x => x.StartsWith("vba", StringComparison.OrdinalIgnoreCase)) || value.StartsWith("_xmlsignatures/", StringComparison.OrdinalIgnoreCase) || value.StartsWith("customUI/", StringComparison.OrdinalIgnoreCase);
    private static bool ActiveType(string value) => new[] { "macroenabled", "vba", "activex", "oleobject", "digital-signature", "executable", "javascript", "image/svg" }.Any(x => value.Contains(x, StringComparison.OrdinalIgnoreCase));
    private static bool ActiveRelationship(string value) => new[] { "/vbaProject", "/vbaData", "/oleObject", "/control", "/package", "/aFChunk", "/attachedTemplate", "/subDocument" }.Any(x => value.EndsWith(x, StringComparison.OrdinalIgnoreCase)) || value.Contains("/digital-signature", StringComparison.OrdinalIgnoreCase);
    private static DocumentRejectedException Rejected() => new("This DOCX is unsupported or malformed. Export a PDF and try again.");
}

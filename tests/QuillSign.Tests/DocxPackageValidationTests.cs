using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class DocxPackageValidationTests
{
    private const string Word = "http://schemas.openxmlformats.org/wordprocessingml/2006/main", Relations = "http://schemas.openxmlformats.org/package/2006/relationships", Office = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/", Types = "http://schemas.openxmlformats.org/package/2006/content-types";
    [Fact]
    public async Task Exact_original_copy_hash_and_readers_are_independent_of_caller_mutation_and_disposal()
    {
        var bytes = GotenbergDocxConverterTests.Docx(); var expected = bytes.ToArray(); using var input = new MemoryStream(bytes);
        var valid = await new DocxPackageValidation(new()).ValidateAsync(input, input.Length); Assert.True(input.CanRead); Assert.Equal(expected.Length, valid.Length); Assert.Equal(SHA256.HashData(expected), valid.OriginalSha256);
        bytes[0] ^= 1; var hash = valid.OriginalSha256; hash[0] ^= 1; using var reader = valid.OpenRead(); Assert.False(reader.CanWrite); Assert.Throws<NotSupportedException>(() => reader.WriteByte(1));
        valid.Dispose(); Assert.True(input.CanRead); Assert.Throws<ObjectDisposedException>(() => valid.OpenRead()); using var copied = new MemoryStream(); await reader.CopyToAsync(copied); Assert.Equal(expected, copied.ToArray());
    }
    [Theory]
    [InlineData("https://example.invalid/synthetic")]
    [InlineData("http://example.invalid/synthetic")]
    [InlineData("mailto:synthetic@example.invalid")]
    public async Task Inert_core_properties_headers_fragmented_page_fields_images_and_explicit_hyperlinks_are_preserved(string target)
    {
        var bytes = Edit(zip =>
        {
            Put(zip, "docProps/core.xml", $"<coreProperties xmlns=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" />", "application/vnd.openxmlformats-package.core-properties+xml");
            Rel(zip, "_rels/.rels", "props", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", "docProps/core.xml");
            Put(zip, "word/header1.xml", $"<w:hdr xmlns:w=\"{Word}\"><w:p><w:r><w:fldChar w:fldCharType=\"begin\"/><w:instrText> PA</w:instrText><w:instrText>GE \\* MERGEFORMAT</w:instrText><w:fldChar w:fldCharType=\"end\"/></w:r></w:p></w:hdr>", "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml");
            Rel(zip, "word/_rels/document.xml.rels", "header", Office + "header", "header1.xml"); Rel(zip, "word/_rels/document.xml.rels", "link", Office + "hyperlink", target, "External");
            Put(zip, "word/media/image1.png", Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aF1sAAAAASUVORK5CYII="), "image/png"); Rel(zip, "word/_rels/document.xml.rels", "image", Office + "image", "media/image1.png");
        });
        using var source = new MemoryStream(bytes); using var valid = await new DocxPackageValidation(new()).ValidateAsync(source, bytes.Length); using var read = valid.OpenRead(); using var copy = new MemoryStream(); await read.CopyToAsync(copy); Assert.Equal(bytes, copy.ToArray());
    }
    [Theory]
    [InlineData("types")]
    [InlineData("root-rels")]
    [InlineData("main")]
    [InlineData("spreadsheet")]
    [InlineData("macro-type")]
    [InlineData("macro-part")]
    [InlineData("embedded")]
    [InlineData("signature")]
    [InlineData("active-rel")]
    [InlineData("external-image")]
    [InlineData("external-main")]
    [InlineData("missing-target")]
    [InlineData("duplicate-rel")]
    [InlineData("template")]
    [InlineData("unsafe-link")]
    [InlineData("doctype")]
    [InlineData("deep")]
    [InlineData("broken-xml")]
    [InlineData("dde-field")]
    [InlineData("split-dde")]
    [InlineData("svg")]
    [InlineData("root-shape")]
    [InlineData("untyped-svg")]
    [InlineData("xml-extension-spoof")]
    [InlineData("alt-chunk")]
    [InlineData("object-element")]
    public async Task Unsupported_packages_active_content_and_unsafe_references_are_rejected_without_private_details(string kind)
    {
        var bytes = Edit(zip =>
        {
            switch (kind)
            {
                case "types": zip.GetEntry("[Content_Types].xml")!.Delete(); break;
                case "root-rels": zip.GetEntry("_rels/.rels")!.Delete(); break;
                case "main": zip.GetEntry("word/document.xml")!.Delete(); break;
                case "spreadsheet": Type(zip, "word/document.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"); break;
                case "macro-type": Type(zip, "word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml"); break;
                case "macro-part": Put(zip, "word/vbaProject.bin", new byte[] { 1, 2, 3 }, "application/octet-stream"); break;
                case "embedded": Put(zip, "word/embeddings/private.bin", new byte[] { 1, 2, 3 }, "application/octet-stream"); break;
                case "signature": Put(zip, "_xmlsignatures/private.xml", "<signature />", "application/xml"); break;
                case "active-rel": Rel(zip, "word/_rels/document.xml.rels", "active", Office + "package", "document.xml"); break;
                case "external-image": Rel(zip, "word/_rels/document.xml.rels", "private", Office + "image", "https://example.invalid/PRIVATE-MARKER", "External"); break;
                case "external-main": ReplaceRootTarget(zip, "https://example.invalid/PRIVATE-MARKER", true); break;
                case "missing-target": Rel(zip, "word/_rels/document.xml.rels", "missing", Office + "image", "media/private.png"); break;
                case "duplicate-rel": Rel(zip, "_rels/.rels", "rId1", Office + "officeDocument", "word/document.xml"); break;
                case "template": Rel(zip, "word/_rels/document.xml.rels", "template", Office + "attachedTemplate", "https://example.invalid/private", "External"); break;
                case "unsafe-link": Rel(zip, "word/_rels/document.xml.rels", "link", Office + "hyperlink", "javascript:PRIVATE-MARKER", "External"); break;
                case "doctype": Put(zip, "word/document.xml", $"<!DOCTYPE w:document [<!ENTITY private SYSTEM 'file:///PRIVATE-MARKER'>]><w:document xmlns:w=\"{Word}\"><w:body><w:p>&private;</w:p></w:body></w:document>"); break;
                case "deep": Put(zip, "word/document.xml", $"<w:document xmlns:w=\"{Word}\"><w:body>" + string.Concat(Enumerable.Repeat("<w:p>", 65)) + string.Concat(Enumerable.Repeat("</w:p>", 65)) + "</w:body></w:document>"); break;
                case "broken-xml": Put(zip, "word/document.xml", "<PRIVATE-MARKER>"); break;
                case "dde-field": Put(zip, "word/document.xml", DocumentXml("<w:fldSimple w:instr=\"DDEAUTO PRIVATE-MARKER\" />")); break;
                case "split-dde": Put(zip, "word/document.xml", DocumentXml("<w:p><w:r><w:fldChar w:fldCharType=\"begin\"/><w:instrText>DD</w:instrText><w:instrText>EAUTO PRIVATE-MARKER</w:instrText><w:fldChar w:fldCharType=\"end\"/></w:r></w:p>")); break;
                case "svg": Put(zip, "word/media/private.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\" />", "image/svg+xml"); break;
                case "root-shape": Put(zip, "word/document.xml", "<PRIVATE-MARKER />"); break;
                case "untyped-svg": Put(zip, "word/media/private.xml", "<svg xmlns=\"http://www.w3.org/2000/svg\" />", "application/xml"); break;
                case "xml-extension-spoof": Put(zip, "word/private.bin", "<!DOCTYPE private><private />", "application/xml"); break;
                case "alt-chunk": Put(zip, "word/document.xml", DocumentXml("<w:altChunk />")); break;
                case "object-element": Put(zip, "word/document.xml", DocumentXml("<w:p><w:r><w:object /></w:r></w:p>")); break;
            }
        });
        using var source = new MemoryStream(bytes); var error = await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(source, bytes.Length)); Assert.True(source.CanRead);
        Assert.DoesNotContain("PRIVATE-MARKER", error.Message); Assert.Null(error.InnerException);
    }
    [Theory]
    [InlineData("../private.xml")]
    [InlineData("/private.xml")]
    [InlineData("C:\\private.xml")]
    [InlineData("word/../private.xml")]
    [InlineData("word%2Fprivate.xml")]
    [InlineData("word/%252e%252e/private.xml")]
    [InlineData("word\\private.xml")]
    [InlineData("word/./private.xml")]
    [InlineData("word//private.xml")]
    [InlineData("word/private.xml ")]
    public async Task Traversal_absolute_and_ambiguous_part_names_never_reach_extraction_or_conversion(string path)
    {
        var bytes = Edit(zip => Put(zip, path, "<synthetic />")); using var source = new MemoryStream(bytes);
        await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(source, bytes.Length));
    }
    [Theory]
    [InlineData("duplicate")]
    [InlineData("case-alias")]
    [InlineData("directory-shadow")]
    [InlineData("symlink")]
    [InlineData("local-name")]
    [InlineData("crc")]
    [InlineData("encryption")]
    [InlineData("trailing")]
    [InlineData("count")]
    public async Task Conflicting_headers_aliases_links_corruption_and_encryption_are_rejected(string kind)
    {
        var bytes = Edit(zip =>
        {
            if (kind is "duplicate" or "case-alias") { using var writer = new StreamWriter(zip.CreateEntry(kind == "duplicate" ? "word/document.xml" : "word/DOCUMENT.XML").Open()); writer.Write(DocumentXml("<w:p />")); }
            if (kind == "directory-shadow") Put(zip, "word", "<synthetic />");
            if (kind == "symlink") { Put(zip, "word/link.xml", "<synthetic />", "application/xml"); zip.GetEntry("word/link.xml")!.ExternalAttributes = unchecked((int)0xa1ff0000); }
        });
        var end = bytes.Length - 22; var central = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(end + 16, 4)); var local = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(central + 42, 4));
        if (kind == "local-name") bytes[local + 30] ^= 1;
        if (kind == "crc") { bytes[central + 16] ^= 1; bytes[local + 14] ^= 1; }
        if (kind == "encryption") { bytes[central + 8] |= 1; bytes[local + 6] |= 1; }
        if (kind == "trailing") bytes = [.. bytes, 1];
        if (kind == "count") { BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(end + 8, 2), ushort.MaxValue); BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(end + 10, 2), ushort.MaxValue); }
        using var source = new MemoryStream(bytes); await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(source, bytes.Length));
    }
    [Theory]
    [InlineData("part")]
    [InlineData("xml")]
    [InlineData("total")]
    [InlineData("entries")]
    public async Task Compressed_input_cannot_expand_beyond_the_explicit_package_limits(string kind)
    {
        var bytes = Edit(zip =>
        {
            if (kind == "part") Put(zip, "word/media/large.bin", new byte[16 * 1024 * 1024 + 1], "application/octet-stream");
            if (kind == "xml") Put(zip, "word/large.xml", Encoding.UTF8.GetBytes("<root>" + new string('x', 8 * 1024 * 1024) + "</root>"), "application/xml");
            if (kind == "total") for (var i = 0; i < 4; i++) Put(zip, $"word/media/large{i}.bin", new byte[16 * 1024 * 1024], "application/octet-stream");
            if (kind == "entries") for (var i = 0; i < 2050; i++) Put(zip, $"word/media/{i}.bin", new byte[] { 1 });
        });
        using var source = new MemoryStream(bytes); await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(source, bytes.Length));
    }
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(100000000)]
    public async Task Invalid_declared_lengths_are_rejected_before_reading(long length)
    {
        using var source = new MemoryStream(GotenbergDocxConverterTests.Docx()); await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(source, length)); Assert.Equal(0, source.Position);
    }
    [Fact]
    public async Task Length_mismatch_and_caller_cancellation_preserve_input_ownership()
    {
        using var source = new MemoryStream(GotenbergDocxConverterTests.Docx()); await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(source, source.Length + 1)); Assert.True(source.CanRead);
        source.Position = 0; using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DocxPackageValidation(new()).ValidateAsync(source, source.Length, cancelled.Token)); Assert.Equal(0, source.Position);
    }

    [Fact]
    public async Task Streaming_zip_data_descriptors_are_supported_only_with_exact_crc_and_sizes()
    {
        var bytes = StreamingPackage(); using (var source = new MemoryStream(bytes)) using (var valid = await new DocxPackageValidation(new()).ValidateAsync(source, bytes.Length)) Assert.Equal(bytes.Length, valid.Length);
        var central = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(bytes.Length - 6, 4));
        var payload = 30 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(26, 2)) + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(28, 2));
        var descriptor = payload + (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(central + 20, 4));
        bytes[descriptor + 4] ^= 1; using var broken = new MemoryStream(bytes); await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(broken, bytes.Length));
    }

    [Theory]
    [InlineData(0x7075)]
    [InlineData(0x0001)]
    [InlineData(0xffff)]
    public async Task Alternate_path_size_or_malformed_extra_records_are_rejected(int kind)
    {
        var bytes = GotenbergDocxConverterTests.Docx(); var end = bytes.Length - 22; var central = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(end + 16, 4));
        var name = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(central + 28, 2)); var at = central + 46 + name;
        byte[] extra = new byte[8]; BinaryPrimitives.WriteUInt16LittleEndian(extra, (ushort)kind); BinaryPrimitives.WriteUInt16LittleEndian(extra.AsSpan(2), kind == 0xffff ? (ushort)20 : (ushort)4);
        var changed = bytes[..at].Concat(extra).Concat(bytes[at..]).ToArray(); BinaryPrimitives.WriteUInt16LittleEndian(changed.AsSpan(central + 30), 8);
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(end + 8 + 12), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(end + 12)) + 8);
        using var source = new MemoryStream(changed); await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(source, changed.Length));
    }

    [Fact]
    public async Task Unlisted_local_records_or_gaps_cannot_hide_before_the_central_directory()
    {
        var bytes = GotenbergDocxConverterTests.Docx(); var end = bytes.Length - 22; var central = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(end + 16, 4));
        var changed = bytes[..central].Concat(new byte[30]).Concat(bytes[central..]).ToArray(); BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(end + 30 + 16), (uint)central + 30);
        using var source = new MemoryStream(changed); await Assert.ThrowsAsync<DocumentRejectedException>(() => new DocxPackageValidation(new()).ValidateAsync(source, changed.Length));
    }

    [Fact]
    public async Task Cancellation_during_input_copy_stops_and_preserves_the_callers_stream()
    {
        using var cancellation = new CancellationTokenSource(); using var source = new CancelOnRead(GotenbergDocxConverterTests.Docx(), cancellation);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DocxPackageValidation(new()).ValidateAsync(source, source.Length, cancellation.Token)); Assert.True(source.CanRead);
    }

    [Fact]
    public async Task External_entity_and_resource_validation_never_contact_a_local_receiver()
    {
        var receiver = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0); receiver.Start();
        try
        {
            var url = "http://127.0.0.1:" + ((System.Net.IPEndPoint)receiver.LocalEndpoint).Port + "/synthetic";
            foreach (var kind in new[] { "entity", "image", "hyperlink" })
            {
                var bytes = Edit(zip =>
                {
                    if (kind == "entity") Put(zip, "word/document.xml", $"<!DOCTYPE w:document [<!ENTITY remote SYSTEM '{url}'>]><w:document xmlns:w=\"{Word}\"><w:body>&remote;</w:body></w:document>");
                    else Rel(zip, "word/_rels/document.xml.rels", "remote", Office + kind, url, "External");
                });
                using var source = new MemoryStream(bytes); var gate = new DocxPackageValidation(new());
                if (kind == "hyperlink") { using var valid = await gate.ValidateAsync(source, bytes.Length); }
                else await Assert.ThrowsAsync<DocumentRejectedException>(() => gate.ValidateAsync(source, bytes.Length));
            }
            Assert.False(receiver.Pending());
        }
        finally { receiver.Stop(); }
    }

    private static byte[] StreamingPackage()
    {
        using var output = new NonSeekingOutput(); using var original = new MemoryStream(GotenbergDocxConverterTests.Docx()); using var input = new ZipArchive(original, ZipArchiveMode.Read);
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true)) foreach (var entry in input.Entries) { using var source = entry.Open(); using var target = zip.CreateEntry(entry.FullName).Open(); source.CopyTo(target); }
        return output.ToArray();
    }
    private sealed class NonSeekingOutput : MemoryStream { public override bool CanSeek => false; public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); }
    private sealed class CancelOnRead(byte[] bytes, CancellationTokenSource cancellation) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { cancellation.Cancel(); return base.ReadAsync(buffer, ct); }
    }
    private static string DocumentXml(string body) => $"<w:document xmlns:w=\"{Word}\"><w:body>{body}</w:body></w:document>";
    private static byte[] Edit(Action<ZipArchive> edit)
    {
        using var bytes = new MemoryStream(); bytes.Write(GotenbergDocxConverterTests.Docx()); bytes.Position = 0; using (var zip = new ZipArchive(bytes, ZipArchiveMode.Update, true)) edit(zip); return bytes.ToArray();
    }
    private static string Text(ZipArchive zip, string path) { using var reader = new StreamReader(zip.GetEntry(path)!.Open()); return reader.ReadToEnd(); }
    private static void Put(ZipArchive zip, string path, string text, string? type = null) => Put(zip, path, Encoding.UTF8.GetBytes(text), type);
    private static void Put(ZipArchive zip, string path, byte[] bytes, string? type = null)
    {
        zip.GetEntry(path)?.Delete(); using (var stream = zip.CreateEntry(path).Open()) stream.Write(bytes); if (type is not null) Type(zip, path, type);
    }
    private static void Type(ZipArchive zip, string path, string type)
    {
        var xml = XDocument.Parse(Text(zip, "[Content_Types].xml")); XNamespace ns = Types; xml.Root!.Elements(ns + "Override").Where(x => (string?)x.Attribute("PartName") == "/" + path).Remove();
        xml.Root.Add(new XElement(ns + "Override", new XAttribute("PartName", "/" + path), new XAttribute("ContentType", type))); Put(zip, "[Content_Types].xml", xml.ToString());
    }
    private static void Rel(ZipArchive zip, string path, string id, string type, string target, string? mode = null)
    {
        XNamespace ns = Relations; var xml = zip.GetEntry(path) is null ? new XDocument(new XElement(ns + "Relationships")) : XDocument.Parse(Text(zip, path));
        var relation = new XElement(ns + "Relationship", new XAttribute("Id", id), new XAttribute("Type", type), new XAttribute("Target", target)); if (mode is not null) relation.Add(new XAttribute("TargetMode", mode)); xml.Root!.Add(relation); Put(zip, path, xml.ToString());
    }
    private static void ReplaceRootTarget(ZipArchive zip, string target, bool external)
    {
        var xml = XDocument.Parse(Text(zip, "_rels/.rels")); var relation = xml.Root!.Elements().Single(); relation.SetAttributeValue("Target", target); if (external) relation.SetAttributeValue("TargetMode", "External"); Put(zip, "_rels/.rels", xml.ToString());
    }
}

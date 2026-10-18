using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace QuillSign.Documents;

public sealed record TextConversion(byte[] Pdf, byte[] OriginalSha256, byte[] PdfSha256, IReadOnlyList<PageGeometry> Pages);

// Internal conversion only. Never hand untrusted .txt to LibreOffice's format
// detector: serialize literal text into a minimal, validated DOCX first.
public sealed class TextPdfConverter(DocumentOptions limits, GotenbergOptions options,
    IHostEnvironment environment, DocxPackageValidation packages, GotenbergDocxConverter converter)
{
    private const string Word = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private const int MaximumXml = 8 * 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public async Task<TextConversion> ConvertAsync(Stream original, long declaredLength, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested(); ArgumentNullException.ThrowIfNull(original);
        if (!options.IsAvailable(environment)) throw new DocumentConversionUnavailableException("Document conversion is not enabled.");
        if (limits.MaximumBytes is < 1024 or > 64 * 1024 * 1024 || limits.MaximumPages is < 1 or > 200)
            throw new InvalidOperationException("Configure supported document conversion limits.");
        if (declaredLength <= 0 || declaredLength > limits.MaximumBytes) throw Rejected();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds)); var token = timeout.Token;
        byte[]? bytes = null;
        try
        {
            using var copy = new MemoryStream(); var buffer = new byte[65536]; int count;
            while ((count = await original.ReadAsync(buffer, token)) != 0)
            {
                if (copy.Length + count > limits.MaximumBytes) throw Rejected();
                await copy.WriteAsync(buffer.AsMemory(0, count), token);
            }
            if (copy.Length != declaredLength) throw Rejected();
            bytes = copy.ToArray(); var offset = bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? 3 : 0;
            var text = Utf8.GetString(bytes, offset, bytes.Length - offset);
            if (string.IsNullOrWhiteSpace(text)) throw Rejected();
            for (var i = 0; i < text.Length; i++)
            {
                if ((i & 4095) == 0) token.ThrowIfCancellationRequested();
                if (char.IsControl(text[i]) && text[i] is not ('\r' or '\n' or '\t')) throw Rejected();
            }
            XmlConvert.VerifyXmlChars(text); token.ThrowIfCancellationRequested();
            using var package = new MemoryStream();
            BuildPackage(package, text, token);
            if (package.Length > limits.MaximumBytes) throw Rejected();
            package.Position = 0;
            using var validated = await packages.ValidateAsync(package, package.Length, token);
            using var source = validated.OpenRead();
            var converted = await converter.ConvertAsync(source, validated.Length, token);
            token.ThrowIfCancellationRequested();
            return new(converted.Pdf, SHA256.HashData(bytes), converted.PdfSha256, converted.Pages);
        }
        catch (DecoderFallbackException) { throw Rejected(); }
        catch (XmlException) { throw Rejected(); }
        catch (IOException) { throw Rejected(); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw new DocumentConversionUnavailableException("Text conversion timed out."); }
        finally { if (bytes is not null) Array.Clear(bytes); }
    }

    private static void BuildPackage(Stream output, string text, CancellationToken ct)
    {
        using var zip = new ZipArchive(output, ZipArchiveMode.Create, true);
        void Part(string name, string content)
        { using var writer = new StreamWriter(zip.CreateEntry(name).Open(), Utf8); writer.Write(content); }
        Part("[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
        Part("_rels/.rels", "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>");
        using var document = new MemoryStream();
        using var bounded = new BoundedDocumentStream(document, MaximumXml);
        using (var xml = XmlWriter.Create(bounded, new XmlWriterSettings { Encoding = Utf8, CloseOutput = false }))
        {
            xml.WriteStartElement("w", "document", Word); xml.WriteStartElement("w", "body", Word);
            xml.WriteStartElement("w", "p", Word); xml.WriteStartElement("w", "r", Word);
            var start = 0;
            void Literal(int end)
            {
                if (start == end) return;
                xml.WriteStartElement("w", "t", Word); xml.WriteAttributeString("xml", "space", null, "preserve");
                xml.WriteString(text[start..end]); xml.WriteEndElement();
            }
            for (var at = 0; at < text.Length; at++)
            {
                if ((at & 4095) == 0) ct.ThrowIfCancellationRequested();
                if (text[at] is not ('\r' or '\n' or '\t')) continue;
                Literal(at);
                if (text[at] == '\t') { xml.WriteStartElement("w", "tab", Word); xml.WriteEndElement(); }
                else
                {
                    xml.WriteEndElement(); xml.WriteEndElement();
                    xml.WriteStartElement("w", "p", Word); xml.WriteStartElement("w", "r", Word);
                    if (text[at] == '\r' && at + 1 < text.Length && text[at + 1] == '\n') at++;
                }
                start = at + 1;
            }
            Literal(text.Length); xml.WriteEndElement(); xml.WriteEndElement();
            xml.WriteStartElement("w", "sectPr", Word);
            xml.WriteStartElement("w", "pgSz", Word); xml.WriteAttributeString("w", "w", Word, "12240"); xml.WriteAttributeString("w", "h", Word, "15840"); xml.WriteEndElement();
            xml.WriteEndElement(); xml.WriteEndElement(); xml.WriteEndElement();
        }
        ct.ThrowIfCancellationRequested(); document.Position = 0;
        using var entry = zip.CreateEntry("word/document.xml").Open(); document.CopyTo(entry);
    }

    private static DocumentRejectedException Rejected() => new("Choose a nonempty UTF-8 plain text file within the conversion limits, or export a PDF.");
}

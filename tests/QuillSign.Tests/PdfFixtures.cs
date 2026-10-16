using System.Globalization;
using System.Text;
using PdfSharp.Pdf.IO;

namespace QuillSign.Tests;

public static class PdfFixtures
{
    public static byte[] Create(int pages = 2, string catalog = "", int rotation = 0, string media = "0 0 612 792", string text = "Synthetic document", string pageEntries = "")
    {
        var objects = new List<string>
        {
            $"<< /Type /Catalog /Pages 2 0 R {catalog} >>",
            $"<< /Type /Pages /Count {pages} /Kids [{string.Join(' ', Enumerable.Range(0, pages).Select(i => $"{4 + 2 * i} 0 R"))}] >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        };
        for (var i = 0; i < pages; i++)
        {
            objects.Add($"<< /Type /Page /Parent 2 0 R /MediaBox [{media}] /Rotate {rotation} {pageEntries} /Resources << /Font << /F1 3 0 R >> >> /Contents {5 + 2 * i} 0 R >>");
            var stream = $"BT /F1 18 Tf 60 700 Td ({text} - page {i + 1}) Tj ET\n";
            objects.Add($"<< /Length {Encoding.ASCII.GetByteCount(stream)} >>\nstream\n{stream}endstream");
        }
        var pdf = new StringBuilder("%PDF-1.7\n%synthetic\n");
        var offsets = new List<int> { 0 };
        for (var i = 0; i < objects.Count; i++)
        { offsets.Add(Encoding.ASCII.GetByteCount(pdf.ToString())); pdf.Append($"{i + 1} 0 obj\n{objects[i]}\nendobj\n"); }
        var xref = Encoding.ASCII.GetByteCount(pdf.ToString());
        pdf.Append($"xref\n0 {objects.Count + 1}\n0000000000 65535 f \n");
        foreach (var offset in offsets.Skip(1)) pdf.Append(offset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n");
        pdf.Append($"trailer\n<< /Size {objects.Count + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        return Encoding.ASCII.GetBytes(pdf.ToString());
    }
    public static byte[] Encrypted(bool userPassword)
    {
        using var input = new MemoryStream(Create());
        using var document = PdfReader.Open(input, PdfDocumentOpenMode.Modify);
        document.SecuritySettings.OwnerPassword = "synthetic-owner-password";
        if (userPassword) document.SecuritySettings.UserPassword = "synthetic-user-password";
        using var result = new MemoryStream(); document.Save(result, false); return result.ToArray();
    }
}

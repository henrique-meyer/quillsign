using System.Security.Claims;
using System.Security.Cryptography;

namespace QuillSign.Documents;

// Validated conversion and atomic persistence behind the sender upload handler.
public sealed class DocxDocumentWorkflow(DocumentWorkflow documents, DocxPackageValidation packages, GotenbergDocxConverter converter)
{
    public const string Mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    public async Task<bool> UploadAsync(ClaimsPrincipal sender, string publicId, byte[] expectedVersion, string filename, Stream input,
        long declaredLength, string? ip, string? userAgent, CancellationToken ct = default)
    {
        if (await documents.CheckConvertedUploadAsync(sender, publicId, expectedVersion, ct) is null) return false;
        var title = Filename(filename); using var validated = await packages.ValidateAsync(input, declaredLength, ct); using var source = validated.OpenRead();
        var converted = await converter.ConvertAsync(source, validated.Length, ct);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(validated.OriginalSha256, converted.OriginalSha256))
                throw new InvalidDataException("Converted source verification failed.");
            ct.ThrowIfCancellationRequested();
            return await documents.StoreConvertedAsync(sender, publicId, expectedVersion, title, validated, converted, ip, userAgent, ct);
        }
        finally { Array.Clear(converted.Pdf); Array.Clear(converted.OriginalSha256); Array.Clear(converted.PdfSha256); }
    }
    private static string Filename(string filename)
    {
        if (!filename.EndsWith(".docx", StringComparison.OrdinalIgnoreCase)) throw new DocumentRejectedException("Choose a supported DOCX file or export it to PDF.");
        return DocumentWorkflow.Filename(filename[..^5] + ".pdf");
    }
}

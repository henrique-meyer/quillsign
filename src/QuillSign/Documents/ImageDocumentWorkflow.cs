using System.Security.Claims;

namespace QuillSign.Documents;

// Internal backend only; the public upload handler still accepts PDF files.
public sealed class ImageDocumentWorkflow(DocumentWorkflow documents,ImagePdfConverter converter)
{
    public async Task<bool> UploadAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,string filename,Stream input,
        long declaredLength,string? ip,string? userAgent,CancellationToken ct=default)
    {
        if(await documents.CheckConvertedUploadAsync(sender,publicId,expectedVersion,ct) is null)return false;
        var (title,extension)=Filename(filename);
        using var converted=await converter.ConvertAsync(input,declaredLength,ct);
        if(converted.SourceMime!=(extension==".png" ? "image/png" : "image/jpeg"))throw Rejected();
        ct.ThrowIfCancellationRequested();
        return await documents.StoreConvertedImageAsync(sender,publicId,expectedVersion,title,extension,converted,ip,userAgent,ct);
    }
    private static (string Title,string Extension) Filename(string filename)
    {
        var extension=filename.EndsWith(".jpeg",StringComparison.OrdinalIgnoreCase) ? ".jpeg" :
            filename.EndsWith(".jpg",StringComparison.OrdinalIgnoreCase) ? ".jpg" : filename.EndsWith(".png",StringComparison.OrdinalIgnoreCase) ? ".png" : throw Rejected();
        return (DocumentWorkflow.Filename(filename[..^extension.Length]+".pdf"),extension);
    }
    private static DocumentRejectedException Rejected()=>new("Choose a supported PNG or JPEG image with a matching filename, or export it to PDF.");
}

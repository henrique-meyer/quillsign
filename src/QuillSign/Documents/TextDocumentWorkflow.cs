using System.Security.Claims;
using System.Security.Cryptography;

namespace QuillSign.Documents;

// The original remains literal UTF-8. Only an owned generated DOCX reaches LibreOffice.
public sealed class TextDocumentWorkflow(DocumentWorkflow documents,TextPdfConverter converter,DocumentOptions limits,GotenbergOptions options,IHostEnvironment environment)
{
    public const string Mime="text/plain";
    public async Task<bool> UploadAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,string filename,Stream input,
        long declaredLength,string? ip,string? userAgent,CancellationToken ct=default)
    {
        if(await documents.CheckConvertedUploadAsync(sender,publicId,expectedVersion,ct) is null)return false;
        if(!limits.EnableTextUploads || !options.IsAvailable(environment))throw new DocumentConversionUnavailableException("Text upload is unavailable. Export your document to PDF and try again.");
        if(limits.MaximumBytes is <1024 or >64*1024*1024 || limits.MaximumPages is <1 or >200)throw new InvalidOperationException("Configure supported text conversion limits.");
        if(!filename.EndsWith(".txt",StringComparison.OrdinalIgnoreCase))throw new DocumentRejectedException("Choose a UTF-8 TXT file, or export it to PDF.");
        var title=DocumentWorkflow.Filename(filename[..^4]+".pdf");
        if(declaredLength<=0 || declaredLength>limits.MaximumBytes)throw new DocumentRejectedException("Choose a UTF-8 text file within the upload size limit.");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));
        var token=timeout.Token;
        try
        {
            await using var original=DocumentWorkflow.TemporaryFile();
            await input.CopyToAsync(new BoundedDocumentStream(original,limits.MaximumBytes),65536,token);
            if(original.Length!=declaredLength)throw new DocumentRejectedException("The uploaded text size did not match. Try uploading it again.");
            original.Position=0;var hash=await SHA256.HashDataAsync(original,token);original.Position=0;
            var converted=await converter.ConvertAsync(original,original.Length,token);
            try
            {
                if(!CryptographicOperations.FixedTimeEquals(hash,converted.OriginalSha256))throw new InvalidDataException("Converted source verification failed.");
                token.ThrowIfCancellationRequested();
                return await documents.StoreConvertedTextAsync(sender,publicId,expectedVersion,title,original,converted,ip,userAgent,token);
            }
            finally {Array.Clear(converted.Pdf);Array.Clear(converted.OriginalSha256);Array.Clear(converted.PdfSha256);}
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested)
        {throw new DocumentConversionUnavailableException("Text conversion timed out.");}
    }
}

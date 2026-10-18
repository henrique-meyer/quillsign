using System.Security.Claims;
using System.Security.Cryptography;

namespace QuillSign.Documents;

public sealed class OfficeDocumentWorkflow(DocumentWorkflow documents,StaticOfficeConverter converter,DocumentOptions limits,
    OfficeConversionOptions formats,GotenbergOptions options,IHostEnvironment environment,PptxPackageValidation pptx,
    XlsxPackageValidation xlsx,OdtPackageValidation odt,RtfPackageValidation rtf)
{
    public bool IsAvailable(OfficeSourceKind kind)
    {
        if(!limits.EnableOfficeUploads||limits.MaximumBytes>64*1024*1024||options.Transport!="Http"||!Enabled(kind))return false;
        try{return options.IsAvailable(environment);}catch(InvalidOperationException){return false;}
    }
    private bool Enabled(OfficeSourceKind kind)=>kind switch{OfficeSourceKind.Pptx=>formats.PptxEnabled,OfficeSourceKind.Xlsx=>formats.XlsxEnabled,OfficeSourceKind.Odt=>formats.OdtEnabled,OfficeSourceKind.Rtf=>formats.RtfEnabled,_=>false};
    public static (string Extension,string Mime,string Pipeline) Family(OfficeSourceKind kind)=>kind switch {
        OfficeSourceKind.Pptx=>(".pptx","application/vnd.openxmlformats-officedocument.presentationml.presentation","static-pptx-gotenberg-v1"),
        OfficeSourceKind.Xlsx=>(".xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","values-xlsx-print-gotenberg-v1"),
        OfficeSourceKind.Odt=>(".odt","application/vnd.oasis.opendocument.text","static-odt-gotenberg-v1"),
        OfficeSourceKind.Rtf=>(".rtf","application/rtf","literal-rtf-docx-gotenberg-v1"),
        _=>throw new DocumentRejectedException("Choose a supported format shown on the upload form, or export a PDF.")};
    public async Task<bool> UploadAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,OfficeSourceKind kind,
        string filename,Stream input,long declaredLength,string? ip,string? userAgent,CancellationToken ct=default)
    {
        if(await documents.CheckConvertedUploadAsync(sender,publicId,expectedVersion,ct) is null)return false;
        if(!IsAvailable(kind))throw new DocumentConversionUnavailableException("This Office format is unavailable here. Export your document to PDF and try again.");
        var family=Family(kind);if(!filename.EndsWith(family.Extension,StringComparison.OrdinalIgnoreCase))throw new DocumentRejectedException("Choose the supported document format shown on the upload form.");
        var title=DocumentWorkflow.Filename(filename[..^family.Extension.Length]+".pdf");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));var token=timeout.Token;
        try
        {
            using var owned=await (kind switch{OfficeSourceKind.Pptx=>pptx.ValidateAsync(input,declaredLength,token),OfficeSourceKind.Xlsx=>xlsx.ValidateAsync(input,declaredLength,token),OfficeSourceKind.Odt=>odt.ValidateAsync(input,declaredLength,token),OfficeSourceKind.Rtf=>rtf.ValidateAsync(input,declaredLength,token),_=>throw new DocumentRejectedException("Choose a supported format.")});
            var converted=await converter.ConvertAsync(owned,token);var hash=owned.OriginalSha256;
            try
            {
                if(!CryptographicOperations.FixedTimeEquals(hash,converted.OriginalSha256))throw new InvalidDataException("Converted source verification failed.");
                token.ThrowIfCancellationRequested();return await documents.StoreConvertedOfficeAsync(sender,publicId,expectedVersion,title,owned,converted,ip,userAgent,token);
            }
            finally {Array.Clear(hash);Array.Clear(converted.Pdf);Array.Clear(converted.OriginalSha256);Array.Clear(converted.PdfSha256);}
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){throw new DocumentConversionUnavailableException("Office conversion timed out.");}
    }
}

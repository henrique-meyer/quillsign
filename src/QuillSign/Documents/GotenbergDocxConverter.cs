using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace QuillSign.Documents;

public sealed class GotenbergOptions
{
    public bool Enabled {get;set;}
    public string BaseUrl {get;set;}="";
    public int TimeoutSeconds {get;set;}=60;
    public string Transport {get;set;}="Http";
    public SandboxConversionOptions Sandbox {get;set;}=new();
    internal bool IsAvailable(IHostEnvironment environment)
    {
        if(!Enabled)return false;
        if(Transport=="Sandbox")
        {
            if(TimeoutSeconds is <1 or >180)throw new InvalidOperationException("Sandbox conversion timeout must be between 1 and 180 seconds.");
            Sandbox.Validate();return true;
        }
        if(Transport!="Http")throw new InvalidOperationException("Choose Http or Sandbox document conversion transport.");
        return Endpoint(environment) is not null;
    }
    internal Uri? Endpoint(IHostEnvironment environment)
    {
        if(TimeoutSeconds is <1 or >120)throw new InvalidOperationException("Gotenberg:TimeoutSeconds must be between 1 and 120.");
        if(!Enabled)return null;
        if(!Uri.TryCreate(BaseUrl,UriKind.Absolute,out var origin) || origin.UserInfo.Length!=0 || origin.Query.Length!=0 || origin.Fragment.Length!=0 || origin.AbsolutePath!="/" ||
            origin.Scheme!=Uri.UriSchemeHttps && !(origin.Scheme==Uri.UriSchemeHttp && environment.IsDevelopment() && (origin.IsLoopback || origin.Host=="gotenberg")))
            throw new InvalidOperationException("Configure a Gotenberg HTTPS origin; HTTP is limited to local Development conversion services.");
        return new(origin,"forms/libreoffice/convert");
    }
}

public sealed record DocxConversion(byte[] Pdf,byte[] OriginalSha256,byte[] PdfSha256,IReadOnlyList<PageGeometry> Pages);
public sealed class DocumentConversionUnavailableException(string message) : Exception(message);

// Transport/normalization only. DocxDocumentWorkflow validates the owned DOCX
// package before this request; no automatic Conversion work producer is used.
public sealed class GotenbergDocxConverter(HttpClient http,GotenbergOptions options,DocumentOptions limits,PdfValidation validation,IHostEnvironment environment,ISandboxDocxTransport? sandbox=null)
{
    public Task<DocxConversion> ConvertAsync(Stream original,long declaredLength,CancellationToken ct=default)
        =>ConvertCoreAsync(original,declaredLength,null,ct);

    internal async Task<DocxConversion> ConvertOfficeAsync(ValidatedOfficeSource package,CancellationToken ct)
    {using var original=package.OpenConversionRead();return await ConvertCoreAsync(original,package.ConversionLength,package.Kind,ct);}

    private async Task<DocxConversion> ConvertCoreAsync(Stream original,long declaredLength,OfficeSourceKind? kind,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if(!options.IsAvailable(environment))throw new DocumentConversionUnavailableException("Document conversion is not enabled.");
        if(kind is not null && options.Transport!="Http")throw new DocumentConversionUnavailableException("This format requires the separately configured isolated Office HTTP transport.");
        var upload=kind switch {
            null=>("document.docx","application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            OfficeSourceKind.Pptx=>("document.pptx","application/vnd.openxmlformats-officedocument.presentationml.presentation"),
            OfficeSourceKind.Xlsx=>("document.xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            OfficeSourceKind.Odt=>("document.odt","application/vnd.oasis.opendocument.text"),
            _=>throw new DocumentRejectedException("Choose a supported Office format, or export a PDF.")};
        var endpoint=options.Transport=="Http" ? options.Endpoint(environment) : null;
        if(limits.MaximumBytes is <1024 or >64*1024*1024 || limits.MaximumPages is <1 or >200)throw new InvalidOperationException("Configure supported document conversion limits.");
        ArgumentNullException.ThrowIfNull(original);
        if(declaredLength is <=0 || declaredLength>limits.MaximumBytes)throw new DocumentRejectedException("Choose a DOCX within the upload size limit.");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));var token=timeout.Token;
        try
        {
            await using var source=DocumentWorkflow.TemporaryFile();
            await Copy(original,source,limits.MaximumBytes,token);
            if(source.Length!=declaredLength)throw new DocumentRejectedException("The uploaded DOCX size did not match.");
            source.Position=0;var originalHash=await SHA256.HashDataAsync(source,token);source.Position=0;
            await using var converted=DocumentWorkflow.TemporaryFile();
            if(options.Transport=="Sandbox")
            {
                var result=await (sandbox??throw Unavailable()).ConvertAsync(source,originalHash,source.Length,token);
                try {if(result.Length is <=0 || result.Length>limits.MaximumBytes)throw Unavailable();await converted.WriteAsync(result,token);}
                finally {Array.Clear(result);}
            }
            else
            {
                using var form=new MultipartFormDataContent();var file=new StreamContent(source);
                file.Headers.ContentType=new MediaTypeHeaderValue(upload.Item2);
                form.Add(file,"files",upload.Item1);form.Add(new StringContent("false"),"exportFormFields");form.Add(new StringContent("true"),"generateTaggedPdf");
                using var request=new HttpRequestMessage(HttpMethod.Post,endpoint) {Content=form};
                using var response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,token);
                if(response.StatusCode==HttpStatusCode.BadRequest)throw new DocumentRejectedException("The DOCX could not be converted. Export a PDF and try again.");
                if(response.StatusCode!=HttpStatusCode.OK)throw Unavailable(); // No redirect/retry or provider error-body disclosure.
                if(!string.Equals(response.Content.Headers.ContentType?.MediaType,"application/pdf",StringComparison.OrdinalIgnoreCase) || response.Content.Headers.ContentEncoding.Count!=0)
                    throw new DocumentConversionUnavailableException("The conversion service did not return a supported PDF.");
                var length=response.Content.Headers.ContentLength;
                if(length is <=0 || length>limits.MaximumBytes)throw new DocumentRejectedException("The converted PDF exceeds the upload size limit.");
                await using var body=await response.Content.ReadAsStreamAsync(token);await Copy(body,converted,limits.MaximumBytes,token);
                if(length is long expected && converted.Length!=expected)throw new DocumentConversionUnavailableException("The converted PDF was incomplete.");
            }
            token.ThrowIfCancellationRequested();await using var normalized=DocumentWorkflow.TemporaryFile();
            var pages=validation.Rewrite(converted,new BoundedDocumentStream(normalized,limits.MaximumBytes));token.ThrowIfCancellationRequested();
            normalized.Position=0;var hash=await SHA256.HashDataAsync(normalized,token);normalized.Position=0;
            using var bytes=new MemoryStream();await normalized.CopyToAsync(bytes,token);token.ThrowIfCancellationRequested();
            return new(bytes.ToArray(),originalHash,hash,pages);
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested) {throw new DocumentConversionUnavailableException("Document conversion timed out.");}
        catch(HttpRequestException) {throw Unavailable();}
        catch(IOException) {throw Unavailable();}
    }

    private static async Task Copy(Stream source,Stream destination,long maximum,CancellationToken ct)
    {
        var buffer=new byte[65536];long total=0;int count;
        while((count=await source.ReadAsync(buffer,ct))!=0)
        {
            total+=count;if(total>maximum)throw new DocumentRejectedException("The document exceeds the conversion size limit.");
            await destination.WriteAsync(buffer.AsMemory(0,count),ct);
        }
    }
    private static DocumentConversionUnavailableException Unavailable()=>new("Document conversion is unavailable. Try again later.");
}

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using QuillSign.Completion;

namespace QuillSign.Verification;

// Runs after the rate limiter and before Razor's normal antiforgery/model binding.
// Only the bounded in-memory form is exposed to those framework filters.
public sealed class VerificationUploadBoundary(RequestDelegate next,UploadedPdfVerificationOptions fileLimits,
    VerificationBrowserOptions browserLimits,IOptions<AntiforgeryOptions> antiforgery)
{
    public const string FileField="Upload";
    public const int FramingBytes=32768;
    private sealed class TooLarge : Exception;
    private sealed class InvalidUpload : Exception;
    public async Task InvokeAsync(HttpContext http)
    {
        if(!VerificationBrowser.IsPath(http)) {await next(http);return;}
        VerificationBrowser.Private(http);
        if(!HttpMethods.IsPost(http.Request.Method)) {await next(http);return;}
        var maximum=fileLimits.MaximumBytes;var total=maximum+(long)FramingBytes;
        if(http.Request.QueryString.HasValue) {await VerificationBrowser.Error(http,400,"Use the verification form to select and submit one PDF.");return;}
        if(http.Request.ContentLength>total) {await VerificationBrowser.Error(http,413,"This upload exceeds the verification size limit. Choose a smaller PDF.");return;}
        var original=http.RequestAborted;var originalForm=http.Features.Get<IFormFeature>();var originalMarker=http.Features.Get<VerificationUploadReadFeature>();MemoryStream? file=null;
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(fileLimits.TimeoutSeconds+browserLimits.BodyTimeoutSeconds));
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(original,deadline.Token);var ct=linked.Token;
        http.RequestAborted=ct;
        try {
            var bodySize=http.Features.Get<IHttpMaxRequestBodySizeFeature>();if(bodySize is {IsReadOnly:false})bodySize.MaxRequestBodySize=total;
            if(!MediaTypeHeaderValue.TryParse(http.Request.ContentType,out var media) || !media.MediaType.Equals("multipart/form-data",StringComparison.OrdinalIgnoreCase))throw new InvalidUpload();
            var boundary=HeaderUtilities.RemoveQuotes(media.Boundary).Value;if(boundary is not {Length:>0 and <=128})throw new InvalidUpload();
            using var bounded=new BodyLimit(http.Request.Body,total);
            var reader=new MultipartReader(boundary,bounded) {HeadersCountLimit=8,HeadersLengthLimit=8192,BodyLengthLimit=Math.Max(maximum+1L,2049)};
            var values=new Dictionary<string,StringValues>(StringComparer.Ordinal);var tokenName=antiforgery.Value.FormFieldName;var sections=0;
            while(await reader.ReadNextSectionAsync(ct) is { } section) {
                if(++sections>2 || section.Headers?.ContainsKey("Content-Transfer-Encoding")==true ||
                    !ContentDispositionHeaderValue.TryParse(section.ContentDisposition,out var disposition) || !disposition.DispositionType.Equals("form-data",StringComparison.OrdinalIgnoreCase))throw new InvalidUpload();
                var name=HeaderUtilities.RemoveQuotes(disposition.Name).Value;
                if(disposition.FileName.HasValue || disposition.FileNameStar.HasValue) {
                    if(name!=FileField || file is not null || disposition.FileName.Length>512 || disposition.FileNameStar.Length>512)throw new InvalidUpload();
                    file=new MemoryStream();await Copy(section.Body,file,maximum,ct);
                    if(section.Headers?.TryGetValue(HeaderNames.ContentLength,out var declared)==true &&
                        (declared.Count!=1 || !long.TryParse(declared.ToString(),NumberStyles.Integer,CultureInfo.InvariantCulture,out var expected) || expected!=file.Length))throw new InvalidUpload();
                } else {
                    if(name!=tokenName || values.ContainsKey(tokenName))throw new InvalidUpload();
                    using var token=new MemoryStream();await Copy(section.Body,token,2048,ct);
                    values.Add(tokenName,new UTF8Encoding(false,true).GetString(token.GetBuffer(),0,checked((int)token.Length)));
                }
            }
            // Include any multipart epilogue in the actual raw-body bound/declaration.
            var discard=new byte[8192];while(await bounded.ReadAsync(discard,ct)!=0) { }
            if(http.Request.ContentLength is { } declaredTotal && declaredTotal!=bounded.Consumed)throw new InvalidUpload();
            var files=new FormFileCollection();
            if(file is not null) {
                file.Position=0;
                files.Add(new FormFile(file,0,file.Length,FileField,"verification.pdf") {Headers=new HeaderDictionary {
                    [HeaderNames.ContentDisposition]="form-data; name=\"Upload\"; filename=\"verification.pdf\"",[HeaderNames.ContentType]="application/pdf"}});
            }
            http.Features.Set<IFormFeature>(new FormFeature(new FormCollection(values,files)));
            http.Features.Set(new VerificationUploadReadFeature());
            await next(http);
            if(!http.Response.HasStarted && http.Response.StatusCode==400)
                await VerificationBrowser.Error(http,400,"The verification request could not be accepted. Choose a PDF again and submit the current form.",ct);
        }
        catch(TooLarge) {if(!http.Response.HasStarted)await VerificationBrowser.Error(http,413,"This upload exceeds a verification size limit. Choose a smaller PDF.",original);else http.Abort();}
        catch(OperationCanceledException) when(!original.IsCancellationRequested) {if(!http.Response.HasStarted)await VerificationBrowser.Error(http,503,"Verification timed out. No integrity result is confirmed. Choose your PDF again to retry.",original);else http.Abort();}
        catch(Exception e) when(e is InvalidUpload or InvalidDataException or FormatException or DecoderFallbackException or BadHttpRequestException or IOException) {
            if(!http.Response.HasStarted)await VerificationBrowser.Error(http,e is BadHttpRequestException {StatusCode:413} ? 413 : 400,"The upload could not be read as one bounded PDF request. Choose a PDF again and submit the current form.",original);
            else http.Abort();
        }
        finally {
            http.RequestAborted=original;http.Features.Set(originalForm);http.Features.Set(originalMarker);
            if(file is not null) {if(file.TryGetBuffer(out var bytes))CryptographicOperations.ZeroMemory(bytes.AsSpan());file.Dispose();}
        }
    }
    private static async Task Copy(Stream input,MemoryStream output,int maximum,CancellationToken ct)
    {
        var buffer=new byte[Math.Min(32768,maximum+1)];
        while(true) {
            var allowed=(int)Math.Min(buffer.Length,maximum+1L-output.Length);var count=await input.ReadAsync(buffer.AsMemory(0,allowed),ct);
            if(count==0)return;if(output.Length+count>maximum)throw new TooLarge();await output.WriteAsync(buffer.AsMemory(0,count),ct);
        }
    }
    private sealed class BodyLimit(Stream inner,long maximum) : Stream
    {
        public long Consumed {get;private set;}
        public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;
        public override long Length=>throw new NotSupportedException();public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        private int Allow(int count)=>checked((int)Math.Min(count,maximum+1-Consumed));
        private int Check(int count) {Consumed+=count;if(Consumed>maximum)throw new TooLarge();return count;}
        public override int Read(byte[] buffer,int offset,int count)=>Check(inner.Read(buffer,offset,Allow(count)));
        public override Task<int> ReadAsync(byte[] buffer,int offset,int count,CancellationToken ct)=>ReadAsync(buffer.AsMemory(offset,count),ct).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default)=>Check(await inner.ReadAsync(buffer[..Allow(buffer.Length)],ct));
        public override void Flush()=>throw new NotSupportedException();public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
    }
}

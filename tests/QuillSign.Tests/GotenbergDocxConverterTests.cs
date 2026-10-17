using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class GotenbergDocxConverterTests
{
    [Theory]
    [InlineData("https://converter.example.invalid", "Production",true)]
    [InlineData("http://127.0.0.1:3000", "Development",true)]
    [InlineData("http://gotenberg:3000", "Development",true)]
    [InlineData("http://gotenberg:3000", "Production",false)]
    [InlineData("http://remote.example.invalid", "Development",false)]
    [InlineData("https://converter.example.invalid/private", "Production",false)]
    [InlineData("https://converter.example.invalid/?query=private", "Production",false)]
    [InlineData("https://name:private@converter.example.invalid", "Production",false)]
    [InlineData("file:///tmp/document.docx", "Development",false)]
    public async Task Only_a_valid_configured_origin_is_used_and_input_cannot_supply_a_route(string url,string environment,bool valid)
    {
        var handler=new Handler(_=>Task.FromResult(Pdf()));using var http=new HttpClient(handler);var service=Client(http,url,environment);
        using var source=new MemoryStream(Docx());
        if(valid) {await service.ConvertAsync(source,source.Length);Assert.Equal(new Uri(new Uri(url),"forms/libreoffice/convert"),handler.Uri);Assert.Equal(1,handler.Calls);}
        else {await Assert.ThrowsAsync<InvalidOperationException>(()=>service.ConvertAsync(source,source.Length));Assert.Equal(0,handler.Calls);Assert.Equal(0,source.Position);}
    }

    [Fact]
    public async Task Successful_conversion_hashes_original_and_exact_normalized_output_and_preserves_caller_stream()
    {
        var input=Docx();var returned=PdfFixtures.Create(rotation:90,text:"SYNTHETIC CONVERSION - NO AGREEMENT");string? multipart=null;
        var handler=new Handler(async request=> {multipart=await request.Content!.ReadAsStringAsync();return Pdf(returned);});using var http=new HttpClient(handler);
        using var source=new MemoryStream(input);var result=await Client(http).ConvertAsync(source,input.Length);
        Assert.Equal(SHA256.HashData(input),result.OriginalSha256);Assert.Equal(input,source.ToArray());Assert.True(source.CanRead);
        Assert.Equal(SHA256.HashData(result.Pdf),result.PdfSha256);Assert.Equal(2,result.Pages.Count);Assert.All(result.Pages,x=>Assert.Equal(90,x.Rotation));
        using var read=new MemoryStream(result.Pdf);using var normalized=new MemoryStream();Assert.Equal(2,new PdfValidation(new()).Rewrite(read,normalized).Count);
        Assert.Contains("document.docx",multipart);Assert.Contains("name=files",multipart);Assert.Contains("exportFormFields",multipart);Assert.Contains("generateTaggedPdf",multipart);
        Assert.Equal(HttpMethod.Post,handler.Method);Assert.Equal(1,handler.Calls);
    }

    [Theory]
    [InlineData("disabled")][InlineData("declared-too-large")][InlineData("declared-empty")][InlineData("mismatch")][InlineData("actual-too-large")][InlineData("cancelled")]
    public async Task Invalid_or_cancelled_input_never_transmits_to_the_converter(string kind)
    {
        var handler=new Handler(_=>Task.FromResult(Pdf()));using var http=new HttpClient(handler);var limits=new DocumentOptions {MaximumBytes=2048};
        var options=Options();options.Enabled=kind!="disabled";var service=new GotenbergDocxConverter(http,options,limits,new(limits),new EnvironmentStub("Development"));
        using var source=new MemoryStream(kind=="actual-too-large" ? new byte[2049] : Docx());using var cancellation=new CancellationTokenSource();if(kind=="cancelled")cancellation.Cancel();
        var length=kind switch {"declared-too-large"=>2049,"declared-empty"=>0,"mismatch"=>source.Length+1,"actual-too-large"=>1024,_=>source.Length};
        var error=await Record.ExceptionAsync(()=>service.ConvertAsync(source,length,cancellation.Token));Assert.NotNull(error);
        if(kind=="disabled")Assert.IsType<DocumentConversionUnavailableException>(error);else if(kind=="cancelled")Assert.IsAssignableFrom<OperationCanceledException>(error);else Assert.IsType<DocumentRejectedException>(error);
        Assert.Equal(0,handler.Calls);
    }

    [Theory]
    [InlineData(302)][InlineData(400)][InlineData(500)][InlineData(503)]
    public async Task Provider_errors_do_not_retry_or_read_or_disclose_the_provider_body(int status)
    {
        var body=new ForbiddenBody();var handler=new Handler(_=>Task.FromResult(new HttpResponseMessage((HttpStatusCode)status) {Content=body}));using var http=new HttpClient(handler);
        using var source=new MemoryStream(Docx());var error=await Record.ExceptionAsync(()=>Client(http).ConvertAsync(source,source.Length));
        if(status==400)Assert.IsType<DocumentRejectedException>(error);else Assert.IsType<DocumentConversionUnavailableException>(error);
        Assert.Equal(1,handler.Calls);Assert.Equal(0,body.Reads);Assert.DoesNotContain("private",error!.Message,StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("media")][InlineData("encoding")][InlineData("header-size")][InlineData("stream-size")][InlineData("truncated")][InlineData("malformed")][InlineData("encrypted")][InlineData("page-limit")]
    public async Task A_bounded_valid_PDF_is_required_before_any_result_is_returned(string kind)
    {
        var limits=new DocumentOptions {MaximumBytes=16384,MaximumPages=1};
        var response=Pdf(kind switch {"malformed"=>Encoding.UTF8.GetBytes("<html>private provider content</html>"),"encrypted"=>PdfFixtures.Encrypted(true),"page-limit"=>PdfFixtures.Create(),_=>PdfFixtures.Create(1)});
        if(kind=="media")response.Content.Headers.ContentType=new("text/html");
        if(kind=="encoding")response.Content.Headers.ContentEncoding.Add("gzip");
        if(kind=="header-size")response.Content.Headers.ContentLength=limits.MaximumBytes+1;
        if(kind=="truncated")response.Content.Headers.ContentLength=response.Content.Headers.ContentLength+1;
        if(kind=="stream-size") {response.Content=new StreamContent(new ForwardStream(new byte[16385]));response.Content.Headers.ContentType=new("application/pdf");}
        var handler=new Handler(_=>Task.FromResult(response));using var http=new HttpClient(handler);using var source=new MemoryStream(Docx());
        var error=await Record.ExceptionAsync(()=>new GotenbergDocxConverter(http,Options(),limits,new(limits),new EnvironmentStub("Development")).ConvertAsync(source,source.Length));
        Assert.True(error is DocumentRejectedException or DocumentConversionUnavailableException);Assert.Equal(1,handler.Calls);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Total_IO_deadline_covers_input_and_response_body_without_retries(bool input)
    {
        var handler=new Handler(_=> {var response=new HttpResponseMessage(HttpStatusCode.OK) {Content=new StreamContent(new WaitingStream())};response.Content.Headers.ContentType=new("application/pdf");return Task.FromResult(response);});
        using var http=new HttpClient(handler);var options=Options();options.TimeoutSeconds=1;var service=new GotenbergDocxConverter(http,options,new(),new(new()),new EnvironmentStub("Development"));
        using Stream source=input ? new WaitingStream() : new MemoryStream(Docx());
        var error=await Assert.ThrowsAsync<DocumentConversionUnavailableException>(()=>service.ConvertAsync(source,input ? 500 : source.Length));
        if(!input)Assert.Contains("timed out",error.Message);Assert.Equal(input ? 0 : 1,handler.Calls);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Transport_failures_do_not_disclose_private_provider_details_or_retry(bool streamFailure)
    {
        var handler=new Handler(_=>Task.FromException<HttpResponseMessage>(streamFailure ? new IOException("private response body") : new HttpRequestException("private provider address")));
        using var http=new HttpClient(handler);using var source=new MemoryStream(Docx());
        var error=await Assert.ThrowsAsync<DocumentConversionUnavailableException>(()=>Client(http).ConvertAsync(source,source.Length));
        Assert.DoesNotContain("private",error.Message);Assert.Null(error.InnerException);Assert.Equal(1,handler.Calls);
    }

    [Fact]
    public async Task Registered_client_does_not_follow_an_actual_local_redirect()
    {
        var builder=WebApplication.CreateBuilder();builder.Logging.ClearProviders();builder.WebHost.UseUrls("http://127.0.0.1:0");await using var app=builder.Build();var followed=0;
        app.MapPost("/forms/libreoffice/convert",()=>Results.Redirect("/unexpected"));app.MapGet("/unexpected",()=> {Interlocked.Increment(ref followed);return Results.Bytes(PdfFixtures.Create(),"application/pdf");});await app.StartAsync();
        var services=new ServiceCollection();services.AddSingleton<IHostEnvironment>(new EnvironmentStub("Development"));services.AddLogging();
        services.AddQuillSignDocuments(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Gotenberg:Enabled"]="true",["Gotenberg:BaseUrl"]=app.Urls.Single() }).Build());
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();var converter=scope.ServiceProvider.GetRequiredService<GotenbergDocxConverter>();
        using var source=new MemoryStream(Docx());await Assert.ThrowsAsync<DocumentConversionUnavailableException>(()=>converter.ConvertAsync(source,source.Length));Assert.Equal(0,followed);await app.StopAsync();
    }

    public static byte[] Docx()
    {
        using var bytes=new MemoryStream();using(var zip=new ZipArchive(bytes,ZipArchiveMode.Create,true))
        {
            void Add(string path,string xml) {using var writer=new StreamWriter(zip.CreateEntry(path).Open(),new UTF8Encoding(false));writer.Write(xml);}
            Add("[Content_Types].xml","<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>");
            Add("_rels/.rels","<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>");
            Add("word/document.xml","<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>SYNTHETIC DOCX CONVERSION - NO AGREEMENT - page 1</w:t></w:r></w:p><w:p><w:r><w:br w:type=\"page\"/><w:t>SYNTHETIC DOCX CONVERSION - NO AGREEMENT - page 2</w:t></w:r></w:p><w:sectPr><w:pgSz w:w=\"12240\" w:h=\"15840\"/><w:pgMar w:top=\"1440\" w:right=\"1440\" w:bottom=\"1440\" w:left=\"1440\"/></w:sectPr></w:body></w:document>");
        }
        return bytes.ToArray();
    }
    private static GotenbergOptions Options()=>new() {Enabled=true,BaseUrl="http://127.0.0.1:3000"};
    private static GotenbergDocxConverter Client(HttpClient http,string url="http://127.0.0.1:3000",string environment="Development")=>new(http,new() {Enabled=true,BaseUrl=url},new(),new(new()),new EnvironmentStub(environment));
    private static HttpResponseMessage Pdf(byte[]? bytes=null) {var response=new HttpResponseMessage(HttpStatusCode.OK) {Content=new ByteArrayContent(bytes ?? PdfFixtures.Create())};response.Content.Headers.ContentType=new MediaTypeHeaderValue("application/pdf");return response;}
    private sealed class Handler(Func<HttpRequestMessage,Task<HttpResponseMessage>> respond):HttpMessageHandler
    {
        public int Calls;public Uri? Uri;public HttpMethod? Method;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct) {Calls++;Uri=request.RequestUri;Method=request.Method;return respond(request);}
    }
    private sealed class ForbiddenBody:HttpContent
    {
        public int Reads;protected override bool TryComputeLength(out long length) {length=0;return false;}
        protected override Task SerializeToStreamAsync(Stream stream,TransportContext? context) {Reads++;throw new InvalidOperationException("private body must not be read");}
    }
    private class ForwardStream(byte[] bytes):MemoryStream(bytes) {public override bool CanSeek=>false;}
    private sealed class WaitingStream:Stream
    {
        public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;public override long Length=>throw new NotSupportedException();public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default) {await Task.Delay(Timeout.Infinite,ct);return 0;}
        public override int Read(byte[] buffer,int offset,int count)=>throw new NotSupportedException();public override void Flush()=>throw new NotSupportedException();public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
    }
    private sealed class EnvironmentStub(string name):IHostEnvironment
    {
        public string EnvironmentName {get;set;}=name;public string ApplicationName {get;set;}="SyntheticConverterTests";public string ContentRootPath {get;set;}="";public IFileProvider ContentRootFileProvider {get;set;}=new NullFileProvider();
    }
}

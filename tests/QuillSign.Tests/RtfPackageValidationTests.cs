using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class RtfPackageValidationTests
{
    [Fact]
    public async Task Explicit_grammar_preserves_format_scope_and_unicode_as_owned_validated_DOCX_without_passing_raw_RTF()
    {
        var original=Package();var expected=original.ToArray();using var input=new MemoryStream(original);using var source=await Gate().ValidateAsync(input,input.Length);Assert.Equal(OfficeSourceKind.Rtf,source.Kind);Assert.Equal(0,source.ExpectedPages);Array.Clear(original);var hash=source.OriginalSha256;Array.Clear(hash);using var owned=source.OpenRead();Assert.Equal(expected,await Read(owned));byte[]? sent=null;
        var handler=new Handler(async request=>{var form=Assert.IsType<MultipartFormDataContent>(request.Content);var file=form.Single(x=>x.Headers.ContentDisposition!.Name!.Trim('"')=="files");Assert.Equal("document.docx",file.Headers.ContentDisposition!.FileName!.Trim('"'));Assert.Equal("application/vnd.openxmlformats-officedocument.wordprocessingml.document",file.Headers.ContentType!.MediaType);sent=await file.ReadAsByteArrayAsync();Assert.NotEqual(expected,sent);using var zip=new ZipArchive(new MemoryStream(sent));Assert.Equal(3,zip.Entries.Count);var xml=XDocument.Load(zip.GetEntry("word/document.xml")!.Open());XNamespace w="http://schemas.openxmlformats.org/wordprocessingml/2006/main";var text=string.Concat(xml.Descendants(w+"t").Select(x=>x.Value));Assert.Contains("café € α",text);Assert.Contains("{literal}",text);Assert.Contains("https://example.invalid",text);Assert.Contains("=SUM(A1:A2)",text);Assert.Contains("\\object",text);Assert.DoesNotContain("\\rtf",text);Assert.Contains(xml.Descendants(w+"r"),x=>x.Element(w+"rPr")?.Element(w+"b") is not null&&x.Element(w+"rPr")?.Element(w+"i") is not null&&x.Value.Contains("nested italic"));Assert.Contains(xml.Descendants(w+"r"),x=>x.Element(w+"rPr")?.Element(w+"b") is null&&x.Value.Contains(" plain."));Assert.Equal("124E78",(string?)xml.Descendants(w+"color").Single().Attribute(w+"val"));Assert.Contains(xml.Descendants(w+"br"),x=>(string?)x.Attribute(w+"type")=="page");return Pdf();});using var http=new HttpClient(handler);var result=await Converter(http).ConvertAsync(source);Assert.Equal(SHA256.HashData(expected),result.OriginalSha256);Assert.NotEqual(SHA256.HashData(sent!),result.OriginalSha256);Assert.Equal(SHA256.HashData(result.Pdf),result.PdfSha256);Assert.Equal(2,result.Pages.Count);Assert.True(input.CanRead);source.Dispose();Assert.Throws<ObjectDisposedException>(()=>source.OpenRead());
    }
    [Theory]
    [InlineData(@"{\rtf1\ansi\ansicpg1252 Raw café.}","Raw café.")]
    [InlineData(@"{\rtf1\ansi\uc1 \u233\'3f}","é")]
    [InlineData(@"{\rtf1\ansi\uc0 \u123\u8364\u125}","{€}")]
    [InlineData(@"{\rtf1\ansi\uc2 \u233??{\uc0 \u945}\u8364??}","éα€")]
    public async Task Codepage_unicode_and_group_scoped_fallback_semantics_are_explicit(string rtf,string expected)
    {
        var bytes=Encoding.Latin1.GetBytes(rtf);using var input=new MemoryStream(bytes);using var source=await Gate().ValidateAsync(input,input.Length);var handler=new Handler(async request=>{var file=((MultipartFormDataContent)request.Content!).Single(x=>x.Headers.ContentDisposition!.Name!.Trim('"')=="files");using var zip=new ZipArchive(new MemoryStream(await file.ReadAsByteArrayAsync()));var xml=XDocument.Load(zip.GetEntry("word/document.xml")!.Open());Assert.Equal(expected,string.Concat(xml.Descendants(XName.Get("t","http://schemas.openxmlformats.org/wordprocessingml/2006/main")).Select(x=>x.Value)));return Pdf();});using var http=new HttpClient(handler);await Converter(http).ConvertAsync(source);
    }
    [Fact]
    public async Task Raw_nonASCII_bytes_require_explicit_Windows1252_and_do_not_depend_on_machine_locale()
    {
        var bytes=Encoding.Latin1.GetBytes(@"{\rtf1\ansi raw café}");using var input=new MemoryStream(bytes);await Assert.ThrowsAsync<DocumentRejectedException>(()=>Gate().ValidateAsync(input,input.Length));
    }
    [Theory]
    [InlineData(@"{\rtf1\ansi\object x}")][InlineData(@"{\rtf1\ansi{\*\objdata x}}")][InlineData(@"{\rtf1\ansi{\pict abc}}")][InlineData(@"{\rtf1\ansi{\field{\fldinst INCLUDEPICTURE x}}}")][InlineData(@"{\rtf1\ansi\bin4 abcd}")][InlineData(@"{\rtf1\ansi{\htmltag x}}")][InlineData(@"{\rtf1\ansi\fromhtml1 x}")][InlineData(@"{\rtf1\ansi\fromtext x}")][InlineData(@"{\rtf1\ansi\file x}")][InlineData(@"{\rtf1\ansi{\stylesheet x}}")][InlineData(@"{\rtf1\ansi{\info x}}")][InlineData(@"{\rtf1\ansi\v hidden}")][InlineData(@"{\rtf1\ansi\unknown x}")][InlineData(@"{\rtf1\ansi{\*\unknown x}}")][InlineData(@"{\rtf1\ansi\obj\'65ct x}")][InlineData(@"{\RTF1\ansi x}")][InlineData(@"{\rtf1\mac x}")][InlineData(@"{\rtf1\ansi\ansicpg932 x}")][InlineData(@"{\rtf1\ansi{\fonttbl{\f0\fcharset2 Symbol;}}\f0 x}")][InlineData(@"{\rtf1\ansi{\fonttbl{\f0 file:///x;}}x}")][InlineData(@"{\rtf1\ansi{\fonttbl{\f0 Good;}{\f0 Duplicate;}}x}")][InlineData(@"{\rtf1\ansi{\colortbl;\red999;}x}")][InlineData(@"{\rtf1\ansi{\colortbl;\red1\red2;}x}")][InlineData(@"{\rtf1\ansi\cf99 x}")][InlineData(@"{\rtf1\ansi\f99 x}")][InlineData(@"{\rtf1\ansi\fs999 x}")][InlineData(@"{\rtf1\ansi\b2 x}")][InlineData(@"{\rtf1\ansi\paperw999 x}")][InlineData(@"{\rtf1\ansi\sect x}")][InlineData(@"{\rtf1\ansi\u-10179?\u-8704?}")][InlineData(@"{\rtf1\ansi\u0?}")][InlineData(@"{\rtf1\ansi\u65535?}")][InlineData(@"{\rtf1\ansi\uc99 x}")][InlineData(@"{\rtf1\ansi\u233}")][InlineData(@"{\rtf1\ansi\u233{?}}")][InlineData(@"{\rtf1\ansi\u65\object x}")][InlineData(@"{\rtf1\ansi\'81}")][InlineData(@"{\rtf1\ansi\'GG}")][InlineData(@"{\rtf1\ansi x")][InlineData(@"{\rtf1\ansi x}}")][InlineData(@"{\rtf1\ansi x}PRIVATE-MARKER")][InlineData(@"{\rtf1\ansi{\qc x}}")][InlineData(@"{\rtf1\ansi x{\fonttbl{\f0 Good;}}}")][InlineData(@"{\rtf1\ansi\b99999999 x}")]
    public async Task Unsupported_destinations_controls_codepages_and_ambiguous_grammar_never_reach_a_service(string rtf)
    {
        var bytes=Encoding.ASCII.GetBytes(rtf);using var input=new MemoryStream(bytes);var error=await Assert.ThrowsAsync<DocumentRejectedException>(()=>Gate().ValidateAsync(input,input.Length));Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Null(error.InnerException);Assert.True(input.CanRead);
    }
    [Theory][InlineData("depth")][InlineData("groups")][InlineData("text")][InlineData("paragraphs")][InlineData("runs")][InlineData("pages")][InlineData("input")][InlineData("length")]
    public async Task Expansion_and_declared_work_limits_fail_before_conversion(string mode)
    {
        var body=mode switch{"depth"=>new string('{',33)+"x"+new string('}',33),"groups"=>string.Concat(Enumerable.Repeat("{}",10001)),"text"=>new string('x',50001),"paragraphs"=>string.Concat(Enumerable.Repeat(@"x\par ",1001)),"runs"=>string.Concat(Enumerable.Repeat(@"\b x\b0 x",5001)),"pages"=>@"x\page y","input"=>new string('x',1024*1024),_=>"x"};var bytes=Encoding.ASCII.GetBytes(@"{\rtf1\ansi "+body+"}");using var input=new MemoryStream(bytes);var limits=new DocumentOptions{MaximumPages=mode=="pages"?1:20};await Assert.ThrowsAsync<DocumentRejectedException>(()=>new RtfPackageValidation(limits,new(limits)).ValidateAsync(input,input.Length+(mode=="length"?1:0)));
    }
    [Theory][InlineData("disabled")][InlineData("sandbox")][InlineData("provider")][InlineData("geometry")][InlineData("cancel")]
    public async Task Opt_in_derived_source_transport_and_output_profile_are_required(string mode)
    {
        Assert.False(new OfficeConversionOptions().RtfEnabled);using var input=new MemoryStream(Package());using var source=await Gate().ValidateAsync(input,input.Length);var handler=new Handler(_=>Task.FromResult(mode=="provider"?new HttpResponseMessage(HttpStatusCode.ServiceUnavailable){Content=new StringContent("PRIVATE-MARKER")}:mode=="geometry"?Pdf("0 0 595 842"):Pdf()));using var http=new HttpClient(handler);using var cancel=new CancellationTokenSource();if(mode=="cancel")cancel.Cancel();var error=await Record.ExceptionAsync(()=>Converter(http,mode!="disabled",mode=="sandbox").ConvertAsync(source,cancel.Token));Assert.NotNull(error);Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Equal(mode is "provider" or "geometry"?1:0,handler.Calls);
    }
    public static byte[] Package()=>Encoding.ASCII.GetBytes(@"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\fswiss\fcharset0 Liberation Sans;}{\f1\fmodern\fcharset0 Liberation Mono;}}{\colortbl;\red18\green78\blue120;}\viewkind4\uc1\pard\fs28\b SYNTHETIC RTF PAGE 1\u8212? NO AGREEMENT\b0\par Plain {\b bold {\i nested italic} bold again} plain. \cf1 Blue text\cf0. \ul underline\ulnone.\par Escapes \{literal\} \\object harmless. caf\'e9 \u8364? \uc0\u945\uc1.\par Literal https://example.invalid and =SUM(A1:A2).\page\pard\f1 SYNTHETIC RTF PAGE 2\u8212? NO AGREEMENT\par First\tab Second\line New line.}");
    private static RtfPackageValidation Gate(){var limits=new DocumentOptions();return new(limits,new(limits));}
    private static async Task<byte[]> Read(Stream input){using var output=new MemoryStream();await input.CopyToAsync(output);return output.ToArray();}
    private static HttpResponseMessage Pdf(string media="0 0 612 792"){var result=new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(PdfFixtures.Create(pages:2,media:media))};result.Content.Headers.ContentType=new("application/pdf");return result;}
    private static StaticOfficeConverter Converter(HttpClient http,bool enabled=true,bool sandbox=false){var limits=new DocumentOptions();var options=new GotenbergOptions{Enabled=true,BaseUrl="https://converter.example.invalid",Transport=sandbox?"Sandbox":"Http"};return new(new(){RtfEnabled=enabled},new(http,options,limits,new(limits),new EnvironmentStub()));}
    private sealed class Handler(Func<HttpRequestMessage,Task<HttpResponseMessage>> send):HttpMessageHandler {public int Calls;protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct){Calls++;ct.ThrowIfCancellationRequested();return send(request);}}
    private sealed class EnvironmentStub:IHostEnvironment {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Tests";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}

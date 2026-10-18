using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class OdtPackageValidationTests
{
    private const string O="urn:oasis:names:tc:opendocument:xmlns:office:1.0",T="urn:oasis:names:tc:opendocument:xmlns:text:1.0",St="urn:oasis:names:tc:opendocument:xmlns:style:1.0",F="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0",Tb="urn:oasis:names:tc:opendocument:xmlns:table:1.0",D="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0",Svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0",X="http://www.w3.org/1999/xlink",M="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Owned_static_ODF_is_sent_with_fixed_name_and_verified_original_and_PDF_hashes(bool assets)
    {
        var original=Package(assets);var expected=original.ToArray();using var input=new MemoryStream(original);using var source=await new OdtPackageValidation(new()).ValidateAsync(input,input.Length);Assert.Equal(OfficeSourceKind.Odt,source.Kind);Assert.Equal(0,source.ExpectedPages);Array.Clear(original);var hash=source.OriginalSha256;Array.Clear(hash);using var independent=source.OpenRead();Assert.Equal(expected,await Read(independent));
        var handler=new Handler(async request=>{var form=Assert.IsType<MultipartFormDataContent>(request.Content);var file=form.Single(x=>x.Headers.ContentDisposition!.Name!.Trim('"')=="files");Assert.Equal("document.odt",file.Headers.ContentDisposition!.FileName!.Trim('"'));Assert.Equal("application/vnd.oasis.opendocument.text",file.Headers.ContentType!.MediaType);Assert.Equal(expected,await file.ReadAsByteArrayAsync());return Pdf();});using var http=new HttpClient(handler);var result=await Converter(http).ConvertAsync(source);Assert.Equal(SHA256.HashData(expected),result.OriginalSha256);Assert.Equal(SHA256.HashData(result.Pdf),result.PdfSha256);Assert.Equal(2,result.Pages.Count);Assert.True(input.CanRead);source.Dispose();Assert.Throws<ObjectDisposedException>(()=>source.OpenRead());
    }
    [Theory]
    [InlineData("compressed-mime")][InlineData("later-mime")][InlineData("wrong-mime")][InlineData("manifest-type")][InlineData("missing-manifest-entry")][InlineData("extra-manifest-entry")][InlineData("encryption")][InlineData("signature")][InlineData("script")][InlineData("event")][InlineData("form")][InlineData("ole")][InlineData("field")][InlineData("external-image")][InlineData("external-style")][InlineData("image-alias")][InlineData("bad-image")][InlineData("orphan-image")][InlineData("xinclude")][InlineData("unknown-extension")][InlineData("unknown-attribute")][InlineData("dtd")][InlineData("processing")][InlineData("zip-alias")][InlineData("truncated")][InlineData("size")][InlineData("large-font")][InlineData("font-url")][InlineData("repeat")][InlineData("style-cycle")][InlineData("large-frame")][InlineData("bad-page")][InlineData("nonfinite")][InlineData("floating-image")][InlineData("master-header")][InlineData("space-work")][InlineData("manifest-case")][InlineData("page-work")]
    public async Task Active_unknown_and_unbounded_ODF_is_rejected_before_converter_calls(string mode)
    {
        var p=Parts(true);var content=Encoding.UTF8.GetString(p["content.xml"]);var styles=Encoding.UTF8.GetString(p["styles.xml"]);var manifest=Encoding.UTF8.GetString(p["META-INF/manifest.xml"]);
        switch(mode)
        {
            case "wrong-mime":p["mimetype"]="application/vnd.oasis.opendocument.spreadsheet"u8.ToArray();break;
            case "manifest-case":manifest=manifest.Replace("Pictures/test.png","PICTURES/TEST.PNG");break;
            case "manifest-type":manifest=manifest.Replace("image/png","image/jpeg");break;
            case "missing-manifest-entry":manifest=manifest.Replace("Pictures/test.png","Pictures/missing.png");break;
            case "extra-manifest-entry":manifest=manifest.Replace("</manifest:manifest>","<manifest:file-entry manifest:full-path=\"unknown.xml\" manifest:media-type=\"text/xml\"/></manifest:manifest>");break;
            case "encryption":manifest=manifest.Replace("manifest:media-type=\"text/xml\"/>","manifest:media-type=\"text/xml\"><manifest:encryption-data/></manifest:file-entry>");break;
            case "signature":p["META-INF/documentsignatures.xml"]="<signature/>"u8.ToArray();break;
            case "script":content=content.Replace("<office:body>","<office:scripts/><office:body>");break;
            case "event":content=content.Replace("<text:p>","<text:p><office:event-listeners/>");break;
            case "form":content=content.Replace("<office:text>","<office:text><office:forms/>");break;
            case "ole":content=content.Replace("<text:p>","<text:p><draw:object/>");break;
            case "field":content=content.Replace("<text:p>","<text:p><text:dde-connection/>");break;
            case "external-image":content=content.Replace("Pictures/test.png","https://PRIVATE-MARKER.example.invalid/a.png");break;
            case "external-style":styles=styles.Replace("<office:styles>","<office:styles><style:background-image xlink:href=\"file:///PRIVATE-MARKER\"/>");break;
            case "image-alias":content=content.Replace("Pictures/test.png","Pictures/%74est.png");break;
            case "bad-image":p["Pictures/test.png"]="<svg/>"u8.ToArray();break;
            case "orphan-image":content=content.Replace("Pictures/test.png","Pictures/unused.png");break;
            case "xinclude":content=content.Replace("<text:p>","<text:p><xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"PRIVATE-MARKER\"/>");break;
            case "unknown-extension":content=content.Replace("<text:p>","<text:p><x:extension xmlns:x=\"urn:PRIVATE-MARKER\"/>");break;
            case "unknown-attribute":content=content.Replace("<text:p>","<text:p text:formula=\"PRIVATE-MARKER\">");break;
            case "dtd":content="<!DOCTYPE x [<!ENTITY x SYSTEM 'https://PRIVATE-MARKER.example.invalid/'>]>"+content;break;
            case "processing":content="<?PRIVATE-MARKER x?>"+content;break;
            case "zip-alias":p["CONTENT.XML"]=p["content.xml"];break;
            case "large-font":styles=styles.Replace("12pt","999pt");break;
            case "font-url":styles=styles.Replace("Liberation Sans","file:///PRIVATE-MARKER");break;
            case "repeat":content=content.Replace("<table:table-row>","<table:table-row table:number-rows-repeated=\"999999999\">");break;
            case "style-cycle":styles=styles.Replace("style:name=\"Break\"","style:name=\"Break\" style:parent-style-name=\"Break\"");break;
            case "large-frame":content=content.Replace("svg:width=\"4cm\"","svg:width=\"999cm\"");break;
            case "bad-page":styles=styles.Replace("21cm","999cm");break;
            case "nonfinite":content=content.Replace("office:value=\"42\"","office:value=\"NaN\"");break;
            case "floating-image":content=content.Replace("text:anchor-type=\"as-char\"","text:anchor-type=\"page\"");break;
            case "master-header":styles=styles.Replace("style:page-layout-name=\"A4\"/>","style:page-layout-name=\"A4\"><style:header/></style:master-page>");break;
            case "page-work":content=content.Replace("</office:text>",string.Concat(Enumerable.Repeat("<text:p text:style-name=\"Break\">Extra page</text:p>",25))+"</office:text>");break;
            case "space-work":content=content.Replace("<text:p>","<text:p>"+string.Concat(Enumerable.Repeat("<text:s text:c=\"100\"/>",501)));break;
        }
        p["content.xml"]=Encoding.UTF8.GetBytes(content);p["styles.xml"]=Encoding.UTF8.GetBytes(styles);p["META-INF/manifest.xml"]=Encoding.UTF8.GetBytes(manifest);var bytes=Zip(p,mode=="compressed-mime",mode=="later-mime");if(mode=="truncated")bytes=bytes[..^8];using var input=new MemoryStream(bytes);var error=await Assert.ThrowsAsync<DocumentRejectedException>(()=>new OdtPackageValidation(new(){MaximumBytes=mode=="size"?1024:20*1024*1024}).ValidateAsync(input,input.Length));Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Null(error.InnerException);
    }
    [Theory][InlineData("disabled")][InlineData("sandbox")][InlineData("provider")][InlineData("geometry")][InlineData("cancel")]
    public async Task Format_opt_in_and_transport_output_bounds_are_required(string mode)
    {
        Assert.False(new OfficeConversionOptions().OdtEnabled);using var input=new MemoryStream(Package());using var source=await new OdtPackageValidation(new()).ValidateAsync(input,input.Length);var handler=new Handler(_=>Task.FromResult(mode=="provider"?new HttpResponseMessage(HttpStatusCode.ServiceUnavailable){Content=new StringContent("PRIVATE-MARKER")}:mode=="geometry"?Pdf("0 0 612 792"):Pdf()));using var http=new HttpClient(handler);using var cancel=new CancellationTokenSource();if(mode=="cancel")cancel.Cancel();var error=await Record.ExceptionAsync(()=>Converter(http,mode!="disabled",mode=="sandbox").ConvertAsync(source,cancel.Token));Assert.NotNull(error);Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Equal(mode is "provider" or "geometry"?1:0,handler.Calls);
    }
    public static byte[] Package(bool assets=false)=>Zip(Parts(assets));
    private static Dictionary<string,byte[]> Parts(bool assets)
    {
        var ns=$"xmlns:office=\"{O}\" xmlns:text=\"{T}\" xmlns:style=\"{St}\" xmlns:fo=\"{F}\" xmlns:table=\"{Tb}\" xmlns:draw=\"{D}\" xmlns:svg=\"{Svg}\" xmlns:xlink=\"{X}\" office:version=\"1.3\"";
        var content=$"<office:document-content {ns}><office:body><office:text><text:p>SYNTHETIC ODT PAGE 1 — NO AGREEMENT</text:p><text:p>Literal &lt;svg&gt; https://example.invalid =SUM(A1:A2) café.</text:p>"+(assets?"<text:p><draw:frame draw:name=\"Raster\" text:anchor-type=\"as-char\" svg:width=\"4cm\" svg:height=\"2cm\"><draw:image xlink:href=\"Pictures/test.png\" xlink:type=\"simple\" xlink:show=\"embed\" xlink:actuate=\"onLoad\"/></draw:frame></text:p>":"")+"<text:p text:style-name=\"Break\">SYNTHETIC ODT PAGE 2 — NO AGREEMENT</text:p><table:table table:name=\"Static\"><table:table-column/><table:table-column/><table:table-row><table:table-cell office:value-type=\"string\"><text:p>Static items</text:p></table:table-cell><table:table-cell office:value-type=\"float\" office:value=\"42\"><text:p>42</text:p></table:table-cell></table:table-row></table:table></office:text></office:body></office:document-content>";
        var styles=$"<office:document-styles {ns}><office:font-face-decls><style:font-face style:name=\"MainFont\" svg:font-family=\"Liberation Sans\"/></office:font-face-decls><office:styles><style:default-style style:family=\"paragraph\"><style:text-properties style:font-name=\"MainFont\" fo:font-size=\"12pt\"/></style:default-style><style:style style:name=\"Break\" style:family=\"paragraph\"><style:paragraph-properties fo:break-before=\"page\"/></style:style></office:styles><office:automatic-styles><style:page-layout style:name=\"A4\"><style:page-layout-properties fo:page-width=\"21cm\" fo:page-height=\"29.7cm\" fo:margin-left=\"2cm\" fo:margin-right=\"2cm\" fo:margin-top=\"2cm\" fo:margin-bottom=\"2cm\"/></style:page-layout></office:automatic-styles><office:master-styles><style:master-page style:name=\"Standard\" style:page-layout-name=\"A4\"/></office:master-styles></office:document-styles>";
        var manifest=$"<manifest:manifest xmlns:manifest=\"{M}\" manifest:version=\"1.3\"><manifest:file-entry manifest:full-path=\"/\" manifest:media-type=\"application/vnd.oasis.opendocument.text\"/><manifest:file-entry manifest:full-path=\"content.xml\" manifest:media-type=\"text/xml\"/><manifest:file-entry manifest:full-path=\"styles.xml\" manifest:media-type=\"text/xml\"/>"+(assets?"<manifest:file-entry manifest:full-path=\"Pictures/test.png\" manifest:media-type=\"image/png\"/>":"")+"</manifest:manifest>";
        var p=new Dictionary<string,byte[]>{["mimetype"]="application/vnd.oasis.opendocument.text"u8.ToArray(),["content.xml"]=Encoding.UTF8.GetBytes(content),["styles.xml"]=Encoding.UTF8.GetBytes(styles),["META-INF/manifest.xml"]=Encoding.UTF8.GetBytes(manifest)};if(assets)p["Pictures/test.png"]=ImagePdfConverterTests.Png();return p;
    }
    private static byte[] Zip(Dictionary<string,byte[]> parts,bool compressMime=false,bool lateMime=false){using var bytes=new MemoryStream();using(var zip=new ZipArchive(bytes,ZipArchiveMode.Create,true))foreach(var(name,data)in parts.OrderBy(x=>lateMime&&x.Key=="mimetype"?1:0)){using var output=zip.CreateEntry(name,name=="mimetype"&&!compressMime?CompressionLevel.NoCompression:CompressionLevel.Optimal).Open();output.Write(data);}return bytes.ToArray();}
    private static async Task<byte[]> Read(Stream input){using var output=new MemoryStream();await input.CopyToAsync(output);return output.ToArray();}
    private static HttpResponseMessage Pdf(string media="0 0 595.2755905511812 841.8897637795276"){var result=new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(PdfFixtures.Create(pages:2,media:media))};result.Content.Headers.ContentType=new("application/pdf");return result;}
    private static StaticOfficeConverter Converter(HttpClient http,bool enabled=true,bool sandbox=false){var limits=new DocumentOptions();var options=new GotenbergOptions{Enabled=true,BaseUrl="https://converter.example.invalid",Transport=sandbox?"Sandbox":"Http"};return new(new(){OdtEnabled=enabled},new(http,options,limits,new(limits),new EnvironmentStub()));}
    private sealed class Handler(Func<HttpRequestMessage,Task<HttpResponseMessage>> send):HttpMessageHandler {public int Calls;protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct){Calls++;ct.ThrowIfCancellationRequested();return send(request);}}
    private sealed class EnvironmentStub:IHostEnvironment {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Tests";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}

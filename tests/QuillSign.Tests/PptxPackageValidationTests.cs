using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class PptxPackageValidationTests
{
    [Fact]
    public async Task Static_slides_are_owned_and_sent_with_fixed_enum_selected_HTTP_name_and_exact_hashes()
    {
        var bytes=Package();var expected=bytes.ToArray();using var input=new MemoryStream(bytes);
        using var source=await new PptxPackageValidation(new()).ValidateAsync(input,bytes.Length);
        Assert.Equal(OfficeSourceKind.Pptx,source.Kind);Assert.Equal(SHA256.HashData(expected),source.OriginalSha256);Assert.True(input.CanRead);
        Array.Clear(bytes);var exposed=source.OriginalSha256;Array.Clear(exposed);using var independent=source.OpenRead();Assert.Equal(expected,await Read(independent));Assert.Equal(SHA256.HashData(expected),source.OriginalSha256);
        var handler=new Handler(async request=>{
            Assert.Equal("/forms/libreoffice/convert",request.RequestUri!.AbsolutePath);var form=Assert.IsType<MultipartFormDataContent>(request.Content);var file=form.Single(x=>x.Headers.ContentDisposition!.Name!.Trim('"')=="files");
            Assert.Equal("document.pptx",file.Headers.ContentDisposition!.FileName!.Trim('"'));Assert.Equal("application/vnd.openxmlformats-officedocument.presentationml.presentation",file.Headers.ContentType!.MediaType);Assert.Equal(expected,await file.ReadAsByteArrayAsync());return Pdf();
        });
        using var http=new HttpClient(handler);var converted=await Converter(http,true).ConvertAsync(source);Assert.Equal(1,handler.Calls);Assert.Equal(SHA256.HashData(expected),converted.OriginalSha256);Assert.Equal(SHA256.HashData(converted.Pdf),converted.PdfSha256);Assert.Equal(2,converted.Pages.Count);
        source.Dispose();Assert.Throws<ObjectDisposedException>(()=>source.OpenRead());Assert.Throws<ObjectDisposedException>(()=>source.OriginalSha256);
    }

    [Theory]
    [InlineData("external")][InlineData("action")][InlineData("ole")][InlineData("macro")][InlineData("embedding")][InlineData("unknown-part")][InlineData("orphan")]
    [InlineData("formula")][InlineData("svg")][InlineData("unknown-namespace")][InlineData("unknown-attribute")][InlineData("unknown-extension")]
    [InlineData("hidden")][InlineData("hidden-slide")][InlineData("missing-slide")][InlineData("duplicate-slide")][InlineData("duplicate-id")][InlineData("foreign-id")]
    [InlineData("wrong-type")][InlineData("missing-type")][InlineData("wrong-root")][InlineData("zip-alias")][InlineData("truncated")][InlineData("dtd")][InlineData("processing")]
    [InlineData("xml-base")][InlineData("target-alias")][InlineData("target-fragment")][InlineData("oversized-slide")][InlineData("too-many-pages")]
    [InlineData("oversized-shape")][InlineData("font-size")][InlineData("shadow-radius")][InlineData("font-url")]
    [InlineData("xml-elements")][InlineData("xml-depth")]
    public async Task Active_unknown_or_ambiguous_packages_are_rejected_without_service_calls(string mode)
    {
        var parts=Parts();
        switch(mode)
        {
            case "external":parts["ppt/_rels/presentation.xml.rels"]=parts["ppt/_rels/presentation.xml.rels"].Replace("Target=\"slides/slide1.xml\"","Target=\"https://PRIVATE-MARKER.example.invalid/slide\" TargetMode=\"External\"");break;
            case "action":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<a:r><a:hlinkClick action=\"ppaction://hlinkfile\"/>");break;
            case "ole":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<p:oleObj/>");break;
            case "macro":parts["ppt/vbaProject.bin"]="PRIVATE-MARKER";break;
            case "embedding":parts["ppt/embeddings/embedded.xlsx"]="PRIVATE-MARKER";break;
            case "unknown-part":parts["ppt/custom.xml"]="<custom/>";break;
            case "orphan":parts["ppt/slides/slide3.xml"]=parts["ppt/slides/slide1.xml"];parts["[Content_Types].xml"]=parts["[Content_Types].xml"].Replace("</Types>","<Override PartName=\"/ppt/slides/slide3.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/></Types>");break;
            case "formula":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<a:fld id=\"PRIVATE-MARKER\"/>");break;
            case "svg":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<svg xmlns=\"http://www.w3.org/2000/svg\"/>");break;
            case "unknown-namespace":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<a:r><x:thing xmlns:x=\"urn:PRIVATE-MARKER\"/>");break;
            case "unknown-attribute":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<a:r src=\"https://PRIVATE-MARKER.example.invalid/\">");break;
            case "unknown-extension":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<a:r><a:extLst/>");break;
            case "hidden":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("name=\"Text\"","name=\"Text\" hidden=\"1\"");break;
            case "hidden-slide":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<p:sld ","<p:sld show=\"0\" ");break;
            case "missing-slide":parts.Remove("ppt/slides/slide2.xml");break;
            case "duplicate-slide":parts["ppt/presentation.xml"]=parts["ppt/presentation.xml"].Replace("rId2","rId1");break;
            case "duplicate-id":parts["ppt/_rels/presentation.xml.rels"]=parts["ppt/_rels/presentation.xml.rels"].Replace("rId2","rId1");break;
            case "foreign-id":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<a:r r:id=\"rId1\">");break;
            case "wrong-type":parts["[Content_Types].xml"]=parts["[Content_Types].xml"].Replace("presentation.main+xml","slideshow.main+xml");break;
            case "missing-type":parts["[Content_Types].xml"]=parts["[Content_Types].xml"].Replace("/ppt/slides/slide1.xml","/ppt/slides/slide9.xml");break;
            case "wrong-root":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("p:sld","p:sldMaster");break;
            case "zip-alias":parts["PPT/SLIDES/SLIDE1.XML"]=parts["ppt/slides/slide1.xml"];break;
            case "dtd":parts["ppt/slides/slide1.xml"]="<!DOCTYPE x [<!ENTITY x SYSTEM 'https://PRIVATE-MARKER.example.invalid/'>]>"+parts["ppt/slides/slide1.xml"];break;
            case "processing":parts["ppt/slides/slide1.xml"]="<?PRIVATE-MARKER x?>"+parts["ppt/slides/slide1.xml"];break;
            case "xml-base":parts["_rels/.rels"]=parts["_rels/.rels"].Replace("<Relationships ","<Relationships xml:base=\"https://PRIVATE-MARKER.example.invalid/\" ");break;
            case "target-alias":parts["ppt/_rels/presentation.xml.rels"]=parts["ppt/_rels/presentation.xml.rels"].Replace("slides/slide1.xml","slides/%73lide1.xml");break;
            case "target-fragment":parts["ppt/_rels/presentation.xml.rels"]=parts["ppt/_rels/presentation.xml.rels"].Replace("slides/slide1.xml","slides/slide1.xml#PRIVATE-MARKER");break;
            case "oversized-slide":parts["ppt/presentation.xml"]=parts["ppt/presentation.xml"].Replace("12192000","9999999999");break;
            case "oversized-shape":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("10363200","9999999999");break;
            case "font-size":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("sz=\"2400\"","sz=\"9999999\"");break;
            case "shadow-radius":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("</p:spPr>","<a:effectLst><a:outerShdw blurRad=\"99999999999\"/></a:effectLst></p:spPr>");break;
            case "font-url":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:rPr ","<a:rPr typeface=\"file:///PRIVATE-MARKER\" ");break;
            case "xml-elements":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<a:r>"+string.Concat(Enumerable.Repeat("<a:br/>",250001)));break;
            case "xml-depth":parts["ppt/slides/slide1.xml"]=parts["ppt/slides/slide1.xml"].Replace("<a:r>","<a:r>"+string.Concat(Enumerable.Repeat("<a:r>",70))+string.Concat(Enumerable.Repeat("</a:r>",70)));break;
        }
        var bytes=Zip(parts);if(mode=="truncated")bytes=bytes[..^8];using var input=new MemoryStream(bytes);var limits=new DocumentOptions{MaximumPages=mode=="too-many-pages"?1:20};var error=await Assert.ThrowsAsync<DocumentRejectedException>(()=>new PptxPackageValidation(limits).ValidateAsync(input,bytes.Length));Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Null(error.InnerException);Assert.True(input.CanRead);
    }

    [Theory][InlineData("disabled")][InlineData("sandbox")][InlineData("provider")][InlineData("output")][InlineData("cancel")][InlineData("pages")][InlineData("geometry")]
    public async Task Disabled_unapproved_transport_and_failed_conversion_return_no_PDF(string mode)
    {
        Assert.False(new OfficeConversionOptions().PptxEnabled);using var input=new MemoryStream(Package());using var source=await new PptxPackageValidation(new()).ValidateAsync(input,input.Length);using var cancel=new CancellationTokenSource();if(mode=="cancel")cancel.Cancel();
        var handler=new Handler(_=>Task.FromResult(mode=="provider"?new HttpResponseMessage(HttpStatusCode.ServiceUnavailable){Content=new StringContent("PRIVATE-MARKER")}:mode=="output"?new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("PRIVATE-MARKER")}:mode=="pages"?Pdf(pages:1):mode=="geometry"?Pdf(media:"0 0 612 792"):Pdf()));using var http=new HttpClient(handler);
        var error=await Record.ExceptionAsync(()=>Converter(http,mode!="disabled",mode=="sandbox").ConvertAsync(source,cancel.Token));Assert.NotNull(error);Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Null(error.InnerException);Assert.Equal(mode is "provider" or "output" or "pages" or "geometry"?1:0,handler.Calls);using var read=source.OpenRead();Assert.Equal(Package().Length,read.Length);
    }

    public static byte[] Package()=>Zip(Parts());
    public static byte[] PackageWithAssets()
    {
        const string p="http://schemas.openxmlformats.org/presentationml/2006/main",a="http://schemas.openxmlformats.org/drawingml/2006/main",r="http://schemas.openxmlformats.org/officeDocument/2006/relationships";
        var parts=Parts();parts["[Content_Types].xml"]=parts["[Content_Types].xml"].Replace("</Types>","<Default Extension=\"png\" ContentType=\"image/png\"/><Override PartName=\"/ppt/slideMasters/slideMaster1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml\"/><Override PartName=\"/ppt/slideLayouts/slideLayout1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml\"/><Override PartName=\"/ppt/theme/theme1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.theme+xml\"/></Types>");
        parts["ppt/presentation.xml"]=parts["ppt/presentation.xml"].Replace("<p:sldIdLst>","<p:sldMasterIdLst><p:sldMasterId id=\"2147483648\" r:id=\"rIdM\"/></p:sldMasterIdLst><p:sldIdLst>");
        parts["ppt/_rels/presentation.xml.rels"]=parts["ppt/_rels/presentation.xml.rels"].Replace("</Relationships>",$"<Relationship Id=\"rIdM\" Type=\"{r}/slideMaster\" Target=\"slideMasters/slideMaster1.xml\"/></Relationships>");
        var tree="<p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree>";
        parts["ppt/slideMasters/slideMaster1.xml"]=$"<p:sldMaster xmlns:p=\"{p}\" xmlns:a=\"{a}\" xmlns:r=\"{r}\"><p:cSld>{tree}</p:cSld><p:clrMap bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" accent1=\"accent1\" accent2=\"accent2\" accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" hlink=\"hlink\" folHlink=\"folHlink\"/><p:sldLayoutIdLst><p:sldLayoutId id=\"2147483649\" r:id=\"rIdL\"/></p:sldLayoutIdLst><p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles></p:sldMaster>";
        parts["ppt/slideMasters/_rels/slideMaster1.xml.rels"]=$"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rIdL\" Type=\"{r}/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/><Relationship Id=\"rIdT\" Type=\"{r}/theme\" Target=\"../theme/theme1.xml\"/></Relationships>";
        parts["ppt/slideLayouts/slideLayout1.xml"]=$"<p:sldLayout xmlns:p=\"{p}\" xmlns:a=\"{a}\" xmlns:r=\"{r}\" type=\"blank\" preserve=\"1\"><p:cSld>{tree}</p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>";
        parts["ppt/slideLayouts/_rels/slideLayout1.xml.rels"]=$"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rIdM\" Type=\"{r}/slideMaster\" Target=\"../slideMasters/slideMaster1.xml\"/></Relationships>";
        var colors=string.Concat(new[]{"dk1","lt1","dk2","lt2","accent1","accent2","accent3","accent4","accent5","accent6","hlink","folHlink"}.Select((x,i)=>$"<a:{x}><a:srgbClr val=\"{(i%2==0?"000000":"FFFFFF")}\"/></a:{x}>"));
        var fill="<a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill>";var line="<a:ln w=\"9525\">"+fill+"<a:prstDash val=\"solid\"/></a:ln>";
        parts["ppt/theme/theme1.xml"]=$"<a:theme xmlns:a=\"{a}\" name=\"Synthetic\"><a:themeElements><a:clrScheme name=\"Synthetic\">{colors}</a:clrScheme><a:fontScheme name=\"Synthetic\"><a:majorFont><a:latin typeface=\"Liberation Sans\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:majorFont><a:minorFont><a:latin typeface=\"Liberation Sans\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:minorFont></a:fontScheme><a:fmtScheme name=\"Synthetic\"><a:fillStyleLst>{fill}{fill}{fill}</a:fillStyleLst><a:lnStyleLst>{line}{line}{line}</a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst>{fill}{fill}{fill}</a:bgFillStyleLst></a:fmtScheme></a:themeElements><a:objectDefaults/><a:extraClrSchemeLst/></a:theme>";
        for(var i=1;i<=2;i++)
        {
            parts[$"ppt/slides/_rels/slide{i}.xml.rels"]=$"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rIdL\" Type=\"{r}/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/><Relationship Id=\"rIdI\" Type=\"{r}/image\" Target=\"../media/image1.png\"/></Relationships>";
            parts[$"ppt/slides/slide{i}.xml"]=parts[$"ppt/slides/slide{i}.xml"].Replace("</p:spTree>",$"<p:pic><p:nvPicPr><p:cNvPr id=\"3\" name=\"Synthetic raster\"/><p:cNvPicPr/><p:nvPr/></p:nvPicPr><p:blipFill><a:blip r:embed=\"rIdI\"/><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr><a:xfrm><a:off x=\"914400\" y=\"4000000\"/><a:ext cx=\"1828800\" cy=\"914400\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></p:spPr></p:pic></p:spTree>");
        }
        var binary=parts.ToDictionary(x=>x.Key,x=>Encoding.UTF8.GetBytes(x.Value));binary["ppt/media/image1.png"]=ImagePdfConverterTests.Png();return Zip(binary);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Master_layout_theme_cycles_and_content_verified_internal_raster_are_supported_but_bad_images_fail(bool corrupt)
    {
        var bytes=PackageWithAssets();if(corrupt){using var zip=new ZipArchive(new MemoryStream(bytes));var parts=zip.Entries.ToDictionary(x=>x.FullName,x=>Read(x.Open()).GetAwaiter().GetResult());parts["ppt/media/image1.png"]="<svg xmlns='http://www.w3.org/2000/svg'/>"u8.ToArray();bytes=Zip(parts);}
        using var source=new MemoryStream(bytes);if(corrupt)await Assert.ThrowsAsync<DocumentRejectedException>(()=>new PptxPackageValidation(new()).ValidateAsync(source,source.Length));else {using var result=await new PptxPackageValidation(new()).ValidateAsync(source,source.Length);Assert.Equal(2,result.ExpectedPages);Assert.Equal(960,result.Width);Assert.Equal(540,result.Height);Assert.Equal(SHA256.HashData(bytes),result.OriginalSha256);}
    }
    private static Dictionary<string,string> Parts()
    {
        const string p="http://schemas.openxmlformats.org/presentationml/2006/main",a="http://schemas.openxmlformats.org/drawingml/2006/main",r="http://schemas.openxmlformats.org/officeDocument/2006/relationships";
        var d=new Dictionary<string,string>{["[Content_Types].xml"]="<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/><Override PartName=\"/ppt/slides/slide1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/><Override PartName=\"/ppt/slides/slide2.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/></Types>",
        ["_rels/.rels"]=$"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"{r}/officeDocument\" Target=\"ppt/presentation.xml\"/></Relationships>",
        ["ppt/presentation.xml"]=$"<p:presentation xmlns:p=\"{p}\" xmlns:r=\"{r}\"><p:sldIdLst><p:sldId id=\"256\" r:id=\"rId1\"/><p:sldId id=\"257\" r:id=\"rId2\"/></p:sldIdLst><p:sldSz cx=\"12192000\" cy=\"6858000\"/><p:notesSz cx=\"6858000\" cy=\"9144000\"/></p:presentation>",
        ["ppt/_rels/presentation.xml.rels"]=$"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"{r}/slide\" Target=\"slides/slide1.xml\"/><Relationship Id=\"rId2\" Type=\"{r}/slide\" Target=\"slides/slide2.xml\"/></Relationships>"};
        for(var i=1;i<=2;i++)d[$"ppt/slides/slide{i}.xml"]=$"<p:sld xmlns:p=\"{p}\" xmlns:a=\"{a}\" xmlns:r=\"{r}\"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/><p:sp><p:nvSpPr><p:cNvPr id=\"2\" name=\"Text\"/><p:cNvSpPr txBox=\"1\"/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x=\"914400\" y=\"914400\"/><a:ext cx=\"10363200\" cy=\"2743200\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></p:spPr><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang=\"en-US\" sz=\"2400\"/><a:t>SYNTHETIC SLIDE {i} — NO AGREEMENT</a:t></a:r></a:p><a:p><a:r><a:t>Static literal text and positioned shapes.</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>";
        return d;
    }
    private static byte[] Zip(Dictionary<string,string> parts){using var bytes=new MemoryStream();using(var zip=new ZipArchive(bytes,ZipArchiveMode.Create,true))foreach(var (name,text) in parts){using var output=new StreamWriter(zip.CreateEntry(name).Open(),new UTF8Encoding(false));output.Write(text);}return bytes.ToArray();}
    private static byte[] Zip(Dictionary<string,byte[]> parts){using var bytes=new MemoryStream();using(var zip=new ZipArchive(bytes,ZipArchiveMode.Create,true))foreach(var (name,value) in parts){using var output=zip.CreateEntry(name).Open();output.Write(value);}return bytes.ToArray();}
    private static async Task<byte[]> Read(Stream input){using var output=new MemoryStream();await input.CopyToAsync(output);return output.ToArray();}
    private static HttpResponseMessage Pdf(int pages=2,string media="0 0 960 540"){var result=new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(PdfFixtures.Create(pages:pages,media:media))};result.Content.Headers.ContentType=new("application/pdf");return result;}
    private static StaticOfficeConverter Converter(HttpClient http,bool enabled,bool sandbox=false){var limits=new DocumentOptions();var options=new GotenbergOptions{Enabled=true,BaseUrl="https://converter.example.invalid",Transport=sandbox?"Sandbox":"Http"};if(sandbox){options.Sandbox.Region="eastus";options.Sandbox.SubscriptionId=Guid.NewGuid().ToString();options.Sandbox.ResourceGroup="synthetic";options.Sandbox.GroupName="synthetic";}return new(new(){PptxEnabled=enabled},new(http,options,limits,new(limits),new EnvironmentStub()));}
    private sealed class Handler(Func<HttpRequestMessage,Task<HttpResponseMessage>> send):HttpMessageHandler {public int Calls;protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct){Calls++;ct.ThrowIfCancellationRequested();return send(request);}}
    private sealed class EnvironmentStub:IHostEnvironment {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Tests";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}

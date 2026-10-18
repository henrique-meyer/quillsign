using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class XlsxPackageValidationTests
{
    private const string S="http://schemas.openxmlformats.org/spreadsheetml/2006/main",R="http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    [Fact]
    public async Task Values_stay_in_owned_original_while_converter_receives_separately_verified_bounded_print_copy()
    {
        var original=Package();var expected=original.ToArray();using var input=new MemoryStream(original);using var source=await new XlsxPackageValidation(new()).ValidateAsync(input,input.Length);
        Assert.Equal(OfficeSourceKind.Xlsx,source.Kind);Assert.Equal(2,source.ExpectedPages);Array.Clear(original);var hash=source.OriginalSha256;Array.Clear(hash);using var owned=source.OpenRead();Assert.Equal(expected,await Read(owned));Assert.Equal(SHA256.HashData(expected),source.OriginalSha256);
        byte[]? sent=null;var handler=new Handler(async request=>{
            var form=Assert.IsType<MultipartFormDataContent>(request.Content);var file=form.Single(x=>x.Headers.ContentDisposition!.Name!.Trim('"')=="files");Assert.Equal("document.xlsx",file.Headers.ContentDisposition!.FileName!.Trim('"'));Assert.Equal("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",file.Headers.ContentType!.MediaType);sent=await file.ReadAsByteArrayAsync();Assert.NotEqual(expected,sent);
            var before=Unzip(expected);var after=Unzip(sent);Assert.Equal(before.Keys.Order(),after.Keys.Order());foreach(var name in before.Keys.Where(x=>!x.StartsWith("xl/worksheets/")))Assert.Equal(before[name],after[name]);
            foreach(var name in before.Keys.Where(x=>x.StartsWith("xl/worksheets/"))){var a=XDocument.Parse(before[name]);var b=XDocument.Parse(after[name]);Assert.True(XNode.DeepEquals(a.Root!.Element(XName.Get("sheetData",S)),b.Root!.Element(XName.Get("sheetData",S))));var setup=b.Root!.Element(XName.Get("pageSetup",S))!;Assert.Equal("landscape",(string?)setup.Attribute("orientation"));Assert.Equal("1",(string?)setup.Attribute("fitToHeight"));Assert.Equal("9",(string?)setup.Attribute("paperSize"));}
            return Pdf();
        });
        using var http=new HttpClient(handler);var result=await Converter(http).ConvertAsync(source);Assert.Equal(1,handler.Calls);Assert.Equal(SHA256.HashData(expected),result.OriginalSha256);Assert.Equal(SHA256.HashData(result.Pdf),result.PdfSha256);Assert.NotEqual(SHA256.HashData(sent!),result.OriginalSha256);Assert.Equal(2,result.Pages.Count);
        source.Dispose();Assert.Throws<ObjectDisposedException>(()=>source.OpenRead());Assert.Throws<ObjectDisposedException>(()=>source.OriginalSha256);
    }
    [Theory]
    [InlineData("formula")][InlineData("cached-formula")][InlineData("external")][InlineData("external-part")][InlineData("macro")][InlineData("ole")][InlineData("chart")][InlineData("hidden-sheet")][InlineData("hidden-row")][InlineData("hidden-column")][InlineData("hidden-zero")][InlineData("names")][InlineData("comments")][InlineData("hyperlink")][InlineData("connection")][InlineData("printer")][InlineData("unknown")][InlineData("bad-type")][InlineData("orphan")][InlineData("duplicate-id")][InlineData("duplicate-cell")][InlineData("duplicate-row")][InlineData("large-grid")][InlineData("wide")][InlineData("tall")][InlineData("merge-data")][InlineData("style")][InlineData("custom-format")][InlineData("large-font")][InlineData("font-url")][InlineData("large-text")][InlineData("foreign-namespace")][InlineData("xml-base")][InlineData("dtd")][InlineData("processing")][InlineData("alias")][InlineData("truncated")][InlineData("pages")][InlineData("shared-reuse-work")][InlineData("extreme-color")][InlineData("rotation")][InlineData("protected-workbook")][InlineData("root-alias")]
    public async Task Active_unknown_ambiguous_and_unbounded_workbooks_fail_before_converter_access(string mode)
    {
        var p=Parts();var sheet=p["xl/worksheets/sheet1.xml"];
        switch(mode)
        {
            case "rotation":AddStyles(p);p["xl/styles.xml"]=p["xl/styles.xml"].Replace("xfId=\"0\"/>","xfId=\"0\"><alignment textRotation=\"999999\"/></xf>");break;
            case "protected-workbook":p["xl/workbook.xml"]=p["xl/workbook.xml"].Replace("</workbook>","<workbookProtection lockStructure=\"1\"/></workbook>");break;
            case "root-alias":p["xl/_rels/workbook.xml.rels"]=p["xl/_rels/workbook.xml.rels"].Replace("worksheets/sheet1.xml","//xl/worksheets/sheet1.xml");break;
            case "formula":sheet=sheet.Replace("<v>42</v>","<f>WEBSERVICE(\"https://PRIVATE-MARKER.example.invalid\")</f><v>42</v>");break;
            case "cached-formula":sheet=sheet.Replace("<v>42</v>","<f>1+1</f><v>2</v>");break;
            case "external":p["xl/_rels/workbook.xml.rels"]=p["xl/_rels/workbook.xml.rels"].Replace("Target=\"worksheets/sheet1.xml\"","Target=\"https://PRIVATE-MARKER.example.invalid\" TargetMode=\"External\"");break;
            case "external-part":p["xl/externalLinks/externalLink1.xml"]="<externalLink/>";break;
            case "macro":p["xl/vbaProject.bin"]="PRIVATE-MARKER";break;
            case "ole":p["xl/embeddings/oleObject1.bin"]="PRIVATE-MARKER";break;
            case "chart":p["xl/charts/chart1.xml"]="<chart/>";break;
            case "hidden-sheet":p["xl/workbook.xml"]=p["xl/workbook.xml"].Replace("name=\"Summary\"","name=\"Summary\" state=\"veryHidden\"");break;
            case "hidden-row":sheet=sheet.Replace("<row r=\"1\">","<row r=\"1\" hidden=\"1\">");break;
            case "hidden-column":sheet=sheet.Replace("<sheetData>","<cols><col min=\"1\" max=\"1\" hidden=\"1\"/></cols><sheetData>");break;
            case "hidden-zero":sheet=sheet.Replace("<sheetData>","<sheetViews><sheetView workbookViewId=\"0\" showZeros=\"false\"/></sheetViews><sheetData>");break;
            case "names":p["xl/workbook.xml"]=p["xl/workbook.xml"].Replace("</workbook>","<definedNames><definedName name=\"x\">EXEC(\"PRIVATE-MARKER\")</definedName></definedNames></workbook>");break;
            case "comments":p["xl/comments/comment1.xml"]="<comments/>";break;
            case "hyperlink":sheet=sheet.Replace("</worksheet>","<hyperlinks><hyperlink ref=\"A1\" location=\"PRIVATE-MARKER\"/></hyperlinks></worksheet>");break;
            case "connection":p["xl/connections.xml"]="<connections/>";break;
            case "printer":p["xl/printerSettings/printerSettings1.bin"]="PRIVATE-MARKER";break;
            case "unknown":sheet=sheet.Replace("<sheetData>","<extLst/><sheetData>");break;
            case "bad-type":p["[Content_Types].xml"]=p["[Content_Types].xml"].Replace("sheet.main+xml","template.main+xml");break;
            case "orphan":p["xl/sharedStrings.xml"]=$"<sst xmlns=\"{S}\"/>";break;
            case "duplicate-id":p["xl/_rels/workbook.xml.rels"]=p["xl/_rels/workbook.xml.rels"].Replace("rId2","rId1");break;
            case "duplicate-cell":sheet=sheet.Replace("<c r=\"B2\"","<c r=\"A2\"");break;
            case "duplicate-row":sheet=sheet.Replace("<row r=\"2\">","<row r=\"1\">");break;
            case "large-grid":sheet=sheet.Replace("B2","M2");break;
            case "wide":sheet=sheet.Replace("<sheetData>","<cols><col min=\"1\" max=\"12\" width=\"999\"/></cols><sheetData>");break;
            case "tall":sheet=sheet.Replace("<row r=\"1\">","<row r=\"1\" ht=\"999\">");break;
            case "merge-data":sheet=sheet.Replace("</worksheet>","<mergeCells count=\"1\"><mergeCell ref=\"A2:B2\"/></mergeCells></worksheet>");break;
            case "style":sheet=sheet.Replace("<c r=\"B2\"","<c r=\"B2\" s=\"999\"");break;
            case "custom-format":AddStyles(p);p["xl/styles.xml"]=p["xl/styles.xml"].Replace("numFmtId=\"0\"","numFmtId=\"164\"");break;
            case "large-font":AddStyles(p);p["xl/styles.xml"]=p["xl/styles.xml"].Replace("val=\"11\"","val=\"999\"");break;
            case "font-url":AddStyles(p);p["xl/styles.xml"]=p["xl/styles.xml"].Replace("Liberation Sans","file:///PRIVATE-MARKER");break;
            case "extreme-color":AddStyles(p);p["xl/styles.xml"]=p["xl/styles.xml"].Replace("<sz val=\"11\"/>","<sz val=\"11\"/><color tint=\"NaN\"/>");break;
            case "large-text":sheet=sheet.Replace("NO AGREEMENT",new string('x',101));break;
            case "foreign-namespace":sheet=sheet.Replace("<v>42</v>","<x:v xmlns:x=\"urn:PRIVATE-MARKER\">42</x:v>");break;
            case "xml-base":sheet=sheet.Replace("<worksheet ","<worksheet xml:base=\"https://PRIVATE-MARKER.example.invalid\" ");break;
            case "dtd":sheet="<!DOCTYPE x [<!ENTITY x SYSTEM 'https://PRIVATE-MARKER.example.invalid'>]>"+sheet;break;
            case "processing":sheet="<?PRIVATE-MARKER x?>"+sheet;break;
            case "alias":p["XL/WORKBOOK.XML"]=p["xl/workbook.xml"];break;
            case "shared-reuse-work":
                AddStrings(p);var many=string.Concat(Enumerable.Range(1,40).Select(row=>$"<row r=\"{row}\">"+string.Concat(Enumerable.Range(1,12).Select(col=>$"<c r=\"{(char)('A'+col-1)}{row}\" t=\"s\"><v>0</v></c>"))+"</row>"));sheet=$"<worksheet xmlns=\"{S}\"><sheetData>{many}</sheetData></worksheet>";p["xl/worksheets/sheet2.xml"]=sheet;p["xl/sharedStrings.xml"]=$"<sst xmlns=\"{S}\" count=\"960\" uniqueCount=\"1\"><si><t>{new string('x',100)}</t></si></sst>";break;
        }
        p["xl/worksheets/sheet1.xml"]=sheet;var bytes=Zip(p);if(mode=="truncated")bytes=bytes[..^8];using var input=new MemoryStream(bytes);var error=await Assert.ThrowsAsync<DocumentRejectedException>(()=>new XlsxPackageValidation(new(){MaximumPages=mode=="pages"?1:20}).ValidateAsync(input,input.Length));Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Null(error.InnerException);Assert.True(input.CanRead);
    }
    [Theory][InlineData("disabled")][InlineData("sandbox")][InlineData("provider")][InlineData("pages")][InlineData("geometry")][InlineData("cancel")]
    public async Task Opt_in_transport_and_exact_page_profile_are_required(string mode)
    {
        Assert.False(new OfficeConversionOptions().XlsxEnabled);using var input=new MemoryStream(Package());using var source=await new XlsxPackageValidation(new()).ValidateAsync(input,input.Length);var handler=new Handler(_=>Task.FromResult(mode=="provider"?new HttpResponseMessage(HttpStatusCode.ServiceUnavailable){Content=new StringContent("PRIVATE-MARKER")}:mode=="pages"?Pdf(1):mode=="geometry"?Pdf(media:"0 0 612 792"):Pdf()));using var http=new HttpClient(handler);using var cancel=new CancellationTokenSource();if(mode=="cancel")cancel.Cancel();var error=await Record.ExceptionAsync(()=>Converter(http,mode!="disabled",mode=="sandbox").ConvertAsync(source,cancel.Token));Assert.NotNull(error);Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Equal(mode is "provider" or "pages" or "geometry"?1:0,handler.Calls);
    }
    [Fact]
    public async Task Shared_strings_and_static_styles_are_supported_without_altering_values()
    {
        var parts=Parts();AddStyles(parts);AddStrings(parts);parts["xl/workbook.xml"]=parts["xl/workbook.xml"].Replace("</workbook>","<workbookProtection/><definedNames/></workbook>");parts["xl/_rels/workbook.xml.rels"]=parts["xl/_rels/workbook.xml.rels"].Replace("worksheets/sheet1.xml","/xl/worksheets/sheet1.xml");parts["xl/worksheets/sheet1.xml"]=parts["xl/worksheets/sheet1.xml"].Replace("<c r=\"A2\" t=\"inlineStr\"><is><t>Items</t></is></c>","<c r=\"A2\" s=\"0\" t=\"s\"><v>0</v></c>");var bytes=Zip(parts);using var input=new MemoryStream(bytes);using var accepted=await new XlsxPackageValidation(new()).ValidateAsync(input,input.Length);Assert.Equal(2,accepted.ExpectedPages);
    }
    public static byte[] Package()=>Zip(Parts());
    private static Dictionary<string,string> Parts()
    {
        var p=new Dictionary<string,string>{["[Content_Types].xml"]="<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/worksheets/sheet2.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>",
        ["_rels/.rels"]=$"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"{R}/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>",
        ["xl/workbook.xml"]=$"<workbook xmlns=\"{S}\" xmlns:r=\"{R}\"><sheets><sheet name=\"Summary\" sheetId=\"1\" r:id=\"rId1\"/><sheet name=\"Details\" sheetId=\"2\" r:id=\"rId2\"/></sheets></workbook>",
        ["xl/_rels/workbook.xml.rels"]=$"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"{R}/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId2\" Type=\"{R}/worksheet\" Target=\"worksheets/sheet2.xml\"/></Relationships>"};
        for(var i=1;i<=2;i++)p[$"xl/worksheets/sheet{i}.xml"]=$"<worksheet xmlns=\"{S}\"><dimension ref=\"A1:B2\"/><sheetData><row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>SYNTHETIC SHEET {i} — NO AGREEMENT</t></is></c></row><row r=\"2\"><c r=\"A2\" t=\"inlineStr\"><is><t>Items</t></is></c><c r=\"B2\"><v>42</v></c></row></sheetData></worksheet>";return p;
    }
    private static void AddStyles(Dictionary<string,string> p){p["[Content_Types].xml"]=p["[Content_Types].xml"].Replace("</Types>","<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/></Types>");p["xl/_rels/workbook.xml.rels"]=p["xl/_rels/workbook.xml.rels"].Replace("</Relationships>",$"<Relationship Id=\"rIdS\" Type=\"{R}/styles\" Target=\"styles.xml\"/></Relationships>");p["xl/styles.xml"]=$"<styleSheet xmlns=\"{S}\"><fonts count=\"1\"><font><name val=\"Liberation Sans\"/><sz val=\"11\"/></font></fonts><fills count=\"1\"><fill><patternFill patternType=\"none\"/></fill></fills><borders count=\"1\"><border/></borders><cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs><cellXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/></cellXfs></styleSheet>";}
    private static void AddStrings(Dictionary<string,string> p){p["[Content_Types].xml"]=p["[Content_Types].xml"].Replace("</Types>","<Override PartName=\"/xl/sharedStrings.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml\"/></Types>");p["xl/_rels/workbook.xml.rels"]=p["xl/_rels/workbook.xml.rels"].Replace("</Relationships>",$"<Relationship Id=\"rIdT\" Type=\"{R}/sharedStrings\" Target=\"sharedStrings.xml\"/></Relationships>");p["xl/sharedStrings.xml"]=$"<sst xmlns=\"{S}\" count=\"1\" uniqueCount=\"1\"><si><t>Items</t></si></sst>";}
    private static byte[] Zip(Dictionary<string,string> parts){using var bytes=new MemoryStream();using(var zip=new ZipArchive(bytes,ZipArchiveMode.Create,true))foreach(var (name,text) in parts){using var output=new StreamWriter(zip.CreateEntry(name).Open(),new UTF8Encoding(false));output.Write(text);}return bytes.ToArray();}
    private static Dictionary<string,string> Unzip(byte[] bytes){using var zip=new ZipArchive(new MemoryStream(bytes));return zip.Entries.ToDictionary(x=>x.FullName,x=>new StreamReader(x.Open()).ReadToEnd());}
    private static async Task<byte[]> Read(Stream input){using var output=new MemoryStream();await input.CopyToAsync(output);return output.ToArray();}
    private static HttpResponseMessage Pdf(int pages=2,string media="0 0 841.8897637795276 595.2755905511812"){var result=new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(PdfFixtures.Create(pages:pages,media:media))};result.Content.Headers.ContentType=new("application/pdf");return result;}
    private static StaticOfficeConverter Converter(HttpClient http,bool enabled=true,bool sandbox=false){var limits=new DocumentOptions();var options=new GotenbergOptions{Enabled=true,BaseUrl="https://converter.example.invalid",Transport=sandbox?"Sandbox":"Http"};return new(new(){XlsxEnabled=enabled},new(http,options,limits,new(limits),new EnvironmentStub()));}
    private sealed class Handler(Func<HttpRequestMessage,Task<HttpResponseMessage>> send):HttpMessageHandler {public int Calls;protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct){Calls++;ct.ThrowIfCancellationRequested();return send(request);}}
    private sealed class EnvironmentStub:IHostEnvironment {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Tests";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}

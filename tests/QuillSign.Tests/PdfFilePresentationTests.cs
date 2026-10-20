using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class PdfFilePresentationTests
{
    [Theory]
    [InlineData(false,"application/pdf","attachment")]
    [InlineData(true,"application/pdf","inline")]
    [InlineData(true,"application/pdf; charset=binary","inline")]
    [InlineData(true,"text/plain","attachment")]
    [InlineData(true,"text/html","attachment")]
    [InlineData(true,"image/svg+xml","attachment")]
    [InlineData(true,"application/vnd.openxmlformats-officedocument.wordprocessingml.document","attachment")]
    public async Task Actual_MVC_executor_preserves_bytes_filename_and_privacy_headers(bool enabled,string type,string expected)
    {
        var services=new ServiceCollection();services.AddLogging();services.AddMvc();
        using var provider=services.BuildServiceProvider();
        var http=new DefaultHttpContext {RequestServices=provider};http.Response.Body=new MemoryStream();
        http.Response.Headers.CacheControl="no-store";http.Response.Headers["X-Robots-Tag"]="noindex";
        http.Response.Headers["Referrer-Policy"]="no-referrer";http.Response.Headers["X-Content-Type-Options"]="nosniff";
        byte[] bytes=[37,80,68,70,45,0,255,13,10];
        var file=new FileContentResult(bytes,type) {FileDownloadName="Synthetic résumé \"NO AGREEMENT\".pdf",EnableRangeProcessing=false};
        var action=new ActionContext(http,new RouteData(),new ActionDescriptor(),new ModelStateDictionary());
        var context=new ResultExecutingContext(action,[],file,new object());
        new PdfFilePresentationFilter(new() {ViewInsteadOfDownload=enabled}).OnResultExecuting(context);
        await file.ExecuteResultAsync(action);
        Assert.Equal(bytes,((MemoryStream)http.Response.Body).ToArray());Assert.Equal(type,http.Response.ContentType);
        Assert.Equal(expected,http.Response.GetTypedHeaders().ContentDisposition!.DispositionType.Value);
        Assert.Contains("NO AGREEMENT",http.Response.Headers.ContentDisposition.ToString());
        Assert.Contains("résumé",http.Response.GetTypedHeaders().ContentDisposition!.FileNameStar.Value);
        Assert.Equal("no-store",http.Response.Headers.CacheControl);Assert.Equal("noindex",http.Response.Headers["X-Robots-Tag"]);
        Assert.Equal("no-referrer",http.Response.Headers["Referrer-Policy"]);Assert.Equal("nosniff",http.Response.Headers["X-Content-Type-Options"]);
        Assert.False(file.EnableRangeProcessing);
    }

    [Theory]
    [InlineData("a",true)] [InlineData("form",true)] [InlineData("button",true)]
    [InlineData("a",false)] [InlineData("form",false)] [InlineData("button",false)]
    public void File_actions_open_an_isolated_tab_only_when_enabled_without_changing_form_authority(string tag,bool enabled)
    {
        var attributes=new TagHelperAttributeList { {"pdf-file-action",""},{"action","/complete/synthetic?handler=Download"},{"method","post"} };
        var context=new TagHelperContext(attributes, new Dictionary<object,object>(),"test");
        var output=new TagHelperOutput(tag,attributes,(_,_)=>Task.FromResult<TagHelperContent>(new DefaultTagHelperContent()));
        output.Content.SetHtmlContent("<input name=\"__RequestVerificationToken\" value=\"synthetic\" />");
        var original=output.Content.GetContent();
        new PdfFileActionTagHelper(new() {ViewInsteadOfDownload=enabled}) {Label=tag=="form" ? null : "exact PDF"}.Process(context,output);
        Assert.False(output.Attributes.ContainsName("pdf-file-action"));Assert.False(output.Attributes.ContainsName("pdf-file-label"));
        Assert.Equal(enabled && tag!="button",output.Attributes.ContainsName("target"));
        if(enabled && tag!="button") {
            Assert.Equal("_blank",output.Attributes["target"].Value);Assert.Equal("noopener noreferrer",output.Attributes["rel"].Value);
        }
        if(tag=="form" || !enabled)Assert.Equal(original,output.Content.GetContent());
        else {Assert.Equal("View exact PDF",output.Content.GetContent());Assert.Contains("opens in a new tab",output.Attributes["aria-label"].Value.ToString());}
        Assert.Equal("post",output.Attributes["method"].Value);Assert.Equal("/complete/synthetic?handler=Download",output.Attributes["action"].Value);
    }
}

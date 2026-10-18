using System.Net;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Documents;
using Browser=QuillSign.Tests.SenderDocumentRetentionTests.BrowserSession;

namespace QuillSign.Tests;

public sealed class TextDocumentIntakeTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false,false)][InlineData(false,true)][InlineData(true,false)][InlineData(true,true)]
    public async Task TXT_requires_its_own_explicit_gate_and_a_usable_converter(bool text,bool converter)
    {
        Assert.False(new DocumentOptions().EnableTextUploads);
        var provider=new DocxDocumentWorkflowTests.Provider();await using var b=await Start(provider,text,converter);
        using var page=await b.Get(b.Path);var html=await page.Content.ReadAsStringAsync();Assert.Equal(text&&converter,html.Contains(",.txt"));Assert.Equal(0,provider.Calls);
        if(!text||!converter){var before=await b.run.H.StateAsync();using var response=await b.Upload(html,"SYNTHETIC - NO AGREEMENT"u8.ToArray(),"synthetic.txt",json:true);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.Equal(0,provider.Calls);Assert.Equal(before.RowVersion,(await b.run.H.StateAsync()).RowVersion);}
    }

    [Theory]
    [InlineData("csrf")][InlineData("stale")][InlineData("encoding")][InlineData("empty")][InlineData("provider")][InlineData("multiple")][InlineData("cutoff")]
    public async Task Failed_text_requests_preserve_confirmed_source_and_allow_explicit_recovery(string mode)
    {
        var provider=new DocxDocumentWorkflowTests.Provider();await using var b=await Start(provider,true,true);var before=await b.run.H.StateAsync();
        await b.run.H.WithAsync(w=>w.ConfirmAsync(b.run.H.Sender,before.PublicId,before.RowVersion,before.PdfBlob!,true,null,null,default));before=await b.run.H.StateAsync();
        using var page=await b.Get(b.Path);var html=await page.Content.ReadAsStringAsync();var bytes=mode switch{"encoding"=>new byte[]{0xff,0xfe,0x41,0},"empty"=>" \n"u8.ToArray(),_=>"SYNTHETIC - NO AGREEMENT\nMarkup <must> be literal."u8.ToArray()};
        if(mode=="provider")provider.Status=HttpStatusCode.ServiceUnavailable;if(mode=="cutoff")provider.Before=()=>{b.Expire();return Task.CompletedTask;};
        using var response=await b.Upload(html,bytes,"synthetic.TXT","application/x-browser-label",csrf:mode!="csrf",version:mode=="stale"?Convert.ToBase64String(new byte[8]):null,extra:mode=="multiple");
        Assert.Equal(mode switch{"stale"=>HttpStatusCode.Conflict,"provider"=>HttpStatusCode.ServiceUnavailable,"cutoff"=>HttpStatusCode.Gone,_=>HttpStatusCode.BadRequest},response.StatusCode);
        if(mode!="csrf")Assert.True(response.Headers.CacheControl!.NoStore);var body=await response.Content.ReadAsStringAsync();Assert.DoesNotContain("PRIVATE-MARKER",body);Assert.DoesNotContain("converter.example",body);
        var after=await b.run.H.StateAsync();Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.PdfBlob,after.PdfBlob);Assert.Equal(before.OriginalBlob,after.OriginalBlob);Assert.Equal(before.PreviewConfirmedAt,after.PreviewConfirmedAt);Assert.Equal(2,await b.run.AuditCount());
        Assert.Equal(mode is "provider" or "cutoff"?1:0,provider.Calls);
        if(mode=="provider"){provider.Status=HttpStatusCode.OK;using var retry=await b.Upload(html,bytes,"recovered.txt");Assert.Equal(HttpStatusCode.Redirect,retry.StatusCode);Assert.Null((await b.run.H.StateAsync()).PreviewConfirmedAt);}
    }

    private async Task<Browser> Start(DocxDocumentWorkflowTests.Provider provider,bool text,bool converter)
    {
        var b=await Browser.Start(fixture,conversion:new(){Enabled=converter,BaseUrl="http://127.0.0.1:3000"},configure:services=>{
            services.AddSingleton(new DocumentOptions{EnableTextUploads=text});services.AddHttpClient<GotenbergDocxConverter>().ConfigurePrimaryHttpMessageHandler(()=>provider);
        });using var session=await b.Get("/test-session");Assert.Equal(HttpStatusCode.OK,session.StatusCode);return b;
    }
}

using System.Net;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Documents;
using Browser=QuillSign.Tests.SenderDocumentRetentionTests.BrowserSession;

namespace QuillSign.Tests;

public sealed class PublicDocumentIntakeTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("pdf")][InlineData("docx")][InlineData("png")][InlineData("jpg")][InlineData("jpeg")]
    public async Task Verified_upload_publishes_only_normalized_PDF_then_requires_explicit_confirmation(string kind)
    {
        var provider=new DocxDocumentWorkflowTests.Provider();await using var b=await Start(provider);var old=await Prepared(b);var page=await Page(b);
        var input=Input(kind);using(var upload=await b.Upload(page,input,"synthetic."+kind,"application/x-ignored-browser-label"))
        {Assert.Equal(HttpStatusCode.Redirect,upload.StatusCode);Assert.Equal(b.Path,upload.Headers.Location!.OriginalString);Assert.True(upload.Headers.CacheControl!.NoStore);Assert.Contains("no-referrer",upload.Headers.GetValues("Referrer-Policy"));}
        var state=await b.run.H.StateAsync();Assert.Null(state.PreviewConfirmedAt);Assert.Equal("synthetic.pdf",state.Title);Assert.NotEqual(old.PdfBlob,state.PdfBlob);
        Assert.Equal(SHA256.HashData(input),state.OriginalSha256);Assert.Equal(kind switch {"pdf"=>"application/pdf","docx"=>DocxDocumentWorkflow.Mime,"png"=>"image/png",_=>"image/jpeg"},state.OriginalMime);
        using(var pdf=await b.Get(b.Path+"/document/"+state.PdfBlob)) {Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);Assert.Equal("application/pdf",pdf.Content.Headers.ContentType!.MediaType);Assert.Equal(state.PdfSha256,SHA256.HashData(await pdf.Content.ReadAsByteArrayAsync()));}
        using(var stale=await b.Get(b.Path+"/document/"+old.PdfBlob))Assert.Equal(HttpStatusCode.NotFound,stale.StatusCode);
        page=await Page(b);Assert.Contains("Review needed",page);Assert.DoesNotContain("Set up signers",page);
        using(var confirm=await b.Post(b.Path+"?handler=Confirm",new(){["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page),["Version"]=SenderSendPageTests.Flow.Value(page,"Version"),["DocumentId"]=state.PdfBlob!,["PreviewMatches"]="true"}))Assert.Equal(HttpStatusCode.Redirect,confirm.StatusCode);
        Assert.Contains("Set up signers",await Page(b));await using var db=fixture.Open();Assert.False(await db.Fields.AnyAsync(x=>x.EnvelopeId==state.Id));
        Assert.Equal(UploadRetention.Digest(b.run.Policy),UploadRetention.Digest(await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==state.Id)));Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==state.Id));var purge=Assert.Single(await db.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==state.Id).ToArrayAsync());Assert.Equal(WorkKind.Purge,purge.Kind);Assert.Equal(b.run.Policy.DeleteAfter,purge.AvailableAt);
        Assert.Equal(kind=="docx" ? 1 : 0,provider.Calls);
    }

    [Theory]
    [InlineData("mismatch")][InlineData("malformed-docx")][InlineData("malformed-image")][InlineData("unsupported")]
    [InlineData("disabled")][InlineData("provider")][InlineData("invalid-pdf")][InlineData("multiple")]
    [InlineData("csrf")][InlineData("stale")][InlineData("wrong-party")][InlineData("cutoff")]
    public async Task Failed_intake_preserves_prior_source_preparation_and_retention(string kind)
    {
        var provider=new DocxDocumentWorkflowTests.Provider();await using var b=await Start(provider,enabled:kind!="disabled");var before=await Prepared(b);var page=await Page(b);
        var bytes=Input("docx");var filename="synthetic.docx";
        if(kind=="mismatch") {bytes=Input("png");filename="synthetic.jpg";}
        if(kind=="malformed-docx")bytes="not a package"u8.ToArray();
        if(kind=="malformed-image") {bytes="not an image"u8.ToArray();filename="synthetic.png";}
        if(kind=="unsupported")filename="synthetic.docm";
        if(kind=="provider")provider.Status=HttpStatusCode.ServiceUnavailable;
        if(kind=="invalid-pdf")provider.InvalidPdf=true;
        if(kind=="cutoff")provider.Before=()=>{b.Expire();return Task.CompletedTask;};
        using var response=await b.Upload(page,bytes,filename,csrf:kind!="csrf",version:kind=="stale" ? Convert.ToBase64String(new byte[8]) : null,extra:kind=="multiple",publicId:kind=="wrong-party" ? Guid.NewGuid().ToString("N") : null,json:kind is "provider" or "disabled");
        Assert.Equal(kind switch {"provider" or "disabled"=>HttpStatusCode.ServiceUnavailable,"stale"=>HttpStatusCode.Conflict,"wrong-party"=>HttpStatusCode.NotFound,"cutoff"=>HttpStatusCode.Gone,_=>HttpStatusCode.BadRequest},response.StatusCode);
        var body=await response.Content.ReadAsStringAsync();Assert.DoesNotContain("PRIVATE-MARKER",body);if(kind is "provider" or "disabled") {Assert.Equal("application/json",response.Content.Headers.ContentType!.MediaType);Assert.True(response.Headers.CacheControl!.NoStore);}
        var after=await b.run.H.StateAsync();Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.PdfBlob,after.PdfBlob);Assert.Equal(before.OriginalBlob,after.OriginalBlob);Assert.Equal(before.PreviewConfirmedAt,after.PreviewConfirmedAt);
        await using var db=fixture.Open();Assert.Single(await db.Fields.Where(x=>x.EnvelopeId==before.Id).ToArrayAsync());Assert.Equal(2,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==before.Id));Assert.Equal(UploadRetention.Digest(b.run.Policy),UploadRetention.Digest(await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==before.Id)));
        if(kind is "provider" or "invalid-pdf") {provider.Status=HttpStatusCode.OK;provider.InvalidPdf=false;using var recovery=await b.Upload(page,Input("docx"),"recovered.docx");Assert.Equal(HttpStatusCode.Redirect,recovery.StatusCode);}
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Form_reflects_actual_DOCX_availability_without_preparing_or_mutating(bool enabled)
    {
        var provider=new DocxDocumentWorkflowTests.Provider();await using var b=await Start(provider,enabled);var before=await b.run.H.StateAsync();var page=await Page(b);
        Assert.Contains("Document file",page);Assert.Contains("data-document-upload",page);Assert.Contains("12 million pixels",page);Assert.Contains(".pdf,.png,.jpg,.jpeg"+(enabled ? ",.docx" : ""),page);
        Assert.Equal(!enabled,page.Contains("DOCX conversion is unavailable here."));Assert.Equal(0,provider.Calls);Assert.Equal(before.RowVersion,(await b.run.H.StateAsync()).RowVersion);Assert.Equal(1,await b.run.AuditCount());
    }

    private async Task<Browser> Start(DocxDocumentWorkflowTests.Provider provider,bool enabled=true)
    {
        var b=await Browser.Start(fixture,conversion:new(){Enabled=enabled,BaseUrl="http://127.0.0.1:3000"},configure:services=>services.AddHttpClient<GotenbergDocxConverter>().ConfigurePrimaryHttpMessageHandler(()=>provider));
        using var session=await b.Get("/test-session");Assert.Equal(HttpStatusCode.OK,session.StatusCode);return b;
    }
    [Theory]
    [InlineData("")][InlineData("http://127.0.0.1:3000/private-path")]
    public async Task Unusable_converter_configuration_is_unavailable_without_exposing_its_endpoint(string origin)
    {
        var provider=new DocxDocumentWorkflowTests.Provider();await using var b=await Browser.Start(fixture,conversion:new(){Enabled=true,BaseUrl=origin},configure:services=>services.AddHttpClient<GotenbergDocxConverter>().ConfigurePrimaryHttpMessageHandler(()=>provider));
        using(var session=await b.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,session.StatusCode);var page=await Page(b);Assert.Contains("DOCX conversion is unavailable here.",page);Assert.DoesNotContain("private-path",page);
        var before=await b.run.H.StateAsync();using var result=await b.Upload(page,Input("docx"),"synthetic.docx",json:true);Assert.Equal(HttpStatusCode.ServiceUnavailable,result.StatusCode);Assert.Equal(0,provider.Calls);Assert.Equal(before.RowVersion,(await b.run.H.StateAsync()).RowVersion);
    }
    [Theory]
    [InlineData("source-bytes")][InlineData("converted-pages")]
    public async Task Configured_limits_reject_intake_without_replacing_the_prior_document(string kind)
    {
        var provider=new DocxDocumentWorkflowTests.Provider();await using var b=await Browser.Start(fixture,conversion:new(){Enabled=true,BaseUrl="http://127.0.0.1:3000"},configure:services=>{
            services.AddSingleton(new DocumentOptions{MaximumBytes=kind=="source-bytes" ? 1024 : 25*1024*1024,MaximumPages=1});
            services.AddHttpClient<GotenbergDocxConverter>().ConfigurePrimaryHttpMessageHandler(()=>provider);
        });
        using(var session=await b.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,session.StatusCode);var before=await Prepared(b);var page=await Page(b);
        using var response=await b.Upload(page,kind=="source-bytes" ? new byte[1025] : Input("docx"),"synthetic.docx");Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);
        Assert.Equal(kind=="source-bytes" ? 0 : 1,provider.Calls);Assert.Equal(before.RowVersion,(await b.run.H.StateAsync()).RowVersion);Assert.Equal(2,await b.run.AuditCount());
    }
    [Fact]
    public async Task Cancelled_conversion_preserves_preparation_and_explicit_retry_recovers()
    {
        using var cancel=new CancellationTokenSource();var provider=new DocxDocumentWorkflowTests.Provider{Before=()=>{cancel.Cancel();return Task.CompletedTask;}};await using var b=await Start(provider);var before=await Prepared(b);var page=await Page(b);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>b.Upload(page,Input("docx"),"synthetic.docx",ct:cancel.Token));
        Assert.Equal(before.RowVersion,(await b.run.H.StateAsync()).RowVersion);Assert.Equal(2,await b.run.AuditCount());provider.Before=null;
        using var recovered=await b.Upload(page,Input("docx"),"synthetic.docx");Assert.Equal(HttpStatusCode.Redirect,recovered.StatusCode);
    }
    private async Task<Envelope> Prepared(Browser b)
    {
        var before=await b.run.H.StateAsync();Assert.True(await b.run.H.WithAsync(w=>w.ConfirmAsync(b.run.H.Sender,before.PublicId,before.RowVersion,before.PdfBlob!,true,null,null,default)));
        await using var db=fixture.Open();db.Fields.Add(new(){EnvelopeId=before.Id,Type=FieldType.Text,Width=.2m,Height=.1m});await db.SaveChangesAsync();return await b.run.H.StateAsync();
    }
    private static async Task<string> Page(Browser b) {using var response=await b.Get(b.Path);Assert.Equal(HttpStatusCode.OK,response.StatusCode);return await response.Content.ReadAsStringAsync();}
    private static byte[] Input(string kind)=>kind switch {"pdf"=>PdfFixtures.Create(),"docx"=>GotenbergDocxConverterTests.Docx(),"png"=>ImagePdfConverterTests.Png(orientation:6),_=>ImagePdfConverterTests.Jpeg(orientation:6)};
}

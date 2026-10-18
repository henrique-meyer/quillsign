using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Documents;
using Browser=QuillSign.Tests.SenderDocumentRetentionTests.BrowserSession;
using Provider=QuillSign.Tests.DocxDocumentWorkflowTests.Provider;

namespace QuillSign.Tests;

public sealed class OfficeDocumentIntakeTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory][InlineData(OfficeSourceKind.Pptx)][InlineData(OfficeSourceKind.Xlsx)][InlineData(OfficeSourceKind.Odt)][InlineData(OfficeSourceKind.Rtf)]
    public async Task Enabled_family_uploads_exact_original_and_PDF_then_requires_explicit_confirmation(OfficeSourceKind kind)
    {
        var provider=OfficeDocumentWorkflowTests.Response(kind);await using var b=await Start(provider,kind);using var page=await b.Get(b.Path);var html=await page.Content.ReadAsStringAsync();Assert.Contains(OfficeDocumentWorkflow.Family(kind).Extension,html);Assert.DoesNotContain(",.doc,",html);Assert.DoesNotContain("rel=\"canonical\"",html);Assert.DoesNotContain("ga4",html);Assert.DoesNotContain("property=\"og:",html);
        var bytes=OfficeDocumentWorkflowTests.Source(kind);using var uploaded=await b.Upload(html,bytes,"synthetic"+OfficeDocumentWorkflow.Family(kind).Extension.ToUpperInvariant(),mime:"application/x-untrusted-browser-label");Assert.Equal(HttpStatusCode.Redirect,uploaded.StatusCode);Assert.Equal(b.Path,uploaded.Headers.Location!.OriginalString);Assert.DoesNotContain("?",uploaded.Headers.Location.OriginalString);var state=await b.run.H.StateAsync();Assert.Equal(SHA256.HashData(bytes),state.OriginalSha256);Assert.Equal(OfficeDocumentWorkflow.Family(kind).Mime,state.OriginalMime);Assert.Null(state.PreviewConfirmedAt);Assert.Equal(1,provider.Calls);
        using var preview=await b.Get(b.Path);var review=await preview.Content.ReadAsStringAsync();Assert.Contains("This preview matches my document.",review);using var downloaded=await b.Get(b.Path+"/document/"+state.PdfBlob);Assert.Equal(HttpStatusCode.OK,downloaded.StatusCode);Assert.Equal(state.PdfSha256,SHA256.HashData(await downloaded.Content.ReadAsByteArrayAsync()));
        using var rejected=await b.Post(b.Path+"?handler=Confirm",new(){["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(review),["Version"]=Convert.ToBase64String(state.RowVersion),["DocumentId"]=state.PdfBlob!,["PreviewMatches"]="false"});Assert.Equal(HttpStatusCode.BadRequest,rejected.StatusCode);Assert.Null((await b.run.H.StateAsync()).PreviewConfirmedAt);
        using var confirmed=await b.Post(b.Path+"?handler=Confirm",new(){["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(review),["Version"]=Convert.ToBase64String(state.RowVersion),["DocumentId"]=state.PdfBlob!,["PreviewMatches"]="true"});Assert.Equal(HttpStatusCode.Redirect,confirmed.StatusCode);Assert.NotNull((await b.run.H.StateAsync()).PreviewConfirmedAt);
    }
    [Theory][InlineData("master")][InlineData("family")][InlineData("converter")][InlineData("sandbox")][InlineData("invalid-configuration")]
    public async Task Intake_gate_family_flag_and_supported_transport_are_all_required(string mode)
    {
        Assert.False(new DocumentOptions().EnableOfficeUploads);var provider=OfficeDocumentWorkflowTests.Response(OfficeSourceKind.Xlsx);await using var b=await Start(provider,OfficeSourceKind.Xlsx,mode);using var page=await b.Get(b.Path);var html=await page.Content.ReadAsStringAsync();Assert.DoesNotContain(",.xlsx",html);var before=await b.run.H.StateAsync();using var response=await b.Upload(html,OfficeDocumentWorkflowTests.Source(OfficeSourceKind.Xlsx),"synthetic.xlsx",json:true);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.Equal(0,provider.Calls);Assert.Equal(before.RowVersion,(await b.run.H.StateAsync()).RowVersion);
    }
    [Theory][InlineData("csrf")][InlineData("stale")][InlineData("multiple")][InlineData("provider")][InlineData("output")][InlineData("cutoff")][InlineData("unsupported-doc")]
    public async Task Failed_Office_posts_preserve_previous_confirmed_source_and_allow_explicit_recovery(string mode)
    {
        var provider=OfficeDocumentWorkflowTests.Response(OfficeSourceKind.Xlsx);await using var b=await Start(provider,OfficeSourceKind.Xlsx);var before=await b.run.H.StateAsync();await b.run.H.WithAsync(w=>w.ConfirmAsync(b.run.H.Sender,before.PublicId,before.RowVersion,before.PdfBlob!,true,null,null,default));before=await b.run.H.StateAsync();using var page=await b.Get(b.Path);var html=await page.Content.ReadAsStringAsync();if(mode=="provider")provider.Status=HttpStatusCode.ServiceUnavailable;if(mode=="output")provider.InvalidPdf=true;if(mode=="cutoff")provider.Before=()=>{b.Expire();return Task.CompletedTask;};var bytes=OfficeDocumentWorkflowTests.Source(OfficeSourceKind.Xlsx);
        using var response=await b.Upload(html,bytes,mode=="unsupported-doc"?"synthetic.doc":"synthetic.xlsx",csrf:mode!="csrf",version:mode=="stale"?Convert.ToBase64String(new byte[8]):null,extra:mode=="multiple");Assert.Equal(mode switch{"stale"=>HttpStatusCode.Conflict,"provider"=>HttpStatusCode.ServiceUnavailable,"cutoff"=>HttpStatusCode.Gone,_=>HttpStatusCode.BadRequest},response.StatusCode);var body=await response.Content.ReadAsStringAsync();Assert.DoesNotContain("PRIVATE-MARKER",body);Assert.DoesNotContain("converter.example",body);var after=await b.run.H.StateAsync();Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.PdfBlob,after.PdfBlob);Assert.Equal(before.OriginalBlob,after.OriginalBlob);Assert.Equal(before.PreviewConfirmedAt,after.PreviewConfirmedAt);Assert.Equal(mode is "provider" or "output" or "cutoff"?1:0,provider.Calls);
        if(mode is "provider" or "output"){provider.Status=HttpStatusCode.OK;provider.InvalidPdf=false;using var retry=await b.Upload(html,bytes,"recovered.xlsx");Assert.Equal(HttpStatusCode.Redirect,retry.StatusCode);Assert.Null((await b.run.H.StateAsync()).PreviewConfirmedAt);}
    }
    [Theory][InlineData(OfficeSourceKind.Pptx)][InlineData(OfficeSourceKind.Xlsx)][InlineData(OfficeSourceKind.Odt)][InlineData(OfficeSourceKind.Rtf)]
    public async Task Format_named_payload_must_pass_its_content_gate_before_provider_work(OfficeSourceKind kind)
    {
        var provider=OfficeDocumentWorkflowTests.Response(kind);await using var b=await Start(provider,kind);var before=await b.run.H.StateAsync();using var page=await b.Get(b.Path);var html=await page.Content.ReadAsStringAsync();using var response=await b.Upload(html,"PRIVATE-MARKER"u8.ToArray(),"disguised"+OfficeDocumentWorkflow.Family(kind).Extension);Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);Assert.Equal(0,provider.Calls);Assert.Equal(before.RowVersion,(await b.run.H.StateAsync()).RowVersion);
    }
    private async Task<Browser> Start(Provider provider,OfficeSourceKind kind,string mode="")
    {
        var b=await Browser.Start(fixture,conversion:new(){Enabled=mode!="converter",BaseUrl=mode=="invalid-configuration"?"not an origin":"http://127.0.0.1:3000",Transport=mode=="sandbox"?"Sandbox":"Http"},configure:services=>{services.AddSingleton(new DocumentOptions{EnableOfficeUploads=mode!="master"});services.AddSingleton(new OfficeConversionOptions{PptxEnabled=kind==OfficeSourceKind.Pptx&&mode!="family",XlsxEnabled=kind==OfficeSourceKind.Xlsx&&mode!="family",OdtEnabled=kind==OfficeSourceKind.Odt&&mode!="family",RtfEnabled=kind==OfficeSourceKind.Rtf&&mode!="family"});services.AddHttpClient<GotenbergDocxConverter>().ConfigurePrimaryHttpMessageHandler(()=>provider);});using var session=await b.Get("/test-session");Assert.Equal(HttpStatusCode.OK,session.StatusCode);return b;
    }
}

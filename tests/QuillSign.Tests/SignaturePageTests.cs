using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Legal;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class SignaturePageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task GET_is_read_only_and_preview_adoption_and_replacement_are_CSRF_protected_scoped_and_truthful()
    {
        await using var run=await Browser.Create(fixture);
        using(var anonymous=await run.Client.GetAsync(run.Path))Assert.Equal(HttpStatusCode.Unauthorized,anonymous.StatusCode);
        await run.Session("sender"); using(var sender=await run.Client.GetAsync(run.Path))Assert.Equal(HttpStatusCode.Unauthorized,sender.StatusCode);
        await run.Session("signer"); var page=await run.Get(); Assert.Contains("Type (keyboard accessible)",page); Assert.Contains("No preview prepared",page); Assert.DoesNotContain("name=\"Acknowledged\" value=\"true\" checked",page);
        await using(var db=fixture.Open()) { Assert.False(await db.SignaturePreviews.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id)); Assert.Null((await db.Signers.SingleAsync(x=>x.Id==run.Signer.Id)).SignatureAdoptionId); }
        using(var missingCsrf=await run.Preview(page,false))Assert.Equal(HttpStatusCode.BadRequest,missingCsrf.StatusCode);
        using var prepared=await run.Preview(page); Assert.Equal(HttpStatusCode.OK,prepared.StatusCode); Assert.True(prepared.Headers.CacheControl!.NoStore);
        using var data=JsonDocument.Parse(await prepared.Content.ReadAsStringAsync()); var receipt=data.RootElement.GetProperty("receipt").GetString()!;
        Assert.Equal(SignaturePng.Normalize(SignatureAdoptionTests.Mark()).Bytes,Convert.FromBase64String(data.RootElement.GetProperty("signature").GetString()!));
        Assert.Equal(SignatureAdoptionStatement.Text,data.RootElement.GetProperty("statement").GetString());
        using(var noAck=await run.Adopt(page,receipt,false))Assert.Equal(HttpStatusCode.BadRequest,noAck.StatusCode);
        using(var noCsrf=await run.Adopt(page,receipt,true,false))Assert.Equal(HttpStatusCode.BadRequest,noCsrf.StatusCode);
        using(var adopted=await run.Adopt(page,receipt))
        {
            Assert.Equal(HttpStatusCode.Redirect,adopted.StatusCode); Assert.Equal(run.Path,adopted.Headers.Location!.OriginalString);
            var notice=Assert.Single(adopted.Headers.GetValues("Set-Cookie")); Assert.Contains("httponly",notice,StringComparison.OrdinalIgnoreCase); run.Cookies(adopted);
        }
        var confirmed=await run.Get(); Assert.Contains("Your signature and initials were adopted",confirmed); Assert.Contains("Apply each field deliberately",confirmed); Assert.DoesNotContain("No document fields have been applied",confirmed);
        Assert.DoesNotContain("Your signature and initials were adopted",await run.Get()); Assert.Contains("Your marks are adopted",await run.Get());
        using(var replay=await run.Adopt(page,receipt))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
        using(var replaced=await run.Preview(confirmed))Assert.Equal(HttpStatusCode.OK,replaced.StatusCode);
        await using var inspect=fixture.Open(); Assert.Single(await inspect.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id).ToArrayAsync());
        Assert.Equal(SignerStatus.Viewed,(await inspect.Signers.SingleAsync(x=>x.Id==run.Signer.Id)).Status);
    }

    [Theory]
    [InlineData("missing")][InlineData("expired")][InlineData("foreign-session")][InlineData("foreign-request")][InlineData("withdrawn-consent")][InlineData("statement")]
    public async Task Missing_stale_or_foreign_adoption_evidence_never_reports_success(string kind)
    {
        await using var run=await Browser.Create(fixture); await run.Session("signer"); var page=await run.Get(); using var prepared=await run.Preview(page);
        using var data=JsonDocument.Parse(await prepared.Content.ReadAsStringAsync()); var receipt=data.RootElement.GetProperty("receipt").GetString()!;
        if(kind=="missing")receipt=""; if(kind=="expired")run.Clock.Advance(TimeSpan.FromMinutes(10));
        if(kind=="foreign-session") { run.Identity=run.Identity with { SessionId=Guid.NewGuid() }; await run.Session("signer"); }
        if(kind=="foreign-request")run.Path="/sign/"+Guid.NewGuid().ToString("N")+"/signature";
        if(kind=="withdrawn-consent") { await using var db=fixture.Open(); await db.Signers.Where(x=>x.Id==run.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ConsentAt,(DateTimeOffset?)null)); }
        using var result=await run.Adopt(page,receipt,version:kind=="statement" ? "old" : SignatureAdoptionStatement.Version);
        Assert.Contains(result.StatusCode,new[]{HttpStatusCode.BadRequest,HttpStatusCode.NotFound});
        await using var inspect=fixture.Open(); Assert.Null((await inspect.Signers.SingleAsync(x=>x.Id==run.Signer.Id)).SignatureAdoptionId);
    }

    [Theory]
    [InlineData("missing-file")][InlineData("mime")][InlineData("oversize")][InlineData("invalid-png")][InlineData("method")]
    public async Task Preview_rejects_bad_file_or_method_before_recording_any_adoption(string kind)
    {
        await using var run=await Browser.Create(fixture); await run.Session("signer"); var page=await run.Get();
        using var result=await run.Preview(page,kind:kind); Assert.Equal(HttpStatusCode.BadRequest,result.StatusCode);
        await using var db=fixture.Open(); Assert.False(await db.SignaturePreviews.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id)); Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id));
    }

    [Fact]
    public async Task Preview_storage_failure_returns_recoverable_error_without_saved_preview_or_adoption()
    {
        await using var run=await Browser.Create(fixture); await run.Session("signer"); var page=await run.Get(); run.Storage.FailRead=true;
        using var result=await run.Preview(page); Assert.Equal(HttpStatusCode.ServiceUnavailable,result.StatusCode);
        Assert.Contains("No adoption was recorded",await result.Content.ReadAsStringAsync());
        await using var db=fixture.Open(); Assert.False(await db.SignaturePreviews.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id)); Assert.Null((await db.Signers.SingleAsync(x=>x.Id==run.Signer.Id)).SignatureAdoptionId);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Hash_verification_failure_returns_recoverable_503_during_preview_or_adoption(bool duringAdoption)
    {
        await using var run=await Browser.Create(fixture); await run.Session("signer"); var page=await run.Get(); string receipt="";
        if(duringAdoption) { using var prepared=await run.Preview(page); using var data=JsonDocument.Parse(await prepared.Content.ReadAsStringAsync()); receipt=data.RootElement.GetProperty("receipt").GetString()!; }
        run.Storage.TamperRead=true;
        using var result=duringAdoption ? await run.Adopt(page,receipt) : await run.Preview(page);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,result.StatusCode);
        Assert.Contains(duringAdoption ? "Adoption could not be confirmed" : "No adoption was recorded",await result.Content.ReadAsStringAsync());
        await using var db=fixture.Open(); Assert.Null((await db.Signers.SingleAsync(x=>x.Id==run.Signer.Id)).SignatureAdoptionId);
    }

    [Fact]
    public async Task JSON_adoption_returns_body_without_redirect_or_notice_cookie_and_current_consent_is_required()
    {
        await using var run=await Browser.Create(fixture); await run.Session("signer"); var page=await run.Get(); using var prepared=await run.Preview(page);
        using var data=JsonDocument.Parse(await prepared.Content.ReadAsStringAsync()); var receipt=data.RootElement.GetProperty("receipt").GetString()!;
        run.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json"); using(var result=await run.Adopt(page,receipt))
        { Assert.Equal(HttpStatusCode.OK,result.StatusCode); Assert.Null(result.Headers.Location); Assert.False(result.Headers.Contains("Set-Cookie")); Assert.Contains("signing is not complete",await result.Content.ReadAsStringAsync(),StringComparison.OrdinalIgnoreCase); }
        await using(var db=fixture.Open())await db.Signers.Where(x=>x.Id==run.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ConsentAt,(DateTimeOffset?)null));
        using(var unavailable=await run.Client.GetAsync(run.Path))Assert.Equal(HttpStatusCode.NotFound,unavailable.StatusCode);
        using(var denied=await run.Preview(page))Assert.Equal(HttpStatusCode.NotFound,denied.StatusCode);
    }

    [Fact]
    public async Task Signature_POST_rate_limit_has_recoverable_HTML_and_JSON_errors()
    {
        await using var run=await Browser.Create(fixture); await run.Session("signer"); var page=await run.Get();
        for(var i=0;i<20;i++) { using var result=await run.Preview(page,kind:"method"); Assert.Equal(HttpStatusCode.BadRequest,result.StatusCode); }
        using(var limited=await run.Preview(page,kind:"method")) { Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode); Assert.Contains("Return to your signature page",await limited.Content.ReadAsStringAsync()); }
        run.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using var json=await run.Preview(page,kind:"method"); Assert.Equal(HttpStatusCode.TooManyRequests,json.StatusCode); Assert.Contains("adoption has not been confirmed",await json.Content.ReadAsStringAsync());
    }

    internal sealed class Browser : IAsyncDisposable
    {
        public WebApplication App=null!; public HttpClient Client=null!; public Envelope Envelope=null!; public Signer Signer=null!; public VerifiedSigner Identity=null!;
        public string Path=""; public Clock Clock=new(); public TestStorage Storage=null!; private readonly Dictionary<string,string> cookies=[];
        public static async Task<Browser> Create(SqlDatabaseFixture fixture)
        {
            var run=new Browser(); var now=run.Clock.GetUtcNow(); run.Envelope=new Envelope { SenderEmail="sender@example.invalid",Title="Synthetic signature UI - NO AGREEMENT",Status=EnvelopeStatus.Sent,SenderVerifiedAt=now,SentPdfBlob=Guid.NewGuid().ToString("N"),SentPdfSha256=SHA256.HashData(new byte[]{1,2,3}),ExpiresAt=now.AddDays(2) };
            var disclosure=new ElectronicRecordDisclosure(ElectronicRecordDisclosureTests.Policy()).Build(run.Envelope.PublicId,run.Envelope.Title,run.Envelope.SenderEmail);
            run.Envelope.ErsdVersion=disclosure.Version; run.Envelope.ErsdText=disclosure.Text; run.Envelope.ErsdSha256=disclosure.Sha256;
            run.Signer=new Signer { EnvelopeId=run.Envelope.Id,Email="signer@example.invalid",FullName="Synthetic signer",ConsentAt=now,Status=SignerStatus.Viewed };
            await using(var db=fixture.Open()) { db.AddRange(run.Envelope,run.Signer); await db.SaveChangesAsync(); }
            run.Identity=new(run.Envelope.Id,run.Envelope.PublicId,run.Signer.Id,run.Signer.Email,Guid.Parse(run.Envelope.SentPdfBlob),Convert.ToHexStringLower(run.Envelope.SentPdfSha256),Convert.ToHexStringLower(disclosure.Sha256),now.AddHours(2)); run.Path="/sign/"+run.Envelope.PublicId+"/signature";
            var builder=WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName=typeof(SignatureAdoption).Assembly.FullName,EnvironmentName="Development",ContentRootPath=AppContext.BaseDirectory }); builder.Logging.ClearProviders(); builder.WebHost.UseTestServer(); builder.Services.AddRazorPages();
            builder.Services.AddScoped(_=>fixture.Open()); builder.Services.AddSingleton<TimeProvider>(run.Clock); builder.Services.AddQuillSignSender(new ConfigurationBuilder().Build(),builder.Environment); builder.Services.AddQuillSignSignerAccess(new ConfigurationBuilder().Build(),builder.Environment);
            builder.Services.AddScoped<SignatureAdoption>(); builder.Services.AddScoped<SignaturePreviewProtection>();
            builder.Services.AddScoped<SignerFields>(); builder.Services.AddScoped<SignerFieldView>(); builder.Services.AddScoped<SignerPdfAccess>();
            builder.Services.AddScoped<SignerReviewCandidates>(); builder.Services.AddScoped<SignerReviewProtection>(); builder.Services.AddScoped<SignerFinish>();
            builder.Services.AddScoped<SignerCheckpointReads>(); builder.Services.AddScoped<SignerCheckpointState>(); builder.Services.AddScoped<SignerCheckpointBlobs>();
            builder.Services.AddScoped<QuillSign.Work.SignerCheckpointJobs>(); builder.Services.AddScoped<Func<QuillSign.Work.IWorkSignals>>(_=>()=>new SignerReviewCandidateTests.CheckpointSignals());
            builder.Services.AddSingleton(new QuillSign.Documents.SignerPdfRenderer(25*1024*1024,20,200)); builder.Services.AddSignerReviewBrowser();
            builder.Services.AddSingleton(new QuillSign.Documents.DocumentOptions());
            builder.Services.AddSingleton(new QuillSign.Email.EmailOptions());
            builder.Services.AddSingleton(new QuillSign.Work.WorkOptions());
            run.Storage=new(new AzureBlobStore(new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)),1024*1024,true)); builder.Services.AddSingleton<IBlobStore>(run.Storage);
            run.App=builder.Build(); run.App.UseRouting(); run.App.UseRateLimiter(); run.App.UseAuthentication(); run.App.UseAuthorization(); run.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
            run.App.MapGet("/test-session/{kind}",async (Microsoft.AspNetCore.Http.HttpContext context,string kind)=> {
                if(kind=="sender")await context.SignInAsync(EnvelopeStorageAuthorization.SenderScheme,SenderConfiguration.Principal(new(run.Envelope.Id,run.Envelope.PublicId,run.Envelope.SenderEmail)));
                else await context.SignInAsync(SignerAccessConfiguration.Scheme,SignerAccessConfiguration.Principal(run.Identity),SignerAccessConfiguration.Ticket(run.Identity)); return "ok";
            }); await run.App.StartAsync(); run.Client=run.App.GetTestClient(); return run;
        }
        public void Cookies(HttpResponseMessage response) { if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values) { var pair=value.Split(';')[0].Split('=',2); cookies[pair[0]]=pair[1]; } Client.DefaultRequestHeaders.Remove("Cookie"); Client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value))); }
        public async Task Session(string kind) { using var result=await Client.GetAsync("/test-session/"+kind); Cookies(result); }
        public async Task<string> Get() { using var result=await Client.GetAsync(Path); Assert.Equal(HttpStatusCode.OK,result.StatusCode); Cookies(result); return await result.Content.ReadAsStringAsync(); }
        public Task<HttpResponseMessage> Preview(string page,bool csrf=true,string? kind=null)
        {
            var form=new MultipartFormDataContent(); if(csrf)form.Add(new StringContent(Token(page)),"__RequestVerificationToken"); form.Add(new StringContent(kind=="method" ? "999" : "Drawn"),"Method");
            foreach(var name in new[]{"Signature","Initials"}) { if(kind=="missing-file" && name=="Initials")continue; var file=new ByteArrayContent(kind=="oversize" ? new byte[512*1024+1] : kind=="invalid-png" ? new byte[]{1,2,3} : SignatureAdoptionTests.Mark()); file.Headers.ContentType=new(kind=="mime" ? "image/jpeg" : "image/png"); form.Add(file,name,"synthetic.png"); }
            return Client.PostAsync(Path+"?handler=Preview",form);
        }
        public Task<HttpResponseMessage> Adopt(string page,string receipt,bool ack=true,bool csrf=true,string version=SignatureAdoptionStatement.Version)
        { var form=new Dictionary<string,string> { ["Receipt"]=receipt,["Acknowledged"]=ack.ToString(),["StatementVersion"]=version }; if(csrf)form["__RequestVerificationToken"]=Token(page); return Client.PostAsync(Path+"?handler=Adopt",new FormUrlEncodedContent(form)); }
        internal static string Token(string page)=>WebUtility.HtmlDecode(Regex.Match(page,"name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        public async ValueTask DisposeAsync() { Client.Dispose(); await App.DisposeAsync(); foreach(var blob in Storage.Created)await Storage.Inner.DeleteAsync(BlobStorageTests.Sender(blob.EnvelopeId),blob); }
    }
    internal sealed class Clock : TimeProvider { private DateTimeOffset now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()); public override DateTimeOffset GetUtcNow()=>now; public void Advance(TimeSpan value)=>now+=value; }
    internal sealed class TestStorage(IBlobStore inner) : IBlobStore
    { public IBlobStore Inner=>inner; public List<DocumentBlob> Created=[]; public bool FailRead,TamperRead;
        public Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,long length,CancellationToken ct=default) { Created.Add(b); return inner.WriteAsync(p,b,s,length,ct); }
        public async Task<long> CopyToAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,CancellationToken ct=default) { if(FailRead)throw new IOException("Synthetic storage unavailable"); if(TamperRead) { EnvelopeStorageAuthorization.DemandRead(p,b); var bytes=SignatureAdoptionTests.Mark(100); await s.WriteAsync(bytes,ct); return bytes.Length; } return await inner.CopyToAsync(p,b,s,ct); }
        public Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct=default)=>inner.DeleteAsync(p,b,ct); }
}

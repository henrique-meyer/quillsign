using System.Security.Claims;
using System.Text.Json.Nodes;
using System.Net;
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
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using Shared=QuillSign.Tests.DocumentWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SenderDocumentRetentionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(-1)][InlineData(0)][InlineData(1)]
    public async Task Authorized_preview_and_confirmation_observe_the_exact_fixed_cutoff(long ticks)
    {
        await using var run=await Retained.Create(fixture);var before=await run.H.StateAsync();run.Clock.Now=run.Policy.DeleteAfter.AddTicks(ticks);
        if(ticks<0)
        {
            Assert.NotNull(await run.H.WithAsync(w=>w.GetAsync(run.H.Sender,run.H.PublicId,default)));
            await using(var pdf=await run.H.WithAsync(w=>w.ReadAsync(run.H.Sender,run.H.PublicId,before.PdfBlob!,default)))Assert.True(pdf!.Length>0);
            Assert.Equal(before.RowVersion,(await run.H.StateAsync()).RowVersion);Assert.Equal(1,await run.AuditCount());
            Assert.True(await run.H.WithAsync(w=>w.ConfirmAsync(run.H.Sender,run.H.PublicId,before.RowVersion,before.PdfBlob!,true,null,null,default)));
        }
        else
        {
            await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>run.H.WithAsync(w=>w.GetAsync(run.H.Sender,run.H.PublicId,default)));
            await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>run.H.WithAsync(w=>w.ReadAsync(run.H.Sender,run.H.PublicId,before.PdfBlob!,default)));
            await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>run.H.WithAsync(w=>w.ConfirmAsync(run.H.Sender,run.H.PublicId,before.RowVersion,before.PdfBlob!,true,null,null,default)));
            Assert.Equal(0,run.H.Store.Reads);Assert.Equal(before.RowVersion,(await run.H.StateAsync()).RowVersion);Assert.Equal(1,await run.AuditCount());
        }
    }

    [Theory]
    [InlineData("missing")][InlineData("policy")][InlineData("audit")][InlineData("marker")]
    public async Task Missing_or_tampered_enrollment_fails_closed_after_authorization_without_reading_storage(string corruption)
    {
        await using var run=await Retained.Create(fixture);var before=await run.H.StateAsync();
        await using(var db=fixture.Open())
        {
            if(corruption=="missing")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==run.H.Id).ExecuteDeleteAsync();
            else if(corruption=="policy")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==run.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Days,30).SetProperty(x=>x.DeleteAfter,run.Policy.StartedAt.AddDays(30)));
            else
            {
                var audit=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.H.Id);var data=JsonNode.Parse(audit.DataJson)!;data["retentionSha256"]=new string('0',64);audit.DataJson=data.ToJsonString();
                if(corruption=="marker")audit.Hash=AuditHash.Compute(audit);
                await db.AuditEvents.Where(x=>x.EnvelopeId==audit.EnvelopeId && x.Sequence==audit.Sequence).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,audit.DataJson).SetProperty(x=>x.Hash,audit.Hash));
            }
        }
        var wrong=SenderConfiguration.Principal(new(run.H.Id,run.H.PublicId,"other@example.invalid"));
        Assert.Null(await run.H.WithAsync(w=>w.GetAsync(wrong,run.H.PublicId,default)));
        Assert.Null(await run.H.WithAsync(w=>w.ReadAsync(new ClaimsPrincipal(),run.H.PublicId,before.PdfBlob!,default)));
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.H.WithAsync(w=>w.GetAsync(run.H.Sender,run.H.PublicId,default)));
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.H.WithAsync(w=>w.ReadAsync(run.H.Sender,run.H.PublicId,before.PdfBlob!,default)));
        Assert.Equal(0,run.H.Store.Reads);Assert.Equal(before.RowVersion,(await run.H.StateAsync()).RowVersion);
    }

    [Theory]
    [InlineData("cutoff")][InlineData("cancel")][InlineData("corrupt")]
    public async Task Slow_or_failed_storage_never_returns_a_verified_PDF_result(string failure)
    {
        await using var run=await Retained.Create(fixture);var before=await run.H.StateAsync();using var cancel=new CancellationTokenSource();
        if(failure=="cutoff")run.H.Store.AfterRead=()=>run.Clock.Now=run.Policy.DeleteAfter;
        if(failure=="cancel")run.H.Store.AfterRead=cancel.Cancel;
        if(failure=="corrupt")run.H.Store.CorruptRead=true;
        var task=run.H.WithAsync(w=>w.ReadAsync(run.H.Sender,run.H.PublicId,before.PdfBlob!,cancel.Token));
        if(failure=="cutoff")await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>task);
        else if(failure=="cancel")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>task);
        else await Assert.ThrowsAsync<InvalidDataException>(()=>task);
        Assert.Equal(1,run.H.Store.Reads);Assert.Equal(before.RowVersion,(await run.H.StateAsync()).RowVersion);Assert.Equal(1,await run.AuditCount());
    }

    [Fact]
    public async Task A_confirmation_crossing_cutoff_during_audit_rolls_back_its_change()
    {
        await using var run=await Retained.Create(fixture);var before=await run.H.StateAsync();run.H.AuditFailure.AfterInsert=()=>run.Clock.Now=run.Policy.DeleteAfter;
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>run.H.WithAsync(w=>w.ConfirmAsync(run.H.Sender,run.H.PublicId,before.RowVersion,before.PdfBlob!,true,null,null,default)));
        Assert.Equal(before.RowVersion,(await run.H.StateAsync()).RowVersion);Assert.Null((await run.H.StateAsync()).PreviewConfirmedAt);Assert.Equal(1,await run.AuditCount());
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Ordinary_and_historical_unenrolled_uploads_remain_readable_without_backfill(bool demo)
    {
        await using var h=await Shared.CreateAsync(fixture,demo);var clock=new Clock();h.Time=clock;Assert.True(await h.UploadAsync(PdfFixtures.Create()));var before=await h.StateAsync();
        h.Retention.PurgeAfterDays=7;clock.Now=clock.Now.AddDays(30);
        Assert.NotNull(await h.WithAsync(w=>w.GetAsync(h.Sender,h.PublicId,default)));
        await using var pdf=await h.WithAsync(w=>w.ReadAsync(h.Sender,h.PublicId,before.PdfBlob!,default));Assert.NotNull(pdf);
        await using var db=fixture.Open();Assert.False(await db.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==h.Id));Assert.Equal(before.RowVersion,(await h.StateAsync()).RowVersion);
    }

    [Fact]
    public async Task Later_or_unset_configuration_does_not_restore_expired_content()
    {
        await using var run=await Retained.Create(fixture);run.Clock.Now=run.Policy.DeleteAfter;run.H.Retention.PurgeAfterDays=30;
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>run.H.WithAsync(w=>w.GetAsync(run.H.Sender,run.H.PublicId,default)));
        run.H.Retention.PurgeAfterDays=null;await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>run.H.WithAsync(w=>w.GetAsync(run.H.Sender,run.H.PublicId,default)));
    }

    [Theory]
    [InlineData("cutoff")][InlineData("slow")][InlineData("missing")]
    public async Task HTTP_preview_and_PDF_fail_privately_without_returning_expired_or_unverified_content(string failure)
    {
        await using var browser=await BrowserSession.Start(fixture);var before=await browser.run.H.StateAsync();
        using(var session=await browser.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,session.StatusCode);
        string reviewed;
        using(var page=await browser.Get(browser.Path)) {Assert.Equal(HttpStatusCode.OK,page.StatusCode);Assert.True(page.Headers.CacheControl!.NoStore);reviewed=await page.Content.ReadAsStringAsync();Assert.Contains(before.Title!,reviewed);}
        using(var pdf=await browser.Get(browser.PdfPath)) {Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);Assert.Equal("application/pdf",pdf.Content.Headers.ContentType!.MediaType);Assert.True((await pdf.Content.ReadAsByteArrayAsync()).Length>0);}
        if(failure=="cutoff")browser.Expire();
        else if(failure=="slow")browser.run.H.Store.AfterRead=browser.Expire;
        else {await using var db=fixture.Open();await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==before.Id).ExecuteDeleteAsync();}
        // Refresh only the test authentication after advancing its fake clock.
        using(var session=await browser.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,session.StatusCode);
        using(var pdf=await browser.Get(browser.PdfPath))
        {
            Assert.Equal(failure=="missing" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Gone,pdf.StatusCode);
            Assert.True(pdf.Headers.CacheControl!.NoStore);var body=await pdf.Content.ReadAsStringAsync();Assert.DoesNotContain("%PDF",body);Assert.DoesNotContain(before.Title!,body);Assert.DoesNotContain(before.SenderEmail,body);
        }
        using(var session=await browser.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,session.StatusCode);
        using(var page=await browser.Get(browser.Path))
        {
            Assert.Equal(failure=="missing" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Gone,page.StatusCode);
            var body=await page.Content.ReadAsStringAsync();Assert.DoesNotContain("data-pdf-upload",body);Assert.DoesNotContain("data-url=",body);Assert.DoesNotContain(before.SenderEmail,body);
            if(failure!="missing")Assert.Contains("Document unavailable.",body);
        }
        using(var confirm=await browser.Post(browser.Path+"?handler=Confirm",new Dictionary<string,string>{["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(reviewed),["Version"]=Convert.ToBase64String(before.RowVersion),["DocumentId"]=before.PdfBlob!,["PreviewMatches"]="true"}))
            Assert.Equal(failure=="missing" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Gone,confirm.StatusCode);
        Assert.Equal(before.RowVersion,(await browser.run.H.StateAsync()).RowVersion);Assert.Equal(1,await browser.run.AuditCount());
    }

    // Owned test host for both HTTP tests and the real browser flow. No work
    // processor or mail sender is registered. Conversion is opt-in for intake QA.
    public sealed class BrowserSession:IAsyncDisposable
    {
        internal Retained run=null!;private WebApplication app=null!;private HttpClient client=null!;private BlobClient key=null!;private readonly Dictionary<string,string> cookies=[];
        public string Path=>"/draft/"+run.H.PublicId;
        public string PdfPath=>Path+"/document/"+run.Policy.PdfObjectId.ToString("N");
        public DateTimeOffset DeleteAfter=>run.Policy.DeleteAfter;
        public void Expire()=>run.Clock.Now=DeleteAfter;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int? port=null,GotenbergOptions? conversion=null,Action<IServiceCollection>? configure=null)
        {
            var b=new BrowserSession{run=await Retained.Create(fixture)};
            try {
            var name="retention-read-"+Guid.NewGuid().ToString("N");var storage=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;
            using var source=fixture.Open();var connection=source.Database.GetConnectionString();
            var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(DocumentWorkflow).Assembly.FullName,EnvironmentName="Development",ContentRootPath=AppContext.BaseDirectory,
                WebRootPath=port is null ? null : System.IO.Path.GetFullPath("../../../../../src/QuillSign/wwwroot",AppContext.BaseDirectory)});builder.Logging.ClearProviders();
            var outputRoot=System.IO.Path.Combine(AppContext.BaseDirectory,"wwwroot");
            if(port is not null && Directory.Exists(outputRoot))builder.Environment.WebRootFileProvider=new Microsoft.Extensions.FileProviders.CompositeFileProvider(builder.Environment.WebRootFileProvider,new Microsoft.Extensions.FileProviders.PhysicalFileProvider(outputRoot));
            builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?>{["ConnectionStrings:Database"]=connection,["Storage:Provider"]="Azurite",["Storage:ConnectionString"]=storage,["DataProtection:ApplicationName"]=name,["DataProtection:KeyRingBlobName"]=name+".xml"});
            if(port is not null)builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?>{["Sender:RequestsPerWindow"]="1000"});
            builder.Services.AddRazorPages();builder.Services.AddDbContext<QuillSignDbContext>(o=>o.UseSqlServer(connection).AddInterceptors(b.run.H.AuditFailure,b.run.H.CommitFailure));
            builder.Services.AddQuillSignStorage(builder.Configuration,builder.Environment);builder.Services.AddQuillSignSender(builder.Configuration,builder.Environment);
            builder.Services.AddSingleton(new QuillSign.Email.EmailOptions());builder.Services.AddSingleton(new QuillSign.Work.WorkOptions());
            builder.Services.AddQuillSignFieldEditor(builder.Configuration);builder.Services.AddQuillSignDocuments(builder.Configuration);
            builder.Services.AddSingleton<TimeProvider>(b.run.Clock);builder.Services.AddSingleton<IBlobStore>(b.run.H.Store);builder.Services.AddSingleton(b.run.H.Retention);
            if(conversion is not null)builder.Services.AddSingleton(conversion);configure?.Invoke(builder.Services);
            if(port is { } number)builder.WebHost.UseUrls("http://127.0.0.1:"+number);else builder.WebHost.UseTestServer();
            b.app=builder.Build();
            b.app.Use(async(context,next)=>{context.Response.Headers["X-Content-Type-Options"]="nosniff";context.Response.Headers["Referrer-Policy"]="no-referrer";context.Response.Headers["Content-Security-Policy"]="default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self' data: blob:; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
                if(Microsoft.AspNetCore.Http.HttpMethods.IsPost(context.Request.Method) && context.Request.Path.StartsWithSegments("/draft") && context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>() is {IsReadOnly:false} body)body.MaxRequestBodySize=b.app.Services.GetRequiredService<DocumentOptions>().MaximumBytes+65536;
                await next();});
            if(port is not null)b.app.UseStaticFiles();b.app.UseRouting();b.app.UseRateLimiter();b.app.UseAuthentication();b.app.UseAuthorization();b.app.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
            b.app.MapGet("/test-session",async(Microsoft.AspNetCore.Http.HttpContext context)=>{await context.SignInAsync(EnvelopeStorageAuthorization.SenderScheme,b.run.H.Sender,new AuthenticationProperties{ExpiresUtc=b.run.Clock.GetUtcNow().AddHours(2),AllowRefresh=false});return "ok";});
            b.key=new BlobServiceClient(storage,new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)).GetBlobContainerClient("keys").GetBlobClient(name+".xml");
            await b.app.StartAsync();b.client=port is null ? b.app.GetTestClient() : new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){BaseAddress=new Uri("http://127.0.0.1:"+port)};return b;
            } catch {await b.DisposeAsync();throw;}
        }
        internal Task<HttpResponseMessage> Get(string path)=>Request(new HttpRequestMessage(HttpMethod.Get,path));
        internal Task<HttpResponseMessage> Post(string path,Dictionary<string,string> form)=>Request(new HttpRequestMessage(HttpMethod.Post,path){Content=new FormUrlEncodedContent(form)});
        internal Task<HttpResponseMessage> Upload(string page,byte[] bytes,string filename,string mime="application/octet-stream",bool csrf=true,string? version=null,bool extra=false,string? publicId=null,bool json=false,CancellationToken ct=default)
        {
            var form=new MultipartFormDataContent();form.Add(new StringContent(version??SenderSendPageTests.Flow.Value(page,"Version")),"Version");
            if(csrf)form.Add(new StringContent(SignaturePageTests.Browser.Token(page)),"__RequestVerificationToken");
            var file=new ByteArrayContent(bytes);file.Headers.ContentType=new(mime);form.Add(file,"Upload",filename);
            if(extra)form.Add(new ByteArrayContent(bytes),"Other","extra.pdf");
            var request=new HttpRequestMessage(HttpMethod.Post,(publicId is null ? Path : "/draft/"+publicId)+"?handler=Upload"){Content=form};
            if(json)request.Headers.Accept.ParseAdd("application/json");return Request(request,ct);
        }
        private async Task<HttpResponseMessage> Request(HttpRequestMessage request,CancellationToken ct=default)
        {
            client.DefaultRequestHeaders.Remove("Cookie");if(cookies.Count>0)client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value)));
            using(request)
            {
                var response=await client.SendAsync(request,ct);if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values){var pair=value.Split(';')[0].Split('=',2);if(pair[1].Length==0)cookies.Remove(pair[0]);else cookies[pair[0]]=pair[1];}return response;
            }
        }
        public async ValueTask DisposeAsync(){client?.Dispose();if(app is not null)await app.DisposeAsync();if(key is not null)await key.DeleteIfExistsAsync();await run.DisposeAsync();}
    }

    internal sealed class Clock:TimeProvider
    {public DateTimeOffset Now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());public override DateTimeOffset GetUtcNow()=>Now;}
    internal sealed class Retained:IAsyncDisposable
    {
        public Shared H=null!;public Clock Clock=new();public DocumentRetentionSnapshot Policy=null!;private SqlDatabaseFixture fixture=null!;
        public static async Task<Retained> Create(SqlDatabaseFixture fixture)
        {
            var run=new Retained{fixture=fixture,H=await Shared.CreateAsync(fixture,true)};run.H.Time=run.Clock;run.H.Retention.PurgeAfterDays=7;
            Assert.True(await run.H.UploadAsync(PdfFixtures.Create(text:"SYNTHETIC RETENTION - NO AGREEMENT")));
            await using var db=fixture.Open();run.Policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.H.Id);return run;
        }
        public async Task<int> AuditCount(){await using var db=fixture.Open();return await db.AuditEvents.CountAsync(x=>x.EnvelopeId==H.Id);}
        public ValueTask DisposeAsync()=>H.DisposeAsync();
    }
}

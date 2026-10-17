using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using QuillSign.Verification;
using Run=QuillSign.Tests.CompletionSealOutputTests.Run;

namespace QuillSign.Tests;

public sealed class CompletionDownloadTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Live_sender_and_accepted_signer_download_exact_pair_with_private_proofs_and_readonly_bounded_replay()
    {
        await using var f=await Flow.Create(fixture); var initial=await f.Count();
        foreach(var role in new[]{"sender","signer"}) {
            await f.Session(role); var page=await f.Page(); Assert.Contains("Final packet",page); Assert.DoesNotContain("name=\"Value\"",page);
            foreach(var kind in new[]{"executed","certificate"}) {
                using(var missing=await f.Post(page,kind,false))Assert.Equal(HttpStatusCode.BadRequest,missing.StatusCode);
                Assert.Equal(initial,await f.Count());
                using var prepared=await f.Post(page,kind); Assert.Equal(HttpStatusCode.Redirect,prepared.StatusCode);
                var url=prepared.Headers.Location!.OriginalString; Assert.Equal(f.Resource(kind),url); Assert.DoesNotContain("?",url);
                var grant=prepared.Headers.GetValues("Set-Cookie").Single(x=>x.StartsWith("QuillSign.Final."));
                Assert.Contains("httponly",grant); Assert.Contains("samesite=strict",grant); Assert.Contains("path="+f.Resource(""),grant);
                Assert.DoesNotContain(f.Cookies.Single(x=>x.Key.StartsWith("QuillSign.Final.")).Value,page);
                var saved=f.Cookies.ToDictionary(); var count=await f.Count(); Assert.Equal(++initial,count);
                for(var replay=0;replay<2;replay++) {
                    f.Restore(saved); using var pdf=await f.Client.GetAsync(url); f.Take(pdf); Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);
                    Assert.Equal("application/pdf",pdf.Content.Headers.ContentType!.MediaType); Assert.Equal("attachment",pdf.Content.Headers.ContentDisposition!.DispositionType);
                    Assert.Contains(kind,pdf.Content.Headers.ContentDisposition.FileName!); Assert.True(pdf.Headers.CacheControl!.NoStore);
                    Assert.Equal("no-referrer",Assert.Single(pdf.Headers.GetValues("Referrer-Policy"))); Assert.Equal("nosniff",Assert.Single(pdf.Headers.GetValues("X-Content-Type-Options")));
                    Assert.Equal(kind=="executed" ? f.Published.ExecutedBytes : f.Published.CertificateBytes,await pdf.Content.ReadAsByteArrayAsync());
                    Assert.Equal(count,await f.Count()); Assert.DoesNotContain(f.Cookies.Keys,x=>x.StartsWith("QuillSign.Final."));
                }
                f.Restore(saved); f.Clock.Advance(TimeSpan.FromMinutes(2));
                using(var expired=await f.Client.GetAsync(url))Assert.Equal(HttpStatusCode.NotFound,expired.StatusCode);
                f.Set(saved.Keys.Single(x=>x.StartsWith("QuillSign.Final.")),null);
            }
        }
        await using var db=fixture.Open(); var events=await db.AuditEvents.Where(x=>x.EnvelopeId==f.Id && x.Event=="final_download_prepared").ToArrayAsync();
        Assert.Equal(4,events.Length); Assert.All(events,x=> {Assert.Contains("receipt or saving is not confirmed",x.DataJson); Assert.DoesNotContain("cookie",x.DataJson); Assert.DoesNotContain(f.Run.Signing.LastReviewReceipt,x.DataJson);});
        var oldTime=f.Published.CompletedAt; Assert.Equal(oldTime,(await f.Run.Signing.Refresh()).CompletedAt); Assert.Equal(2,f.Run.Seal.Requests); Assert.Equal(2,f.Store.Writes);
    }

    [Fact]
    public async Task Grants_cannot_cross_cookie_sessions_parties_envelopes_file_kinds_or_acceptance_proofs_and_GET_never_prepares()
    {
        await using var f=await Flow.Create(fixture); f.PaddedSender=true; await f.Session("sender"); Assert.StartsWith("chunks-",f.Cookies["QuillSign.Sender"]); var page=await f.Page(); var before=await f.Count();
        using(var unprepared=await f.Client.GetAsync(f.Resource("executed")))Assert.Equal(HttpStatusCode.NotFound,unprepared.StatusCode); Assert.Equal(before,await f.Count());
        using(var badKind=await f.Post(page,"source"))Assert.Equal(HttpStatusCode.NotFound,badKind.StatusCode); Assert.Equal(before,await f.Count());
        using(var prepared=await f.Post(page,"executed"))Assert.Equal(HttpStatusCode.Redirect,prepared.StatusCode);
        var saved=f.Cookies.ToDictionary(); var url=f.Resource("executed"); var reads=f.Store.Reads;
        foreach(var path in new[]{f.Resource("certificate"),url.Replace(f.PublicId,Guid.NewGuid().ToString("N")),url.Replace("/draft/","/sign/")}) {
            using var denied=await f.Client.GetAsync(path); Assert.Equal(HttpStatusCode.NotFound,denied.StatusCode);
        }
        var senderGrant=saved.Single(x=>x.Key.StartsWith("QuillSign.Final.Sender."));
        f.Set(senderGrant.Key.Replace("Executed","Certificate"),senderGrant.Value);
        using(var renamedKind=await f.Client.GetAsync(f.Resource("certificate")))Assert.Equal(HttpStatusCode.NotFound,renamedKind.StatusCode);
        f.Restore(saved);
        f.Set("QuillSign.Sender",null); using(var none=await f.Client.GetAsync(url))Assert.Equal(HttpStatusCode.NotFound,none.StatusCode);
        f.Restore(saved); f.Clock.Advance(TimeSpan.FromSeconds(1)); await f.Session("sender");
        using(var newSession=await f.Client.GetAsync(url))Assert.Equal(HttpStatusCode.NotFound,newSession.StatusCode);
        Assert.Equal(reads,f.Store.Reads);
        await f.Session("signer"); f.Set(senderGrant.Key.Replace("Sender","Signer"),senderGrant.Value);
        using(var renamedParty=await f.Client.GetAsync(f.Resource("executed")))Assert.Equal(HttpStatusCode.NotFound,renamedParty.StatusCode);
        f.Set(senderGrant.Key.Replace("Sender","Signer"),null); page=await f.Page(); using(var prepare=await f.Post(page,"executed"))Assert.Equal(HttpStatusCode.Redirect,prepare.StatusCode);
        var accepted=f.Cookies.ToDictionary();
        foreach(var receipt in new string?[]{null,"forged"}) {f.Set(SignerReviewBrowser.AcceptedCookie,receipt); using var denied=await f.Client.GetAsync(f.Resource("executed")); Assert.Equal(HttpStatusCode.NotFound,denied.StatusCode);}
        f.Restore(accepted); f.Set("QuillSign.Signer",null); using(var noSession=await f.Client.GetAsync(f.Resource("executed")))Assert.Equal(HttpStatusCode.NotFound,noSession.StatusCode);
        f.Restore(accepted); var grant=accepted.Keys.Single(x=>x.StartsWith("QuillSign.Final.Signer")); f.Set(grant,"forged");
        using(var forged=await f.Client.GetAsync(f.Resource("executed")))Assert.Equal(HttpStatusCode.NotFound,forged.StatusCode);
        f.Restore(accepted); f.Clock.Advance(TimeSpan.FromHours(3)); using(var expired=await f.Client.GetAsync(f.Resource("executed")))Assert.Equal(HttpStatusCode.NotFound,expired.StatusCode);
        Assert.Equal(before+2,await f.Count()); Assert.Equal(2,f.Store.Writes);
    }

    [Theory]
    [InlineData("missing")][InlineData("corrupt")][InlineData("source")][InlineData("publication")]
    public async Task Changed_or_unavailable_saved_packet_never_serves_or_regenerates_and_storage_retry_is_explicit(string fault)
    {
        await using var f=await Flow.Create(fixture); await f.Session("sender"); var page=await f.Page();
        using(var prepare=await f.Post(page,"executed"))Assert.Equal(HttpStatusCode.Redirect,prepare.StatusCode);
        var count=await f.Count(); var writes=f.Store.Writes; var seals=f.Run.Seal.Requests;
        if(fault is "missing" or "corrupt")f.Store.Fault=fault;
        else {await using var db=fixture.Open(); if(fault=="source")await db.Envelopes.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Title,"Changed synthetic source"));
            else await db.CompletionPublicationResults.Where(x=>x.EnvelopeId==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CompletedAt,f.Published.CompletedAt.AddSeconds(-1)));}
        using(var rejected=await f.Client.GetAsync(f.Resource("executed"))) {
            Assert.Equal(HttpStatusCode.ServiceUnavailable,rejected.StatusCode); var body=await rejected.Content.ReadAsStringAsync();
            Assert.Contains("Return to your private confirmation page",body); Assert.Contains("href=\""+f.PagePath+"\"",body);
        }
        using(var rejected=await f.Post(page,"executed")) {
            Assert.Equal(HttpStatusCode.ServiceUnavailable,rejected.StatusCode);
            if(fault is "missing" or "corrupt") {var body=await rejected.Content.ReadAsStringAsync(); Assert.Contains("Final packet",body); Assert.Contains("href=\""+f.PagePath+"\"",body);}
        }
        Assert.Equal(count,await f.Count()); Assert.Equal(writes,f.Store.Writes); Assert.Equal(seals,f.Run.Seal.Requests);
        if(fault is "missing" or "corrupt") {
            f.Store.Fault=null; using var retry=await f.Post(page,"executed"); Assert.Equal(HttpStatusCode.Redirect,retry.StatusCode);
            using var pdf=await f.Client.GetAsync(f.Resource("executed")); Assert.Equal(f.Published.ExecutedBytes,await pdf.Content.ReadAsByteArrayAsync());
        }
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Expiry_during_final_storage_IO_rejects_preparation_and_download_without_audit_or_files(bool reading)
    {
        await using var f=await Flow.Create(fixture); await f.Session("sender"); var page=await f.Page();
        if(reading)using(var prepared=await f.Post(page,"executed"))Assert.Equal(HttpStatusCode.Redirect,prepared.StatusCode);
        var count=await f.Count(); var changed=false;
        f.Store.AfterRead=()=> {if(!changed) {changed=true; f.Clock.Advance(reading ? TimeSpan.FromMinutes(3) : TimeSpan.FromHours(2));} return Task.CompletedTask;};
        using var response=reading ? await f.Client.GetAsync(f.Resource("executed")) : await f.Post(page,"executed");
        Assert.Contains(response.StatusCode,new[]{HttpStatusCode.NotFound,HttpStatusCode.ServiceUnavailable}); Assert.True(changed); Assert.Equal(count,await f.Count()); Assert.Equal(2,f.Store.Writes);
    }

    [Theory]
    [InlineData("audit")][InlineData("lost-commit")][InlineData("uncertain-commit")]
    public async Task Audit_and_commit_failures_issue_no_grant_and_explicit_retry_preserves_the_published_pair(string failure)
    {
        await using var f=await Flow.Create(fixture); await f.Session("sender"); var page=await f.Page();
        f.Faults.Event="final_download_prepared"; f.Faults.RejectAudit=failure=="audit"; f.Faults.LoseCommit=failure=="lost-commit"; f.Faults.RejectCommit=failure=="uncertain-commit";
        using(var failed=await f.Post(page,"certificate")) {
            Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode);
            Assert.False(failed.Headers.TryGetValues("Set-Cookie",out var values) && values.Any(x=>x.StartsWith("QuillSign.Final.")));
        }
        Assert.Equal(failure=="lost-commit" ? 1 : 0,await f.Count()); f.Faults.RejectAudit=false; f.Faults.Event="";
        using(var retry=await f.Post(page,"certificate"))Assert.Equal(HttpStatusCode.Redirect,retry.StatusCode);
        using var pdf=await f.Client.GetAsync(f.Resource("certificate")); Assert.Equal(HttpStatusCode.OK,pdf.StatusCode); Assert.Equal(f.Published.CertificateBytes,await pdf.Content.ReadAsByteArrayAsync());
        Assert.Equal(2,f.Store.Writes); Assert.Equal(2,f.Run.Seal.Requests);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Concurrent_frozen_source_changes_or_voiding_during_IO_cannot_issue_a_download_grant(bool voided)
    {
        await using var f=await Flow.Create(fixture); await f.Session("sender"); var page=await f.Page(); var changed=false;
        f.Store.AfterRead=async ()=> {
            if(changed)return; changed=true; await using var db=fixture.Open();
            if(voided)await db.Envelopes.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            else await db.Envelopes.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Title,"Concurrent synthetic change"));
        };
        using var failed=await f.Post(page,"executed"); Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode);
        Assert.True(changed); Assert.Equal(0,await f.Count()); Assert.Equal(2,f.Store.Writes); Assert.Equal(2,f.Run.Seal.Requests);
    }

    [Fact]
    public async Task Readonly_final_GETs_have_private_rate_limit_errors_without_SQL_or_proof_creation()
    {
        await using var f=await Flow.Create(fixture); f.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json"); var before=await f.Count(); var reads=f.Store.Reads;
        for(var i=0;i<120;i++) {using var response=await f.Client.GetAsync(f.Resource("executed")); Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);}
        using var limited=await f.Client.GetAsync(f.Resource("executed")); Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode); Assert.True(limited.Headers.CacheControl!.NoStore);
        Assert.Contains("preparing a new download",await limited.Content.ReadAsStringAsync()); Assert.Equal(before,await f.Count()); Assert.Equal(reads,f.Store.Reads);
    }

    [Fact]
    public async Task A_completed_source_conflict_after_IO_returns_a_controlled_private_error_without_a_grant()
    {
        await using var f=await Flow.Create(fixture); await f.Session("sender"); var page=await f.Page(); var changed=false;
        f.Store.AfterRead=async ()=> {if(changed)return;changed=true;await using var db=fixture.Open();await db.Signers.Where(x=>x.EnvelopeId==f.Id && x.Order==2)
            .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Viewed));};
        using var response=await f.Post(page,"executed"); Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        var body=await response.Content.ReadAsStringAsync(); Assert.Contains("could not be verified",body); Assert.DoesNotContain("Stack Trace",body);
        Assert.False(response.Headers.TryGetValues("Set-Cookie",out var values) && values.Any(x=>x.StartsWith("QuillSign.Final.")));
        Assert.True(changed); Assert.Equal(0,await f.Count()); Assert.Equal(2,f.Store.Writes); Assert.Equal(2,f.Run.Seal.Requests);
    }

    internal sealed class Flow : IAsyncDisposable
    {
        public Run Run=null!; public WebApplication App=null!; public HttpClient Client=null!; public FinalStore Store=null!; public PublishedCompletion Published=null!;
        public Dictionary<string,string> Cookies=[]; public string Role="sender"; private SqlDatabaseFixture fixture=null!;
        public CompletionSealOutputTests.Faults Faults=new();
        public bool PaddedSender,CompletionNotifications;
        public SendDraftWorkflowTests.Clock Clock=>Run.Signing.H.Clock; public Guid Id=>Run.Signing.Envelope.Id; public string PublicId=>Run.Signing.Envelope.PublicId;
        public string PagePath=>"/"+(Role=="sender" ? "draft/" : "sign/")+PublicId+(Role=="sender" ? "/sent" : "/confirmed");
        public string Resource(string kind)=>"/"+(Role=="sender" ? "draft/" : "sign/")+PublicId+"/final"+(kind.Length==0 ? "" : "/"+kind);
        public static async Task<Flow> Create(SqlDatabaseFixture fixture,bool completionReaders=false,bool chunkedReader=false,bool completionNotifications=false,bool publish=true,bool senderAlsoSigns=false,bool verificationBrowser=false)
        {
            var f=new Flow {fixture=fixture,Run=await Run.Create(fixture,senderAlsoSigns:senderAlsoSigns),CompletionNotifications=completionNotifications}; f.Store=new(f.Clock); _=await f.Run.Prepare();
            await using var db=fixture.Open(); if(publish)f.Published=(await f.Publication(db).PublishAsync(f.Id))!;
            var connection=db.Database.GetConnectionString();
            var builder=WebApplication.CreateBuilder(new WebApplicationOptions {ApplicationName=typeof(CompletionDownloads).Assembly.FullName,EnvironmentName="Development",ContentRootPath=AppContext.BaseDirectory});
            builder.Logging.ClearProviders(); builder.WebHost.UseTestServer(); builder.Services.AddRazorPages();
            builder.Services.AddDbContext<QuillSignDbContext>(o=>o.UseSqlServer(connection).AddInterceptors(f.Faults));
            builder.Services.AddQuillSignEmail(builder.Configuration,builder.Environment); builder.Services.AddQuillSignWork(builder.Configuration,builder.Environment); builder.Services.AddSingleton<TimeProvider>(f.Clock);
            builder.Services.AddSingleton(f.Run.Signing.H.App.Services.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>()); builder.Services.AddSingleton<IBlobStore>(f.Run.Storage); builder.Services.AddSingleton(new DocumentOptions());
            builder.Services.AddQuillSignSender(builder.Configuration,builder.Environment); builder.Services.AddQuillSignSignerAccess(builder.Configuration,builder.Environment);
            builder.Services.AddScoped<SignerCheckpointReads>(); builder.Services.AddScoped<SignerReviewProtection>(); builder.Services.AddSignerReviewBrowser(); builder.Services.AddScoped<SenderSentStatus>();
            builder.Services.AddCompletionDownloads(); builder.Services.AddScoped<CompletionEvidenceCollector>(sp=>f.Run.Collector(sp.GetRequiredService<QuillSignDbContext>()));
            if(completionReaders) {builder.Services.AddCompletionAccess(builder.Configuration);builder.Services.AddCompletionReaderBrowser(builder.Environment);}
            if(chunkedReader)builder.Services.Configure<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>(CompletionAccessProtection.Scheme,
                o=> {o.Cookie.Name="QuillSign.CustomReader";o.CookieManager=new Microsoft.AspNetCore.Authentication.Cookies.ChunkingCookieManager {ChunkSize=900};});
            if(completionNotifications)builder.Services.AddSingleton<IWorkSignals>(f.Run.Signing.H.Signals);
            builder.Services.AddScoped<CompletionPublication>(sp=>f.Publication(sp.GetRequiredService<QuillSignDbContext>()));
            if(verificationBrowser)builder.Services.AddPdfVerificationBrowser(builder.Configuration);
            f.App=builder.Build();
            if(completionNotifications) {
                f.App.Services.GetRequiredService<WorkOptions>().Enabled=true;
                var email=f.App.Services.GetRequiredService<EmailOptions>();email.Enabled=true;email.Provider="Smtp";email.FromEmail="noreply@example.invalid";email.BaseUrl="https://example.invalid";
                email.Smtp=new() {Host="127.0.0.1",Port=int.Parse(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_SMTP_PORT")!),UseStartTls=false};
            }
            f.App.UseRouting(); f.App.UseRateLimiter();if(verificationBrowser)f.App.UseMiddleware<VerificationUploadBoundary>(); f.App.UseAuthentication(); f.App.UseAuthorization(); f.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
            f.App.MapGet("/fixture/{role}",async (HttpContext http,string role,SignerReviewBrowser browser)=> {
                if(role=="sender") {
                    var sender=f.Run.Signing.Sender.Clone(); if(f.PaddedSender)((ClaimsIdentity)sender.Identity!).AddClaim(new("synthetic-padding",new string('x',6000)));
                    await http.SignInAsync(EnvelopeStorageAuthorization.SenderScheme,sender,new AuthenticationProperties {ExpiresUtc=f.Clock.GetUtcNow().AddHours(1)});
                }
                else {var identity=SignerAccessConfiguration.ReadIdentity(f.Run.Signing.LastSigner,f.Clock.GetUtcNow())!; await http.SignInAsync(SignerAccessConfiguration.Scheme,f.Run.Signing.LastSigner,SignerAccessConfiguration.Ticket(identity));
                    browser.Put(http,SignerReviewBrowser.AcceptedCookie,f.Run.Signing.LastReviewReceipt,identity);} return "Synthetic fixture";
            });
            await f.App.StartAsync(); f.Client=f.App.GetTestClient(); return f;
        }
        internal CompletionPublication Publication(QuillSignDbContext db)=>new(db,Run.Candidates(db),Run.Service(db),Run.Collector(db),Store,new(db,Clock),Clock,
            new() {DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},Run.Seal.App.Environment,notifications:CompletionNotifications ? ()=>new(db,new(db,Run.Collector(db),()=>Publication(db),Clock),
                new(Run.Signing.H.App.Services.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>()),()=>Run.Signing.H.Signals,new() {Enabled=true},new(db,Clock),Clock) : null);
        public async Task<int> Count() {await using var db=fixture.Open(); return await db.AuditEvents.CountAsync(x=>x.EnvelopeId==Id && x.Event=="final_download_prepared");}
        public async Task Session(string role) {Role=role; using var response=await Client.GetAsync("/fixture/"+role); Take(response); Assert.Equal(HttpStatusCode.OK,response.StatusCode);}
        public async Task<string> Page() {using var response=await Client.GetAsync(PagePath); Take(response); var body=await response.Content.ReadAsStringAsync(); Assert.True(response.StatusCode==HttpStatusCode.OK,$"{response.StatusCode}: {body.Split('\n')[0]}"); return body;}
        public async Task<HttpResponseMessage> Post(string page,string kind,bool csrf=true) {
            var values=new Dictionary<string,string> {{"kind",kind}}; if(csrf)values["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page);
            var result=await Client.PostAsync(PagePath+"?handler=Download",new FormUrlEncodedContent(values)); Take(result); return result;
        }
        public void Take(HttpResponseMessage response) {if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values) {var pair=value.Split(';')[0].Split('=',2); Set(pair[0],pair[1]);}}
        public void Restore(Dictionary<string,string> cookies) {Cookies=cookies.ToDictionary(); Set("unused",null);}
        public void Set(string name,string? value) {if(string.IsNullOrEmpty(value))Cookies.Remove(name); else Cookies[name]=value; Client.DefaultRequestHeaders.Remove("Cookie"); if(Cookies.Count>0)Client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",Cookies.Select(x=>x.Key+"="+x.Value)));}
        public async ValueTask DisposeAsync() {Client.Dispose(); await App.DisposeAsync(); await Run.DisposeAsync();}
    }
    internal sealed class FinalStore(TimeProvider time) : ICompletionFinalStore
    {
        private readonly Dictionary<FinalDocument,byte[]> files=[]; private readonly Dictionary<FinalDocument,FinalStoredDocument> records=[]; public int Writes,Reads; public string? Fault; public Func<Task>? AfterRead;
        public async Task<FinalStoredDocument> WriteAsync(ClaimsPrincipal p,FinalDocument target,Stream source,long length,byte[] hash,DateTimeOffset? until,CancellationToken ct=default) {
            Demand("DemandWrite",p,target,length,hash,until); using var bytes=new MemoryStream(); await source.CopyToAsync(bytes,ct);
            if(records.TryGetValue(target,out var existing)) {Assert.Equal(files[target],bytes.ToArray());Assert.Equal(existing.Length,length);Assert.Equal(existing.Sha256,hash);return existing;}
            Writes++;files.Add(target,bytes.ToArray());var record=new FinalStoredDocument(target,length,hash,"synthetic-version","synthetic-etag",FinalProtection.DevelopmentWriteOnce,null,time.GetUtcNow());records.Add(target,record);return record;
        }
        public async Task ReadAsync(ClaimsPrincipal p,FinalStoredDocument stored,Stream output,CancellationToken ct=default) {
            Demand("DemandRead",p,stored); Reads++; if(Fault=="missing")throw new IOException("Synthetic missing final file"); var bytes=files[stored.Document].ToArray();
            if(Fault=="corrupt")bytes[^1]^=1; await output.WriteAsync(bytes,ct); if(AfterRead is not null)await AfterRead();
        }
        private static void Demand(string method,params object?[] args) {try {typeof(IBlobStore).Assembly.GetType("QuillSign.Storage.CompletionFinalCapability",true)!.GetMethod(method,BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,args);}
            catch(TargetInvocationException e) {System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException!).Throw();}}
    }
}

using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using QuillSign.Completion;
using QuillSign.Sender;

namespace QuillSign.Tests;

public sealed class CompletionReaderEntryTests
{
    [Fact]
    public async Task Scanner_GET_and_explicit_pending_preparation_need_no_SQL_or_completion_services_and_do_not_echo_codes()
    {
        await using var f=await Entry.Create();var code=WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));var page=await f.Get("/complete/access");
        foreach(var suffix in new[]{"?token="+code,"?handler=Redeem&code="+code}) {
            using var scanner=await f.Client.GetAsync("/complete/access"+suffix);Assert.Equal(HttpStatusCode.OK,scanner.StatusCode);Assert.DoesNotContain(code,await scanner.Content.ReadAsStringAsync());
            Assert.DoesNotContain(scanner.Headers.TryGetValues("Set-Cookie",out var values) ? values : [],x=>x.StartsWith("QuillSign.CompletionReader="));
        }
        using(var missing=await f.Post(page,"Begin",new() {{"code",code}},false))Assert.Equal(HttpStatusCode.BadRequest,missing.StatusCode);
        using(var begin=await f.Post(page,"Begin",new() {{"code",code}})) {
            Assert.Equal(HttpStatusCode.Redirect,begin.StatusCode);var cookie=begin.Headers.GetValues("Set-Cookie").Single(x=>x.StartsWith(CompletionReaderBrowser.PendingCookie+"="));
            Assert.Contains("httponly",cookie);Assert.Contains("samesite=strict",cookie);Assert.Contains("path=/complete/access",cookie);Assert.DoesNotContain(code,cookie);
        }
        page=await f.Get("/complete/access");Assert.Contains("Open records</button>",page);Assert.DoesNotContain(code,page);
        var nonce=CompletionReaderPageTests.Nonce(page);Assert.Equal(32,nonce.Length);f.Clock.Advance(TimeSpan.FromMinutes(10));
        using(var expired=await f.Post(page,"Redeem",new() {{"nonce",nonce}}))Assert.Equal(HttpStatusCode.Conflict,expired.StatusCode);
        const string invalid="<script>private-invalid-code</script>";
        using(var bad=await f.Post(page,"Begin",new() {{"code",invalid}})) {Assert.Equal(HttpStatusCode.BadRequest,bad.StatusCode);Assert.DoesNotContain("private-invalid-code",await bad.Content.ReadAsStringAsync());}
        using(var privatePage=await f.Client.GetAsync("/complete/"+Guid.NewGuid().ToString("N")))Assert.Equal(HttpStatusCode.NotFound,privatePage.StatusCode);
        using(var health=await f.Client.GetAsync("/health"))Assert.Equal("{\"status\":\"ok\"}",await health.Content.ReadAsStringAsync());
    }
    [Fact]
    public async Task Entry_rate_limits_are_private_and_do_not_resolve_SQL_or_return_transport()
    {
        await using var f=await Entry.Create(2);var page=await f.Get("/complete/access");var code=WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        for(var i=0;i<2;i++)using(await f.Post(page,"Begin",new() {{"code",code}})) {}
        using var limited=await f.Post(page,"Begin",new() {{"code",code}});Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode);Assert.True(limited.Headers.CacheControl!.NoStore);
        Assert.Equal("no-referrer",Assert.Single(limited.Headers.GetValues("Referrer-Policy")));Assert.DoesNotContain(code,await limited.Content.ReadAsStringAsync());
    }
    private sealed class Entry : IAsyncDisposable
    {
        public WebApplication App=null!;public HttpClient Client=null!;public SignerFieldTests.Clock Clock=new();private readonly Dictionary<string,string> cookies=[];
        public static async Task<Entry> Create(int limit=100) {
            var f=new Entry();var builder=WebApplication.CreateBuilder(new WebApplicationOptions {ApplicationName=typeof(CompletionReaderBrowser).Assembly.FullName,EnvironmentName="Development",ContentRootPath=AppContext.BaseDirectory});
            builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> {{"Sender:RequestsPerWindow",limit.ToString()}});
            builder.Logging.ClearProviders();builder.WebHost.UseTestServer();builder.Services.AddRazorPages();builder.Services.AddSingleton<TimeProvider>(f.Clock);
            builder.Services.AddQuillSignSender(builder.Configuration,builder.Environment);builder.Services.AddCompletionReaderBrowser(builder.Environment);builder.Services.AddCompletionDownloads();
            builder.Services.RemoveAll<SenderAvailability>();builder.Services.RemoveAll<SenderWorkflow>();builder.Services.RemoveAll<QuillSign.Data.AuditWriter>();builder.Services.RemoveAll<CompletionDownloads>();
            // Deliberately no DbContext, CompletionAccess or publication registration.
            f.App=builder.Build();f.App.UseRouting();f.App.UseRateLimiter();f.App.UseAuthentication();f.App.UseAuthorization();f.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
            f.App.MapGet("/health",()=>Microsoft.AspNetCore.Http.Results.Json(new {status="ok"}));await f.App.StartAsync();f.Client=f.App.GetTestClient();return f;
        }
        public async Task<string> Get(string path) {using var r=await Client.GetAsync(path);Take(r);Assert.Equal(HttpStatusCode.OK,r.StatusCode);return await r.Content.ReadAsStringAsync();}
        public async Task<HttpResponseMessage> Post(string page,string handler,Dictionary<string,string> body,bool csrf=true) {
            if(csrf)body["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page);var r=await Client.PostAsync("/complete/access?handler="+handler,new FormUrlEncodedContent(body));Take(r);return r;
        }
        private void Take(HttpResponseMessage r) {
            if(r.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values) {var pair=value.Split(';')[0].Split('=',2);if(pair[1].Length==0)cookies.Remove(pair[0]);else cookies[pair[0]]=pair[1];}
            Client.DefaultRequestHeaders.Remove("Cookie");Client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value)));
        }
        public async ValueTask DisposeAsync() {Client.Dispose();await App.DisposeAsync();}
    }
}

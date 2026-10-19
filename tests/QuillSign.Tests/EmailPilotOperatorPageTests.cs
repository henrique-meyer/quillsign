using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotOperatorPageTests
{
    private const string Capability="1234567890123456789012345678901234567890123";
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Anonymous_GET_and_invalid_unlock_never_resolve_SQL_provider_or_private_backend(bool enabled)
    {
        await using var h=await Host.Create(enabled);
        using var get=await h.Client.GetAsync("/operator/pilot?Capability="+Capability);
        Assert.Equal(enabled?HttpStatusCode.OK:HttpStatusCode.NotFound,get.StatusCode);Private(get);
        var html=await get.Content.ReadAsStringAsync();Assert.DoesNotContain(Capability,html);
        Assert.DoesNotContain("googletagmanager",html);Assert.DoesNotContain("property=\"og:",html);Assert.DoesNotContain("rel=\"canonical\"",html);
        if(enabled){h.Take(get);using var wrong=await h.Post(new(){["Capability"]=new string('x',43)},"Unlock");Assert.Equal(HttpStatusCode.Forbidden,wrong.StatusCode);Private(wrong);Assert.DoesNotContain(new string('x',43),await wrong.Content.ReadAsStringAsync());}
        Assert.Equal(0,h.Backends);
        Assert.DoesNotContain(h.Keys.Purposes,x=>x.StartsWith("QuillSign.Pilot",StringComparison.Ordinal));
    }
    [Fact]
    public async Task Capability_is_body_only_CSRF_required_and_success_redirect_has_no_secret_or_state()
    {
        await using var h=await Host.Create();
        using(var query=await h.Post(new(),"Unlock&Capability="+Capability))Assert.Equal(HttpStatusCode.Forbidden,query.StatusCode);
        using(var noCsrf=await h.Post(new(){["Capability"]=Capability},"Unlock",false)){Assert.Equal(HttpStatusCode.BadRequest,noCsrf.StatusCode);Private(noCsrf);}
        using(var ok=await h.Post(new(){["Capability"]=Capability},"Unlock")){
            Assert.Equal(HttpStatusCode.Redirect,ok.StatusCode);Assert.Equal("/operator/pilot",ok.Headers.Location?.OriginalString);Private(ok);
            Assert.DoesNotContain(Capability,string.Join(";",ok.Headers.GetValues("Set-Cookie")));
        }
        Assert.Equal(0,h.Backends);
        using var status=await h.Client.GetAsync("/operator/pilot");Assert.Equal(HttpStatusCode.ServiceUnavailable,status.StatusCode);Private(status);
        Assert.Contains("Start or recover two-signer completion",await status.Content.ReadAsStringAsync(),StringComparison.OrdinalIgnoreCase);
    }
    [Fact]
    public async Task Missing_operator_cookie_rejects_each_fixed_action_before_backend_and_private_CSRF_failure_is_inert()
    {
        await using var h=await Host.Create();
        foreach(var action in new[]{"Envelope","Lookup","Simulator"}){
            using var result=await h.Post(new(){["scenario"]="Completion",["kind"]="Success"},action);
            Assert.Equal(HttpStatusCode.Forbidden,result.StatusCode);Private(result);
        }
        using var csrf=await h.Post(new(),"Envelope",false);Assert.Equal(HttpStatusCode.BadRequest,csrf.StatusCode);Private(csrf);Assert.Equal(0,h.Backends);
    }
    [Fact]
    public async Task Operator_rate_partition_rejects_before_backend_and_keeps_private_headers()
    {
        await using var h=await Host.Create(limit:1);
        using(var first=await h.Post(new(){["Capability"]="invalid"},"Unlock"))Assert.Equal(HttpStatusCode.Forbidden,first.StatusCode);
        using var second=await h.Post(new(){["Capability"]=Capability},"Unlock");Assert.Equal(HttpStatusCode.TooManyRequests,second.StatusCode);Private(second);
        Assert.Contains("check saved status",await second.Content.ReadAsStringAsync());Assert.Equal(0,h.Backends);
    }
    [Fact]
    public async Task Disable_or_rotation_revokes_existing_operator_cookie_before_backend_resolution()
    {
        await using var h=await Host.Create();using(var unlock=await h.Post(new(){["Capability"]=Capability},"Unlock"))Assert.Equal(HttpStatusCode.Redirect,unlock.StatusCode);
        h.App.Services.GetRequiredService<EmailPilotAdmissionOptions>().CapabilitySha256=new string('a',64);
        using var action=await h.Post(new(){["scenario"]="Completion"},"Envelope");Assert.Equal(HttpStatusCode.Forbidden,action.StatusCode);Private(action);Assert.Equal(0,h.Backends);
    }
    private static void Private(HttpResponseMessage response)
    {Assert.Contains("no-store",response.Headers.CacheControl?.ToString());Assert.Equal("no-referrer",Assert.Single(response.Headers.GetValues("Referrer-Policy")));Assert.Contains("noindex",Assert.Single(response.Headers.GetValues("X-Robots-Tag")));}
    private sealed class Host:IAsyncDisposable
    {
        internal WebApplication App=null!;internal HttpClient Client=null!;internal int Backends;internal readonly Keys Keys=new();private string csrf="";private readonly Dictionary<string,string> cookies=[];
        internal static async Task<Host> Create(bool enabled=true,int limit=20)
        {
            var h=new Host();var b=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(EmailPilotOptions).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
            b.Logging.ClearProviders();b.WebHost.UseTestServer();
            // This boundary host deliberately has no database/worker backends.
            b.Host.UseDefaultServiceProvider(o=>{o.ValidateScopes=true;o.ValidateOnBuild=false;});
            b.Configuration.AddInMemoryCollection(new Dictionary<string,string?>{
                ["EmailPilot:Enabled"]=enabled.ToString(),["EmailPilot:RunId"]=Guid.NewGuid().ToString("N"),
                ["EmailPilot:Mailboxes:Sender"]="sender@example.invalid",["EmailPilot:Mailboxes:FirstSigner"]="first@example.invalid",["EmailPilot:Mailboxes:SecondSigner"]="second@example.invalid",["EmailPilot:Mailboxes:Recipient"]="recipient@example.invalid",
                ["EmailPilot:Admission:CapabilitySha256"]=Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(Capability))),["Sender:RequestsPerWindow"]=limit.ToString()});
            b.Services.AddRazorPages();b.Services.AddQuillSignDatabase(b.Configuration);b.Services.AddQuillSignEmail(b.Configuration,b.Environment);
            b.Services.AddQuillSignWork(b.Configuration,b.Environment,registerHandlers:false);b.Services.AddQuillSignSender(b.Configuration,b.Environment);
            b.Services.AddRestrictedEmailPilotRuntime(b.Configuration);b.Services.AddSingleton<IDataProtectionProvider>(h.Keys);
            b.Services.AddScoped<Func<EmailPilotOperator>>(_=>()=>{h.Backends++;throw new InvalidOperationException("Synthetic backend is deliberately absent.");});
            h.App=b.Build();h.App.Services.GetRequiredService<WorkOptions>().Enabled=true;
            h.App.Use((http,next)=>{http.Connection.RemoteIpAddress=IPAddress.Loopback;SenderConfiguration.PrivateStatusHeaders(http);return next();});
            h.App.UseRouting();h.App.UseRateLimiter();h.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
            await h.App.StartAsync();h.Client=h.App.GetTestClient();h.Client.BaseAddress=new("http://localhost");return h;
        }
        internal void Take(HttpResponseMessage response)
        {
            if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values){var pair=value.Split(';')[0].Split('=',2);cookies[pair[0]]=pair[1];}
            Client.DefaultRequestHeaders.Remove("Cookie");if(cookies.Count>0)Client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value)));
        }
        internal async Task<HttpResponseMessage> Post(Dictionary<string,string> fields,string action,bool withCsrf=true)
        {
            if(withCsrf && csrf==""){using var page=await Client.GetAsync("/operator/pilot");Take(page);csrf=Regex.Match(await page.Content.ReadAsStringAsync(),"name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;Assert.NotEmpty(csrf);}
            if(withCsrf)fields["__RequestVerificationToken"]=csrf;
            var result=await Client.PostAsync("/operator/pilot?handler="+action,new FormUrlEncodedContent(fields));Take(result);return result;
        }
        public async ValueTask DisposeAsync(){Client.Dispose();await App.DisposeAsync();}
    }
    private sealed class Keys:IDataProtectionProvider
    {
        private readonly IDataProtectionProvider inner=new EphemeralDataProtectionProvider();internal readonly List<string> Purposes=[];
        public IDataProtector CreateProtector(string purpose){Purposes.Add(purpose);return inner.CreateProtector(purpose);}
    }
}

using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using QuillSign.Lifecycle;
using QuillSign.Operator;

namespace QuillSign.Tests;

// Confirmation/HTTP boundary tests only. Real OIDC and connected deletion
// acceptance remain separate; the HTTP facade below performs no business effect.
public sealed class ProductionOperatorDeletionTests
{
    private const string Issuer="https://operator.example.invalid",Subject="synthetic-operator";
    private const string Commitment="Synthetic configured exact-record copy statement; no legal assurance.";
    [Fact]
    public void Dedicated_permission_is_explicit_and_old_grants_do_not_authorize_deletion()
    {
        var time=new Clock();var options=Options();var ticket=Ticket(time);options.Grants[0].AuthorizeDeletion=false;
        Assert.Throws<UnauthorizedAccessException>(()=>ProductionOperatorAuthority.FromValidatedTicket(ticket,options.Policy(),ProductionOperatorPermission.AuthorizeDeletion,time));
        options.Grants[0].AuthorizeDeletion=true;options.Grants[0].PlaceHold=true;options.Grants[0].ReleaseHold=true;options.Grants[0].ReadEvidence=true;
        var authority=ProductionOperatorAuthority.FromValidatedTicket(ticket,options.Policy(),ProductionOperatorPermission.AuthorizeDeletion,time);Assert.Equal(ticket.Properties.IssuedUtc,authority.IssuedAt);Assert.Equal(ticket.Principal.FindFirst(ProductionOperatorAuthentication.SessionClaim)!.Value,authority.SessionId);Assert.Equal(5,options.Policy().Grants.Single().Permissions.Count);
        Assert.Throws<UnauthorizedAccessException>(()=>authority.Demand(options.Policy(),ProductionOperatorPermission.ReleaseHold,time));
        options.Grants[0].AuthorizeDeletion=false;Assert.Throws<UnauthorizedAccessException>(()=>authority.Demand(options.Policy(),ProductionOperatorPermission.AuthorizeDeletion,time));
    }
    [Fact]
    public void Confirmation_binds_exact_record_packet_receipts_configured_statement_and_original_session()
    {
        var time=new Clock();var browser=new ProductionOperatorBrowser(Options(),new EphemeralDataProtectionProvider(),time);var ticket=Ticket(time);var record=Guid.NewGuid();var deletion=Guid.NewGuid();var facts=new ProductionDeletionCompletedFacts(Guid.NewGuid(),new('b',64),new('c',64));
        var raw=browser.ConfirmDeletion(ticket,record,deletion,17,new('a',64),facts,Commitment,"Synthetic exact purpose");var saved=browser.OpenDeletion(ticket,raw);
        Assert.Equal(record,saved.RecordId);Assert.Equal(deletion,saved.DeletionId);Assert.Equal(facts.PublicationId,saved.PublicationId);Assert.Equal(facts.FinalReceiptsSha256,saved.FinalReceiptsSha256);
        Assert.Equal(Commitment,saved.Commitment);Assert.Equal(time.Now.AddMinutes(2),saved.Until);Assert.Equal(ticket.Properties.IssuedUtc,saved.TicketIssuedAt);Assert.Equal(ticket.Properties.ExpiresUtc,saved.TicketExpiresAt);
        Assert.NotEqual(saved.AuthorizationId,browser.OpenDeletion(ticket,browser.ConfirmDeletion(ticket,record,deletion,17,new('a',64),facts,Commitment,"Synthetic exact purpose")).AuthorizationId);
    }
    [Theory]
    [InlineData("expired")][InlineData("session")][InlineData("issuer")][InlineData("subject")][InlineData("issued")][InlineData("extended-ticket")][InlineData("short-ticket")][InlineData("backwards")][InlineData("tamper")]
    public void Expired_rebound_changed_or_renewed_confirmation_fails_closed(string fault)
    {
        var time=new Clock();var browser=new ProductionOperatorBrowser(Options(),new EphemeralDataProtectionProvider(),time);var ticket=Ticket(time);
        var raw=browser.ConfirmDeletion(ticket,Guid.NewGuid(),Guid.NewGuid(),17,new('a',64),new(Guid.NewGuid(),new('b',64),new('c',64)),Commitment,"Synthetic purpose");
        if(fault=="expired")time.Now=time.Now.AddMinutes(2);if(fault=="backwards")time.Now=time.Now.AddSeconds(-1);
        if(fault=="issued")ticket.Properties.IssuedUtc=ticket.Properties.IssuedUtc!.Value.AddSeconds(-1);
        if(fault=="extended-ticket")ticket.Properties.ExpiresUtc=ticket.Properties.ExpiresUtc!.Value.AddMinutes(1);
        if(fault=="short-ticket")ticket.Properties.ExpiresUtc=ticket.Properties.ExpiresUtc!.Value.AddMinutes(-1);
        if(fault is "session" or "issuer" or "subject")
        {
            var identity=(ClaimsIdentity)ticket.Principal.Identity!;var type=fault=="session"?ProductionOperatorAuthentication.SessionClaim:fault=="issuer"?"iss":"sub";
            identity.RemoveClaim(identity.FindFirst(type)!);identity.AddClaim(new(type,fault=="session"?Guid.NewGuid().ToString("N"):"changed",ClaimValueTypes.String,Issuer));
        }
        if(fault=="tamper"){var at=raw.Length/2;raw=raw[..at]+(raw[at]=='A'?"B":"A")+raw[(at+1)..];}
        Assert.Throws<UnauthorizedAccessException>(()=>browser.OpenDeletion(ticket,raw));
    }
    [Theory]
    [InlineData("future")][InlineData("duplicate")][InlineData("wrong-purpose")]
    public void Correctly_protected_unknown_or_duplicate_fields_and_hold_tokens_are_rejected(string fault)
    {
        var time=new Clock();var keys=new EphemeralDataProtectionProvider();var browser=new ProductionOperatorBrowser(Options(),keys,time);var ticket=Ticket(time);
        var raw=browser.ConfirmDeletion(ticket,Guid.NewGuid(),Guid.NewGuid(),1,new('a',64),new(Guid.NewGuid(),new('b',64),new('c',64)),Commitment,"Synthetic purpose");
        var purpose="production-operator-deletion-confirmation-v1";var protector=keys.CreateProtector(purpose);var json=protector.Unprotect(raw);
        raw=fault switch{"future"=>protector.Protect(json[..^1]+",\"Future\":true}"),"duplicate"=>protector.Protect(json[..^1]+",\"Sequence\":1}"),_=>keys.CreateProtector("production-operator-confirmation-v1").Protect(json)};
        Assert.Throws<UnauthorizedAccessException>(()=>browser.OpenDeletion(ticket,raw));
    }
    [Fact]
    public async Task Disabled_and_missing_csrf_HTTP_paths_do_not_call_the_facade_or_disclose_record_state()
    {
        await using(var disabled=await Host.Create(false))
        {using var response=await disabled.Client.GetAsync("/operator/retention");Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);Assert.DoesNotContain("Synthetic",await response.Content.ReadAsStringAsync());Assert.Equal(0,disabled.Actions.Calls);}
        await using var h=await Host.Create(true);using var denied=await h.Client.PostAsync("/operator/retention/ConfirmDeletion",new FormUrlEncodedContent(new Dictionary<string,string>{{"Attested","true"},{"Confirmation","synthetic-transport-marker"}}));
        Assert.Equal(HttpStatusCode.BadRequest,denied.StatusCode);Assert.Equal(0,h.Actions.Calls);Assert.Contains("no-store",denied.Headers.CacheControl!.ToString());
    }
    [Fact]
    public async Task HTTP_review_is_private_encodes_statement_and_confirmation_requires_explicit_record_affirmation()
    {
        await using var h=await Host.Create(true);var record=Guid.NewGuid().ToString("N");
        using(var review=await h.Post("ReviewDeletion",new(){["RecordId"]=record,["Purpose"]="Synthetic purpose"}))
        {
            Assert.Equal(HttpStatusCode.OK,review.StatusCode);var html=await review.Content.ReadAsStringAsync();Assert.Contains("&lt;b&gt;Synthetic configured statement&lt;/b&gt;",html);Assert.DoesNotContain("<b>Synthetic configured statement</b>",html);
            Assert.Contains("not independently prove",html);Assert.Contains("noindex",string.Join(" ",review.Headers.GetValues("X-Robots-Tag")));Assert.Equal("no-referrer",string.Join(" ",review.Headers.GetValues("Referrer-Policy")));
        }
        var calls=h.Actions.Calls;using(var uncheckedResult=await h.Post("ConfirmDeletion",new(){["Confirmation"]="synthetic-transport-marker"}))Assert.Equal(HttpStatusCode.Redirect,uncheckedResult.StatusCode);
        Assert.Equal(calls,h.Actions.Calls);
        using var confirmed=await h.Post("ConfirmDeletion",new(){["Confirmation"]="synthetic-transport-marker",["Attested"]="true"});Assert.Equal(HttpStatusCode.Redirect,confirmed.StatusCode);Assert.Equal("/operator/retention",confirmed.Headers.Location!.OriginalString);Assert.Equal(calls+1,h.Actions.Calls);
    }
    private static ProductionOperatorOptions Options()=>new(){Enabled=true,Issuer=Issuer,ClientId="synthetic-client",ClientSecret="synthetic-secret",Grants=[new(){Subject=Subject,Status=true,AuthorizeDeletion=true}]};
    private static AuthenticationTicket Ticket(Clock time)=>new(new ClaimsPrincipal(new ClaimsIdentity([new("iss",Issuer,ClaimValueTypes.String,Issuer),new("sub",Subject,ClaimValueTypes.String,Issuer),new(ProductionOperatorAuthentication.SessionClaim,"00000000000000000000000000000001",ClaimValueTypes.String,Issuer)],ProductionOperatorAuthority.OidcScheme)),new(){IssuedUtc=time.Now.AddMinutes(-1),ExpiresUtc=time.Now.AddMinutes(4)},ProductionOperatorAuthority.CookieScheme);
    private sealed class Clock:TimeProvider{internal DateTimeOffset Now=new(2032,1,1,12,0,0,TimeSpan.Zero);public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed class Host:IAsyncDisposable
    {
        internal WebApplication App=null!;internal HttpClient Client=null!;internal readonly Facade Actions=new();private readonly Dictionary<string,string> cookies=[];
        internal static async Task<Host> Create(bool enabled)
        {
            var h=new Host();var time=new Clock();var options=Options();options.Enabled=enabled;
            var b=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(ProductionOperatorBrowser).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});b.Logging.ClearProviders();b.WebHost.UseTestServer();b.Services.AddRazorPages();b.Services.AddDataProtection();b.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());b.Services.AddSingleton<TimeProvider>(time);b.Services.AddSingleton(options);b.Services.AddScoped<ProductionOperatorBrowser>();b.Services.AddSingleton<IProductionOperatorActions>(h.Actions);
            b.Services.AddSingleton(Ticket(time));b.Services.AddAuthentication(ProductionOperatorAuthority.CookieScheme).AddScheme<AuthenticationSchemeOptions,TestAuthentication>(ProductionOperatorAuthority.CookieScheme,_=>{});
            b.Services.AddRateLimiter(o=>o.AddFixedWindowLimiter("production-operator",v=>{v.PermitLimit=32;v.Window=TimeSpan.FromMinutes(1);v.QueueLimit=0;}));
            h.App=b.Build();h.App.UseProductionOperatorPrivacy();h.App.UseRouting();h.App.UseRateLimiter();h.App.UseAuthentication();h.App.UseAuthorization();h.App.MapRazorPages();await h.App.StartAsync();h.Client=h.App.GetTestClient();h.Client.BaseAddress=new("https://localhost");return h;
        }
        internal async Task<HttpResponseMessage> Post(string handler,Dictionary<string,string> fields)
        {
            using var page=await Request(HttpMethod.Get,"/operator/retention",null);var html=await page.Content.ReadAsStringAsync();
            var token=Regex.Match(html,"name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;Assert.NotEmpty(token);fields["__RequestVerificationToken"]=WebUtility.HtmlDecode(token);
            return await Request(HttpMethod.Post,"/operator/retention/"+handler,fields);
        }
        private async Task<HttpResponseMessage> Request(HttpMethod method,string path,Dictionary<string,string>? fields)
        {
            using var request=new HttpRequestMessage(method,path);if(cookies.Count>0)request.Headers.TryAddWithoutValidation("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value)));if(fields is not null)request.Content=new FormUrlEncodedContent(fields);
            var response=await Client.SendAsync(request);if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var cookie in values){var pair=cookie.Split(';')[0].Split('=',2);cookies[pair[0]]=pair[1];}return response;
        }
        public async ValueTask DisposeAsync(){Client.Dispose();await App.DisposeAsync();}
    }
    private sealed class TestAuthentication(IOptionsMonitor<AuthenticationSchemeOptions> options,ILoggerFactory logger,UrlEncoder encoder,AuthenticationTicket ticket):AuthenticationHandler<AuthenticationSchemeOptions>(options,logger,encoder)
    {protected override Task<AuthenticateResult> HandleAuthenticateAsync()=>Task.FromResult(AuthenticateResult.Success(ticket));}
    private sealed class Facade:IProductionOperatorActions
    {
        internal int Calls;public bool DeletionEnabled=>true;
        public Task<ProductionOperatorDeletionReview> ReviewDeletionAsync(Microsoft.AspNetCore.Http.HttpContext context,Guid id,string purpose,CancellationToken ct){Calls++;return Task.FromResult(new ProductionOperatorDeletionReview("synthetic-transport-marker",id.ToString("N"),"<b>Synthetic configured statement</b>",purpose));}
        public Task<string> ExecuteDeletionAsync(Microsoft.AspNetCore.Http.HttpContext context,string proof,CancellationToken ct){Calls++;return Task.FromResult("Synthetic recorded statement");}
        public Task<ProductionOperatorView> StatusAsync(Microsoft.AspNetCore.Http.HttpContext c,Guid id,bool inspect,CancellationToken ct)=>throw new NotSupportedException();
        public Task<ProductionOperatorReview> ReviewAsync(Microsoft.AspNetCore.Http.HttpContext c,Guid id,string op,Guid? hold,string purpose,string reason,string reference,CancellationToken ct)=>throw new NotSupportedException();
        public Task<string> ExecuteAsync(Microsoft.AspNetCore.Http.HttpContext c,string proof,CancellationToken ct)=>throw new NotSupportedException();
        public Task<byte[]> ExportAsync(Microsoft.AspNetCore.Http.HttpContext c,Guid id,string purpose,CancellationToken ct)=>throw new NotSupportedException();
    }
}

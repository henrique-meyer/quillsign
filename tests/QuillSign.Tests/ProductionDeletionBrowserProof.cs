using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using Azure.Core.Pipeline;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Operator;
using QuillSign.Sealing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

// Opt-in, disposable browser bridge inside the SAME genuine completed-record
// acceptance case. No production endpoint, authority shortcut or second fixture.
internal static class ProductionDeletionBrowserProof
{
    internal const string Statement="Synthetic operator attests exact completed packet copies were retained; software does not prove possession or legal adequacy.";
    internal static async Task<bool> RunIfRequestedAsync(SqlDatabaseFixture fixture,Guid recordId,IDataProtectionProvider keys,
        TimeProvider time,ProductionHoldWitnessJournal journal,ProductionHoldCoordinator holds,ProductionDeletionCoordinator deletion,Func<Task> performWork)
    {
        if(Environment.GetEnvironmentVariable("QUILLSIGN_Q149_BROWSER_PROOF")!="1")return false;
        var privateRoot=Environment.GetEnvironmentVariable("QUILLSIGN_PRIVATE_DATA");
        if(string.IsNullOrWhiteSpace(privateRoot)||!Path.IsPathFullyQualified(privateRoot))throw new InvalidOperationException("Explicit private browser evidence directory is required.");
        var output=Path.Combine(privateRoot,"QUILS-149-browser-proof");Directory.CreateDirectory(output);
        using var certificate=Certificate();using var idp=new ProductionOperatorOidcTests.FakeIdp();
        const string origin="https://localhost:18150";
        await using var db=fixture.Open();var connection=db.Database.GetConnectionString()!;
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{
            ["ProductionOperator:Enabled"]="true",["ProductionOperator:Issuer"]=ProductionOperatorOidcTests.FakeIdp.Issuer,
            ["ProductionOperator:ClientId"]=ProductionOperatorOidcTests.FakeIdp.ClientId,["ProductionOperator:ClientSecret"]="synthetic-secret",
            ["ProductionOperator:Grants:0:Subject"]="synthetic-operator",["ProductionOperator:Grants:0:Status"]="true",
            ["ProductionOperator:Grants:0:PlaceHold"]="true",["ProductionOperator:Grants:0:ReleaseHold"]="true",
            ["ProductionOperator:Grants:0:ReadEvidence"]="true",["ProductionOperator:Grants:0:AuthorizeDeletion"]="true",
            ["ProductionHolds:Enabled"]="true",["ProductionHolds:InstallationId"]="00000000000000000000000000000001",
            ["ProductionHolds:ServiceUri"]="https://storage.example.invalid/",["ProductionHolds:WitnessContainerUri"]="https://storage.example.invalid/witness",
            ["ProductionHolds:AllowIndefiniteWitnessLegalHold"]="true",["Storage:Provider"]="Azure",["Storage:BlobServiceUri"]="https://storage.example.invalid/",
            ["Work:Enabled"]="true",["Records:Mode"]="Production",["Records:Production:Version"]="synthetic-v1",
            ["Records:Production:ArchiveResponsibility"]="Synthetic fixture only",["Records:Production:AbandonedDraftDays"]="30",
            ["Records:Production:ExpiredDays"]="30",["Records:Production:DeclinedDays"]="30",["Records:Production:VoidedDays"]="30",["Records:Production:CompletedDays"]="30",
            ["ProductionDeletion:Enabled"]="true",["ProductionDeletion:CompletedCommitmentStatement"]=Statement,["ConnectionStrings:Database"]=connection
        }).Build();
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(ProductionOperatorBrowser).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.WebHost.UseStaticWebAssets();builder.WebHost.ConfigureKestrel(k=>k.ListenLocalhost(18150,l=>l.UseHttps(certificate)));
        builder.Services.AddRazorPages();builder.Services.AddDataProtection();builder.Services.AddSingleton(keys);builder.Services.AddSingleton(time);
        builder.Services.AddDbContext<QuillSignDbContext>(o=>o.UseSqlServer(connection));builder.Services.AddSingleton(new DocumentOptions());
        builder.Services.AddSingleton(new WorkOptions{Enabled=true});builder.Services.AddPlatformPdfSeals(config);builder.Services.AddProductionOperator(config);
        builder.Services.AddScoped<ProductionHoldCoordinator>(_=>holds);builder.Services.AddScoped<ProductionDeletionCoordinator>(_=>deletion);
        builder.Services.AddScoped<IProductionHoldArchiveInspectionStore>(_=>new AzureProductionHoldArchiveInspectionStore(new("https://storage.example.invalid/"),
            new ProductionHoldArchiveReleaseTests.Credential(),time,new HttpClientTransport(new HttpClient(new NoNetwork()))));
        builder.Services.Configure<OpenIdConnectOptions>(ProductionOperatorAuthority.OidcScheme,o=>{
            o.Backchannel=new HttpClient(idp,false);o.TimeProvider=time;
            // Replace only the synthetic authorization UI transport. Actual
            // signed issuer/audience/nonce/state/code/PKCE validation is intact.
            o.Events.OnRedirectToIdentityProvider=c=>{c.ProtocolMessage.IssuerAddress=origin+"/__fixture/idp";return Task.CompletedTask;};
        });
        builder.Services.Configure<CookieAuthenticationOptions>(ProductionOperatorAuthority.CookieScheme,o=>o.TimeProvider=time);
        await using var app=builder.Build();app.UseProductionOperatorPrivacy();app.UseStaticFiles();app.UseRouting();app.UseRateLimiter();app.UseAuthentication();app.UseAuthorization();
        app.MapRazorPages().WithProductionOperatorRateLimit();
        var done=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var workStarted=0;var workDone=false;
        app.MapGet("/__fixture/idp",(HttpContext c)=>{
            string Field(string name)=>"<input type=hidden name=\""+name+"\" value=\""+HtmlEncoder.Default.Encode(c.Request.Query[name].ToString())+"\">";
            return Results.Content("<!doctype html><title>Synthetic identity provider</title><h1>Synthetic identity provider</h1><form method=post>"+
                string.Concat(new[]{"nonce","code_challenge","redirect_uri","state"}.Select(Field))+"<button>Continue as synthetic operator</button></form>","text/html");
        });
        app.MapPost("/__fixture/idp",async(HttpContext c)=>{
            var form=await c.Request.ReadFormAsync();var redirect=form["redirect_uri"].ToString();
            if(redirect!=origin+ProductionOperatorAuthentication.Page+"/signin-oidc")return Results.BadRequest();
            var code=idp.Authorize(form["nonce"].ToString(),form["code_challenge"].ToString(),redirect);
            return Results.Content("<!doctype html><title>Synthetic identity response</title><h1>Signed synthetic identity response</h1><form method=post action=\""+HtmlEncoder.Default.Encode(redirect)+"\"><input type=hidden name=state value=\""+
                HtmlEncoder.Default.Encode(form["state"].ToString())+"\"><input type=hidden name=code value=\""+code+"\"><button>Return to QuillSign</button></form>","text/html");
        });
        app.MapGet("/__fixture/control",()=>Results.Content("<!doctype html><title>Synthetic worker control</title><h1>Synthetic worker control</h1><p>Only this disposable acceptance fixture.</p><form method=post action=/__fixture/run-work><button>Run the prepared synthetic worker</button></form><form method=post action=/__fixture/finish><button>Finish browser acceptance</button></form>","text/html"));
        app.MapPost("/__fixture/run-work",async()=>{
            if((await journal.ReadAsync(recordId)).Deletion?.Disposition is null||Interlocked.Exchange(ref workStarted,1)!=0)return Results.BadRequest();
            try{await performWork();workDone=true;return Results.Content("<!doctype html><h1>Synthetic worker completed</h1><a href=/operator/retention>Read recorded status</a>","text/html");}
            catch(Exception e){done.TrySetException(e);throw;}
        });
        app.MapPost("/__fixture/finish",()=>{if(!workDone||!idp.PkceVerified)return Results.BadRequest();done.TrySetResult();return Results.Content("Browser acceptance finished.","text/plain");});
        await app.StartAsync();
        await File.WriteAllTextAsync(Path.Combine(output,"ready.private.json"),JsonSerializer.Serialize(new{recordId=recordId.ToString("N"),origin,at=DateTimeOffset.UtcNow,statement=Statement,fixtureClock=time.GetUtcNow()}));
        try{await done.Task.WaitAsync(TimeSpan.FromMinutes(9));Assert.True(workDone);Assert.True(idp.PkceVerified);return true;}
        finally{await app.StopAsync();}
    }
    private static X509Certificate2 Certificate()
    {
        using var own=new X509Store(StoreName.My,StoreLocation.CurrentUser);own.Open(OpenFlags.ReadOnly);
        using var roots=new X509Store(StoreName.Root,StoreLocation.CurrentUser);roots.Open(OpenFlags.ReadOnly);
        var now=DateTime.UtcNow;var cert=own.Certificates.FirstOrDefault(c=>c.Subject=="CN=localhost"&&c.HasPrivateKey&&c.NotBefore<now&&c.NotAfter>now&&roots.Certificates.Contains(c));
        return cert is null?throw new InvalidOperationException("An existing trusted localhost development certificate is required; browser security must not be bypassed."):new X509Certificate2(cert);
    }
    private sealed class NoNetwork:HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)=>throw new InvalidOperationException("No cloud request is allowed in this synthetic browser proof.");}
}

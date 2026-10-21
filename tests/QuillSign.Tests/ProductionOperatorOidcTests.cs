using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Operator;
using QuillSign.Sealing;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionOperatorOidcTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("issuer")][InlineData("audience")][InlineData("subject")][InlineData("nonce")][InlineData("signature")][InlineData("expired")]
    public async Task Actual_oidc_middleware_rejects_wrong_signed_identity_protocol_or_lifetime(string fault)
    {
        await using var h=await Host.Create(fixture);h.Idp.Fault=fault;
        var response=await h.Login();Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);
        Assert.DoesNotContain(h.Cookies.Keys,x=>x=="__Host-QuillSign.Operator");
        Assert.Equal(0,await h.CountAudits());
    }
    [Fact]
    public async Task Actual_oidc_status_export_two_independent_hold_confirmations_and_separate_releases_are_connected()
    {
        await using var h=await Host.Create(fixture);using(var login=await h.Login())Assert.Equal(HttpStatusCode.Redirect,login.StatusCode);
        Assert.True(h.Idp.PkceVerified);var page=await h.Page();Assert.Contains("Record identifier",page);Assert.DoesNotContain("Application account",page);
        using(var csrf=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")},false))Assert.Equal(HttpStatusCode.BadRequest,csrf.StatusCode);
        Assert.Equal(0,await h.CountAudits());
        using(var status=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.OK,status.StatusCode);
        Assert.Equal(1,await h.CountAudits());
        var first=await h.Review();var stale=await h.Review();
        using(var confirmed=await h.Post("Confirm",new(){["Confirmation"]=first}))Assert.Equal(HttpStatusCode.Redirect,confirmed.StatusCode);
        var state=await h.Coordinator().ReadVerifiedAsync(h.Id);Assert.Single(state.Holds);Assert.True(state.Holds.Values.Single().Effective);
        using(var replay=await h.Post("Confirm",new(){["Confirmation"]=first}))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
        using(var obsolete=await h.Post("Confirm",new(){["Confirmation"]=stale}))Assert.Equal(HttpStatusCode.Redirect,obsolete.StatusCode);
        Assert.Single((await h.Coordinator().ReadVerifiedAsync(h.Id)).Holds);
        var second=await h.Review();using(var confirmed=await h.Post("Confirm",new(){["Confirmation"]=second}))Assert.Equal(HttpStatusCode.Redirect,confirmed.StatusCode);
        state=await h.Coordinator().ReadVerifiedAsync(h.Id);Assert.Equal(2,state.Holds.Count);Assert.True(state.Holds.Values.All(x=>x.Effective));
        using(var exported=await h.Post("Export",new(){["RecordId"]=h.Id.ToString("N"),["Purpose"]="Synthetic authorized inventory"})){
            Assert.Equal(HttpStatusCode.OK,exported.StatusCode);Assert.Equal("application/json",exported.Content.Headers.ContentType!.MediaType);
            var json=await exported.Content.ReadAsStringAsync();Assert.Contains("Synthetic private reason",json);Assert.DoesNotContain("VersionId",json);Assert.DoesNotContain("storage.example",json);}
        var holds=state.Holds.Keys.ToArray();foreach(var hold in holds){var proof=await h.Review("Release",hold);using var done=await h.Post("Confirm",new(){["Confirmation"]=proof});Assert.Equal(HttpStatusCode.Redirect,done.StatusCode);
            var after=await h.Coordinator().ReadVerifiedAsync(h.Id);Assert.True(after.Holds[hold].Released);if(hold==holds[0])Assert.True(after.Frozen);}
        Assert.False((await h.Coordinator().ReadVerifiedAsync(h.Id)).Frozen);
        await using var db=fixture.Open();Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==h.Id&&x.DataJson.Contains("Synthetic private reason")));
        var receipts=await db.ProductionOperatorAccessReceipts.Where(x=>!h.InitialAuditIds.Contains(x.Id)).ToArrayAsync();Assert.Equal(2,receipts.Length);Assert.All(receipts,x=>Assert.DoesNotContain("synthetic-operator",x.ProtectedReceipt));
    }
    [Fact]
    public async Task Permission_revocation_and_lost_correlation_never_inherit_participant_or_status_authority()
    {
        await using var h=await Host.Create(fixture);using var login=await h.Login();Assert.Equal(HttpStatusCode.Redirect,login.StatusCode);
        using(var status=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.OK,status.StatusCode);
        h.Options.Grants[0].PlaceHold=false;using(var denied=await h.Post("Review",h.Fields()))Assert.Equal(HttpStatusCode.NotFound,denied.StatusCode);
        using(var none=await h.Client.PostAsync(ProductionOperatorAuthentication.Page+"/signin-oidc",new FormUrlEncodedContent(new Dictionary<string,string>{{"code","invented"},{"state","invented"}})))Assert.Equal(HttpStatusCode.NotFound,none.StatusCode);
        Assert.Empty((await h.Coordinator().ReadVerifiedAsync(h.Id)).Holds);
    }

    [Fact]
    public async Task Original_confirmation_and_absolute_cookie_expire_without_new_authority()
    {
        await using var h=await Host.Create(fixture);using var login=await h.Login();
        using(var status=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.OK,status.StatusCode);
        var proof=await h.Review();h.Clock.Advance(TimeSpan.FromMinutes(2)+TimeSpan.FromSeconds(1));
        using(var expired=await h.Post("Confirm",new(){["Confirmation"]=proof}))Assert.Equal(HttpStatusCode.Redirect,expired.StatusCode);
        Assert.Empty((await h.Coordinator().ReadVerifiedAsync(h.Id)).Holds);
        h.Clock.Advance(TimeSpan.FromMinutes(3));
        using(var expired=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.NotFound,expired.StatusCode);
        Assert.Equal(1,await h.CountAudits());
    }

    [Fact]
    public async Task Audit_failure_and_missing_sensitive_permission_deny_response_without_participant_audit()
    {
        await using var h=await Host.Create(fixture);using var login=await h.Login();h.FailAudit=true;
        using(var refused=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.NotFound,refused.StatusCode);
        Assert.Equal(0,await h.CountAudits());h.FailAudit=false;
        using(var status=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.OK,status.StatusCode);
        h.Options.Grants[0].ReadEvidence=false;
        using(var refused=await h.Post("Export",new(){["RecordId"]=h.Id.ToString("N"),["Purpose"]="Synthetic authorized inventory"}))Assert.Equal(HttpStatusCode.NotFound,refused.StatusCode);
        Assert.Equal(1,await h.CountAudits());
    }

    [Fact]
    public async Task Unknown_preservation_readback_stays_pending_and_confirmation_replay_never_repeats_provider_effects()
    {
        await using var h=await Host.Create(fixture);using var login=await h.Login();
        using var status=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")});Assert.Equal(HttpStatusCode.OK,status.StatusCode);
        var proof=await h.Review();h.Provider.Fault="bad-bytes";
        using(var pending=await h.Post("Confirm",new(){["Confirmation"]=proof}))Assert.Equal(HttpStatusCode.Redirect,pending.StatusCode);
        var state=await h.Coordinator().ReadVerifiedAsync(h.Id);Assert.True(state.Frozen);Assert.Single(state.Holds);Assert.False(state.Holds.Values.Single().Effective);
        var requests=h.Provider.Calls.Count;
        using(var replay=await h.Post("Confirm",new(){["Confirmation"]=proof}))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
        Assert.Equal(requests,h.Provider.Calls.Count);Assert.True((await h.Coordinator().ReadVerifiedAsync(h.Id)).Frozen);
    }

    [Fact]
    public async Task Disable_retains_real_held_witness_read_and_fresh_protection_is_an_explicit_observation()
    {
        await using var h=await Host.Create(fixture);using var login=await h.Login();
        using(var status=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.OK,status.StatusCode);
        var proof=await h.Review();using(var confirmed=await h.Post("Confirm",new(){["Confirmation"]=proof}))Assert.Equal(HttpStatusCode.Redirect,confirmed.StatusCode);
        var reader=new ReadOnlyProductionWitnessStore(h.Witness);var original=await reader.ReadAsync(h.Id);Assert.NotEmpty(original);
        var kernel=new ProductionRecordOperationAdmission(fixture.Open,h.Keys,h.Clock,new(reader,h.Keys,h.Clock,Host.Installation)){
            AuthenticatedDemoOrigin=true,ProductionAdmissionEnabled=false};
        await Assert.ThrowsAsync<InvalidDataException>(()=>kernel.BeginAsync(h.Id,Guid.NewGuid(),"sender/details","synthetic"));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>reader.CreateAsync(new(h.Id,original.Count+1,[1])));
        Assert.Equal(original.Count,(await reader.ReadAsync(h.Id)).Count);
        using(var observed=await h.Post("Inspect",new(){["RecordId"]=h.Id.ToString("N")})){
            Assert.Equal(HttpStatusCode.OK,observed.StatusCode);Assert.Contains("Explicit inspection completed",await observed.Content.ReadAsStringAsync());}
        Assert.True((await h.Coordinator().ReadVerifiedAsync(h.Id)).Frozen);Assert.Equal(0,h.Provider.Clears);
    }

    [Fact]
    public async Task Enabled_central_composition_fences_real_participant_mutation_after_operator_hold_and_restores_ordinary_result_only_after_exact_release()
    {
        await using var h=await Host.Create(fixture,runtime:true);using var login=await h.Login();
        using(var status=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.OK,status.StatusCode);
        var proof=await h.Review();using(var confirmed=await h.Post("Confirm",new(){["Confirmation"]=proof}))Assert.Equal(HttpStatusCode.Redirect,confirmed.StatusCode);
        var state=await h.Coordinator().ReadVerifiedAsync(h.Id);Assert.True(state.Holds.Values.Single().Effective);
        using(var scope=h.App.Services.CreateScope()){
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Id);
            var principal=Participant(e);var details=scope.ServiceProvider.GetRequiredService<QuillSign.Documents.DraftDetails>();
            var denied=await details.ChangeAsync(principal,e.PublicId,new(QuillSign.Documents.DetailsChangeKind.SaveDetails,Convert.ToBase64String(e.RowVersion),Title:"Synthetic attempted change"),"127.0.0.1","Synthetic composition");
            Assert.Equal(QuillSign.Documents.DetailsError.Conflict,denied.Error);Assert.Equal(e.RowVersion,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Id)).RowVersion);
        }
        var release=await h.Review("Release",state.Holds.Keys.Single());using(var confirmed=await h.Post("Confirm",new(){["Confirmation"]=release}))Assert.Equal(HttpStatusCode.Redirect,confirmed.StatusCode);
        using(var scope=h.App.Services.CreateScope()){
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Id);
            var ordinary=await scope.ServiceProvider.GetRequiredService<QuillSign.Documents.DraftDetails>().ChangeAsync(Participant(e),e.PublicId,
                new(QuillSign.Documents.DetailsChangeKind.SaveDetails,Convert.ToBase64String(e.RowVersion),Title:"Synthetic attempted change"),"127.0.0.1","Synthetic composition");
            Assert.Equal(QuillSign.Documents.DetailsError.PreviewRequired,ordinary.Error);
        }
        Assert.False((await h.Coordinator().ReadVerifiedAsync(h.Id)).Frozen);
    }

    [Fact]
    public async Task A_concurrent_real_command_during_read_audit_denies_the_stale_status_response()
    {
        await using var h=await Host.Create(fixture);using var login=await h.Login();
        var cookie=h.App.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>().Get(ProductionOperatorAuthority.CookieScheme);
        var ticket=cookie.TicketDataFormat.Unprotect(h.Cookies["__Host-QuillSign.Operator"])!;
        var authority=ProductionOperatorAuthority.FromValidatedTicket(ticket,h.Options.Policy(),ProductionOperatorPermission.PlaceHold,h.Clock);
        h.AfterAudit=async()=>{_=await h.Coordinator().SubmitAsync(authority,h.Options.Policy(),new(Guid.NewGuid(),h.Id,Guid.NewGuid(),0,ProductionHoldOperation.Place,
            "Synthetic concurrent preservation","Synthetic private reason","synthetic-concurrent"));};
        using(var stale=await h.Post("Status",new(){["RecordId"]=h.Id.ToString("N")}))Assert.Equal(HttpStatusCode.NotFound,stale.StatusCode);
        Assert.Equal(1,await h.CountAudits());var state=await h.Coordinator().ReadVerifiedAsync(h.Id);Assert.Single(state.Holds);Assert.True(state.Frozen);Assert.Empty(h.Provider.Calls);
    }
    private static System.Security.Claims.ClaimsPrincipal Participant(Envelope e)=>new(new System.Security.Claims.ClaimsIdentity([
        new(EnvelopeStorageAuthorization.EnvelopeClaim,e.Id.ToString("N")),new(System.Security.Claims.ClaimTypes.Email,e.SenderEmail),new(SenderConfiguration.PublicIdClaim,e.PublicId)],EnvelopeStorageAuthorization.SenderScheme));

    internal sealed class Host:IAsyncDisposable
    {
        internal static readonly string Installation=ProductionHoldRuntimeOptions.IdentityDigest("00000000000000000000000000000001","https://storage.example.invalid/witness");
        internal readonly TestClock Clock=new();internal bool FailAudit;internal Func<Task>? AfterAudit;
        internal Guid Id;internal Guid[] InitialAuditIds=[];internal SqlDatabaseFixture Fixture=null!;internal WebApplication App=null!;internal HttpClient Client=null!;
        internal IDataProtectionProvider Keys=new EphemeralDataProtectionProvider();internal readonly FakeIdp Idp=new();
        internal ProductionOperatorOptions Options=null!;internal readonly Dictionary<string,string> Cookies=[];
        internal readonly MemoryWitness Witness=new();internal readonly ProductionHoldArchiveReleaseTests.Provider Provider=new();
        private BlobServiceClient Service=null!;private string Connection="";
        internal ProductionHoldCoordinator Coordinator()=>new(Fixture.Open,Keys,Clock,new(Witness,Keys,Clock,Installation),new EmptyObjects(),new(Service),new(Service));
        internal static async Task<Host> Create(SqlDatabaseFixture fixture,bool runtime=false)
        {
            var h=new Host{Fixture=fixture};if(!runtime)await h.GenuineDraft();await using var db=fixture.Open();h.Connection=db.Database.GetConnectionString()!;h.InitialAuditIds=await db.ProductionOperatorAccessReceipts.Select(x=>x.Id).ToArrayAsync();
            var transport=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03){Transport=new HttpClientTransport(new HttpClient(h.Provider,false))};transport.Retry.MaxRetries=0;
            h.Service=new(new Uri("https://storage.example.invalid"),new ProductionHoldArchiveReleaseTests.Credential(),transport);
            var b=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(ProductionOperatorBrowser).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
            b.Logging.ClearProviders();b.WebHost.UseTestServer();b.Services.AddRazorPages();b.Services.AddDataProtection();b.Services.AddSingleton<IDataProtectionProvider>(h.Keys);
            b.Services.AddSingleton<TimeProvider>(h.Clock);b.Services.AddDbContext<QuillSignDbContext>(o=>o.UseSqlServer(h.Connection).AddInterceptors(new AuditFailure(h)));b.Services.AddSingleton(new QuillSign.Documents.DocumentOptions());
            var data=new Dictionary<string,string?>{
                ["ProductionOperator:Enabled"]="true",["ProductionOperator:Issuer"]=FakeIdp.Issuer,["ProductionOperator:ClientId"]=FakeIdp.ClientId,["ProductionOperator:ClientSecret"]="synthetic-secret",
                ["ProductionOperator:Grants:0:Subject"]="synthetic-operator",["ProductionOperator:Grants:0:Status"]="true",["ProductionOperator:Grants:0:PlaceHold"]="true",
                ["ProductionOperator:Grants:0:ReleaseHold"]="true",["ProductionOperator:Grants:0:ReadEvidence"]="true",["ProductionHolds:Enabled"]="true",
                ["ProductionHolds:InstallationId"]="00000000000000000000000000000001",["ProductionHolds:ServiceUri"]="https://storage.example.invalid/",["ProductionHolds:WitnessContainerUri"]="https://storage.example.invalid/witness",
                ["ProductionHolds:AllowIndefiniteWitnessLegalHold"]="true",["Storage:Provider"]="Azure",["Storage:BlobServiceUri"]="https://storage.example.invalid/",["Work:Enabled"]="true",["Records:Mode"]="Production",
                ["Records:Production:Version"]="synthetic-v1",["Records:Production:ArchiveResponsibility"]="Synthetic fixture only",["Records:Production:AbandonedDraftDays"]="30",
                ["Records:Production:ExpiredDays"]="30",["Records:Production:DeclinedDays"]="30",["Records:Production:VoidedDays"]="30",["Records:Production:CompletedDays"]="30"};
            data["ConnectionStrings:Database"]=h.Connection;
            var config=new ConfigurationBuilder().AddInMemoryCollection(data).Build();
            if(runtime){
                var email=new EmailOptions{Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};var work=new WorkOptions{Enabled=true};
                b.Services.AddSingleton(email);b.Services.AddSingleton(work);b.Services.AddSingleton(new SenderOptions());b.Services.AddSingleton(new QuillSign.Documents.PreparationOptions());
                b.Services.AddSingleton<IWorkSignals>(new EmailPilotAdmissionTests.Signals());b.Services.AddSingleton(new EmailPayloadProtection(h.Keys));b.Services.AddSingleton<IEmailSender>(new Captured());
                b.Services.AddScoped<RazorEmailViews>();b.Services.AddScoped<VerificationEmailTemplate>();b.Services.AddScoped<EmailOutboxWriter>();b.Services.AddScoped<WorkStore>();
                b.Services.AddScoped<AuditWriter>(sp=>new(sp.GetRequiredService<QuillSignDbContext>(),h.Clock));
                b.Services.AddScoped<SenderWorkflow>(sp=>new(sp.GetRequiredService<QuillSignDbContext>(),sp.GetRequiredService<SenderOptions>(),new(email,work,config),
                    ()=>sp.GetRequiredService<EmailOutboxWriter>(),sp.GetRequiredService<AuditWriter>(),h.Clock,
                    lifecycle:config.GetSection("Records").Get<RecordLifecycleOptions>(),electronicRecords:ProductionRetentionAdmissionContractTests.Policies()));
                b.Services.AddScoped<QuillSign.Documents.DraftDetails>();
                b.Services.AddScoped<EmailWorkHandler>(sp=>new(sp.GetRequiredService<QuillSignDbContext>(),email,sp.GetRequiredService<EmailPayloadProtection>(),
                    sp.GetRequiredService<VerificationEmailTemplate>(),sp.GetRequiredService<IEmailSender>(),h.Clock));
            }
            b.Services.AddPlatformPdfSeals(config);b.Services.AddProductionOperator(config);
            b.Services.AddScoped<IProductionHoldWitnessStore>(_=>h.Witness);
            b.Services.AddScoped<ProductionHoldCoordinator>(_=>h.Coordinator());b.Services.AddScoped<IProductionHoldArchiveInspectionStore>(_=>new AzureProductionHoldArchiveInspectionStore(new("https://storage.example.invalid/"),
                new ProductionHoldArchiveReleaseTests.Credential(),h.Clock,new HttpClientTransport(new HttpClient(h.Provider,false))));
            b.Services.Configure<OpenIdConnectOptions>(ProductionOperatorAuthority.OidcScheme,o=>{o.Backchannel=new HttpClient(h.Idp,false);o.TimeProvider=h.Clock;});
            b.Services.Configure<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>(ProductionOperatorAuthority.CookieScheme,o=>o.TimeProvider=h.Clock);
            b.Services.AddRateLimiter(o=>o.AddFixedWindowLimiter("fixture-public-pages",w=>{w.PermitLimit=1;w.Window=TimeSpan.FromMinutes(1);w.QueueLimit=0;}));
            h.App=b.Build();h.App.UseProductionOperatorPrivacy();h.App.UseRouting();h.App.UseRateLimiter();h.App.UseAuthentication();h.App.UseAuthorization();
            h.App.MapRazorPages().RequireRateLimiting("fixture-public-pages").WithProductionOperatorRateLimit();await h.App.StartAsync();
            h.Options=h.App.Services.GetRequiredService<ProductionOperatorOptions>();h.Client=h.App.GetTestClient();h.Client.BaseAddress=new("https://localhost");if(runtime)await h.GenuineRuntimeDraft();return h;
        }
        private async Task GenuineRuntimeDraft()
        {
            using var scope=App.Services.CreateScope();var sender=scope.ServiceProvider.GetRequiredService<SenderWorkflow>();var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
            var address="synthetic-runtime-"+Guid.NewGuid().ToString("N")+"@example.invalid";Assert.Equal(SenderRequestOutcome.Neutral,await sender.RequestAsync(address,"127.0.0.1","Synthetic composition"));
            var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.To==address);var raw=scope.ServiceProvider.GetRequiredService<EmailPayloadProtection>().Unprotect(mail.PayloadJson);
            var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(mail.Id,default)).Lease!;Assert.NotNull(lease);
            var result=await scope.ServiceProvider.GetRequiredService<EmailWorkHandler>().ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
            Id=(await sender.VerifyAsync(raw.Token,"127.0.0.1","Synthetic composition"))!.EnvelopeId;
            Assert.Equal(1,((Captured)scope.ServiceProvider.GetRequiredService<IEmailSender>()).Calls);
            var state=await Coordinator().ReadVerifiedAsync(Id);Assert.True(state.Initialized);Assert.Equal(2,state.SettledOperations.Count);
        }
        private async Task GenuineDraft()
        {
            await using var db=Fixture.Open();var signals=new EmailPilotAdmissionTests.Signals();var email=new EmailOptions{Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};var work=new WorkOptions{Enabled=true};var payloads=new EmailPayloadProtection(Keys);
            var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"ConnectionStrings:Database","synthetic-configured"},{"Storage:Provider","Azurite"}}).Build();
            var sender=new SenderWorkflow(db,new(),new(email,work,config),()=>new(db,signals,payloads,work,email,Clock),new(db,Clock),Clock,
                lifecycle:ProductionRetentionAdmissionContractTests.Settings(),electronicRecords:ProductionRetentionAdmissionContractTests.Policies());
            var address="synthetic-operator-"+Guid.NewGuid().ToString("N")+"@example.invalid";Assert.Equal(SenderRequestOutcome.Neutral,await sender.RequestAsync(address,"127.0.0.1","Synthetic operator"));
            var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.To==address);var token=payloads.Unprotect(mail.PayloadJson);var store=new WorkStore(db,work,Clock);var lease=(await store.ClaimAsync(mail.Id,default)).Lease!;
            var b=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SenderWorkflow).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});b.Logging.ClearProviders();b.Services.AddRazorPages();b.Services.AddScoped<RazorEmailViews>();
            await using var app=b.Build();using var scope=app.Services.CreateScope();var captured=new Captured();var handler=new EmailWorkHandler(db,email,payloads,new(email,scope.ServiceProvider.GetRequiredService<RazorEmailViews>()),captured,Clock);
            var result=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);Assert.Equal(1,captured.Calls);
            Id=(await sender.VerifyAsync(token.Token,"127.0.0.1","Synthetic operator"))!.EnvelopeId;
        }
        internal async Task<HttpResponseMessage> Login()
        {
            var html=await Page();using var challenge=await Post("SignIn",[]);Assert.Equal(HttpStatusCode.Redirect,challenge.StatusCode);
            var query=Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(challenge.Headers.Location!.Query);var code=Idp.Authorize(query["nonce"].ToString(),query["code_challenge"].ToString(),query["redirect_uri"].ToString());
                        var result=await Request(HttpMethod.Post,ProductionOperatorAuthentication.Page+"/signin-oidc",new(){["state"]=query["state"].ToString(),["code"]=code});
            if(result.StatusCode==HttpStatusCode.Redirect){
                Assert.True(Cookies.TryGetValue("__Host-QuillSign.Operator",out var cookie),"OIDC success did not persist the dedicated cookie.");
                var options=App.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>().Get(ProductionOperatorAuthority.CookieScheme);
                var ticket=options.TicketDataFormat.Unprotect(cookie!);Assert.NotNull(ticket);
                ProductionOperatorAuthentication.DemandPrincipal(ticket.Principal,Options);
                _=ProductionOperatorAuthority.FromValidatedTicket(ticket,Options.Policy(),ProductionOperatorPermission.Status,Clock);
            }
            return result;
        }
        internal async Task<string> Page(){using var response=await Request(HttpMethod.Get,ProductionOperatorAuthentication.Page,null);Assert.Equal(HttpStatusCode.OK,response.StatusCode);return await response.Content.ReadAsStringAsync();}
        internal Dictionary<string,string> Fields(string operation="Place",Guid? hold=null)=>new(){["RecordId"]=Id.ToString("N"),["Operation"]=operation,["HoldId"]=hold?.ToString("N")??"",["Purpose"]="Synthetic operator preservation",["Reason"]="Synthetic private reason",["Reference"]="synthetic-reference"};
        internal async Task<string> Review(string operation="Place",Guid? hold=null){using var response=await Post("Review",Fields(operation,hold));Assert.Equal(HttpStatusCode.OK,response.StatusCode);return Regex.Match(await response.Content.ReadAsStringAsync(),"name=\"Confirmation\" value=\"([^\"]+)\"").Groups[1].Value;}
        internal async Task<HttpResponseMessage> Post(string handler,Dictionary<string,string> fields,bool csrf=true)
        {if(csrf)fields["__RequestVerificationToken"]=WebUtility.HtmlDecode(Regex.Match(await Page(),"name=\"__RequestVerificationToken\"[^>]+value=\"([^\"]+)\"").Groups[1].Value);return await Request(HttpMethod.Post,ProductionOperatorAuthentication.Page+"/"+handler,fields);}
        private async Task<HttpResponseMessage> Request(HttpMethod method,string path,Dictionary<string,string>? fields)
        {
            using var request=new HttpRequestMessage(method,path);if(Cookies.Count>0)request.Headers.Add("Cookie",string.Join("; ",Cookies.Select(x=>x.Key+"="+x.Value)));if(fields is not null)request.Content=new FormUrlEncodedContent(fields);
            var result=await Client.SendAsync(request);if(result.Headers.TryGetValues("Set-Cookie",out var cookies))foreach(var raw in cookies){var pair=raw.Split(';')[0].Split('=',2);if(pair[1].Length==0)Cookies.Remove(pair[0]);else Cookies[pair[0]]=pair[1];}return result;
        }
        internal async Task<int> CountAudits(){await using var db=Fixture.Open();return await db.ProductionOperatorAccessReceipts.CountAsync(x=>!InitialAuditIds.Contains(x.Id));}
        private sealed class AuditFailure(Host owner):Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesInterceptor
        {
            public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> SavingChangesAsync(Microsoft.EntityFrameworkCore.Diagnostics.DbContextEventData e,Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result,CancellationToken ct=default)
            {
                if(owner.FailAudit&&e.Context!.ChangeTracker.Entries<ProductionOperatorAccessReceipt>().Any(x=>x.State==EntityState.Added))throw new DbUpdateException("Synthetic audit refusal.");
                return base.SavingChangesAsync(e,result,ct);
            }
            public override async ValueTask<int> SavedChangesAsync(Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesCompletedEventData e,int result,CancellationToken ct=default)
            {
                if(owner.AfterAudit is {} callback){owner.AfterAudit=null;await callback();}
                return await base.SavedChangesAsync(e,result,ct);
            }
        }
        public async ValueTask DisposeAsync(){Client.Dispose();await App.DisposeAsync();Idp.Dispose();Provider.Dispose();}
    }
    internal sealed class TestClock:TimeProvider
    {
        private DateTimeOffset now=DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow()=>now;
        internal void Advance(TimeSpan delta)=>now+=delta;
    }
    internal sealed class MemoryWitness:IProductionHoldWitnessStore
    {
        private readonly List<ProductionHoldWitnessObject> rows=[];
        public Task<IReadOnlyList<ProductionHoldWitnessObject>> ReadAsync(Guid id,CancellationToken ct=default)
        {ct.ThrowIfCancellationRequested();lock(rows)return Task.FromResult<IReadOnlyList<ProductionHoldWitnessObject>>(rows.Where(x=>x.Path.Contains($"/{id:N}/",StringComparison.Ordinal)).Select(x=>x with{ProtectedPayload=x.ProtectedPayload.ToArray()}).ToArray());}
        public Task<ProductionHoldWitnessObject> CreateAsync(ProductionHoldWitnessWrite w,CancellationToken ct=default)
        {
            ct.ThrowIfCancellationRequested();lock(rows){var path=$"production-hold-witnesses/{Host.Installation}/{w.RecordId:N}/{w.Sequence:D10}";if(rows.Any(x=>x.Path==path))throw new IOException("Synthetic conditional conflict.");
                var bytes=w.ProtectedPayload.ToArray();var row=new ProductionHoldWitnessObject(w.Sequence,path,"synthetic-version-"+w.Sequence,"\"synthetic-etag-"+w.Sequence+"\"",bytes.Length,ProductionHoldWitnessJournal.Digest(bytes),bytes,true);rows.Add(row);return Task.FromResult(row with{ProtectedPayload=bytes.ToArray()});}
        }
    }
    private sealed class Captured:IEmailSender{internal int Calls;public Task<EmailDelivery> SendAsync(OutgoingEmail m,CancellationToken ct=default){Calls++;return Task.FromResult(new EmailDelivery("SyntheticCapture","synthetic-receipt"));}}
    private sealed class EmptyObjects:IProductionHoldObjectSource
    {public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope s,string area,string? continuation,int max,CancellationToken ct)=>Task.FromResult(new HoldObjectPage([],null));public Task<string> HashAsync(ProductionHoldObjectScope s,HoldObjectAddress a,CancellationToken ct)=>throw new InvalidOperationException("Empty genuine draft has no document objects.");}
    internal sealed class FakeIdp:HttpMessageHandler
    {
        internal const string Issuer="https://operator.example.invalid",ClientId="synthetic-client";private readonly RSA rsa=RSA.Create(2048);private readonly RSA foreign=RSA.Create(2048);
        private readonly Dictionary<string,(string Nonce,string Challenge,string Redirect)> Codes=[];internal string Fault="";internal bool PkceVerified;
        internal string Authorize(string nonce,string challenge,string redirect){var code=Guid.NewGuid().ToString("N");Codes.Add(code,(nonce,challenge,redirect));return code;}
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            object response;if(request.RequestUri!.AbsolutePath.EndsWith("openid-configuration"))response=new{issuer=Issuer,authorization_endpoint=Issuer+"/authorize",token_endpoint=Issuer+"/token",jwks_uri=Issuer+"/keys",response_types_supported=new[]{"code"},subject_types_supported=new[]{"public"},id_token_signing_alg_values_supported=new[]{"RS256"},code_challenge_methods_supported=new[]{"S256"}};
            else if(request.RequestUri.AbsolutePath=="/keys"){var key=rsa.ExportParameters(false);response=new{keys=new[]{new{kty="RSA",kid="synthetic",@use="sig",alg="RS256",n=Base64UrlEncoder.Encode(key.Modulus),e=Base64UrlEncoder.Encode(key.Exponent)}}};}
            else if(request.RequestUri.AbsolutePath=="/token"){
                var form=Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(ct));var code=form["code"].ToString();if(!Codes.Remove(code,out var original))throw new InvalidDataException("Synthetic code cannot be reused.");
                PkceVerified=Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"].ToString())))==original.Challenge;
                if(!PkceVerified||form["redirect_uri"].ToString()!=original.Redirect||form["client_id"]!=ClientId||form["client_secret"]!="synthetic-secret")throw new InvalidDataException("Synthetic token request scope changed.");
                var now=DateTimeOffset.UtcNow;var body=new{iss=Fault=="issuer"?"https://other.example.invalid":Issuer,sub=Fault=="subject"?"unknown-subject":"synthetic-operator",aud=Fault=="audience"?"other-client":ClientId,
                    exp=now.AddMinutes(Fault=="expired"?-1:5).ToUnixTimeSeconds(),iat=now.ToUnixTimeSeconds(),nbf=now.AddSeconds(-1).ToUnixTimeSeconds(),nonce=Fault=="nonce"?"wrong":original.Nonce};
                var header=Base64UrlEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(new{alg="RS256",kid="synthetic",typ="JWT"}));var payload=Base64UrlEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(body));var input=header+"."+payload;
                var signature=(Fault=="signature"?foreign:rsa).SignData(Encoding.ASCII.GetBytes(input),HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                response=new{access_token="synthetic-access-token",token_type="Bearer",expires_in=300,id_token=input+"."+Base64UrlEncoder.Encode(signature)};
            }else throw new InvalidOperationException("Unexpected synthetic IdP request.");return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(response),Encoding.UTF8,"application/json")};
        }
        protected override void Dispose(bool disposing){if(disposing){rsa.Dispose();foreign.Dispose();}base.Dispose(disposing);}
    }
}

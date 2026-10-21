using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionDemoOriginTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Default_disabled_genuine_demo_request_worker_finish_and_verification_use_authenticated_original_origin()
    {
        await using var h=await Run.Create(fixture);
        var payload=h.Protection.Unprotect(h.Mail.PayloadJson);Assert.NotNull(payload.DemoOrigin);
        Assert.True(h.Operations.AuthenticatedDemoOrigin);Assert.False(h.Operations.ProductionAdmissionEnabled);
        var store=new WorkStore(h.Db,h.Work,TimeProvider.System,h.Admission);
        var lease=(await store.ClaimAsync(h.Mail.Id,default)).Lease!;Assert.NotNull(lease);
        var b=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SenderWorkflow).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        b.Logging.ClearProviders();b.Services.AddRazorPages();b.Services.AddScoped<RazorEmailViews>();await using var app=b.Build();using var services=app.Services.CreateScope();
        var sent=new Captured();var handler=new EmailWorkHandler(h.Db,h.Email,h.Protection,new(h.Email,services.ServiceProvider.GetRequiredService<RazorEmailViews>()),sent,TimeProvider.System){HoldAdmission=h.Admission};
        var result=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
        Assert.Equal(1,sent.Calls);var token=await h.Db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==payload.TokenId);var expiry=token.ExpiresAt;
        var verified=await h.Sender.VerifyAsync(payload.Token,"127.0.0.1","Synthetic origin");Assert.NotNull(verified);
        Assert.True(await h.Operations.IsUnenrolledDemoAsync(h.Db,verified.EnvelopeId));
        Assert.Equal(expiry,(await h.Db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==payload.TokenId)).ExpiresAt);
        Assert.Equal(WorkStatus.Completed,(await h.Db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id)).Status);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>h.Witness.ReadAsync(verified.EnvelopeId));
    }

    [Theory]
    [InlineData("missing")][InlineData("foreign")][InlineData("created")][InlineData("future-field")][InlineData("wrong-key")]
    public async Task Missing_foreign_rebound_or_unknown_demo_proof_never_becomes_witness_absence(string fault)
    {
        await using var h=await Run.Create(fixture);var payload=h.Protection.Unprotect(h.Mail.PayloadJson);var original=payload.DemoOrigin!;
        switch(fault){
            case "missing":payload=payload with{DemoOrigin=null};break;
            case "foreign":payload=payload with{DemoOrigin=original with{RecordId=Guid.NewGuid()}};break;
            case "created":payload=payload with{DemoOrigin=original with{CreatedAt=original.CreatedAt.AddTicks(1)}};break;
        }
        var json=h.Protection.Protect(payload);
        if(fault=="future-field"){
            var raw=JsonSerializer.Serialize(payload);raw=raw[..^1]+",\"FutureOrigin\":true}";
            json=JsonSerializer.Serialize(new ProtectedWorkPayload(h.Keys.CreateProtector("QuillSign.EmailPayload.v1").Protect(raw)));
        }
        if(fault=="wrong-key")json=new EmailPayloadProtection(new EphemeralDataProtectionProvider()).Protect(payload);
        await h.Db.EmailOutbox.Where(x=>x.Id==h.Mail.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,json));
        var e=await h.Db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Mail.EnvelopeId);
        var error=await Record.ExceptionAsync(()=>h.Operations.IsUnenrolledDemoAsync(h.Db,e.Id));
        Assert.True(error is InvalidDataException or UnauthorizedAccessException);
        Assert.Null(await h.Sender.VerifyAsync(payload.Token,"127.0.0.1","Synthetic origin"));
        Assert.False(await h.Db.AuthTokens.AnyAsync(x=>x.Id==payload.TokenId));
    }

    [Fact]
    public void Old_production_payload_bytes_remain_exact_and_null_omitted()
    {
        var id=Guid.NewGuid();var p=new VerificationPayload("synthetic",id);
        Assert.Equal(JsonSerializer.Serialize(new{Token="synthetic",TokenId=id}),JsonSerializer.Serialize(p));
        Assert.DoesNotContain("DemoOrigin",JsonSerializer.Serialize(p));
    }

    internal sealed class Run:IAsyncDisposable
    {
        internal QuillSignDbContext Db=null!;internal readonly IDataProtectionProvider Keys=new EphemeralDataProtectionProvider();
        internal readonly ClosedProductionStores Witness=new();internal ProductionRecordOperationAdmission Operations=null!;
        internal ProductionWorkAdmission Admission=null!;internal SenderWorkflow Sender=null!;internal EmailPayloadProtection Protection=null!;internal EmailOutbox Mail=null!;
        internal readonly WorkOptions Work=new(){Enabled=true};internal readonly EmailOptions Email=new(){Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};
        internal static async Task<Run> Create(SqlDatabaseFixture fixture){
            var h=new Run{Db=fixture.Open()};h.Protection=new(h.Keys);h.Operations=new(fixture.Open,h.Keys,TimeProvider.System,new(h.Witness,h.Keys,TimeProvider.System,"")){
                AuthenticatedDemoOrigin=true,ProductionAdmissionEnabled=false};h.Admission=new(fixture.Open,h.Operations);
            var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"ConnectionStrings:Database","synthetic-configured"},{"Storage:Provider","Azurite"}}).Build();
            h.Sender=new(h.Db,new(),new(h.Email,h.Work,config),()=>new(h.Db,new EmailPilotAdmissionTests.Signals(),h.Protection,h.Work,h.Email,TimeProvider.System),new(h.Db,TimeProvider.System),TimeProvider.System,
                lifecycle:new()){HoldAdmission=h.Operations};var address="synthetic-demo-"+Guid.NewGuid().ToString("N")+"@example.invalid";
            Assert.Equal(SenderRequestOutcome.Neutral,await h.Sender.RequestAsync(address,"127.0.0.1","Synthetic origin"));
            h.Mail=await h.Db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.To==address);return h;
        }
        public ValueTask DisposeAsync()=>Db.DisposeAsync();
    }
    private sealed class Captured:IEmailSender {internal int Calls;public Task<EmailDelivery> SendAsync(OutgoingEmail m,CancellationToken ct=default){Calls++;return Task.FromResult(new EmailDelivery("SyntheticCapture","synthetic-receipt"));}}
}

using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SigningExpiryCommandTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Actual_resume_command_prepares_one_future_job_without_echoing_private_scope_or_enabling_mail()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var db=fixture.Open();
        await SigningExpiryWorkTests.LegacyAsync(h,fixture);
        var name="expiry-cli-"+Guid.NewGuid().ToString("N");var connection=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;
        var queue=new Azure.Storage.Queues.QueueClient(connection,name,new(Azure.Storage.Queues.QueueClientOptions.ServiceVersion.V2023_11_03));
        var hints=new Azure.Storage.Blobs.BlobServiceClient(connection,new(Azure.Storage.Blobs.BlobClientOptions.ServiceVersion.V2023_11_03)).GetBlobContainerClient(name);
        var root=Path.Combine(Path.GetTempPath(),name);Directory.CreateDirectory(root);
        try {
            for(var attempt=0;attempt<2;attempt++) {
                var assembly=typeof(SigningExpiryCommandTests).Assembly.Location;
                var start=new ProcessStartInfo("dotnet") {RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root};
                foreach(var arg in new[]{"exec","--runtimeconfig",Path.ChangeExtension(assembly,".runtimeconfig.json"),"--depsfile",Path.ChangeExtension(assembly,".deps.json"),typeof(SigningExpiry).Assembly.Location,"work","resume-signing-expiry",h.Envelope.Id.ToString("N")})start.ArgumentList.Add(arg);
                start.Environment["ConnectionStrings__Database"]=db.Database.GetConnectionString();start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";
                start.Environment["Storage__Provider"]="Azurite";start.Environment["Storage__ConnectionString"]=connection;
                start.Environment["Work__Enabled"]="true";start.Environment["Work__QueueName"]=name;start.Environment["Work__HintContainer"]=name;start.Environment["Email__Enabled"]="false";
                using var process=Process.Start(start)!;var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(45));try {await process.WaitForExitAsync(timeout.Token);}catch {if(!process.HasExited)process.Kill(entireProcessTree:true);throw;}
                var text=await output;Assert.True(process.ExitCode==0,await error);Assert.DoesNotContain(h.Envelope.PublicId,text);Assert.DoesNotContain(h.Envelope.Id.ToString("N"),text);Assert.DoesNotContain(h.Envelope.SenderEmail,text);
                using var json=JsonDocument.Parse(text);Assert.Equal("ok",json.RootElement.GetProperty("status").GetString());Assert.Equal(1,json.RootElement.GetProperty("count").GetInt32());
            }
            var row=Assert.Single(await db.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==h.Envelope.Id && x.Kind==WorkKind.Expiry).ToArrayAsync());Assert.Equal(0,row.Attempts);Assert.Equal(h.Envelope.ExpiresAt,row.AvailableAt);Assert.Equal(0,h.Sender.Calls);
        } finally {await queue.DeleteIfExistsAsync();await hints.DeleteIfExistsAsync();Directory.Delete(root);}
    }
    [Fact]
    public async Task Actual_finite_command_expires_once_with_work_email_and_storage_disabled_without_issuing_new_authority()
    {
        var root=Path.Combine(Path.GetTempPath(),"quillsign-expiry-cli-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        // The child has no storage configured: it must authenticate the actual
        // original demo carrier, not infer no hold from a hand-built legacy row.
        // Same application/content root uses the framework's persistent local
        // keyring in both processes. Never delete that shared keyring.
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions {ApplicationName=typeof(SigningExpiry).Assembly.GetName().Name,
            ContentRootPath=root,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddScoped<RazorEmailViews>();
        await using var app=builder.Build();using var scope=app.Services.CreateScope();
        var keys=app.Services.GetRequiredService<IDataProtectionProvider>();
        await using var db=fixture.Open();var h=await PrepareGenuineSentDemo(db,keys,scope.ServiceProvider.GetRequiredService<RazorEmailViews>());
        var wait=h.Envelope.ExpiresAt!.Value-DateTimeOffset.UtcNow+TimeSpan.FromMilliseconds(50);if(wait>TimeSpan.Zero)await Task.Delay(wait);
        var work=await db.WorkItems.CountAsync();var mail=await db.EmailOutbox.CountAsync();var tokens=await db.AuthTokens.CountAsync();
        try {
            var first=await Run();Assert.Equal(1,first.GetProperty("Expired").GetInt32());Assert.Equal("ok",first.GetProperty("status").GetString());
            Assert.Equal(0,(await Run()).GetProperty("Examined").GetInt32());Assert.Equal(EnvelopeStatus.Expired,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
            Assert.Equal(work,await db.WorkItems.CountAsync());Assert.Equal(mail,await db.EmailOutbox.CountAsync());Assert.Equal(tokens,await db.AuthTokens.CountAsync());
            Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ToArrayAsync());Assert.Equal(1,h.Sender.Calls);
            Assert.Equal(h.OriginalCarrier,(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==h.VerificationMailId)).PayloadJson);
            Assert.Equal(h.OriginalTokenExpiry,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==h.VerificationTokenId)).ExpiresAt);
        } finally {Directory.Delete(root);}
        async Task<JsonElement> Run() {
            var testAssembly=typeof(SigningExpiryCommandTests).Assembly.Location;var start=new ProcessStartInfo("dotnet") {RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root};
            foreach(var arg in new[]{"exec","--runtimeconfig",Path.ChangeExtension(testAssembly,".runtimeconfig.json"),"--depsfile",Path.ChangeExtension(testAssembly,".deps.json"),typeof(SigningExpiry).Assembly.Location,"work","expire","1"})start.ArgumentList.Add(arg);
            start.Environment["ConnectionStrings__Database"]=db.Database.GetConnectionString();start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";
            start.Environment["Storage__Provider"]="";start.Environment["Work__Enabled"]="false";start.Environment["Email__Enabled"]="false";
            using var process=Process.Start(start)!;var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(45));try {await process.WaitForExitAsync(timeout.Token);}catch {if(!process.HasExited)process.Kill(entireProcessTree:true);throw;}
            var text=await output;var failure=await error;Assert.True(process.ExitCode==0,$"Finite expiry command failed: {failure}");Assert.DoesNotContain(h.Envelope.PublicId,text);Assert.DoesNotContain(h.Envelope.SenderEmail,text);
            using var json=JsonDocument.Parse(text);return json.RootElement.Clone();
        }
    }

    private async Task<FiniteDemo> PrepareGenuineSentDemo(QuillSignDbContext db,IDataProtectionProvider keys,RazorEmailViews views)
    {
        var time=TimeProvider.System;var work=new WorkOptions{Enabled=true};
        var email=new EmailOptions{Enabled=true,FromEmail="noreply@example.invalid",BaseUrl="https://example.invalid"};
        var signals=new DocumentWorkflowTests.PurgeTestSignals();var protection=new EmailPayloadProtection(keys);
        var closed=new ClosedProductionStores();var operations=new ProductionRecordOperationAdmission(fixture.Open,keys,time,new(closed,keys,time,""))
            {AuthenticatedDemoOrigin=true,ProductionAdmissionEnabled=false};
        var admission=new ProductionWorkAdmission(fixture.Open,operations);
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Database"]="synthetic-configured",["Storage:Provider"]="Azurite"}).Build();
        var sender=new SenderWorkflow(db,new(),new(email,work,config),()=>new(db,signals,protection,work,email,time),new(db,time),time,
            lifecycle:new()){HoldAdmission=operations};
        var address="expiry-origin-"+Guid.NewGuid().ToString("N")+"@example.invalid";
        Assert.Equal(SenderRequestOutcome.Neutral,await sender.RequestAsync(address,"127.0.0.1","Synthetic expiry command"));
        var verification=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.To==address);var payload=protection.Unprotect(verification.PayloadJson);
        Assert.NotNull(payload.DemoOrigin);
        var store=new WorkStore(db,work,time,admission);var lease=(await store.ClaimAsync(verification.Id,default)).Lease!;
        var capture=new CapturedSender();var handler=new EmailWorkHandler(db,email,protection,new(email,views),capture,time){HoldAdmission=admission};
        var result=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
        Assert.NotNull(await sender.VerifyAsync(payload.Token,"127.0.0.1","Synthetic expiry command"));
        var originalTokenExpiry=(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==payload.TokenId)).ExpiresAt;
        db.ChangeTracker.Clear();var e=await db.Envelopes.SingleAsync(x=>x.Id==verification.EnvelopeId);
        using var normalized=new MemoryStream();var pages=new PdfValidation(new()).Rewrite(new MemoryStream(PdfFixtures.Create(text:"Synthetic expiry command")),normalized);
        var bytes=normalized.ToArray();e.Title="Synthetic expiry command";e.PdfBlob=Guid.NewGuid().ToString("N");e.PdfSha256=SHA256.HashData(bytes);
        e.PageCount=pages.Count;e.PageSizesJson=JsonSerializer.Serialize(pages);e.PreviewConfirmedAt=time.GetUtcNow();
        var signer=new Signer{EnvelopeId=e.Id,FullName="Synthetic signer",Email="signer-"+Guid.NewGuid().ToString("N")+"@example.invalid",Order=1};
        db.Add(signer);db.Add(new DocumentField{EnvelopeId=e.Id,SignerId=signer.Id,Type=FieldType.Signature,Page=1,X=.1m,Y=.5m,Width=.4m,Height=.1m});
        // Establish one original signing deadline after genuine intake/verification;
        // it is frozen by normal Send and never extended by either CLI invocation.
        e.ExpiresAt=time.GetUtcNow().AddSeconds(10);await db.SaveChangesAsync();var version=e.RowVersion.ToArray();
        var principal=SenderConfiguration.Principal(new(e.Id,e.PublicId,e.SenderEmail));var blobs=new MemoryBlobs();
        await blobs.WriteAsync(principal,new(e.Id,DocumentBlobKind.Normalized,Guid.Parse(e.PdfBlob)),new MemoryStream(bytes),bytes.Length);
        var workflow=new SendDraftWorkflow(db,blobs,new(),new(),new(),new(),new(32*1024*1024,200,200),new(ElectronicRecordDisclosureTests.Policy()),
            new(db,()=>signals,work,email,new(keys),time),work,email,new(db,time),time,NullLogger<SendDraftWorkflow>.Instance,new(db,new(db,time),()=>signals,work,time))
            {HoldAdmission=new(operations,closed)};
        db.ChangeTracker.Clear();Assert.NotNull(await workflow.SendAsync(principal,e.PublicId,version,true,true,SenderSendStatement.Version,null,null));
        return new(e,capture,verification.Id,payload.TokenId,verification.PayloadJson,originalTokenExpiry);
    }
    private sealed record FiniteDemo(Envelope Envelope,CapturedSender Sender,Guid VerificationMailId,Guid VerificationTokenId,string OriginalCarrier,DateTimeOffset OriginalTokenExpiry);
    private sealed class CapturedSender:IEmailSender
    {
        internal int Calls;
        public Task<EmailDelivery> SendAsync(OutgoingEmail message,CancellationToken ct=default){Calls++;return Task.FromResult(new EmailDelivery("SyntheticCapture","synthetic-expiry-receipt"));}
    }
    private sealed class MemoryBlobs:IBlobStore
    {
        private readonly Dictionary<DocumentBlob,byte[]> objects=[];
        public async Task WriteAsync(ClaimsPrincipal sender,DocumentBlob blob,Stream source,long length,CancellationToken ct=default)
        {EnvelopeStorageAuthorization.Demand(sender,blob);using var bytes=new MemoryStream();await source.CopyToAsync(bytes,ct);Assert.Equal(length,bytes.Length);objects.Add(blob,bytes.ToArray());}
        public async Task<long> CopyToAsync(ClaimsPrincipal sender,DocumentBlob blob,Stream destination,CancellationToken ct=default)
        {EnvelopeStorageAuthorization.DemandRead(sender,blob);var bytes=objects[blob];await destination.WriteAsync(bytes,ct);return bytes.Length;}
        public Task DeleteAsync(ClaimsPrincipal sender,DocumentBlob blob,CancellationToken ct=default)
        {EnvelopeStorageAuthorization.DemandDelete(sender,blob);objects.Remove(blob);return Task.CompletedTask;}
    }
}

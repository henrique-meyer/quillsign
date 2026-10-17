using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SigningExpiryCommandTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Actual_finite_command_expires_once_with_work_email_and_storage_disabled_without_issuing_new_authority()
    {
        await using var h=await Shared.Create(fixture);var end=h.Clock.GetUtcNow().AddSeconds(1);
        await using(var seed=fixture.Open()) {await seed.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,end));h.Version=(await seed.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).RowVersion;}
        Assert.NotNull(await h.Send());var wait=end-DateTimeOffset.UtcNow+TimeSpan.FromMilliseconds(50);if(wait>TimeSpan.Zero)await Task.Delay(wait);
        await using var db=fixture.Open();var work=await db.WorkItems.CountAsync();var mail=await db.EmailOutbox.CountAsync();var tokens=await db.AuthTokens.CountAsync();
        var root=Path.Combine(Path.GetTempPath(),"quillsign-expiry-cli-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try {
            var first=await Run();Assert.Equal(1,first.GetProperty("Expired").GetInt32());Assert.Equal("ok",first.GetProperty("status").GetString());
            Assert.Equal(0,(await Run()).GetProperty("Examined").GetInt32());Assert.Equal(EnvelopeStatus.Expired,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
            Assert.Equal(work,await db.WorkItems.CountAsync());Assert.Equal(mail,await db.EmailOutbox.CountAsync());Assert.Equal(tokens,await db.AuthTokens.CountAsync());
            Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ToArrayAsync());Assert.Equal(0,h.Sender.Calls);
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
}

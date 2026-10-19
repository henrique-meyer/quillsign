using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MimeKit;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotRuntimeTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";
    [Theory]
    [InlineData(EmailPilotScenario.Completion)][InlineData(EmailPilotScenario.Void)][InlineData(EmailPilotScenario.Decline)]
    public async Task Composed_runtime_admits_unverified_then_normal_worker_captures_counted_exact_MIME_and_real_verification(EmailPilotScenario scenario)
    {
        var runId=Guid.NewGuid().ToString("N");var capture=new Capture();var factoryCalls=0;
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["EmailPilot:Enabled"]="true",["EmailPilot:RunId"]=runId,["EmailPilot:Admission:CapabilitySha256"]=Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(Capability))),
            ["EmailPilot:Mailboxes:Sender"]="runtime-"+runId+"@example.invalid",["EmailPilot:Mailboxes:FirstSigner"]="first@example.invalid",
            ["EmailPilot:Mailboxes:SecondSigner"]="second@example.invalid",["EmailPilot:Mailboxes:Recipient"]="recipient@example.invalid"}).Build();
        await using var h=await SendDraftWorkflowTests.Harness.Create(fixture,browser:true,configure:services=>{
            services.AddRestrictedEmailPilotRuntime(config);
            services.AddScoped<Func<EmailPilotSesSettings,IPreparedEmailTransport>>(_=>_=>{factoryCalls++;return capture;});
        });
        var email=h.App.Services.GetRequiredService<EmailOptions>();email.Enabled=false;email.Provider="Ses";email.Ses.Region="us-east-1";email.Ses.ConfigurationSet="synthetic";
        // The fixture's pre-existing unrelated draft is never enrolled or used
        // as authentication evidence. The pilot starts before verification.
        Guid envelopeId,workId;DateTimeOffset expiry;
        using(var scope=h.App.Services.CreateScope()) {
            var browser=scope.ServiceProvider.GetRequiredService<EmailPilotOperatorBrowser>();var session=Login(browser);
            var op=scope.ServiceProvider.GetRequiredService<EmailPilotOperator>();Assert.Null(await op.ReadAsync(session));
            Assert.Equal(0,factoryCalls);Assert.Equal(EmailPilotOperatorNotice.EnvelopeSaved,await op.EnvelopeAsync(session,scenario,"192.0.2.1","Synthetic runtime test"));
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var enrollment=await db.EmailPilotEnrollments.AsNoTracking().SingleAsync(x=>x.RunId==Guid.ParseExact(runId,"N"));
            envelopeId=enrollment.SubjectEnvelopeId;workId=await db.EmailOutbox.Where(x=>x.EnvelopeId==envelopeId).Select(x=>x.Id).SingleAsync();
            Assert.Null((await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelopeId)).SenderVerifiedAt);
            Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==envelopeId));Assert.Equal(0,factoryCalls);
            Assert.True(await db.WorkItems.AnyAsync(x=>x.Id==EmailPilotSecretJobs.WorkId(enrollment.RunId)));
            expiry=(await op.ReadAsync(session))!.ExpiresAt;
        }
        using(var scope=h.App.Services.CreateScope()) {
            var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(workId,default)).Lease!;
            var handler=scope.ServiceProvider.GetServices<IWorkHandler>().Single(x=>x.Kind==WorkKind.Email);
            var result=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var reservation=await db.EmailPilotReservations.SingleAsync(x=>x.RunId==Guid.ParseExact(runId,"N"));
            Assert.Equal(capture.Bytes!.Length,reservation.EncodedBytes);Assert.Equal(SHA256.HashData(capture.Bytes),reservation.RequestSha256);
            Assert.Equal(EmailPilotRole.Sender,reservation.Role);Assert.Equal(1,factoryCalls);
            Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SenderWorkflow>().VerifyAsync(capture.Token,"192.0.2.1","Synthetic runtime test"));
            Assert.True((await db.AuthTokens.SingleAsync(x=>x.EnvelopeId==envelopeId)).ExpiresAt<=expiry);
        }
        using(var scope=h.App.Services.CreateScope()) {
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelopeId);Assert.NotNull(envelope.SenderVerifiedAt);
            if(scenario==EmailPilotScenario.Completion) {
                var browser=scope.ServiceProvider.GetRequiredService<EmailPilotOperatorBrowser>();var op=scope.ServiceProvider.GetRequiredService<EmailPilotOperator>();
                Assert.Equal(EmailPilotOperatorNotice.SimulatorSaved,await op.SimulatorAsync(Login(browser),EmailPilotSimulatorKind.Bounce));
                var id=EmailPilotSimulator.Identity(Guid.ParseExact(runId,"N"),EmailPilotSimulatorKind.Bounce);
                var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(id,default)).Lease!;
                var handler=scope.ServiceProvider.GetServices<IWorkHandler>().Single(x=>x.Kind==WorkKind.Email);
                var result=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
                Assert.Equal(2,capture.Calls);Assert.Equal(2,factoryCalls);
                var budget=(await op.ReadAsync(Login(browser)))!.Budget;Assert.Equal(1,budget.ApplicationAttempts);Assert.Equal(1,budget.SimulatorAttempts);
            }
            h.App.Services.GetRequiredService<EmailPilotOptions>().Enabled=false;
            var bounds=scope.ServiceProvider.GetRequiredService<EmailPilotReadBounds>();await Assert.ThrowsAsync<EmailPilotAccessUnavailableException>(()=>bounds.ReadAsync(envelope,default));
        }
        Assert.False(email.Enabled);Assert.Equal(0,h.Sender.Calls);Assert.Equal(scenario==EmailPilotScenario.Completion?2:1,capture.Calls);
    }
    private static EmailPilotOperatorSession Login(EmailPilotOperatorBrowser browser)
    {
        var http=new DefaultHttpContext();http.Request.Scheme="http";http.Request.Host=new("localhost");Assert.True(browser.Unlock(http,Capability));
        var next=new DefaultHttpContext();next.Request.Headers.Cookie=http.Response.Headers.SetCookie.Single()!.Split(';')[0];return browser.Read(next)!;
    }
    private sealed class Capture:IPreparedEmailTransport
    {
        internal byte[]? Bytes;internal string Token="";internal int Calls;
        public async Task<EmailDelivery> SendAsync(PreparedRawMime message,CancellationToken ct)
        {
            Calls++;using var input=message.OpenRead();using var output=new MemoryStream();await input.CopyToAsync(output,ct);Bytes=output.ToArray();
            var mime=MimeMessage.Load(new MemoryStream(Bytes));
            if(message.EnvelopeId is not null){Token=Regex.Match(mime.TextBody!,@"[?&]token=([A-Za-z0-9_-]{43})").Groups[1].Value;Assert.NotEmpty(Token);}
            else Assert.Equal(EmailPilotSimulator.Target(EmailPilotSimulatorKind.Bounce),message.Recipient);
            return new("Ses","synthetic-runtime-receipt-"+Calls);
        }
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class EmailPilotCompletionReadTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_completion_reader_and_accepted_signer_proofs_obey_cohort_changes_and_discard_after_IO_bytes()
    {
        await using var h=await PilotTimestampBoundaryTests.Harness.Create(fixture);
        var clock=h.Run.Signing.H.Clock;var publicId=h.Run.Signing.Envelope.PublicId;
        Assert.NotNull(await h.Outputs.PrepareAsync(h.Id,timestampWork:await h.Context()));
        var store=new CompletionDownloadTests.FinalStore(clock);
        CompletionPublication Published(QuillSignDbContext db)=>new(db,h.Run.Candidates(db),h.Run.Service(db),h.Run.Collector(db),store,new(db,clock),clock,
            new(){DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},h.Run.Seal.App.Environment);
        await using(var db=fixture.Open())Assert.NotNull(await Published(db).PublishAsync(h.Id));
        var retained=(await h.Run.Signing.Refresh()).PurgeAfter;
        var end=(await h.Db.EmailPilotRuns.AsNoTracking().SingleAsync(x=>x.Id==h.RunId)).ExpiresAt;
        CompletionAccess Access(QuillSignDbContext db)
        {
            var bounds=new EmailPilotReadBounds(()=>db,()=>new(()=>db,()=>h.LedgerFor(db),()=>h.Payload,h.Admission,h.Work),clock);
            return new(db,new(db,h.Run.Collector(db),()=>Published(db),clock,bounds),new(h.Keys,clock),new(),new(db,clock),clock,()=>Published(db),bounds);
        }
        async Task<T> Use<T>(Func<CompletionAccess,Task<T>> action){await using var db=fixture.Open();return await action(Access(db));}
        var link=Assert.IsType<CompletionAccessLink>(await Use(a=>a.IssueAsync(h.Id,PartyType.Sender,null)));
        var unused=Assert.IsType<CompletionAccessLink>(await Use(a=>a.IssueAsync(h.Id,PartyType.Recipient,
            h.Db.Recipients.AsNoTracking().Single(x=>x.EnvelopeId==h.Id).Id)));
        var session=Assert.IsType<CompletionReaderSession>(await Use(a=>a.RedeemAsync(link.RawToken)));
        var principal=CompletionAccessProtection.Principal(session.Identity);
        Assert.Equal(end,link.ExpiresAt);Assert.Equal(end,session.Identity.ExpiresAt);
        foreach(var kind in new[]{FinalDocumentKind.Executed,FinalDocumentKind.Certificate}) {
            var file=Assert.IsType<CompletionReaderFile>(await Use(a=>a.ReadAsync(principal,publicId,session.Receipt,kind)));
            await using var db=fixture.Open();var expected=(await Published(db).ReadAsync(h.Id))!;
            Assert.Equal(kind==FinalDocumentKind.Executed?expected.ExecutedBytes:expected.CertificateBytes,file.Pdf);
        }
        async Task AcceptedSigner()
        {
            await using var db=fixture.Open();var bounds=new EmailPilotReadBounds(()=>db,()=>new(()=>db,()=>h.LedgerFor(db),()=>h.Payload,h.Admission,h.Work),clock);
            var access=new SignerAccess(db,new(db,clock),new(),clock,bounds);
            var checkpoints=new SignerCheckpointReads(db,access,new(db,clock),new(h.Run.Storage,clock),new(h.Keys,clock),clock);
            Assert.NotNull(await checkpoints.ReadAsync(h.Run.Signing.LastSigner,publicId,h.Run.Signing.LastReviewReceipt));
        }
        await AcceptedSigner();
        // Protect a genuine existing sender principal with an intentionally longer
        // ordinary cookie ticket. The new download proof must keep the run cutoff.
        clock.Advance(end-clock.GetUtcNow()-TimeSpan.FromMinutes(1));
        using(var scope=h.Run.Signing.H.App.Services.CreateScope()) {
            await using var db=fixture.Open();var sp=scope.ServiceProvider;
            var bounds=new EmailPilotReadBounds(()=>db,()=>new(()=>db,()=>h.LedgerFor(db),()=>h.Payload,h.Admission,h.Work),clock);
            var signerAccess=new SignerAccess(db,new(db,clock),new(),clock,bounds);
            var checkpoints=new SignerCheckpointReads(db,signerAccess,new(db,clock),new(h.Run.Storage,clock),new(h.Keys,clock),clock);
            var cookies=sp.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();var settings=cookies.Get(EnvelopeStorageAuthorization.SenderScheme);
            var ticket=new AuthenticationTicket(h.Run.Signing.Sender,new(){IssuedUtc=clock.GetUtcNow(),ExpiresUtc=clock.GetUtcNow().AddHours(2)},EnvelopeStorageAuthorization.SenderScheme);
            var http=new DefaultHttpContext{RequestServices=sp};http.Request.Scheme="http";http.Request.Host=new("localhost");
            http.Request.Headers.Cookie=settings.Cookie.Name+"="+settings.TicketDataFormat.Protect(ticket);
            var downloads=new CompletionDownloads(db,clock,h.Run.Seal.App.Environment,cookies,h.Keys,checkpoints,h.Run.Collector(db),()=>Published(db),
                new(db,clock),()=>throw new Exception("No completion-reader authority is requested."),bounds);
            var proof=Assert.IsType<PreparedFinalDownload>(await downloads.PrepareAsync(http,publicId,PartyType.Sender,"executed"));
            Assert.Equal(end,proof.ExpiresAt);Assert.True(http.Response.Headers.SetCookie.Count>0);
        }
        var run=h.Options.RunId;var capability=h.Admission.CapabilitySha256;
        foreach(var change in new[]{"disabled","run","capability","public"}) {
            if(change=="disabled")h.Options.Enabled=false;
            if(change=="run")h.Options.RunId=Guid.NewGuid().ToString("N");
            if(change=="capability")h.Admission.CapabilitySha256=new string('a',64);
            if(change=="public")h.Email.Enabled=true;
            var reads=store.Reads;
            await Assert.ThrowsAsync<EmailPilotAccessUnavailableException>(()=>Use(a=>a.ReadAsync(principal,publicId,session.Receipt,FinalDocumentKind.Executed)));
            await Assert.ThrowsAsync<EmailPilotAccessUnavailableException>(()=>Use(a=>a.RedeemAsync(unused.RawToken)));
            await Assert.ThrowsAsync<EmailPilotAccessUnavailableException>(AcceptedSigner);
            Assert.Equal(reads,store.Reads);
            await using(var db=fixture.Open())Assert.Null((await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==unused.TokenId)).UsedAt);
            h.Options.Enabled=true;h.Options.RunId=run;h.Admission.CapabilitySha256=capability;h.Email.Enabled=false;
        }
        var invalidated=false;store.AfterRead=()=>{invalidated=true;h.Options.Enabled=false;return Task.CompletedTask;};
        await Assert.ThrowsAsync<EmailPilotAccessUnavailableException>(()=>Use(a=>a.ReadAsync(principal,publicId,session.Receipt,FinalDocumentKind.Certificate)));
        Assert.True(invalidated);store.AfterRead=null;h.Options.Enabled=true;
        store.AfterRead=()=>{clock.Advance(end-clock.GetUtcNow()+TimeSpan.FromMilliseconds(1));return Task.CompletedTask;};
        Assert.Null(await Use(a=>a.ReadAsync(principal,publicId,session.Receipt,FinalDocumentKind.Executed)));
        store.AfterRead=null;
        await using(var db=fixture.Open()) {
            Assert.Equal(retained,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Id)).PurgeAfter);
            Assert.Equal(end,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==link.TokenId)).ExpiresAt);
            Assert.Equal(2,await db.EmailPilotReservations.CountAsync(x=>x.RunId==h.RunId && x.Kind==EmailPilotAttemptKind.Timestamp));
        }
        Assert.Equal(2,h.Run.Seal.Requests);Assert.Equal(2,store.Writes);Assert.False(h.Email.Enabled);
    }
}

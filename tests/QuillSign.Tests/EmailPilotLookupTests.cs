using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Data.Common;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.TestHost;
using MimeKit;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotLookupTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private static readonly IDataProtectionProvider LookupKeys=new EphemeralDataProtectionProvider();
    private const string Capability="1234567890123456789012345678901234567890123";

    [Fact]
    public async Task Disabled_or_wrong_operator_capability_never_resolves_dependencies()
    {
        var options=new EmailPilotOptions();var admission=new EmailPilotAdmissionOptions();
        EmailPilotLookupAdmission Service()=>new(options,new(),new(){Enabled=true},admission,
            ()=>throw new Exception("No SQL"),()=>throw new Exception("No ledger"),()=>throw new Exception("No cohort"),
            ()=>throw new Exception("No completion"),()=>throw new Exception("No request"),()=>throw new Exception("No access"),
            ()=>throw new Exception("No keys"),()=>throw new Exception("No retention"),()=>throw new Exception("No signals"),TimeProvider.System);
        Assert.Null(await Service().RequestAsync(Capability,null));options.Enabled=true;
        admission.CapabilitySha256=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(Capability)));
        Assert.Null(await Service().RequestAsync("different",null));
        var sender=new EmailPilotLookupSender(new(),new(),new(),()=>throw new Exception("No access"),()=>throw new Exception("No ledger"),
            ()=>throw new Exception("No SQL"),_=>throw new Exception("No credentials"),TimeProvider.System);
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>sender.SendAsync(null!,null!));
    }

    [Fact]
    public async Task Real_completion_lookup_preserves_null_envelope_and_proves_mailbox_before_exact_cohort_listing_and_download()
    {
        await using var h=await Harness.Create(fixture);
        await using var unrelated=await CompletionDownloadTests.Flow.Create(fixture,mailbox:h.T.Options.Mailboxes.Sender);
        var latest=new[]{h.Time.GetUtcNow(),unrelated.Clock.GetUtcNow()}.Max();h.T.Run.Signing.H.Clock.Advance(latest-h.Time.GetUtcNow()+TimeSpan.FromSeconds(1));
        var admitted=await h.Admit();Assert.False(admitted.Recovered);
        var replay=await h.Admit();Assert.True(replay.Recovered);Assert.Equal(admitted.RequestId,replay.RequestId);
        var row=await h.Db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==admitted.RequestId);
        var work=await h.Db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==admitted.RequestId);
        Assert.Null(row.EnvelopeId);Assert.Null(work.EnvelopeId);Assert.Equal(h.T.Options.Mailboxes.Sender,row.To);
        Assert.False(h.T.Email.Enabled);Assert.Single(await h.Db.EmailPilotLookupRequests.Where(x=>x.RunId==h.T.RunId).ToArrayAsync());
        var result=await h.Deliver(admitted.RequestId);Assert.Equal(WorkOutcome.Completed,result.Outcome);Assert.Equal(1,h.Transport.Calls);
        var token=await h.Db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EmailPilotLookupRequestId==admitted.RequestId);
        Assert.Equal(TokenPurpose.Lookup,token.Purpose);Assert.Null(token.EnvelopeId);Assert.Equal(PartyType.System,token.PartyType);Assert.Null(token.PartyId);Assert.Equal("",token.Email);
        Assert.Single(await h.Db.EmailPilotLookupTokens.Where(x=>x.RequestId==admitted.RequestId).ToArrayAsync());
        var budget=(await h.T.Ledger.ReadBudgetAsync())!;Assert.Equal(1,budget.ApplicationAttempts);Assert.Equal(2,budget.TimestampAttempts);
        var reservation=await h.Db.EmailPilotReservations.AsNoTracking().SingleAsync(x=>x.RunId==h.T.RunId && x.Kind==EmailPilotAttemptKind.Application);
        Assert.Equal(h.T.Id,reservation.SubjectEnvelopeId);Assert.Equal(h.Transport.Bytes!.Length,reservation.EncodedBytes);Assert.Equal(SHA256.HashData(h.Transport.Bytes),reservation.RequestSha256);
        using var mime=MimeMessage.Load(new MemoryStream(h.Transport.Bytes));Assert.Null(mime.Headers["X-QuillSign-Envelope"]);Assert.Single(mime.To);
        var session=Assert.IsType<DocumentLookupSession>(await h.Lookup.RedeemAsync(h.Transport.Code));
        Assert.Null(await h.Lookup.RedeemAsync(h.Transport.Code));
        Assert.True(session.Identity.ExpiresAt<=h.Time.GetUtcNow().AddHours(1));
        var principal=DocumentLookupProtection.Principal(session.Identity);
        h.T.Run.Signing.H.Clock.Advance(TimeSpan.FromMinutes(16)); // A live redeemed session survives its original link expiry.
        var page=Assert.IsType<DocumentLookupPage>(await h.Lookup.ListAsync(principal,session.Receipt));Assert.Equal(h.PublicId,Assert.Single(page.Entries).PublicId);Assert.Null(page.NextCursor);
        Assert.Null(await h.Lookup.ListAsync(principal,session.Receipt,"foreign-cursor"));
        var reads=h.Store.Reads;Assert.Null(await h.Packet.OpenAsync(principal,session.Receipt,unrelated.PublicId));Assert.Equal(reads,h.Store.Reads);
        Assert.Null(await h.Packet.OpenAsync(principal,session.Receipt,Guid.NewGuid().ToString("N")));
        var reader=Assert.IsType<CompletionReaderSession>(await h.Packet.OpenAsync(principal,session.Receipt,h.PublicId));
        Assert.True(reader.Identity.ExpiresAt<=session.Identity.ExpiresAt);
        var bytes=Assert.IsType<CompletionReaderFile>(await h.Reader.ReadAsync(CompletionAccessProtection.Principal(reader.Identity),h.PublicId,reader.Receipt,QuillSign.Storage.FinalDocumentKind.Executed));
        Assert.True(bytes.Pdf.Length>100);Assert.Equal(1,h.Transport.Calls);Assert.Equal(2,h.T.Run.Seal.Requests);
        var marker=await h.Db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==reader.Identity.TokenId);Assert.True(marker.ExpiresAt<=session.Identity.ExpiresAt);
    }

    [Theory]
    [InlineData("disabled")][InlineData("public-email")][InlineData("capability")][InlineData("run")][InlineData("secret")][InlineData("request-binding")][InlineData("source")]
    public async Task Changed_known_authority_never_reaches_provider_or_falls_back(string change)
    {
        await using var h=await Harness.Create(fixture);var request=await h.Admit();
        if(change=="disabled")h.T.Options.Enabled=false;
        if(change=="public-email")h.T.Email.Enabled=true;
        if(change=="capability")h.T.Admission.CapabilitySha256=new string('a',64);
        if(change=="run")h.T.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="secret")await h.Db.EmailPilotSecrets.Where(x=>x.RunId==h.T.RunId).ExecuteDeleteAsync();
        if(change=="request-binding")await h.Db.EmailPilotLookupRequests.Where(x=>x.RequestId==request.RequestId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ProtectedBinding,"corrupt"));
        if(change=="source")await h.Db.WorkItems.Where(x=>x.Id==request.RequestId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
        var result=await h.Deliver(request.RequestId);Assert.Equal(WorkOutcome.Failed,result.Outcome);Assert.Equal(0,h.Transport.Calls);
        Assert.False(await h.Db.EmailPilotReservations.AnyAsync(x=>x.Kind==EmailPilotAttemptKind.Application && x.RunId==h.T.RunId));
    }

    [Theory]
    [InlineData("disabled")][InlineData("capability")][InlineData("run")][InlineData("mapping")][InlineData("token-map")][InlineData("expiry")]
    public async Task Previously_redeemed_lookup_is_denied_after_authority_is_lost(string change)
    {
        await using var h=await Harness.Create(fixture);var request=await h.Admit();await h.Deliver(request.RequestId);
        var session=Assert.IsType<DocumentLookupSession>(await h.Lookup.RedeemAsync(h.Transport.Code));var principal=DocumentLookupProtection.Principal(session.Identity);
        if(change=="disabled")h.T.Options.Enabled=false;
        if(change=="capability")h.T.Admission.CapabilitySha256=new string('a',64);
        if(change=="run")h.T.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="mapping"){await h.Db.EmailPilotLookupTokens.Where(x=>x.RequestId==request.RequestId).ExecuteDeleteAsync();await h.Db.EmailPilotLookupRequests.Where(x=>x.RequestId==request.RequestId).ExecuteDeleteAsync();}
        if(change=="token-map")await h.Db.EmailPilotLookupTokens.Where(x=>x.RequestId==request.RequestId).ExecuteDeleteAsync();
        if(change=="expiry")h.T.Run.Signing.H.Clock.Advance(TimeSpan.FromHours(2));
        Assert.Null(await h.Lookup.AuthenticateAsync(principal,session.Receipt));Assert.Null(await h.Lookup.ListAsync(principal,session.Receipt));
        Assert.Null(await h.Packet.OpenAsync(principal,session.Receipt,h.PublicId));Assert.Equal(1,h.Transport.Calls);
    }

    [Fact]
    public async Task Ordinary_lookup_cannot_list_or_open_an_enrolled_pilot_completion()
    {
        await using var h=await Harness.Create(fixture);var link=await h.Lookup.IssueAsync(h.T.Options.Mailboxes.Sender);
        var session=Assert.IsType<DocumentLookupSession>(await h.Lookup.RedeemAsync(link.Transport));var principal=DocumentLookupProtection.Principal(session.Identity);
        var page=Assert.IsType<DocumentLookupPage>(await h.Lookup.ListAsync(principal,session.Receipt));Assert.Empty(page.Entries);
        Assert.Null(await h.Packet.OpenAsync(principal,session.Receipt,h.PublicId));Assert.Equal(0,h.Transport.Calls);
    }

    [Fact]
    public async Task Marker_cannot_restore_mailbox_wide_authority_when_optional_gate_is_absent()
    {
        await using var h=await Harness.Create(fixture);var request=await h.Admit();await h.Deliver(request.RequestId);
        var ordinary=new DocumentLookup(h.Db,h.State,new(h.T.Keys,h.Time),new(),h.Time);
        Assert.Null(await ordinary.RedeemAsync(h.Transport.Code));Assert.Equal(1,h.Transport.Calls);
    }

    [Fact]
    public async Task Concurrent_explicit_requests_recover_one_original_request_and_lost_commit_ack_never_duplicates_it()
    {
        await using var h=await Harness.Create(fixture);
        await using var first=fixture.Open();await using var second=fixture.Open();
        var results=await Task.WhenAll(h.For(first).Admit(),h.For(second).Admit());
        Assert.Equal(results[0].RequestId,results[1].RequestId);Assert.Single(results,x=>!x.Recovered);
        Assert.Equal(1,await h.Db.EmailPilotLookupRequests.CountAsync(x=>x.RunId==h.T.RunId));
        Assert.Equal(0,h.Transport.Calls);
    }

    [Fact]
    public async Task Lost_admission_commit_acknowledgement_recovers_exact_existing_outbox_and_mapping()
    {
        await using var h=await Harness.Create(fixture);var fault=new LostAdmissionCommit();
        await using var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(h.Db.Database.GetConnectionString()).AddInterceptors(fault).Options);
        await Assert.ThrowsAsync<IOException>(()=>h.For(db).Admission.RequestAsync(Capability,"192.0.2.1"));
        var recovered=await h.Admit();Assert.True(recovered.Recovered);Assert.True(recovered.WakeupPublished);
        Assert.Equal(1,await h.Db.EmailPilotLookupRequests.CountAsync(x=>x.RunId==h.T.RunId));
        Assert.Equal(1,await h.Db.EmailOutbox.CountAsync(x=>x.Id==recovered.RequestId));Assert.Equal(0,h.Transport.Calls);
    }

    [Fact]
    public async Task Unknown_provider_result_consumes_one_application_attempt_and_recovery_never_replays_it()
    {
        await using var h=await Harness.Create(fixture);var request=await h.Admit();h.Transport.Failure=new IOException("Synthetic unknown submission");
        await Assert.ThrowsAsync<IOException>(()=>h.Deliver(request.RequestId));Assert.Equal(1,h.Transport.Calls);
        var row=await h.Db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==request.RequestId);Assert.NotNull(row.SubmissionStartedAt);
        var item=await h.Db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==request.RequestId);
        var lease=new WorkLease(item.Id,item.LeaseOwner!.Value,item.Kind,item.Attempts,item.LeaseExpiresAt!.Value);
        var message=new OutgoingEmail(h.T.Options.Mailboxes.Sender,"Replay","Replay","Replay");
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>h.Sender.SendAsync(lease,message));Assert.Equal(1,h.Transport.Calls);
        h.T.Run.Signing.H.Clock.Advance(lease.Until-h.Time.GetUtcNow());
        var recovered=await new WorkStore(h.Db,h.T.Work,h.Time).ClaimAsync(request.RequestId,default);Assert.True(recovered.Terminal);
        Assert.Equal("submission-ambiguous",(await h.Db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==request.RequestId)).LastError);
        Assert.Equal(1,(await h.T.Ledger.ReadBudgetAsync())!.ApplicationAttempts);
    }

    [Theory]
    [InlineData("expiry")][InlineData("capability")]
    public async Task Actual_admission_commit_crossing_authority_cutoff_returns_no_stale_result(string change)
    {
        await using var h=await Harness.Create(fixture);var fault=new LostAdmissionCommit{After=()=>{
            if(change=="expiry")h.T.Run.Signing.H.Clock.Advance(TimeSpan.FromHours(2));else h.T.Admission.CapabilitySha256=new string('a',64);
        }};
        await using var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(h.Db.Database.GetConnectionString()).AddInterceptors(fault).Options);
        Assert.Null(await h.For(db).Admission.RequestAsync(Capability,"192.0.2.1"));Assert.Equal(0,h.Transport.Calls);
        Assert.Equal(1,await h.Db.EmailPilotLookupRequests.CountAsync(x=>x.RunId==h.T.RunId));
    }

    private sealed class LostAdmissionCommit:DbTransactionInterceptor,ISaveChangesInterceptor
    {
        internal Action? After;private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> result,CancellationToken ct=default)
        {if(e.Context!.ChangeTracker.Entries<EmailPilotLookupRequestRecord>().Any(x=>x.State==EntityState.Added))armed=true;return ValueTask.FromResult(result);}
        public override Task TransactionCommittedAsync(DbTransaction tx,TransactionEndEventData e,CancellationToken ct=default)
        {if(armed){armed=false;if(After is not null){After();return Task.CompletedTask;}throw new IOException("Synthetic unknown admission commit acknowledgement");}return Task.CompletedTask;}
    }

    [Fact]
    public async Task App_role_can_insert_read_only_mapping_evidence_but_cannot_rewrite_or_delete_it_or_change_token_markers()
    {
        await using var db=fixture.Open();Assert.False(db.Database.HasPendingModelChanges());
        foreach(var type in new[]{typeof(EmailPilotLookupRequestRecord),typeof(EmailPilotLookupTokenRecord)})
            Assert.All(db.Model.FindEntityType(type)!.GetForeignKeys(),fk=>Assert.DoesNotContain(fk.PrincipalEntityType.ClrType,new[]{typeof(Envelope),typeof(AuthToken),typeof(EmailOutbox)}));
        await db.Database.OpenConnectionAsync();var connection=(Microsoft.Data.SqlClient.SqlConnection)db.Database.GetDbConnection();
        await using var command=connection.CreateCommand();command.CommandText="IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN";await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection);command.CommandText="EXECUTE AS USER='app_runtime'";await command.ExecuteNonQueryAsync();
        try
        {
            foreach(var table in new[]{"EmailPilotLookupRequests","EmailPilotLookupTokens"})
            {
                foreach(var permission in new[]{"SELECT","INSERT","UPDATE","DELETE"})
                {command.CommandText=$"SELECT HAS_PERMS_BY_NAME('dbo.{table}','OBJECT','{permission}')";Assert.Equal(permission is "SELECT" or "INSERT"?1:0,Convert.ToInt32(await command.ExecuteScalarAsync()));}
            }
            command.CommandText="SELECT HAS_PERMS_BY_NAME('dbo.AuthTokens','OBJECT','UPDATE','EmailPilotLookupRequestId','COLUMN')";Assert.Equal(0,Convert.ToInt32(await command.ExecuteScalarAsync()));
        }
        finally{command.CommandText="REVERT";await command.ExecuteNonQueryAsync();}
    }

    [Fact]
    public void Ordinary_lookup_payload_serialization_keeps_legacy_bytes_without_pilot_authority()
    {
        var payload=new LookupMailPayload("lookup-mail-v1",Guid.NewGuid(),"sender@example.invalid",new string('a',64),DateTimeOffset.UtcNow,DateTimeOffset.UtcNow.AddHours(1),null);
        Assert.DoesNotContain("PilotRunId",System.Text.Json.JsonSerializer.Serialize(payload));
        Assert.DoesNotContain("EmailPilotLookupRequestId",System.Text.Json.JsonSerializer.Serialize(new AuthToken()));
    }

    [Fact]
    public async Task Private_browser_uses_normal_mailbox_confirmation_and_CSRF_without_restoring_public_intake()
    {
        await using var h=await Harness.Create(fixture);var request=await h.Admit();await h.Deliver(request.RequestId);
        await using var browser=await PilotLookupBrowserFixture.Create(h);
        if(int.TryParse(Environment.GetEnvironmentVariable("QUILLSIGN_PILOT_LOOKUP_BROWSER_PORT"),out _))
        {
            await browser.PauseForBrowser();return;
        }
        using var client=browser.App.GetTestClient();
        var cookies=new Dictionary<string,string>();
        void Take(HttpResponseMessage response)
        {
            if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values){var pair=value.Split(';')[0].Split('=',2);if(pair[1].Length==0)cookies.Remove(pair[0]);else cookies[pair[0]]=pair[1];}
            client.DefaultRequestHeaders.Remove("Cookie");if(cookies.Count>0)client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value)));
        }
        async Task<string> Get(string path)
        {
            using var response=await client.GetAsync(path);Take(response);Assert.Equal(System.Net.HttpStatusCode.OK,response.StatusCode);
            Assert.Contains("no-store",response.Headers.CacheControl!.ToString());Assert.Contains("noindex",string.Join(",",response.Headers.GetValues("X-Robots-Tag")));
            return await response.Content.ReadAsStringAsync();
        }
        async Task<HttpResponseMessage> Post(string path,string page,Dictionary<string,string> values,bool csrf=true)
        {if(csrf)values["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page);var response=await client.PostAsync(path,new FormUrlEncodedContent(values));Take(response);return response;}
        var page=await Get("/find/access");
        using(var denied=await Post("/find/access/Begin",page,new(){["code"]=h.Transport.Code},false))Assert.Equal(System.Net.HttpStatusCode.BadRequest,denied.StatusCode);
        using(var begin=await Post("/find/access/Begin",page,new(){["code"]=h.Transport.Code}))Assert.Equal("/find/access",begin.Headers.Location!.OriginalString);
        page=await Get("/find/access");var nonce=Regex.Match(page,"name=\"nonce\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;Assert.NotEmpty(nonce);
        using(var redeem=await Post("/find/access/Redeem",page,new(){["nonce"]=nonce}))Assert.Equal("/find/documents",redeem.Headers.Location!.OriginalString);
        page=await Get("/find/documents");Assert.Contains(h.PublicId,page);Assert.DoesNotContain(h.T.Options.Mailboxes.Sender,page);
        using(var bad=await Post("/find/documents/Open",page,new(){["publicId"]=h.PublicId},false))Assert.Equal(System.Net.HttpStatusCode.BadRequest,bad.StatusCode);
        using(var opened=await Post("/find/documents/Open",page,new(){["publicId"]=h.PublicId}))Assert.Equal("/complete/"+h.PublicId,opened.Headers.Location!.OriginalString);
        Assert.Contains("Download",await Get("/complete/"+h.PublicId));Assert.False(h.T.Email.Enabled);Assert.Equal(1,h.Transport.Calls);
    }

    internal sealed class Harness : IAsyncDisposable
    {
        internal PilotTimestampBoundaryTests.Harness T=null!;internal QuillSignDbContext Db=null!;internal TimeProvider Time=>T.Run.Signing.H.Clock;
        internal CompletionDownloadTests.FinalStore Store=null!;internal CompletionPublication Publication=null!;internal CompletionAccessState State=null!;
        internal EmailPilotLookupAccess Access=null!;internal EmailPilotLookupAdmission Admission=null!;internal DocumentLookup Lookup=null!;
        internal CompletionAccess Reader=null!;internal LookupPacketAccess Packet=null!;internal LookupContactRetention Retention=null!;internal LookupDeliveryProtection Payload=null!;
        internal LookupDeliveryOptions Limits=new(){DailyRequests=1000,DailyAddressRequests=1000,DailyIpRequests=1000};internal Capture Transport=new();
        internal EmailPilotLookupSender Sender=null!;internal string PublicId=>T.Run.Signing.Envelope.PublicId;
        internal EmailPilotEnvelopeAccess Cohorts=>new(()=>Db,()=>T.LedgerFor(Db),()=>T.Payload,T.Admission,T.Work);
        internal static async Task<Harness> Create(SqlDatabaseFixture fixture)
        {
            var h=new Harness{T=await PilotTimestampBoundaryTests.Harness.Create(fixture)};h.Db=h.T.Db;
            Assert.NotNull(await h.T.Outputs.PrepareAsync(h.T.Id,timestampWork:await h.T.Context()));
            h.Store=new(h.Time);h.Publication=new(h.Db,h.T.Run.Candidates(h.Db),h.T.Outputs,h.T.Run.Collector(h.Db),h.Store,new(h.Db,h.Time),h.Time,
                new(){DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},h.T.Run.Seal.App.Environment);
            Assert.NotNull(await h.Publication.PublishAsync(h.T.Id));
            h.Bind();
            return h;
        }
        private void Bind()
        {
            var h=this;
            h.State=new(h.Db,h.T.Run.Collector(h.Db),()=>h.Publication,h.Time);
            h.Payload=new(LookupKeys);h.Retention=new(h.Db,new(){Days=7},h.Payload,()=>h.T.Run.Signing.H.Signals,h.Time);
            h.Access=new(()=>h.Db,()=>new(h.T.Keys),()=>h.Cohorts,()=>h.T.LedgerFor(h.Db),h.T.Admission,h.T.Work,()=>h.Payload,()=>h.Retention,h.Limits,()=>h.State,h.Time);
            h.Lookup=new(h.Db,h.State,new(h.T.Keys,h.Time),new(),h.Time,h.Access);
            h.Reader=new(h.Db,h.State,new(h.T.Keys,h.Time),new(),new(h.Db,h.Time),h.Time,()=>h.Publication);
            h.Packet=new(h.Db,h.Lookup,h.Reader,h.State,new(h.Db,h.Time),h.Time);
            var requests=new DocumentLookupRequests(h.Db,h.Limits,h.Payload,h.T.Email,h.T.Work,()=>h.T.Run.Signing.H.Signals,h.Time,h.Retention);
            h.Admission=new(h.T.Options,h.T.Email,h.T.Work,h.T.Admission,()=>h.Db,()=>h.T.LedgerFor(h.Db),()=>h.Cohorts,()=>h.State,()=>requests,()=>h.Access,()=>new(h.T.Keys),()=>h.Retention,()=>h.T.Run.Signing.H.Signals,h.Time);
            h.T.Email.Provider="Ses";h.T.Email.Ses.Region="us-east-1";h.T.Email.Ses.ConfigurationSet="synthetic";
            h.Sender=new(h.T.Options,h.T.Email,h.T.Work,()=>h.Access,()=>h.T.LedgerFor(h.Db),()=>h.Db,_=>h.Transport,h.Time);
        }
        internal Harness For(QuillSignDbContext db)
        {
            var h=new Harness{T=T,Db=db,Store=Store,Transport=Transport,Limits=Limits};
            h.Publication=new(db,T.Run.Candidates(db),T.Run.Service(db),T.Run.Collector(db),Store,new(db,Time),Time,
                new(){DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},T.Run.Seal.App.Environment);
            h.Bind();return h;
        }
        internal async Task<EmailPilotLookupAdmissionResult> Admit()=>Assert.IsType<EmailPilotLookupAdmissionResult>(await Admission.RequestAsync(Capability,"192.0.2.1"));
        internal async Task<WorkResult> Deliver(Guid id)
        {
            var lease=(await new WorkStore(Db,T.Work,Time).ClaimAsync(id,default)).Lease!;Assert.NotNull(lease);
            var app=T.Run.Signing.H.App;using var viewScope=app.Services.CreateScope();
            var delivery=new LookupLinkDelivery(Db,Limits,Payload,new(T.Keys,Time),()=>Lookup,
                ()=>new(T.Email,viewScope.ServiceProvider.GetRequiredService<RazorEmailViews>(),new(T.Keys,Time),app.Environment),
                new NoOrdinarySender(),T.Email,T.Work,Time,Retention,Access,()=>Sender);
            return await delivery.ExecuteAsync(lease,default);
        }
        public async ValueTask DisposeAsync()=>await T.DisposeAsync();
    }
    internal sealed class Capture:IPreparedEmailTransport
    {
        internal int Calls;internal byte[]? Bytes;internal string Code="";internal Exception? Failure;
        public async Task<EmailDelivery> SendAsync(PreparedRawMime mime,CancellationToken ct)
        {
            Calls++;using var input=mime.OpenRead();using var output=new MemoryStream();await input.CopyToAsync(output,ct);Bytes=output.ToArray();
            using var parsed=MimeMessage.Load(new MemoryStream(Bytes));Code=Regex.Match(parsed.TextBody!,@"#token=([A-Za-z0-9_-]+)").Groups[1].Value;Assert.NotEmpty(Code);
            if(Failure is not null)throw Failure;return new("Ses","synthetic-lookup-receipt");
        }
    }
    private sealed class NoOrdinarySender:IEmailSender
    {public Task<EmailDelivery> SendAsync(OutgoingEmail mail,CancellationToken ct=default)=>throw new Exception("Ordinary sender must stay disabled.");}
}

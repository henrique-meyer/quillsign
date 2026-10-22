using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotCoexistenceTests
{
    [Fact]
    public void Shared_purpose_binds_mode_and_private_set_but_not_host_role_and_preserves_legacy_bytes()
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();var legacy=JsonSerializer.Serialize(h.Options.Capture());
        Assert.DoesNotContain("Coexistence",legacy);Assert.DoesNotContain("HostRole",legacy);
        h.Options.HostRole=EmailPilotCloseoutHostRole.Web;h.Options.PrivateConfigurationSet="private-set";
        var web=JsonSerializer.Serialize(h.Options.Capture());Assert.Contains("filtered-closeout-coexistence-v1",web);
        h.Options.HostRole=EmailPilotCloseoutHostRole.Pass;Assert.Equal(web,JsonSerializer.Serialize(h.Options.Capture()));
        h.Options.HostRole=EmailPilotCloseoutHostRole.Handoff;Assert.Equal(web,JsonSerializer.Serialize(h.Options.CaptureReceiptConfiguration()));
        h.Options.PrivateConfigurationSet="rotated";Assert.NotEqual(web,JsonSerializer.Serialize(h.Options.CaptureReceiptConfiguration()));
    }
    [Theory]
    [InlineData(EmailPilotCloseoutHostRole.Web,true,false)]
    [InlineData(EmailPilotCloseoutHostRole.Pass,false,true)]
    [InlineData(EmailPilotCloseoutHostRole.Handoff,false,false)]
    public void Closed_roles_cannot_enable_another_execution_plane(EmailPilotCloseoutHostRole role,bool browser,bool sender)
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();h.Email.Enabled=true;h.Email.Ses.ConfigurationSet="normal";
        h.Options.HostRole=role;h.Options.PrivateConfigurationSet="private";if(role==EmailPilotCloseoutHostRole.Handoff)h.Options.Enabled=false;
        Assert.Equal(browser,h.Options.Host(h.Email,h.Work,true));
        var c=new EmailPilotCloseout(h.Options,h.Email,h.Work,()=>throw new InvalidOperationException(),()=>throw new InvalidOperationException(),()=>new(h.Keys),h.Clock);
        Assert.Equal(sender,c.CanSend);Assert.Equal(role==EmailPilotCloseoutHostRole.Web,c.CanAdmit);Assert.Equal(role==EmailPilotCloseoutHostRole.Pass,c.PassHost);
        Assert.Equal(browser,h.Browser.Available);
    }
    [Theory]
    [InlineData("")][InlineData("bad value")][InlineData("bad/arn")][InlineData("*")]
    public void Invalid_private_set_never_becomes_enabled(string set)
    {var h=new EmailPilotCloseoutBrowserTests.Harness();h.Options.HostRole=EmailPilotCloseoutHostRole.Web;h.Options.PrivateConfigurationSet=set;Assert.Throws<InvalidOperationException>(h.Options.Validate);}
    [Fact]
    public void Normal_set_may_not_be_relabelled_private_and_legacy_stays_EmailOFF()
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();h.Email.Enabled=true;h.Email.Ses.ConfigurationSet="same";Assert.False(h.Options.Host(h.Email,h.Work));
        h.Options.HostRole=EmailPilotCloseoutHostRole.Web;h.Options.PrivateConfigurationSet="same";Assert.False(h.Options.Host(h.Email,h.Work));Assert.False(h.Browser.Available);
        h.Options.PrivateConfigurationSet="private";Assert.True(h.Options.Host(h.Email,h.Work));h.Email.Enabled=false;Assert.False(h.Options.Host(h.Email,h.Work));
    }
    [Fact]
    public void Send25_is_independent_of_original_settlement_and_cookie_Until30()
    {
        const string capability="1234567890123456789012345678901234567890123";
        var h=new EmailPilotCloseoutBrowserTests.Harness();h.Email.Enabled=true;h.Email.Ses.ConfigurationSet="normal";h.Options.PrivateConfigurationSet="private";h.Options.HostRole=EmailPilotCloseoutHostRole.Web;
        var http=new DefaultHttpContext();http.Request.Scheme="http";http.Request.Host=new("localhost");Assert.True(h.Browser.Unlock(http,capability));
        var cookie=http.Response.Headers.SetCookie.Single()!.Split(';')[0];h.Options.HostRole=EmailPilotCloseoutHostRole.Pass;
        var c=new EmailPilotCloseout(h.Options,h.Email,h.Work,()=>throw new InvalidOperationException(),()=>throw new InvalidOperationException(),()=>new(h.Keys),h.Clock);
        h.Clock.Now=h.Options.StartsAt.AddMinutes(25).AddTicks(-1);Assert.True(c.CanSend);h.Clock.Now=h.Options.StartsAt.AddMinutes(25);Assert.False(c.CanSend);Assert.False(c.CanAdmit);Assert.True(c.Available);
        h.Options.HostRole=EmailPilotCloseoutHostRole.Web;var request=new DefaultHttpContext();request.Request.Headers.Cookie=cookie;Assert.NotNull(h.Browser.Read(request));
        h.Clock.Now=h.Options.Until;Assert.Null(h.Browser.Read(request));Assert.False(c.Available);
    }
    [Theory]
    [InlineData("none")][InlineData("body")][InlineData("work")][InlineData("kind")][InlineData("legacy")][InlineData("oversized")]
    public void Coexistence_dynamic_snapshot_is_exact_hash_bound_and_bounded_without_changing_legacy_receipt_bytes(string fault)
    {
        var record=Guid.NewGuid();var work=Guid.NewGuid();var queue=new EmailPilotCloseoutQueue(EmailPilotCloseoutStep.DeclineVerification,record,work,"{}","{}");
        var hash=Convert.ToHexStringLower(EmailPilotCanonical.Hash(new{Mail=queue.MailJson,Work=queue.WorkJson}));
        var receipt=new EmailPilotCloseoutReceipt(EmailPilotCloseoutLimits.Version,Guid.NewGuid(),0,queue.Step,record,work,DateTimeOffset.UtcNow,0,hash,Queued:queue);
        var legacy=receipt with{Queued=null};Assert.DoesNotContain("Queued",JsonSerializer.Serialize(legacy));EmailPilotCloseout.DemandBoundQueue(legacy,false);
        if(fault=="none"){EmailPilotCloseout.DemandBoundQueue(receipt,true);return;}
        receipt=fault switch {"body"=>receipt with{Queued=queue with{MailJson="{\"Changed\":true}"}},"work"=>receipt with{Queued=queue with{WorkId=Guid.NewGuid()}},"kind"=>receipt with{Kind=1},"oversized"=>receipt with{Queued=queue with{MailJson=new string('x',8192)}},_=>receipt};
        Assert.Throws<InvalidDataException>(()=>EmailPilotCloseout.DemandBoundQueue(receipt,fault!="legacy"));
    }
    [Fact]
    public void Handoff_cannot_be_enabled_as_a_positive_purpose()
    {var h=new EmailPilotCloseoutBrowserTests.Harness();h.Options.HostRole=EmailPilotCloseoutHostRole.Handoff;h.Options.PrivateConfigurationSet="private";Assert.Throws<InvalidOperationException>(h.Options.Validate);}
    [Fact]
    public void Normal_startup_cannot_resolve_a_pass_role_as_an_ordinary_host()
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"EmailPilot:Closeout:HostRole","Pass"},{"EmailPilot:Closeout:PrivateConfigurationSet","private"}}).Build();
        Assert.Throws<InvalidOperationException>(()=>new ServiceCollection().AddRestrictedEmailPilotRuntime(config));
        // Explicit command host registration has no queue/provider/SQL resolution.
        new ServiceCollection().AddRestrictedEmailPilotRuntime(config,privatePass:true);
    }
    [Fact]
    public void Only_explicit_handoff_recovery_registers_SQL_and_key_ring_without_handlers_or_transport()
    {
        var environment=new TestEnvironment();var none=new ConfigurationBuilder().Build();var defaults=new ServiceCollection();
        defaults.AddCloseoutHandoffRecovery(none,environment);Assert.DoesNotContain(defaults,x=>x.ServiceType==typeof(QuillSignDbContext));
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{
            {"EmailPilot:Closeout:HostRole","Handoff"},{"EmailPilot:Closeout:PrivateConfigurationSet","private"},
            {"Email:Enabled","true"},{"Email:Ses:ConfigurationSet","normal"},{"Storage:Provider","Azure"},
            {"Storage:BlobServiceUri","https://storage.example.invalid/"},{"DataProtection:KeyVaultKeyIdentifier","https://keys.example.invalid/keys/data-protection"},
            {"ConnectionStrings:Database","Server=localhost;Database=synthetic;Integrated Security=true;TrustServerCertificate=true"}}).Build();
        var services=new ServiceCollection();services.AddLogging();services.AddSingleton(new WorkOptions{Enabled=true});services.AddCloseoutHandoffRecovery(config,environment);
        Assert.Contains(services,x=>x.ServiceType==typeof(QuillSignDbContext));Assert.Contains(services,x=>x.ServiceType==typeof(IDataProtectionProvider));
        Assert.DoesNotContain(services,x=>x.ServiceType==typeof(IWorkHandler)||x.ServiceType==typeof(IEmailSender)||x.ServiceType==typeof(IPreparedEmailTransport));
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<QuillSignDbContext>());Assert.NotNull(scope.ServiceProvider.GetRequiredService<EmailPilotCloseout>());
    }
    private sealed class TestEnvironment:Microsoft.Extensions.Hosting.IHostEnvironment
    {public string EnvironmentName{get;set;}="Production";public string ApplicationName{get;set;}="Synthetic";public string ContentRootPath{get;set;}=".";public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider{get;set;}=new Microsoft.Extensions.FileProviders.NullFileProvider();}
    [Fact]
    public async Task Disabled_legacy_handler_keeps_its_zero_SQL_short_circuit()
    {
        var handler=new EmailWorkHandler(null!,new(),null!,null!,null!,TimeProvider.System);
        var result=await handler.ExecuteAsync(new(Guid.NewGuid(),Guid.NewGuid(),WorkKind.Email,1,DateTimeOffset.UtcNow.AddMinutes(5)),default);
        Assert.Equal(new WorkResult(WorkOutcome.Retry,"delivery-disabled"),result);
    }
    [Theory]
    [InlineData(EmailPilotCloseoutHostRole.Web,false)]
    [InlineData(EmailPilotCloseoutHostRole.Pass,true)]
    public async Task Web_or_original25_cutoff_cannot_reach_SQL_reservation_or_lazy_provider(EmailPilotCloseoutHostRole role,bool cutoff)
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();h.Email.Enabled=true;h.Email.Ses.ConfigurationSet="normal";h.Options.PrivateConfigurationSet="private";h.Options.HostRole=role;
        if(cutoff)h.Clock.Now=h.Options.StartsAt.AddMinutes(25);
        var reads=0;var providers=0;var core=new EmailPilotCloseout(h.Options,h.Email,h.Work,()=>{reads++;throw new InvalidOperationException();},()=>throw new InvalidOperationException(),()=>new(h.Keys),h.Clock);
        var sender=new EmailPilotCloseoutSender(h.Email,()=>core,()=>{reads++;throw new InvalidOperationException();},_=>{providers++;throw new InvalidOperationException();},h.Clock);
        await Assert.ThrowsAsync<EmailPilotTransportRefusedException>(()=>sender.SendAsync(new(Guid.NewGuid(),Guid.NewGuid(),WorkKind.Email,1,h.Options.Until),new("sender@example.invalid","subject","text","html")));
        Assert.Equal(0,reads);Assert.Equal(0,providers);
    }
}

public sealed class EmailPilotCoexistenceClaimTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Known_private_hint_handoff_preserves_every_SQL_byte_and_does_not_starve_ordinary_work(bool malformed)
    {
        await using var db=fixture.Open();var at=DateTimeOffset.UtcNow;var parent=new Envelope{SenderEmail="sender@example.invalid"};db.Add(parent);await db.SaveChangesAsync();
        var originalId=Guid.NewGuid();var ordinaryId=Guid.NewGuid();var auth=Guid.NewGuid();var privateId=malformed?EmailPilotCloseout.AliasId(auth,originalId):Guid.NewGuid();
        if(malformed)db.Add(new WorkItem{Id=originalId,EnvelopeId=parent.Id,Kind=WorkKind.Email,AvailableAt=at,PayloadJson="{}"});
        db.Add(new EmailPilotCloseoutHeaderRecord{Id=auth,CreatedAt=at,Until=at.AddMinutes(30),DeleteAfter=at.AddDays(1),CapabilitySha256=new byte[32],ManifestSha256=new byte[32],ProtectedManifest=null});
        if(!malformed)db.Add(new EmailPilotCloseoutOperationRecord{Id=Guid.NewGuid(),CloseoutId=auth,Kind=0,Step=(int)EmailPilotCloseoutStep.DeclineVerification,SubjectEnvelopeId=parent.Id,WorkId=privateId,At=at,EncodedBytes=0,RequestSha256=new byte[32],ProtectedReceipt="denial-only-not-authority"});
        foreach(var id in new[]{privateId,ordinaryId})db.AddRange(new EmailOutbox{Id=id,EnvelopeId=malformed&&id==privateId?null:parent.Id,To=parent.SenderEmail,Template="sender-verification",PayloadJson="{\"Protected\":\"not-provider-authority\"}",AvailableAt=at},new WorkItem{Id=id,EnvelopeId=parent.Id,Kind=WorkKind.Email,AvailableAt=at,PayloadJson="{}"});
        await db.SaveChangesAsync();db.ChangeTracker.Clear();var before=await Rows(db,privateId);
        try {
        var email=new EmailOptions{Enabled=true,Ses=new(){ConfigurationSet="normal"}};var work=new WorkOptions{Enabled=true};
        var closeout=new EmailPilotCloseout(new(){HostRole=EmailPilotCloseoutHostRole.Handoff,PrivateConfigurationSet="private"},email,work,()=>db,()=>throw new InvalidOperationException(),()=>throw new InvalidOperationException(),TimeProvider.System);
        var signals=new Signals(privateId,ordinaryId);var handler=new NormalHandler();var processor=new WorkProcessor(new(db,work,TimeProvider.System,closeout),signals,[handler],TimeProvider.System);
        Assert.True(await processor.RunOnceAsync(default));db.ChangeTracker.Clear();Assert.Equal(before,await Rows(db,privateId));Assert.Equal(0,handler.Calls);Assert.Empty(signals.Acknowledged);Assert.Equal(1,signals.Deferred);
        Assert.True(await processor.RunOnceAsync(default));Assert.Equal(1,handler.Calls);Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==ordinaryId)).Status);
        Assert.Equal(1,signals.Deferred);Assert.Equal(TimeSpan.FromMinutes(15),signals.DeferredFor);Assert.Single(signals.Postponed);Assert.Single(signals.Acknowledged);Assert.Equal(before,await Rows(db,privateId));
        var authority=new EmailPilotWorkAuthority(new(),email,work,new(),()=>throw new InvalidOperationException(),()=>db,()=>throw new InvalidOperationException(),TimeProvider.System){Closeout=()=>closeout};
        var ordinarySends=0;var dispatch=new EmailPilotDispatch(db,email,()=>authority,(_,_,_)=>throw new InvalidOperationException("No private provider"),new NeverSender(()=>ordinarySends++));
        var privateLease=new WorkLease(privateId,Guid.NewGuid(),WorkKind.Email,1,at.AddMinutes(5));
        Assert.Equal(EmailPilotDispatchRoute.RefusedKnown,(await dispatch.DecideAsync(privateLease,default)).Route);
        await Assert.ThrowsAsync<EmailDisabledException>(()=>dispatch.SendAsync(privateLease,null!,default));Assert.Equal(0,ordinarySends);Assert.Equal(before,await Rows(db,privateId));
        // An accidentally selected pass host may not claim the ordinary row.
        var pass=new EmailPilotCloseout(new(){Enabled=true,HostRole=EmailPilotCloseoutHostRole.Pass,PrivateConfigurationSet="private"},email,work,()=>db,()=>throw new InvalidOperationException(),()=>throw new InvalidOperationException(),TimeProvider.System);
        await using var tx=await db.Database.BeginTransactionAsync();var normal=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==ordinaryId);
        await Assert.ThrowsAsync<InvalidDataException>(()=>pass.DemandClaimLockedAsync(db,normal,default));await tx.RollbackAsync();
        } finally {
            db.ChangeTracker.Clear();await db.EmailPilotCloseoutOperations.Where(x=>x.CloseoutId==auth).ExecuteDeleteAsync();await db.EmailPilotCloseouts.Where(x=>x.Id==auth).ExecuteDeleteAsync();
            var owned=new[]{privateId,ordinaryId,originalId};await db.EmailOutbox.Where(x=>owned.Contains(x.Id)).ExecuteDeleteAsync();await db.WorkItems.Where(x=>owned.Contains(x.Id)).ExecuteDeleteAsync();await db.Envelopes.Where(x=>x.Id==parent.Id).ExecuteDeleteAsync();
        }
    }
    private static async Task<string> Rows(QuillSignDbContext db,Guid id)=>JsonSerializer.Serialize(new{Work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id),Mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==id)});
    private sealed class NormalHandler:IWorkHandler{public WorkKind Kind=>WorkKind.Email;internal int Calls;public Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct){Calls++;return Task.FromResult(new WorkResult(WorkOutcome.Completed));}}
    private sealed class NeverSender(Action called):IEmailSender{public Task<EmailDelivery> SendAsync(OutgoingEmail mail,CancellationToken ct=default){called();throw new InvalidOperationException("No ordinary fallback");}}
    private sealed class Signals(params Guid[] ids):IWorkSignals
    {
        private readonly Queue<Guid> pending=new(ids);internal readonly List<Guid> Acknowledged=[];internal int Deferred;internal TimeSpan DeferredFor;internal readonly List<Guid> Postponed=[];
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>Task.FromResult(pending.TryDequeue(out var id)?new WorkDelivery(id.ToString("N"),"synthetic",id):null);
        public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>Task.FromResult<DateTimeOffset?>(null);
        public Task AcknowledgeAsync(WorkDelivery d,CancellationToken ct){Acknowledged.Add(d.WorkId!.Value);return Task.CompletedTask;}
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>Task.CompletedTask;
        public Task DeferAsync(WorkDelivery d,TimeSpan delay,CancellationToken ct){Deferred++;DeferredFor=delay;return Task.CompletedTask;}
        public Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct){Postponed.Add(id);return Task.CompletedTask;}
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct)=>throw new InvalidOperationException("No publish");
        public Task<int> RecoverAsync(DateTimeOffset at,CancellationToken ct)=>throw new InvalidOperationException("No recovery");
        public Task VerifyAsync(CancellationToken ct)=>throw new InvalidOperationException("No verify");
    }
}

// Own xUnit fixture database: the selected one-header protocol must not share a
// database with the legacy genuine case. Reuses exactly the existing setup.
public sealed class EmailPilotCoexistenceRuntimeTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public Task Direct_pass_isolates_private_MIME_and_preserves_normal_email_and_failed_originals()=>new EmailPilotFailedNoticeRuntimeTests(fixture).GenuineAlias(true);
}

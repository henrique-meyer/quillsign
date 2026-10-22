using System.Data;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotCommittedReceiptTests
{
    [Fact]
    public async Task Receipt_deadline_crossed_during_final_read_rollback_never_returns_an_export()
    {
        await using var h=await ReceiptFixture.Create();var session=h.Login();var connection=h.Db.Database.GetConnectionString();
        await h.Db.DisposeAsync();h.Db=new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection)
            .AddInterceptors(new ExpireOnRollback(h.Clock,h.Options.Until)).Options);
        await Assert.ThrowsAsync<EmailDisabledException>(()=>h.Operator.ReadCommittedReceiptAsync(session));
        Assert.NotNull((await h.Db.EmailPilotCloseouts.AsNoTracking().SingleAsync()).ProtectedManifest);
    }
    [Fact]
    public async Task Factual_read_and_cleanup_stages_refuse_a_nonserializable_transaction_before_effects()
    {
        await using var h=await ReceiptFixture.Create(expired:true);var expected=await h.Operator.ReadCommittedReceiptAsync(h.Login());
        await using var tx=await h.Db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        await Assert.ThrowsAsync<InvalidDataException>(()=>h.Core.ReadCommittedReceiptLockedAsync(h.Db,expected.AuthorizationId,default));
        await Assert.ThrowsAsync<InvalidDataException>(()=>HostedCloseoutCleanupReceipt.ApplyLockedAsync(h.Db,expected,default));
        Assert.NotNull((await h.Db.EmailPilotCloseouts.AsNoTracking().SingleAsync()).ProtectedManifest);await tx.RollbackAsync();
    }
    private sealed class ExpireOnRollback(ReceiptFixture.ClockProvider clock,DateTimeOffset until):DbTransactionInterceptor
    {public override Task TransactionRolledBackAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken cancellationToken=default){clock.Now=until;return Task.CompletedTask;}}
    [Fact]
    public async Task Fresh_authenticated_committed_receipt_remains_read_only_after_disable_until_original_expiry()
    {
        await using var h=await ReceiptFixture.Create();var session=h.Login();
        var first=await h.Operator.ReadCommittedReceiptAsync(session);Assert.Equal(5,first.OriginalParentIds.Length);Assert.Equal(6,first.OriginalWorkIds.Length);
        Assert.Equal((12,4,4,27918L),(first.OriginalApplication,first.OriginalSimulator,first.OriginalTimestamp,first.OriginalEncodedBytes));
        Assert.Equal((1,37L),(first.NewApplication,first.NewEncodedBytes));Assert.Equal(h.Header.ManifestSha256,Convert.FromHexString(first.ManifestSha256));
        Assert.Equal(h.Header.DeleteAfter,first.ActualOriginalParentDeleteAfterMinimum);Assert.True(first.OriginalPairsPreserved);
        var raw=JsonSerializer.Serialize(first);Assert.True(Encoding.UTF8.GetByteCount(raw)<=16384);Assert.DoesNotContain("original-ciphertext",raw);Assert.DoesNotContain("sender@example.invalid",raw);
        h.Options.Enabled=false;Assert.False(h.Core.Available);Assert.False(h.Browser.Live(session));Assert.False(h.Browser.Unlock(ReceiptFixture.Http(),ReceiptFixture.Capability));
        await Assert.ThrowsAsync<EmailDisabledException>(()=>h.Operator.StartAsync(session));
        Assert.NotNull(h.Browser.ReadReceipt(ReceiptFixture.Http(h.Cookie)));Assert.Null(h.Browser.Read(ReceiptFixture.Http(h.Cookie)));
        var final=await h.Operator.ReadCommittedReceiptAsync(session);Assert.Equal(first.OperationsSha256,final.OperationsSha256);Assert.Equal(first.OriginalWorkSha256,final.OriginalWorkSha256);
        Assert.NotNull((await h.Db.EmailPilotCloseouts.AsNoTracking().SingleAsync()).ProtectedManifest);
        h.Clock.Now=h.Options.Until;Assert.Null(h.Browser.ReadReceipt(ReceiptFixture.Http(h.Cookie)));
        await Assert.ThrowsAsync<EmailDisabledException>(()=>h.Operator.ReadCommittedReceiptAsync(session));
    }

    [Theory]
    [InlineData("header")][InlineData("original")][InlineData("operation")][InlineData("config")][InlineData("old-pilot")]
    public async Task Receipt_refuses_changed_or_unauthenticated_state_without_mutating_rows(string fault)
    {
        await using var h=await ReceiptFixture.Create();var session=h.Login();
        if(fault=="header")await h.Db.EmailPilotCloseouts.ExecuteUpdateAsync(x=>x.SetProperty(y=>y.ProtectedManifest,"tampered"));
        if(fault=="original")await h.Db.EmailOutbox.Where(x=>x.Id==h.OriginalIds[0]).ExecuteUpdateAsync(x=>x.SetProperty(y=>y.PayloadJson,"{\"Protected\":\"changed\"}"));
        if(fault=="operation")await h.Db.EmailPilotCloseoutOperations.ExecuteUpdateAsync(x=>x.SetProperty(y=>y.ProtectedReceipt,"tampered"));
        if(fault=="config")h.Options.AuthorizationId=Guid.NewGuid().ToString("N");if(fault=="old-pilot")h.Pilot.Enabled=true;
        var before=await h.Db.WorkItems.AsNoTracking().Select(x=>Convert.ToBase64String(x.RowVersion)).ToArrayAsync();
        await Assert.ThrowsAnyAsync<Exception>(()=>h.Operator.ReadCommittedReceiptAsync(session));
        Assert.Equal(before,await h.Db.WorkItems.AsNoTracking().Select(x=>Convert.ToBase64String(x.RowVersion)).ToArrayAsync());
    }

    [Fact]
    public async Task Cleanup_exact_due_worker_stage_retains_tombstones_and_already_absent_is_not_a_second_removal()
    {
        await using var h=await ReceiptFixture.Create(expired:true);var expected=await h.Operator.ReadCommittedReceiptAsync(h.Login());
        await h.RestrictWorker();
        await using(var tx=await h.Db.Database.BeginTransactionAsync(IsolationLevel.Serializable)) {
            Assert.Equal("app_worker",await h.Scalar("SELECT USER_NAME()"));
            // The real command must reject native S as E, even with its actual SID.
            var sid=(byte[])(await h.Scalar("SELECT sid FROM sys.database_principals WHERE principal_id=USER_ID()"))!;
            await Assert.ThrowsAsync<InvalidDataException>(()=>HostedCloseoutCleanupReceipt.DemandWorkerAsync(h.Db,h.Db.Database.GetDbConnection().Database,sid,default));
            var removed=await HostedCloseoutCleanupReceipt.ApplyLockedAsync(h.Db,expected,default);Assert.True(removed.RemovedByThisCall);Assert.False(removed.WorkerIdentityVerified);
            await tx.RollbackAsync();
        }
        Assert.NotNull((await h.Db.EmailPilotCloseouts.AsNoTracking().SingleAsync()).ProtectedManifest);
        await using(var tx=await h.Db.Database.BeginTransactionAsync(IsolationLevel.Serializable)) {
            var removed=await HostedCloseoutCleanupReceipt.ApplyLockedAsync(h.Db,expected,default);Assert.True(removed.RemovedByThisCall);Assert.False(removed.AlreadyAbsent);
            Assert.Equal(expected.OperationsSha256,removed.OperationsSha256);await tx.CommitAsync();
        }
        await using(var tx=await h.Db.Database.BeginTransactionAsync(IsolationLevel.Serializable)) {
            var absent=await HostedCloseoutCleanupReceipt.ApplyLockedAsync(h.Db,expected,default);Assert.True(absent.AlreadyAbsent);Assert.False(absent.RemovedByThisCall);
            Assert.True(absent.ImmutableFactsUnchanged);await tx.RollbackAsync();
        }
        Assert.Single(await h.Db.EmailPilotCloseouts.ToArrayAsync());Assert.Single(await h.Db.EmailPilotCloseoutOperations.ToArrayAsync());
        Assert.Equal(12,await h.Db.WorkItems.CountAsync());
    }

    [Theory]
    [InlineData("not-due")][InlineData("header")][InlineData("counter")][InlineData("original")][InlineData("missing")][InlineData("original-counter")]
    public async Task Cleanup_proof_refuses_unknown_mismatched_or_not_due_state(string fault)
    {
        await using var h=await ReceiptFixture.Create(expired:fault!="not-due");var expected=await h.Operator.ReadCommittedReceiptAsync(h.Login());
        if(fault=="header")expected=expected with{ManifestSha256=new string('f',64)};
        if(fault=="counter")expected=expected with{NewEncodedBytes=38};
        if(fault=="original")await h.Db.EmailOutbox.Where(x=>x.Id==h.OriginalIds[0]).ExecuteUpdateAsync(x=>x.SetProperty(y=>y.PayloadJson,"{\"Protected\":\"changed\"}"));
        if(fault=="original-counter") {
            h.Db.Add(new EmailPilotReservationRecord{RunId=expected.OriginalParentIds[0],SubjectEnvelopeId=null,OperationId=Guid.NewGuid(),Kind=EmailPilotAttemptKind.Simulator,
                Role=EmailPilotRole.Simulator,EncodedBytes=1,RequestSha256=new byte[32],ReservedAt=expected.CreatedAt.AddMinutes(-10),ProtectedReceipt="unverified appended row"});
            await h.Db.SaveChangesAsync();h.Db.ChangeTracker.Clear();
        }
        if(fault=="missing")expected=expected with{AuthorizationId=Guid.NewGuid()};
        await using var tx=await h.Db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await Assert.ThrowsAsync<InvalidDataException>(()=>HostedCloseoutCleanupReceipt.ApplyLockedAsync(h.Db,expected,default));await tx.RollbackAsync();
        if(fault!="missing")Assert.NotNull((await h.Db.EmailPilotCloseouts.AsNoTracking().SingleAsync()).ProtectedManifest);
    }
}

// Authenticated native reader fixture, not a fabricated completed signing or
// provider acceptance proof. The existing genuine producer case separately
// exercises Create -> this same receipt on disposable-stack CI.
internal sealed class ReceiptFixture:IAsyncDisposable
{
    internal const string Capability="1234567890123456789012345678901234567890123";
    private readonly SqlDatabaseFixture fixture=new();
    internal QuillSignDbContext Db=null!;internal readonly ClockProvider Clock=new();internal readonly EmailPilotOptions Pilot=new();
    internal readonly IDataProtectionProvider Keys=new EphemeralDataProtectionProvider();internal EmailPilotCloseoutOptions Options=null!;
    internal EmailPilotCloseout Core=null!;internal EmailPilotCloseoutOperatorBrowser Browser=null!;internal EmailPilotCloseoutOperator Operator=null!;
    internal EmailPilotCloseoutHeaderRecord Header=null!;internal Guid[] OriginalIds=[];internal string Cookie="";private bool workerContext;
    internal static async Task<ReceiptFixture> Create(bool expired=false)
    {
        var h=new ReceiptFixture();try {
        await h.fixture.InitializeAsync();h.Db=h.fixture.Open();Console.WriteLine("ReceiptFixtureOwnedDatabase: "+h.Db.Database.GetDbConnection().Database);h.Clock.Now=DateTimeOffset.UtcNow.AddDays(expired?-8:-1);
        var email=new EmailOptions();var work=new WorkOptions{Enabled=true};var proof=new EmailPilotProtection(h.Keys);var boxes=EmailPilotProtectionTests.Mailboxes();
        var records=Enumerable.Range(0,3).Select(_=>new Envelope{SenderEmail=boxes.Sender,IsDemo=true}).ToArray();h.Db.AddRange(records);await h.Db.SaveChangesAsync();
        var parents=new List<Guid>();var ledgers=new List<EmailPilotLedger>();
        for(var n=0;n<5;n++) {
            var o=new EmailPilotOptions{Enabled=true,RunId=Guid.NewGuid().ToString("N"),Mailboxes=boxes};parents.Add(Guid.ParseExact(o.RunId,"N"));
            var ledger=new EmailPilotLedger(o,email,()=>h.Db,()=>proof,h.Clock);ledgers.Add(ledger);await ledger.CreateAsync(Capability);
        }
        Assert.True(await ledgers[0].EnrollAsync(Capability,records[0].Id,EmailPilotScenario.Completion));
        for(var n=0;n<20;n++)Assert.Equal(EmailPilotReservationOutcome.Reserved,await ledgers[0].ReserveAsync(new(Guid.NewGuid(),n is >=12 and <16?null:records[0].Id,
            Guid.NewGuid(),n<12?EmailPilotAttemptKind.Application:n<16?EmailPilotAttemptKind.Simulator:EmailPilotAttemptKind.Timestamp,
            n<12?EmailPilotRole.Sender:n<16?EmailPilotRole.Simulator:EmailPilotRole.None,n==0?27903:n<16?1:0,new string('a',64)),n<12?boxes.Sender:null));
        h.Clock.Now=h.Clock.Now.AddMinutes(61);var pairs=new List<(EmailOutbox Mail,WorkItem Work)>();
        for(var n=0;n<6;n++) {
            var m=new EmailOutbox{EnvelopeId=records[n<4?0:1].Id,To=boxes.Sender,Template=n<4?CompletionNotificationJobs.Template:VoidNotificationJobs.Template,
                PayloadJson="{\"Protected\":\"original-ciphertext\"}",Status=EmailStatus.Failed,LastError="pilot-delivery-unavailable",AvailableAt=h.Clock.Now.AddMinutes(-1)};
            var w=new WorkItem{Id=m.Id,EnvelopeId=m.EnvelopeId,Kind=WorkKind.Email,Status=WorkStatus.Failed,Attempts=1,LastError=m.LastError,AvailableAt=m.AvailableAt,
                PayloadJson=n<4?CompletionNotificationJobs.WorkJson(m.Id):VoidNotificationJobs.WorkJson(m.Id)};h.Db.AddRange(m,w);pairs.Add((m,w));
        }
        await h.Db.SaveChangesAsync();h.OriginalIds=pairs.Select(x=>x.Mail.Id).ToArray();
        h.Options=new(){Enabled=true,AuthorizationId=Guid.NewGuid().ToString("N"),CapabilitySha256=Convert.ToHexStringLower(EmailPilotCanonical.Capability(Capability)),
            StartsAt=h.Clock.Now,Until=h.Clock.Now.AddMinutes(30),AccountingParentRunIds=parents.Select(x=>x.ToString("N")).ToArray(),CompletionParentRunId=parents[0].ToString("N"),VoidParentRunId=parents[1].ToString("N"),
            CompletionRecordId=records[0].Id.ToString("N"),VoidRecordId=records[1].Id.ToString("N"),DeclineRecordId=records[2].Id.ToString("N"),
            CompletionWorkIds=h.OriginalIds.Take(4).Select(x=>x.ToString("N")).ToArray(),VoidWorkIds=h.OriginalIds.Skip(4).Select(x=>x.ToString("N")).ToArray()};
        var cfg=h.Options.Capture();await using(var tx=await h.Db.Database.BeginTransactionAsync()) {
            var histories=new List<EmailPilotHistoricalState>();for(var n=0;n<5;n++)histories.Add(await ledgers[n].ReadHistoricalLockedAsync(h.Db,parents[n],default));
            var queue=new List<EmailPilotCloseoutQueue>();for(var n=0;n<6;n++)queue.Add(await EmailPilotCloseout.InsertAliasPairLockedAsync(h.Db,cfg.AuthorizationId,(EmailPilotCloseoutStep)n,pairs[n].Mail,pairs[n].Work,h.Clock.Now));
            var manifest=new EmailPilotCloseoutManifest(EmailPilotCloseoutLimits.Version,cfg.AuthorizationId,h.Clock.Now,cfg.Until,histories.Min(x=>x.DeleteAfter),
                Convert.ToHexStringLower(EmailPilotCanonical.Hash(cfg)),parents.Select((id,n)=>new EmailPilotCloseoutParent(id,histories[n].Sha256)).ToArray(),queue.ToArray(),new string('b',64));
            h.Header=new(){Id=cfg.AuthorizationId,CreatedAt=manifest.CreatedAt,Until=manifest.Until,DeleteAfter=manifest.DeleteAfter,CapabilitySha256=Convert.FromHexString(cfg.CapabilitySha256),
                ManifestSha256=EmailPilotCanonical.Hash(manifest),ProtectedManifest=proof.Protect(cfg.AuthorizationId,"bounded-failed-notice-closeout-manifest-v1",manifest)};
            h.Db.Add(h.Header);await h.Db.SaveChangesAsync();
            var value=new EmailPilotCloseoutReceipt(EmailPilotCloseoutLimits.Version,cfg.AuthorizationId,1,EmailPilotCloseoutStep.CompletionSender,records[0].Id,queue[0].WorkId,h.Clock.Now,37,new string('a',64));
            h.Db.Add(new EmailPilotCloseoutOperationRecord{Id=EmailPilotCloseout.Identity(cfg.AuthorizationId,1,value.Step),CloseoutId=cfg.AuthorizationId,Kind=1,Step=0,SubjectEnvelopeId=value.SubjectEnvelopeId,
                WorkId=value.WorkId,At=value.At,EncodedBytes=37,RequestSha256=Convert.FromHexString(value.RequestSha256),ProtectedReceipt=proof.Protect(cfg.AuthorizationId,"bounded-failed-notice-closeout-operation-v1",value)});
            await h.Db.SaveChangesAsync();await tx.CommitAsync();
        }
        h.Db.ChangeTracker.Clear();h.Core=new(h.Options,email,work,()=>h.Db,()=>ledgers[0],()=>proof,h.Clock){ReceiptPilotOptions=h.Pilot};
        h.Browser=new(h.Options,email,work,h.Clock,new Environment(),()=>h.Keys,h.Pilot);
        h.Operator=new(h.Browser,()=>h.Core,()=>h.Db,()=>throw new InvalidOperationException(),()=>throw new InvalidOperationException(),()=>throw new InvalidOperationException(),h.Clock);return h;
        }catch{await h.DisposeAsync();throw;}
    }
    internal EmailPilotCloseoutOperatorSession Login(){var http=Http();Assert.True(Browser.Unlock(http,Capability));Cookie=http.Response.Headers.SetCookie.Single()!.Split(';')[0];return Browser.Read(Http(Cookie))!;}
    internal static DefaultHttpContext Http(string? cookie=null){var h=new DefaultHttpContext();h.Request.Scheme="http";h.Request.Host=new("localhost");if(cookie is not null)h.Request.Headers.Cookie=cookie;return h;}
    internal async Task<object?> Scalar(string sql){await using var c=Db.Database.GetDbConnection().CreateCommand();c.CommandText=sql;c.Transaction=Db.Database.CurrentTransaction?.GetDbTransaction();return await c.ExecuteScalarAsync();}
    internal async Task RestrictWorker()
    {
        await Db.Database.OpenConnectionAsync();var connection=(SqlConnection)Db.Database.GetDbConnection();
        await using var c=connection.CreateCommand();c.CommandText="CREATE USER [app_runtime] WITHOUT LOGIN; CREATE USER [app_worker] WITHOUT LOGIN;";await c.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection);c.CommandText="ALTER ROLE [app_runtime_role] ADD MEMBER [app_worker]";await c.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantEmailPilotRetentionAsync(connection);await DatabasePermissions.GrantDemoPurgeAsync(connection);await DatabasePermissions.GrantLookupRetentionAsync(connection);
        c.CommandText="EXECUTE AS USER='app_worker'";await c.ExecuteNonQueryAsync();workerContext=true;
    }
    public async ValueTask DisposeAsync(){if(Db is not null){if(workerContext&&Db.Database.GetDbConnection().State==ConnectionState.Open){await using var c=Db.Database.GetDbConnection().CreateCommand();c.CommandText="REVERT";await c.ExecuteNonQueryAsync();}await Db.DisposeAsync();}await fixture.DisposeAsync();}
    internal sealed class ClockProvider:TimeProvider{internal DateTimeOffset Now;public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed class Environment:IHostEnvironment{public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Synthetic";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}

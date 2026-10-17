using System.Data.Common;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Storage;
using QuillSign.Work;
using Shared=QuillSign.Tests.DocumentWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class DemoPurgeCoordinatorTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Disabled_purge_prevents_new_demo_enrollment_and_preserves_ordinary_uploads(bool demo)
    {
        await using var h=await Shared.CreateAsync(fixture,demo);h.Retention.PurgeAfterDays=1;var before=await h.StateAsync();var options=new DocumentOptions();
        var result=await Record.ExceptionAsync(()=>h.WithDatabaseAsync(async db=> {
            var jobs=new DemoPurgeJobs(db,()=>throw new InvalidOperationException("Disabled scheduling must not resolve signals"),new(),h.Time);
            var documents=new DocumentWorkflow(db,h.Store,new(options),options,new(db,h.Time),h.Time,Microsoft.Extensions.Logging.Abstractions.NullLogger<DocumentWorkflow>.Instance,h.Retention,jobs);
            var bytes=PdfFixtures.Create(text:"SYNTHETIC DISABLED RETENTION NO AGREEMENT");using var source=new MemoryStream(bytes);
            return await documents.UploadAsync(h.Sender,h.PublicId,before.RowVersion,"synthetic.pdf",source,bytes.Length,null,null,default);
        }));
        if(demo)Assert.IsType<DocumentRejectedException>(result);else Assert.Null(result);
        await using var check=fixture.Open();Assert.False(await check.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==h.Id));Assert.False(await check.WorkItems.AnyAsync(x=>x.EnvelopeId==h.Id));
        Assert.Equal(demo ? 0:1,await check.AuditEvents.CountAsync(x=>x.EnvelopeId==h.Id && x.Event=="document_uploaded"));
    }
    [Fact]
    public async Task First_upload_has_one_frozen_job_and_durable_hint_and_replacement_never_reschedules_it()
    {
        await using var f=await Flow.Create(fixture);var original=f.Policy.DeleteAfter;var work=await f.Job();
        Assert.Equal(DemoPurgeAuthority.Payload(f.Policy),work.PayloadJson);Assert.Equal(original,work.AvailableAt);
        Assert.Equal(original,await f.Signals.ReadDueAsync(work.Id,default));Assert.Equal(1,f.Signals.Publishes);
        f.H.Retention.PurgeAfterDays=30;f.Time.Now=f.Time.Now.AddHours(2);
        Assert.True(await f.H.UploadAsync(PdfFixtures.Create(text:"SYNTHETIC REPLACEMENT NO AGREEMENT")));
        var again=await f.Job();Assert.Equal(work.Id,again.Id);Assert.Equal(work.PayloadJson,again.PayloadJson);Assert.Equal(original,again.AvailableAt);
        await using var db=fixture.Open();Assert.Single(await db.WorkItems.Where(x=>x.EnvelopeId==f.H.Id && x.Kind==WorkKind.Purge).ToArrayAsync());
        Assert.Equal(original,(await db.DocumentRetentionSnapshots.SingleAsync(x=>x.EnvelopeId==f.H.Id)).DeleteAfter);
    }
    [Theory]
    [InlineData("hint")][InlineData("hint-lost")][InlineData("commit-rejected")][InlineData("commit-lost")][InlineData("publish")]
    public async Task Upload_and_schedule_rollback_or_unknown_acknowledgement_recover_without_duplicate_authority(string fault)
    {
        await using var f=await Flow.Create(fixture,upload:false);
        f.Signals.FailHint=fault=="hint";f.Signals.LoseHint=fault=="hint-lost";f.Signals.FailPublish=fault=="publish";
        // Existing shared commit interceptor targets the actual upload transaction.
        f.H.CommitFailure.Enabled=fault=="commit-lost";
        if(fault=="commit-rejected")f.H.CommitFailure.Reject=true;
        var error=await Record.ExceptionAsync(()=>f.H.UploadAsync(PdfFixtures.Create(text:"SYNTHETIC ATOMIC UPLOAD NO AGREEMENT")));
        await using(var db=fixture.Open()) {
            var committed=fault is "publish" or "commit-lost";
            Assert.Equal(committed,await db.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==f.H.Id));
            Assert.Equal(committed,await db.WorkItems.AnyAsync(x=>x.EnvelopeId==f.H.Id && x.Kind==WorkKind.Purge));
            Assert.Equal(committed,await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==f.H.Id && x.Event=="document_uploaded"));
            if(committed)Assert.NotNull((await f.H.StateAsync()).PdfBlob);else Assert.Null((await f.H.StateAsync()).PdfBlob);
        }
        Assert.Equal(fault!="publish",error is not null);Assert.Equal(fault=="publish" ? 1:0,f.Signals.Publishes);
        f.H.CommitFailure.Enabled=false;f.H.CommitFailure.Reject=false;f.Signals.FailHint=false;f.Signals.LoseHint=false;f.Signals.FailPublish=false;
        if(fault is "publish" or "commit-lost") {await f.ReadPolicy();await using var db=fixture.Open();Assert.NotNull(await new DemoPurgeJobs(db,()=>f.Signals,f.Options,f.Time).ResumeAsync(f.H.Id));}
        else {Assert.True(await f.H.UploadAsync(PdfFixtures.Create(text:"SYNTHETIC RETRY NO AGREEMENT")));await f.ReadPolicy();}
        Assert.Equal(f.Policy.DeleteAfter,await f.Signals.ReadDueAsync((await f.Job()).Id,default));
    }
    [Fact]
    public async Task Missing_legacy_job_is_not_created_by_read_or_replacement_and_explicit_resume_preserves_original_policy()
    {
        await using var f=await Flow.Create(fixture);var original=DemoPurgeAuthority.Payload(f.Policy);var id=(await f.Job()).Id;
        await using(var db=fixture.Open())await db.WorkItems.Where(x=>x.Id==id).ExecuteDeleteAsync();await f.Signals.RemoveHintAsync(id,default);
        await using(var db=fixture.Open()) {
            var review=await new DraftReview(db,f.Time).GetAsync(f.H.Sender,f.H.PublicId);Assert.NotNull(review);
            Assert.Contains(review.Errors,x=>x.Message.Contains("retention service",StringComparison.Ordinal));Assert.False(await db.WorkItems.AnyAsync(x=>x.Id==id));
        }
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>f.H.UploadAsync(PdfFixtures.Create(text:"UNSCHEDULED SYNTHETIC REPLACEMENT")));
        await using(var db=fixture.Open())Assert.Equal(id,await new DemoPurgeJobs(db,()=>f.Signals,f.Options,f.Time).ResumeAsync(f.H.Id));
        Assert.Equal(original,(await f.Job()).PayloadJson);Assert.True(await f.H.UploadAsync(PdfFixtures.Create(text:"RESUMED SYNTHETIC REPLACEMENT")));
    }
    [Fact]
    public async Task Actual_due_worker_removes_private_SQL_and_blobs_once_and_keeps_marker_for_late_writes()
    {
        await using var f=await Flow.Create(fixture,historical:true);var job=await f.Job();await f.Wake();Assert.True(await f.Once());
        await using(var db=fixture.Open()) {
            Assert.False(await db.Envelopes.AnyAsync(x=>x.Id==f.H.Id));Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==f.H.Id));
            Assert.False(await db.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==f.H.Id));var saved=await db.WorkItems.SingleAsync(x=>x.Id==job.Id);
            Assert.Equal(WorkStatus.Completed,saved.Status);Assert.Null(saved.EnvelopeId);Assert.Equal(job.PayloadJson,saved.PayloadJson);
        }
        Assert.Null(await f.Signals.ReadDueAsync(job.Id,default));Assert.True((await f.Marker.ExistsAsync()).Value);
        Assert.Equal(0,(await f.Recovery.RecoverBatchAsync()).Deleted);
        var late=f.Blobs.GetBlobContainerClient("normalized").GetBlobClient($"{f.H.Id:N}/completion-candidates/{Guid.NewGuid():N}");
        await late.UploadAsync(BinaryData.FromString("LATE SYNTHETIC NO AGREEMENT"));Assert.Equal(1,(await f.Recovery.RecoverBatchAsync()).Deleted);
        await f.Signals.PublishAsync(job.Id,TimeSpan.Zero,default);Assert.True(await f.Once());
        await using var gone=fixture.Open();Assert.False(await gone.Envelopes.AnyAsync(x=>x.Id==f.H.Id));
    }
    [Fact]
    public async Task Pending_bounded_inventory_retries_beyond_ordinary_attempts_then_completes_without_SQL_recreation()
    {
        await using var f=await Flow.Create(fixture,historical:true);f.Options.MaximumAttempts=1;
        for(var i=0;i<38;i++)await f.Blobs.GetBlobContainerClient("normalized").GetBlobClient($"{f.H.Id:N}/completion-candidates/{Guid.NewGuid():N}").UploadAsync(BinaryData.FromString("SYNTHETIC BOUNDED INVENTORY"));
        await f.Wake();Assert.True(await f.Once());var row=await f.Job();Assert.Equal(WorkStatus.Queued,row.Status);Assert.Null(row.EnvelopeId);Assert.Equal(1,row.Attempts);
        for(var i=0;i<6 && row.Status!=WorkStatus.Completed;i++) {
            // Expedite mutable retry scheduling only. The frozen policy and the
            // next genuine lease remain unchanged and use real SQL server time.
            f.Time.Now=DateTimeOffset.UtcNow;
            await using(var retryDb=fixture.Open())await retryDb.WorkItems.Where(x=>x.Id==row.Id && x.Status==WorkStatus.Queued)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.AvailableAt,f.Time.Now));
            await f.Signals.PutHintAsync(row.Id,f.Time.Now,default);await f.Signals.PublishAsync(row.Id,TimeSpan.Zero,default);
            Assert.True(await f.Once());row=await f.Job();
        }
        Assert.Equal(WorkStatus.Completed,row.Status);Assert.True(row.Attempts>f.Options.MaximumAttempts);
        await using var db=fixture.Open();Assert.False(await db.Envelopes.AnyAsync(x=>x.Id==f.H.Id));Assert.Equal(0,(await f.Recovery.RecoverBatchAsync()).Deleted);
    }
    [Theory]
    [InlineData("rollback")][InlineData("lost")][InlineData("storage")]
    public async Task Durable_worker_recovers_SQL_commit_uncertainty_and_storage_failure_without_abandoning_cleanup(string fault)
    {
        await using var f=await Flow.Create(fixture,historical:true);f.Options.MaximumAttempts=1;
        var commit=new PurgeCommitFault(f,fault);f.Storage.Fail=fault=="storage";await f.Wake();Assert.True(await f.Once(commit));
        var row=await f.Job();Assert.Equal(WorkStatus.Queued,row.Status);Assert.Equal(1,row.Attempts);Assert.True((await f.Marker.ExistsAsync()).Value);
        await using(var db=fixture.Open())Assert.Equal(fault=="rollback",await db.Envelopes.AnyAsync(x=>x.Id==f.H.Id));
        if(fault!="storage")Assert.True(commit.Fired);
        f.Storage.Fail=false;f.Time.Now=DateTimeOffset.UtcNow;
        await using(var db=fixture.Open())await db.WorkItems.Where(x=>x.Id==row.Id && x.Status==WorkStatus.Queued).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.AvailableAt,f.Time.Now));
        await f.Signals.PutHintAsync(row.Id,f.Time.Now,default);await f.Signals.PublishAsync(row.Id,TimeSpan.Zero,default);Assert.True(await f.Once());
        Assert.Equal(WorkStatus.Completed,(await f.Job()).Status);await using var final=fixture.Open();Assert.False(await final.Envelopes.AnyAsync(x=>x.Id==f.H.Id));
    }
    [Fact]
    public async Task Empty_queue_and_wrong_kind_do_not_materialize_purge_storage_or_connect_SQL()
    {
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(EmailOptions).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> {
            ["Storage:Provider"]="Azurite",["Storage:ConnectionString"]=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),
            ["Work:Enabled"]="true",["Work:QueueName"]="synthetic-empty",["Work:HintContainer"]="synthetic-empty",
            ["Email:Enabled"]="false",["Email:FromEmail"]="synthetic@example.invalid",["Email:BaseUrl"]="https://example.invalid/"});
        var connections=new ConnectionTripwire();var unreachable=new SqlConnectionStringBuilder{DataSource="127.0.0.1,1",InitialCatalog="unreachable",IntegratedSecurity=true,Encrypt=false,ConnectTimeout=1};
        builder.Services.AddDbContext<QuillSignDbContext>(o=>o.UseSqlServer(unreachable.ConnectionString).AddInterceptors(connections));
        builder.Services.AddRazorPages();builder.Services.AddQuillSignStorage(builder.Configuration,builder.Environment);builder.Services.AddQuillSignEmail(builder.Configuration,builder.Environment);builder.Services.AddQuillSignWork(builder.Configuration,builder.Environment);
        builder.Services.AddSingleton<IWorkSignals>(new DocumentWorkflowTests.PurgeTestSignals());builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        builder.Services.AddSingleton<DemoPurgeRecovery>(_=>throw new InvalidOperationException("Empty work must not resolve purge storage/protection"));
        builder.Services.AddScoped<DemoPurgeSql>(_=>throw new InvalidOperationException("Empty work must not resolve purge SQL"));
        await using var app=builder.Build();await using var scope=app.Services.CreateAsyncScope();
        var processor=scope.ServiceProvider.GetRequiredService<WorkProcessor>();Assert.False(await processor.RunOnceAsync(default));
        var handler=scope.ServiceProvider.GetServices<IWorkHandler>().Single(x=>x.Kind==WorkKind.Purge);
        Assert.Equal(WorkOutcome.Failed,(await handler.ExecuteAsync(new(Guid.NewGuid(),Guid.NewGuid(),WorkKind.Email,1,DateTimeOffset.UtcNow.AddMinutes(5)),default)).Outcome);Assert.Equal(0,connections.Opens);
    }
    private sealed class ConnectionTripwire:DbConnectionInterceptor
    {public int Opens;public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection connection,ConnectionEventData data,InterceptionResult result,CancellationToken ct=default){Opens++;throw new InvalidOperationException("Empty queue opened SQL");}}
    private sealed class PurgeCommitFault(Flow flow,string mode):DbTransactionInterceptor
    {
        public bool Fired;
        private async Task<bool> Removed(DbConnection connection,DbTransaction? transaction,CancellationToken ct) {
            if(Fired || !(await flow.Marker.ExistsAsync(ct)).Value)return false;
            await using var command=connection.CreateCommand();command.Transaction=transaction;command.CommandText="SELECT COUNT(*) FROM dbo.Envelopes WHERE Id=@id";
            command.Parameters.Add(new SqlParameter("@id",flow.H.Id));return Convert.ToInt32(await command.ExecuteScalarAsync(ct))==0;
        }
        public override async ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,TransactionEventData data,InterceptionResult result,CancellationToken ct=default) {
            if(mode=="rollback" && await Removed(transaction.Connection!,transaction,ct)){Fired=true;throw new IOException("Synthetic uncommitted purge failure");}return result;
        }
        public override async Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData data,CancellationToken ct=default) {
            if(mode=="lost" && await Removed(data.Context!.Database.GetDbConnection(),null,ct)){Fired=true;throw new IOException("Synthetic lost purge acknowledgement");}
        }
    }
    private sealed class FaultPurgeStore(IEnvelopePurgeStore inner):IEnvelopePurgeStore
    {
        public bool Fail;
        public Task<PurgeStorageBatch> SweepAsync(DemoPurgeAuthority authority,int maximumObjects,PurgeStorageCursor? cursor=null,CancellationToken ct=default) {
            if(Fail)throw new IOException("Synthetic object storage outage");return inner.SweepAsync(authority,maximumObjects,cursor,ct);
        }
    }
    private sealed class Flow(SqlDatabaseFixture fixture,Shared harness):IAsyncDisposable
    {
        public Shared H=harness;public DemoPurgeStorageTests.Clock Time=new(){Now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds())};
        public WorkOptions Options=new(){Enabled=true};public BlobServiceClient Blobs=DemoPurgeStorageTests.Service();public BlobContainerClient Hints=null!;public QueueClient Queue=null!;public Signals Signals=null!;
        public DocumentRetentionSnapshot Policy=null!;public IDataProtectionProvider Protection=new EphemeralDataProtectionProvider();public FaultPurgeStore Storage=null!;
        public DemoPurgeRecovery Recovery=>new(Hints,Protection,Storage,Time);
        public BlobClient Marker=>Hints.GetBlobClient(DemoPurgeRecovery.Prefix+H.Id.ToString("N"));
        public static async Task<Flow> Create(SqlDatabaseFixture fixture,bool upload=true,bool historical=false) {
            var h=await Shared.CreateAsync(fixture,true);var f=new Flow(fixture,h);var name="purge-coordinator-"+Guid.NewGuid().ToString("N");
            f.Storage=new(new AzureEnvelopePurgeStore(f.Blobs));f.Options.QueueName=name;f.Options.HintContainer=name;f.Hints=f.Blobs.GetBlobContainerClient(name);await f.Hints.CreateIfNotExistsAsync();
            f.Queue=new(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),name,new QueueClientOptions(QueueClientOptions.ServiceVersion.V2023_11_03));
            await f.Queue.CreateIfNotExistsAsync();f.Signals=new(new AzureWorkSignals(f.Queue,f.Hints,f.Options,true));h.PurgeSignals=f.Signals;h.Retention.PurgeAfterDays=1;
            if(historical)f.Time.Now=f.Time.Now.AddDays(-2);h.Time=f.Time;
            await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==h.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CreatedAt,f.Time.Now).SetProperty(x=>x.SenderVerifiedAt,f.Time.Now));
            if(upload){Assert.True(await h.UploadAsync(PdfFixtures.Create(text:"SYNTHETIC PURGE COORDINATOR NO AGREEMENT")));await f.ReadPolicy();}return f;
        }
        public async Task ReadPolicy(){await using var db=fixture.Open();Policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==H.Id);}
        public async Task<WorkItem> Job(){await using var db=fixture.Open();return await db.WorkItems.AsNoTracking().SingleAsync(x=>x.PayloadJson==DemoPurgeAuthority.Payload(Policy) && x.Kind==WorkKind.Purge);}
        public async Task Wake(){Time.Now=DateTimeOffset.UtcNow;await Signals.PublishAsync((await Job()).Id,TimeSpan.Zero,default);}
        public async Task<bool> Once(DbTransactionInterceptor? fault=null) {
            await using var baseline=fixture.Open();var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString());if(fault is not null)options.AddInterceptors(fault);
            await using var db=new QuillSignDbContext(options.Options);await db.Database.OpenConnectionAsync();var connection=(SqlConnection)db.Database.GetDbConnection();
            await db.Database.ExecuteSqlRawAsync("IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER app_runtime WITHOUT LOGIN; IF DATABASE_PRINCIPAL_ID('app_worker') IS NULL CREATE USER app_worker WITHOUT LOGIN");
            await DatabasePermissions.GrantRuntimeAsync(connection);await db.Database.ExecuteSqlRawAsync("ALTER ROLE app_runtime_role ADD MEMBER app_worker");await DatabasePermissions.GrantDemoPurgeAsync(connection);
            await db.Database.ExecuteSqlRawAsync("EXECUTE AS USER='app_worker'");
            try{return await new WorkProcessor(new(db,Options,Time),Signals,[new DemoPurgeHandler(db,()=>new(db,Recovery,Time),()=>Recovery,Time)],Time).RunOnceAsync(default);}
            finally{await db.Database.ExecuteSqlRawAsync("REVERT");}
        }
        public async ValueTask DisposeAsync(){await Queue.DeleteIfExistsAsync();await Hints.DeleteIfExistsAsync();await H.DisposeAsync();}
    }
    private sealed class Signals(IWorkSignals inner):IWorkSignals
    {
        public bool FailHint,LoseHint,FailPublish;public int Publishes;
        public async Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct){if(FailHint)throw new IOException("Synthetic hint failure");await inner.PutHintAsync(id,due,ct);if(LoseHint)throw new IOException("Synthetic lost hint acknowledgement");}
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>inner.RemoveHintAsync(id,ct);public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>inner.ReadDueAsync(id,ct);
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct){Publishes++;if(FailPublish)throw new IOException("Synthetic publish failure");return inner.PublishAsync(id,delay,ct);}
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>inner.ReceiveAsync(ct);public Task DeferAsync(WorkDelivery d,TimeSpan delay,CancellationToken ct)=>inner.DeferAsync(d,delay,ct);
        public Task AcknowledgeAsync(WorkDelivery d,CancellationToken ct)=>inner.AcknowledgeAsync(d,ct);public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>inner.RecoverAsync(now,ct);public Task VerifyAsync(CancellationToken ct)=>inner.VerifyAsync(ct);
    }
}

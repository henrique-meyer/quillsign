using System.Data;
using System.Data.Common;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;
using QuillSign.Work;
using Run=QuillSign.Tests.DemoPurgeStorageTests.Run;

namespace QuillSign.Tests;

public sealed class DemoPurgeSqlTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Worker_only_guarded_cleanup_preserves_direct_denials_neighbors_and_late_blob_recovery()
    {
        await using var f=await Scope.Create(fixture);await f.Provision();
        await using(var seed=fixture.Open()) {
            seed.Suppressions.Add(new(){Email="global-"+Guid.NewGuid().ToString("N")+"@example.invalid",Reason=SuppressionReason.Bounce});
            seed.Envelopes.Add(new(){Title="Unrelated synthetic record",SenderEmail="neighbor@example.invalid"});
            seed.EmailOutbox.Add(new(){To="pre-envelope@example.invalid"});await seed.SaveChangesAsync();
        }
        foreach(var user in new[]{"app_runtime","app_worker"})await f.User(user,async db=> {
            var error=await Assert.ThrowsAsync<SqlException>(()=>db.Database.ExecuteSqlRawAsync("DELETE FROM dbo.AuditEvents WHERE 1=0"));Assert.Equal(229,error.Number);return true;
        });
        var denied=await Assert.ThrowsAsync<SqlException>(()=>f.User("app_runtime",db=>new DemoPurgeSql(db,f.Recovery,f.R.Time).RemoveAsync(f.R.Lease)));Assert.Equal(229,denied.Number);
        await f.Exists();Assert.True(await f.Remove());await f.Absent();Assert.False(await f.Remove());
        await using(var check=fixture.Open()) {
            Assert.Equal(1,await check.Suppressions.CountAsync());Assert.True(await check.Envelopes.AnyAsync(x=>x.SenderEmail=="neighbor@example.invalid"));
            Assert.True(await check.EmailOutbox.AnyAsync(x=>x.EnvelopeId==null && x.To=="pre-envelope@example.invalid"));
            var work=await check.WorkItems.SingleAsync(x=>x.Id==f.R.Lease.Id);Assert.Null(work.EnvelopeId);Assert.Equal(WorkStatus.Leased,work.Status);
            Assert.Equal(DemoPurgeAuthority.Payload(f.R.Policy),work.PayloadJson);
            await new WorkStore(check,new(),f.R.Time).FinishAsync(f.R.Lease,new(WorkOutcome.Completed),default);
        }
        var swept=await f.Recovery.RecoverBatchAsync();Assert.Equal(2,swept.Deleted);Assert.Equal(0,swept.Failed);
        var late=f.Service.GetBlobContainerClient("normalized").GetBlobClient($"{f.R.H.Id:N}/completion-candidates/{Guid.NewGuid():N}");
        await late.UploadAsync(BinaryData.FromString("LATE SYNTHETIC NO AGREEMENT"));Assert.Equal(1,(await f.Recovery.RecoverBatchAsync()).Deleted);
        Assert.True((await f.Marker.ExistsAsync()).Value);
        await f.User("app_worker",async db=> {var error=await Assert.ThrowsAsync<SqlException>(()=>db.Database.ExecuteSqlRawAsync("DELETE FROM dbo.DocumentRetentionSnapshots WHERE 1=0"));Assert.Equal(229,error.Number);return true;});
    }
    [Theory]
    [InlineData("ordinary")][InlineData("missing-policy")][InlineData("corrupt-policy")][InlineData("corrupt-audit")]
    [InlineData("owner")][InlineData("attempt")][InlineData("kind")][InlineData("payload")][InlineData("expired")][InlineData("future-server-time")]
    public async Task Wrong_policy_lease_payload_or_server_time_preserves_all_private_records(string fault)
    {
        await using var f=await Scope.Create(fixture,future:fault=="future-server-time");await f.Provision();
        await using(var db=fixture.Open()) {
            if(fault=="ordinary")await db.Envelopes.Where(x=>x.Id==f.R.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.IsDemo,false));
            if(fault=="missing-policy")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteDeleteAsync();
            if(fault=="corrupt-policy")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.OriginalSha256,new byte[32]));
            if(fault=="corrupt-audit")await db.AuditEvents.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));
            if(fault=="payload")await db.WorkItems.Where(x=>x.Id==f.R.Lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,DemoPurgeAuthority.Payload(f.R.Policy)+" "));
        }
        f.R.Lease=fault switch {"owner"=>f.R.Lease with{Owner=Guid.NewGuid()},"attempt"=>f.R.Lease with{Attempt=f.R.Lease.Attempt+1},
            "kind"=>f.R.Lease with{Kind=WorkKind.Email},"expired"=>f.R.Lease with{Until=f.R.Time.Now},_=>f.R.Lease};
        var error=await Record.ExceptionAsync(()=>f.Remove());Assert.True(error is UnauthorizedAccessException or InvalidDataException or SqlException,error?.ToString());
        if(fault=="future-server-time")Assert.Equal(50001,Assert.IsType<SqlException>(error).Number);
        await f.Exists();
    }
    [Theory]
    [InlineData("owner")][InlineData("attempt")][InlineData("digest")][InlineData("deadline")][InlineData("ordinary")][InlineData("payload")][InlineData("no-transaction")]
    [InlineData("changed-days")][InlineData("changed-hash")][InlineData("changed-version")]
    public async Task Direct_worker_module_invocation_independently_rejects_mixed_scope(string fault)
    {
        await using var f=await Scope.Create(fixture);await f.Provision();await f.Recovery.RememberAsync(await f.R.Authorize());
        if(fault is "ordinary" or "payload" or "changed-days" or "changed-hash" or "changed-version") {await using var db=fixture.Open();
            if(fault=="ordinary")await db.Envelopes.Where(x=>x.Id==f.R.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.IsDemo,false));
            if(fault=="payload")await db.WorkItems.Where(x=>x.Id==f.R.Lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
            if(fault=="changed-days")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Days,2).SetProperty(x=>x.StartedAt,f.R.Policy.StartedAt.AddDays(-1)));
            if(fault=="changed-hash")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.OriginalSha256,new byte[32]));
            if(fault=="changed-version")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PolicyVersion,UploadRetention.Version+" "));
        }
        var error=await Assert.ThrowsAsync<SqlException>(()=>f.User("app_worker",async db=> {
            await using var tx=fault=="no-transaction" ? null : await db.Database.BeginTransactionAsync();
            await using var command=((SqlConnection)db.Database.GetDbConnection()).CreateCommand();command.Transaction=(SqlTransaction?)tx?.GetDbTransaction();
            command.CommandText="dbo.RemoveExpiredDemoPrivateRecords";command.CommandType=CommandType.StoredProcedure;
            command.Parameters.AddWithValue("@EnvelopeId",f.R.H.Id);command.Parameters.AddWithValue("@WorkId",f.R.Lease.Id);
            command.Parameters.AddWithValue("@Owner",fault=="owner" ? Guid.NewGuid() : f.R.Lease.Owner);
            command.Parameters.AddWithValue("@Attempt",f.R.Lease.Attempt+(fault=="attempt" ? 1:0));command.Parameters.AddWithValue("@Until",f.R.Lease.Until);
            command.Parameters.AddWithValue("@PolicySha256",fault=="digest" ? new string('0',64) : UploadRetention.Digest(f.R.Policy));
            command.Parameters.AddWithValue("@DeleteAfter",f.R.Policy.DeleteAfter.AddSeconds(fault=="deadline" ? -1:0));return Convert.ToBoolean(await command.ExecuteScalarAsync());
        }));Assert.Equal(50001,error.Number);await f.Exists();
    }
    [Theory]
    [InlineData("tamper")][InlineData("storage-unavailable")][InlineData("cancel")][InlineData("rollback")][InlineData("lost-commit")]
    public async Task Marker_failures_and_transaction_uncertainty_never_lose_recovery_authority(string fault)
    {
        await using var f=await Scope.Create(fixture);await f.Provision();await f.Recovery.RememberAsync(await f.R.Authorize());
        if(fault=="tamper")await f.Marker.UploadAsync(BinaryData.FromString("not an authenticated marker"),true);
        var recovery=f.Recovery;
        if(fault=="storage-unavailable") {var options=new BlobClientOptions();options.Retry.MaxRetries=0;
            recovery=new(new BlobContainerClient(new Uri("http://127.0.0.1:1/synthetic-unavailable"),options),f.Protection,new AzureEnvelopePurgeStore(f.Service),f.R.Time);}
        using var stop=new CancellationTokenSource();if(fault=="cancel")stop.Cancel();
        var interceptor=new CommitFault {Mode=fault};
        var error=await Record.ExceptionAsync(()=>f.User("app_worker",db=>new DemoPurgeSql(db,recovery,f.R.Time).RemoveAsync(f.R.Lease,stop.Token),interceptor));Assert.NotNull(error);
        if(fault=="lost-commit") {await f.Absent();Assert.False(await f.Remove());}
        else {await f.Exists();if(fault=="rollback")Assert.True(await f.Remove());}
        Assert.True((await f.Marker.ExistsAsync()).Value);
    }
    [Fact]
    public async Task Already_removed_replay_still_requires_the_exact_authenticated_marker_and_current_lease()
    {
        await using var f=await Scope.Create(fixture);await f.Provision();Assert.True(await f.Remove());
        var bytes=(await f.Marker.DownloadContentAsync()).Value.Content;await f.Marker.UploadAsync(BinaryData.FromString("corrupt"),true);
        Assert.NotNull(await Record.ExceptionAsync(()=>f.Remove()));await f.Marker.UploadAsync(bytes,true);
        f.R.Lease=f.R.Lease with{Owner=Guid.NewGuid()};await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Remove());await f.Absent();
    }
    [Fact]
    public async Task Genuine_completed_chain_with_publication_tokens_and_current_finish_cycle_is_removed_in_FK_order()
    {
        var started=DateTimeOffset.UtcNow.AddDays(-2);
        await using var completed=await CompletionSealOutputTests.Run.Create(fixture,uploadRetentionDays:1,initialTime:started);
        _=await completed.Prepare();var id=completed.Signing.Envelope.Id;var service=completed.Signing.H.App.Services.GetRequiredService<BlobServiceClient>();
        await using(var db=fixture.Open()) {
            // Synthetic historical publication metadata follows the fixture clock;
            // Azurite itself correctly timestamps new blobs with real UTC.
            var store=new CompletionDownloadTests.FinalStore(completed.Signing.H.Clock);
            var publication=new CompletionPublication(db,completed.Candidates(db),completed.Service(db),completed.Collector(db),store,new(db,completed.Signing.H.Clock),completed.Signing.H.Clock,
                new(){AllowDevelopmentWriteOnce=true,DemoPurgeAfterDays=30},completed.Seal.App.Environment);
            Assert.NotNull(await publication.PublishAsync(id));
            var result=await db.CompletionPublicationResults.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id);
            db.AuthTokens.Add(new(){EnvelopeId=id,Purpose=TokenPurpose.CompletionAccess,PartyType=PartyType.Sender,Email="synthetic@example.invalid",
                CompletionPublicationId=result.Id,CompletionRecipeSha256=new byte[32],CompletionPartySha256=new byte[32],TokenSha256=System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)});
            await db.SaveChangesAsync();Assert.True(await db.CompletionSealOutputs.AnyAsync(x=>x.EnvelopeId==id));
            Assert.True(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==id));Assert.NotNull((await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id)).CurrentFinishId);
        }
        var time=new DemoPurgeStorageTests.Clock{Now=DateTimeOffset.UtcNow};DocumentRetentionSnapshot policy;WorkLease lease;
        await using(var db=fixture.Open()) {policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id);
            var work=new WorkItem{EnvelopeId=id,Kind=WorkKind.Purge,PayloadJson=DemoPurgeAuthority.Payload(policy),AvailableAt=time.Now};db.WorkItems.Add(work);await db.SaveChangesAsync();
            lease=(await new WorkStore(db,new(),time).ClaimAsync(work.Id,default)).Lease!;}
        var hints=service.GetBlobContainerClient("purge-sql-"+Guid.NewGuid().ToString("N"));await hints.CreateIfNotExistsAsync();
        try {
            var recovery=new DemoPurgeRecovery(hints,new EphemeralDataProtectionProvider(),new AzureEnvelopePurgeStore(service),time);
            await using var db=fixture.Open();await Scope.Provision(db);await Scope.AsUser(db,"app_worker",async context=>Assert.True(await new DemoPurgeSql(context,recovery,time).RemoveAsync(lease)));
            foreach(var table in OwnedTables)Assert.Equal(0,await Count(db,table,id));
            var sweep=await recovery.RecoverBatchAsync();Assert.Equal(0,sweep.Failed);Assert.True(sweep.Deleted>0);
        }finally{await hints.DeleteIfExistsAsync();}
    }
    private static readonly string[] OwnedTables=["Envelopes","DocumentRetentionSnapshots","AuditEvents","AuthTokens","Fields","Signers","Recipients","SignaturePreviews","SignerReviewCandidates","SignerFinishAcceptances","CompletionCandidates","CompletionSealOutputs","CompletionPublicationIntents","CompletionPublicationResults","EmailOutbox"];
    private static async Task<int> Count(QuillSignDbContext db,string table,Guid id) {
        // Table names are the fixed test inventory above, never caller input.
        await db.Database.OpenConnectionAsync();await using var command=db.Database.GetDbConnection().CreateCommand();
        command.CommandText=$"SELECT COUNT(*) FROM dbo.[{table}] WHERE [{(table=="Envelopes" ? "Id":"EnvelopeId")}]=@id";
        command.Parameters.Add(new SqlParameter("@id",id));return Convert.ToInt32(await command.ExecuteScalarAsync());
    }
    private sealed class CommitFault:DbTransactionInterceptor
    {
        public string Mode="";
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,TransactionEventData data,InterceptionResult result,CancellationToken ct=default)
        {if(Mode=="rollback")throw new IOException("Synthetic rejected cleanup commit");return ValueTask.FromResult(result);}
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData data,CancellationToken ct=default)
        {if(Mode=="lost-commit")throw new IOException("Synthetic lost cleanup acknowledgement");return Task.CompletedTask;}
    }
    private sealed class Scope(SqlDatabaseFixture fixture,Run run):IAsyncDisposable
    {
        public Run R=run;public BlobServiceClient Service=DemoPurgeStorageTests.Service();public BlobContainerClient Hints=null!;
        public IDataProtectionProvider Protection=new EphemeralDataProtectionProvider();
        public BlobClient Marker=>Hints.GetBlobClient(DemoPurgeRecovery.Prefix+R.H.Id.ToString("N"));
        public DemoPurgeRecovery Recovery=>new(Hints,Protection,new AzureEnvelopePurgeStore(Service),R.Time);
        public static async Task<Scope> Create(SqlDatabaseFixture fixture,bool future=false) {
            var run=await Run.Create(fixture,future ? DateTimeOffset.UtcNow : DateTimeOffset.UtcNow.AddDays(-2));
            var f=new Scope(fixture,run);f.Hints=f.Service.GetBlobContainerClient("purge-sql-"+Guid.NewGuid().ToString("N"));await f.Hints.CreateIfNotExistsAsync();
            if(!future) {run.Time.Now=DateTimeOffset.UtcNow;await using var db=fixture.Open();run.Lease=(await new WorkStore(db,new(),run.Time).ClaimAsync(run.Lease.Id,default)).Lease!;}
            return f;
        }
        public async Task Provision(){await using var db=fixture.Open();await Provision(db);}
        public static async Task Provision(QuillSignDbContext db) {
            await db.Database.OpenConnectionAsync();var connection=(SqlConnection)db.Database.GetDbConnection();
            await db.Database.ExecuteSqlRawAsync("IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER app_runtime WITHOUT LOGIN; IF DATABASE_PRINCIPAL_ID('app_worker') IS NULL CREATE USER app_worker WITHOUT LOGIN");
            await DatabasePermissions.GrantRuntimeAsync(connection);await db.Database.ExecuteSqlRawAsync("ALTER ROLE app_runtime_role ADD MEMBER app_worker");
            await DatabasePermissions.GrantDemoPurgeAsync(connection);await DatabasePermissions.GrantDemoPurgeAsync(connection);
        }
        public async Task<T> User<T>(string user,Func<QuillSignDbContext,Task<T>> action,CommitFault? fault=null) {
            await using var baseline=fixture.Open();var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString());if(fault is not null)options.AddInterceptors(fault);
            await using var db=new QuillSignDbContext(options.Options);T value=default!;await AsUser(db,user,async context=>value=await action(context));return value;
        }
        public static async Task AsUser(QuillSignDbContext db,string user,Func<QuillSignDbContext,Task> action) {
            if(user is not("app_runtime" or "app_worker"))throw new ArgumentException("Fixed synthetic principals only");
            await db.Database.OpenConnectionAsync();
            if(user=="app_worker")await db.Database.ExecuteSqlRawAsync("EXECUTE AS USER='app_worker'");
            else await db.Database.ExecuteSqlRawAsync("EXECUTE AS USER='app_runtime'");
            try {await action(db);}finally{await db.Database.ExecuteSqlRawAsync("REVERT");}
        }
        public Task<bool> Remove()=>User("app_worker",db=>new DemoPurgeSql(db,Recovery,R.Time).RemoveAsync(R.Lease));
        public async Task Exists(){await using var db=fixture.Open();Assert.True(await db.Envelopes.AnyAsync(x=>x.Id==R.H.Id));Assert.True(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==R.H.Id));}
        public async Task Absent(){await using var db=fixture.Open();foreach(var table in OwnedTables)Assert.Equal(0,await Count(db,table,R.H.Id));}
        public async ValueTask DisposeAsync(){await Hints.DeleteIfExistsAsync();await R.DisposeAsync();}
    }
}

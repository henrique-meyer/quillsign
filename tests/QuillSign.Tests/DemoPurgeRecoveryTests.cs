using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using System.Diagnostics;
using System.Text.Json;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Work;
using Run=QuillSign.Tests.DemoPurgeStorageTests.Run;

namespace QuillSign.Tests;

public sealed class DemoPurgeRecoveryTests(SqlDatabaseFixture database):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Persistent_authenticated_marker_recovers_without_SQL_or_original_lease_and_keeps_recovering_late_writes()
    {
        await using var f=await Fixture.Create(database);await f.Remember();
        var protectedBody=(await f.Marker.DownloadContentAsync()).Value.Content.ToString();Assert.DoesNotContain(f.R.H.Email,protectedBody);Assert.DoesNotContain(f.R.H.Id.ToString("N"),protectedBody);
        // Simulate the following coordinator removing this small synthetic fixture's private SQL state.
        await using(var db=database.Open()) {
            await db.WorkItems.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteDeleteAsync();await db.AuditEvents.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteDeleteAsync();
            await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.R.H.Id).ExecuteDeleteAsync();await db.Envelopes.Where(x=>x.Id==f.R.H.Id).ExecuteDeleteAsync();
        }
        f.R.Time.Now=f.R.Time.Now.AddDays(10);var restarted=f.Recovery(f.Protection());
        var first=await restarted.RecoverBatchAsync();Assert.Equal(1,first.Swept);Assert.Equal(2,first.Deleted);Assert.Equal(0,first.Failed);Assert.True((await f.Marker.ExistsAsync()).Value);
        var empty=await restarted.RecoverBatchAsync();Assert.Equal(0,empty.Deleted);Assert.Equal(1,empty.Swept);
        var late=await f.Put("normalized","completion-candidates/");Assert.True((await late.ExistsAsync()).Value);
        var again=await restarted.RecoverBatchAsync();Assert.Equal(1,again.Deleted);Assert.False((await late.ExistsAsync()).Value);Assert.True((await f.Marker.ExistsAsync()).Value);
    }
    [Theory]
    [InlineData("tampered")][InlineData("oversized")][InlineData("other-envelope")][InlineData("other-container")][InlineData("other-application")]
    public async Task Corrupt_or_rebound_markers_never_authorize_document_deletion(string fault)
    {
        await using var f=await Fixture.Create(database);await f.Remember();var bytes=(await f.Marker.DownloadContentAsync()).Value.Content;
        var container=f.Hints;var recovery=f.Recovery();BlobContainerClient? other=null;
        try {
            if(fault=="tampered")await f.Marker.UploadAsync(BinaryData.FromString(bytes.ToString()+"broken"),true);
            if(fault=="oversized")await f.Marker.UploadAsync(BinaryData.FromString(new string('x',40000)),true);
            if(fault=="other-envelope") {await f.Marker.DeleteAsync();await container.GetBlobClient(DemoPurgeRecovery.Prefix+Guid.NewGuid().ToString("N")).UploadAsync(bytes);}
            if(fault=="other-container") {other=f.Service.GetBlobContainerClient("purge-"+Guid.NewGuid().ToString("N"));await other.CreateIfNotExistsAsync();await other.GetBlobClient(f.Marker.Name).UploadAsync(bytes);recovery=new(other,f.Protection(),new AzureEnvelopePurgeStore(f.Service),f.R.Time);}
            if(fault=="other-application")recovery=f.Recovery(f.Protection("Foreign synthetic application"));
            var result=await recovery.RecoverBatchAsync();Assert.Equal(1,result.Failed);Assert.Equal(0,result.Deleted);Assert.True((await f.Source().ExistsAsync()).Value);
        }finally{if(other is not null)await other.DeleteIfExistsAsync();}
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Lost_marker_creation_or_progress_acknowledgement_is_resolved_only_by_exact_readback(bool progress)
    {
        await using var f=await Fixture.Create(database);var fault=new FaultPolicy(progress ? "progress" : "create");var recovery=f.Recovery(container:f.With(fault));
        await recovery.RememberAsync(await f.R.Authorize());Assert.Equal(progress ? 0 : 1,fault.Calls);
        var result=await recovery.RecoverBatchAsync();Assert.Equal(0,result.Failed);Assert.Equal(2,result.Deleted);Assert.Equal(1,fault.Calls);Assert.Equal(0,(await recovery.RecoverBatchAsync()).Deleted);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Scope_expiry_before_or_after_effective_deletion_is_incomplete_then_fresh_storage_authority_recovers(bool after)
    {
        await using var f=await Fixture.Create(database);await f.Remember();var inner=new AzureEnvelopePurgeStore(f.Service);Action expire=()=>f.R.Time.Now=f.R.Time.Now.AddMinutes(1);
        var fault=new FaultStore(inner,after ? null : expire,after ? expire : null);var result=await f.Recovery(storage:fault).RecoverBatchAsync();Assert.Equal(1,result.Failed);Assert.Equal(0,result.Swept);
        Assert.True((await f.Marker.ExistsAsync()).Value);var retry=await f.Recovery().RecoverBatchAsync();Assert.Equal(1,retry.Swept);Assert.Equal(0,retry.Failed);Assert.Equal(after ? 0 : 2,retry.Deleted);
    }
    [Fact]
    public async Task Active_marker_lease_excludes_concurrent_sweeps_without_breaking_or_losing_it()
    {
        await using var f=await Fixture.Create(database);await f.Remember();var gate=new GateStore(new AzureEnvelopePurgeStore(f.Service));var first=f.Recovery(storage:gate).RecoverBatchAsync();
        await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try {var other=await f.Recovery().RecoverBatchAsync();Assert.Equal(1,other.Busy);Assert.Equal(0,other.Deleted);Assert.Equal(0,other.Failed);}
        finally {gate.Release.TrySetResult();}
        Assert.Equal(2,(await first).Deleted);Assert.Equal(1,gate.Calls);Assert.Equal(0,(await f.Recovery().RecoverBatchAsync()).Failed);
    }
    [Fact]
    public async Task Lost_acquisition_acknowledgement_preserves_a_finite_owned_lease_and_marker_for_retry()
    {
        await using var f=await Fixture.Create(database);await f.Remember();var fault=new FaultPolicy("acquire");var recovery=f.Recovery(container:f.With(fault));
        var result=await recovery.RecoverBatchAsync();Assert.Equal(1,result.Failed);Assert.Equal(0,result.Deleted);Assert.NotNull(fault.LeaseId);
        Assert.Equal(1,(await f.Recovery().RecoverBatchAsync()).Busy);
        // Test cleanup releases only the exact lease ID observed in its own successful server response.
        await f.Marker.GetBlobLeaseClient(fault.LeaseId).ReleaseAsync();Assert.Equal(2,(await f.Recovery().RecoverBatchAsync()).Deleted);
    }
    [Fact]
    public async Task Cancellation_after_marker_write_preserves_durable_authority_without_returning_a_false_success()
    {
        await using var f=await Fixture.Create(database);using var cancel=new CancellationTokenSource();var fault=new FaultPolicy("create",()=>cancel.Cancel());var cap=await f.R.Authorize();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>f.Recovery(container:f.With(fault)).RememberAsync(cap,cancel.Token));
        Assert.True((await f.Marker.ExistsAsync()).Value);Assert.Equal(2,(await f.Recovery().RecoverBatchAsync()).Deleted);
    }
    [Fact]
    public async Task Bounded_object_progress_survives_a_new_provider_and_an_empty_pass_keeps_the_marker()
    {
        await using var f=await Fixture.Create(database);for(var i=0;i<20;i++)await f.Put("originals");await f.Remember();
        var first=await f.Recovery().RecoverBatchAsync(1);Assert.Equal(16,first.Deleted);Assert.Equal(1,first.Pending);Assert.False(first.More);
        var rest=await f.Recovery(f.Protection()).RecoverBatchAsync(1);Assert.Equal(6,rest.Deleted);Assert.Equal(0,rest.Pending);
        Assert.Equal(0,(await f.Recovery().RecoverBatchAsync(1)).Deleted);Assert.True((await f.Marker.ExistsAsync()).Value);
    }
    [Fact]
    public async Task Bounded_marker_cursor_rotates_across_envelopes_without_SQL_or_raw_cursor_output()
    {
        await using var f=await Fixture.Create(database);await using var second=await Run.Create(database);await using var third=await Run.Create(database);
        await f.Remember();await f.Recovery().RememberAsync(await second.Authorize());await f.Recovery().RememberAsync(await third.Authorize());
        var ids=new List<Guid>();var recorder=new RecordingStore(new AzureEnvelopePurgeStore(f.Service),ids);var recovery=f.Recovery(storage:recorder);
        for(var i=0;i<3;i++){var result=await recovery.RecoverBatchAsync(1);Assert.Equal(1,result.Examined);Assert.Equal(i<2,result.More);Assert.Equal(0,result.Failed);Assert.DoesNotContain("Cursor",System.Text.Json.JsonSerializer.Serialize(result));}
        Assert.Equal(3,ids.Distinct().Count());Assert.Equal(1,(await recovery.RecoverBatchAsync(1)).Examined);
    }
    [Fact]
    public async Task Recovery_registration_has_no_SQL_and_ordinary_recover_never_materializes_a_key_ring()
    {
        await using var f=await Fixture.Create(database);await f.Remember();var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Storage:Provider"]="Azurite",["Storage:ConnectionString"]=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),["Work:Enabled"]="true",["Work:QueueName"]=f.Hints.Name,["Work:HintContainer"]=f.Hints.Name}).Build();
        var environment=new EnvironmentStub();var services=new ServiceCollection();services.AddLogging();services.AddQuillSignWork(config,environment,registerHandlers:false);
        services.AddQuillSignStorage(config,environment);services.AddDemoPurgeRecovery();services.AddSingleton<TimeProvider>(f.R.Time);services.AddSingleton(f.Protection());
        Assert.DoesNotContain(services,x=>x.ServiceType==typeof(QuillSignDbContext) || x.ServiceType==typeof(IWorkHandler));
        using(var provider=services.BuildServiceProvider()){Assert.Equal(2,(await provider.GetRequiredService<DemoPurgeRecovery>().RecoverBatchAsync()).Deleted);}
        var original=new ServiceCollection();original.AddQuillSignWork(config,environment,registerHandlers:false);
        original.AddSingleton<IDataProtectionProvider>(_=>throw new InvalidOperationException("Ordinary recovery must not resolve keys"));
        using var untouched=original.BuildServiceProvider();Assert.Equal(0,await untouched.GetRequiredService<IWorkSignals>().RecoverAsync(f.R.Time.GetUtcNow(),default));
    }
    [Fact]
    public async Task Actual_CLI_recovers_with_persistent_storage_keys_and_no_database_configuration()
    {
        await using var f=await Fixture.Create(database,DateTimeOffset.UtcNow.AddDays(-2));var name="purge-cli-"+Guid.NewGuid().ToString("N");var keyName=name+".xml";
        var connection=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Storage:Provider"]="Azurite",["Storage:ConnectionString"]=connection,["Work:Enabled"]="true",["Work:QueueName"]=f.Hints.Name,["Work:HintContainer"]=f.Hints.Name,
            ["DataProtection:ApplicationName"]=name,["DataProtection:KeyRingBlobName"]=keyName}).Build();
        var environment=new EnvironmentStub();var services=new ServiceCollection();services.AddLogging();services.AddQuillSignWork(config,environment,registerHandlers:false);
        services.AddQuillSignStorage(config,environment);services.AddDemoPurgeRecovery();services.AddSingleton<TimeProvider>(f.R.Time);
        var key=f.Service.GetBlobContainerClient("keys").GetBlobClient(keyName);
        try {
            using(var provider=services.BuildServiceProvider())await provider.GetRequiredService<DemoPurgeRecovery>().RememberAsync(await f.R.Authorize());
            var configuration=Directory.GetParent(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar))!.Name;
            var app=Path.GetFullPath("../../../../../src/QuillSign/bin/"+configuration+"/net10.0/QuillSign.dll",AppContext.BaseDirectory);Assert.True(File.Exists(app));
            var start=new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")??"dotnet") {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Path.GetDirectoryName(app)!};
            start.ArgumentList.Add(app);start.ArgumentList.Add("work");start.ArgumentList.Add("purge-recover");start.ArgumentList.Add("1");
            foreach(var variable in start.Environment.Keys.Where(x=>x.StartsWith("ConnectionStrings__",StringComparison.OrdinalIgnoreCase)).ToArray())start.Environment.Remove(variable);
            start.Environment.Remove("QUILLSIGN_TEST_DATABASE");
            start.Environment["ConnectionStrings__Database"]="";
            foreach(var pair in new Dictionary<string,string> { ["DOTNET_ENVIRONMENT"]="Development",["ASPNETCORE_ENVIRONMENT"]="Development",["Storage__Provider"]="Azurite",["Storage__ConnectionString"]=connection,
                ["Work__Enabled"]="true",["Work__QueueName"]=f.Hints.Name,["Work__HintContainer"]=f.Hints.Name,["DataProtection__ApplicationName"]=name,["DataProtection__KeyRingBlobName"]=keyName,["Email__Enabled"]="false" })start.Environment[pair.Key]=pair.Value;
            using var process=Process.Start(start)!;using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(50));
            try {
                var output=process.StandardOutput.ReadToEndAsync(timeout.Token);var errors=process.StandardError.ReadToEndAsync(timeout.Token);await process.WaitForExitAsync(timeout.Token);
                var text=await output;var error=await errors;Assert.True(process.ExitCode==0,$"Recovery CLI exited {process.ExitCode}: {error}");
                Assert.False(text.Contains(f.R.H.Id.ToString("N"),StringComparison.Ordinal) || text.Contains(f.R.H.Email,StringComparison.Ordinal) || text.Contains(connection,StringComparison.Ordinal),"CLI must emit only counters");
                using var json=JsonDocument.Parse(text);Assert.Equal("work-purge-recover",json.RootElement.GetProperty("operation").GetString());Assert.Equal(2,json.RootElement.GetProperty("Deleted").GetInt32());Assert.Equal(0,json.RootElement.GetProperty("Failed").GetInt32());
            }finally {if(!process.HasExited){process.Kill(entireProcessTree:true);await process.WaitForExitAsync();}}
        }finally {await key.DeleteIfExistsAsync();}
    }
    [Theory]
    [InlineData("0")][InlineData("33")][InlineData("not-a-number")]
    public async Task Invalid_CLI_batch_never_initializes_storage_or_SQL(string batch)
        =>Assert.Equal(2,await WorkCommands.RunAsync(["purge-recover",batch]));
    private sealed class EnvironmentStub:IHostEnvironment
    {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="QuillSign.Tests";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
    private sealed class FaultStore(IEnvelopePurgeStore inner,Action? before,Action? after):IEnvelopePurgeStore
    {public async Task<PurgeStorageBatch> SweepAsync(DemoPurgeAuthority a,int maximum,PurgeStorageCursor? cursor=null,CancellationToken ct=default){before?.Invoke();var result=await inner.SweepAsync(a,maximum,cursor,ct);after?.Invoke();return result;}}
    private sealed class RecordingStore(IEnvelopePurgeStore inner,List<Guid> ids):IEnvelopePurgeStore
    {public Task<PurgeStorageBatch> SweepAsync(DemoPurgeAuthority a,int maximum,PurgeStorageCursor? cursor=null,CancellationToken ct=default){ids.Add(a.EnvelopeId);return inner.SweepAsync(a,maximum,cursor,ct);}}
    private sealed class GateStore(IEnvelopePurgeStore inner):IEnvelopePurgeStore
    {
        public TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously),Release=new(TaskCreationOptions.RunContinuationsAsynchronously);public int Calls;
        public async Task<PurgeStorageBatch> SweepAsync(DemoPurgeAuthority a,int maximum,PurgeStorageCursor? cursor=null,CancellationToken ct=default){Calls++;Entered.TrySetResult();await Release.Task.WaitAsync(ct);return await inner.SweepAsync(a,maximum,cursor,ct);}
    }
    private sealed class FaultPolicy(string mode,Action? cancel=null):HttpPipelinePolicy
    {
        public int Calls;public string? LeaseId;
        public override void Process(HttpMessage message,ReadOnlyMemory<HttpPipelinePolicy> pipeline){ProcessNext(message,pipeline);Fault(message);}
        public override async ValueTask ProcessAsync(HttpMessage message,ReadOnlyMemory<HttpPipelinePolicy> pipeline){await ProcessNextAsync(message,pipeline);Fault(message);}
        private void Fault(HttpMessage message)
        {
            var uri=message.Request.Uri.ToUri();if(Calls!=0 || message.Request.Method!=RequestMethod.Put || message.Response.Status!=201 || !uri.AbsolutePath.Contains("/"+DemoPurgeRecovery.Prefix,StringComparison.Ordinal))return;
            var acquiring=uri.Query.Contains("comp=lease",StringComparison.Ordinal);var progress=message.Request.Headers.TryGetValue("x-ms-lease-id",out _);
            if(mode=="acquire" ? !acquiring : acquiring || (mode=="progress")!=progress)return;
            Calls++;if(acquiring && message.Response.Headers.TryGetValue("x-ms-lease-id",out var id))LeaseId=id;
            cancel?.Invoke();if(cancel is not null)throw new OperationCanceledException();throw new IOException("Synthetic lost marker response");
        }
    }
    private sealed class Fixture:IAsyncDisposable
    {
        public Run R=null!;public BlobServiceClient Service=null!;public BlobContainerClient Hints=null!;private string keys="";private readonly List<BlobClient> created=[];
        public BlobClient Marker=>Hints.GetBlobClient(DemoPurgeRecovery.Prefix+R.H.Id.ToString("N"));
        public static async Task<Fixture> Create(SqlDatabaseFixture database,DateTimeOffset? initialTime=null)
        {
            var f=new Fixture {R=await Run.Create(database,initialTime),Service=DemoPurgeStorageTests.Service()};Assert.True(f.Service.Uri.IsLoopback);
            f.Hints=f.Service.GetBlobContainerClient("purge-"+Guid.NewGuid().ToString("N"));await f.Hints.CreateIfNotExistsAsync(PublicAccessType.None);
            f.keys=Path.GetFullPath("../../../../../artifacts/QUILS-78-keys-"+Guid.NewGuid().ToString("N"),AppContext.BaseDirectory);Directory.CreateDirectory(f.keys);return f;
        }
        public IDataProtectionProvider Protection(string application="QuillSign.SyntheticPurgeRecovery")=>DataProtectionProvider.Create(new DirectoryInfo(keys),o=>o.SetApplicationName(application));
        public DemoPurgeRecovery Recovery(IDataProtectionProvider? protection=null,IEnvelopePurgeStore? storage=null,BlobContainerClient? container=null)=>new(container??Hints,protection??Protection(),storage??new AzureEnvelopePurgeStore(Service),R.Time);
        public async Task Remember()=>await Recovery().RememberAsync(await R.Authorize());
        public BlobClient Source()=>Service.GetBlobContainerClient("originals").GetBlobClient($"{R.H.Id:N}/{R.Policy.OriginalObjectId:N}");
        public async Task<BlobClient> Put(string area,string path=""){var c=Service.GetBlobContainerClient(area);await c.CreateIfNotExistsAsync();var b=c.GetBlobClient($"{R.H.Id:N}/{path}{Guid.NewGuid():N}");created.Add(b);await b.UploadAsync(BinaryData.FromString("SYNTHETIC LATE CONTENT NO AGREEMENT"));return b;}
        public BlobContainerClient With(FaultPolicy policy){var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);options.AddPolicy(policy,HttpPipelinePosition.PerCall);return new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),options).GetBlobContainerClient(Hints.Name);}
        public async ValueTask DisposeAsync()
        {
            foreach(var blob in created)await blob.DeleteIfExistsAsync();await R.DisposeAsync();await Hints.DeleteIfExistsAsync();var root=Path.GetFullPath("../../../../../artifacts/",AppContext.BaseDirectory);
            if(!Path.GetFullPath(keys).StartsWith(root,StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(keys).StartsWith("QUILS-78-keys-",StringComparison.Ordinal))throw new InvalidOperationException("Unsafe synthetic key cleanup path");
            if(Directory.Exists(keys))Directory.Delete(keys,true);
        }
    }
}

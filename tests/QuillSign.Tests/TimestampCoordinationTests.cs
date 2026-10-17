using System.Diagnostics;
using System.Security.Cryptography;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Specialized;
using QuillSign.Sealing;

namespace QuillSign.Tests;

public sealed class TimestampCoordinationTests
{
    [Fact]
    public async Task Independent_workers_serialize_shared_provider_and_restart_preserves_empty_private_storage()
    {
        await using var h=await Harness.Create();var first=h.Coordinator();var second=h.Coordinator();var endpoint=new Uri("https://tsa.example.invalid/tsr");
        var order=new List<long>();var inside=0;var maximum=0;
        async Task Use(ITimestampRequestCoordinator coordinator) {
            await using var lease=await coordinator.AcquireAsync(endpoint,default);await lease.EnsureOwnedAsync(default);
            lock(order) {inside++;maximum=Math.Max(maximum,inside);order.Add(Stopwatch.GetTimestamp());}
            await Task.Delay(25);lock(order)inside--;
        }
        await Task.WhenAll(Use(first),Use(second),Use(h.Coordinator()));
        Assert.Equal(1,maximum);Assert.Equal(3,order.Count);
        for(var i=1;i<order.Count;i++)Assert.True(Stopwatch.GetElapsedTime(order[i-1],order[i])>=TimeSpan.FromSeconds(1));
        var names=new List<string>();await foreach(var item in h.Container.GetBlobsAsync())names.Add(item.Name);
        var name=Assert.Single(names);Assert.DoesNotContain("tsa.example.invalid",name);var blob=h.Container.GetBlobClient(name);
        Assert.Empty((await blob.DownloadContentAsync()).Value.Content.ToArray());Assert.Empty((await blob.GetPropertiesAsync()).Value.Metadata);
    }

    [Fact]
    public async Task FreeTSA_host_aliases_share_one_lock_and_contention_is_bounded_without_fallback()
    {
        await using var h=await Harness.Create();await using var lease=await h.Coordinator().AcquireAsync(new("https://freetsa.org/tsr"),default);
        await lease.EnsureOwnedAsync(default);var timer=Stopwatch.StartNew();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>h.Coordinator(1).AcquireAsync(new("https://WWW.FreeTSA.org/another-path"),default));
        Assert.InRange(timer.Elapsed.TotalSeconds,.9,8);var count=0;await foreach(var item in h.Container.GetBlobsAsync())count++;Assert.Equal(1,count);
    }

    [Fact]
    public async Task Cancelled_wait_does_not_disturb_owner_and_cancelled_attempt_retains_cooldown()
    {
        await using var h=await Harness.Create();var endpoint=new Uri("https://tsa.example.invalid/tsr");
        var owner=await h.Coordinator().AcquireAsync(endpoint,default);using var cancellation=new CancellationTokenSource(150);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>h.Coordinator().AcquireAsync(endpoint,cancellation.Token));await owner.EnsureOwnedAsync(default);
        var timer=Stopwatch.StartNew();await owner.DisposeAsync();Assert.True(timer.Elapsed>=TimeSpan.FromSeconds(1));
        using var attempt=new CancellationTokenSource();var next=await h.Coordinator().AcquireAsync(endpoint,attempt.Token);await next.EnsureOwnedAsync(default);attempt.Cancel();
        timer.Restart();await next.DisposeAsync();Assert.True(timer.Elapsed>=TimeSpan.FromSeconds(1));
        await using var recovered=await h.Coordinator().AcquireAsync(endpoint,default);await recovered.EnsureOwnedAsync(default);
    }

    [Fact]
    public async Task Lost_lease_is_rejected_before_request_and_storage_absence_never_authorizes_a_fallback()
    {
        await using var h=await Harness.Create();await using var lease=await h.Coordinator().AcquireAsync(new("https://tsa.example.invalid/tsr"),default);
        string? name=null;await foreach(var item in h.Container.GetBlobsAsync())name=item.Name;Assert.NotNull(name);
        await h.Container.GetBlobClient(name).GetBlobLeaseClient().BreakAsync(TimeSpan.Zero);
        await Assert.ThrowsAsync<SealUnavailableException>(()=>lease.EnsureOwnedAsync(default));
        var absent=h.Service.GetBlobContainerClient("missing-"+Guid.NewGuid().ToString("N"));
        await Assert.ThrowsAsync<SealUnavailableException>(()=>new BlobTimestampRequestCoordinator(absent,new(){Enabled=true},false).AcquireAsync(new("https://tsa.example.invalid/tsr"),default));
    }

    [Fact]
    public async Task An_abandoned_finite_storage_lease_blocks_restarts_until_it_expires()
    {
        await using var h=await Harness.Create();var endpoint=new Uri("https://tsa.example.invalid/tsr");
        await (await h.Coordinator().AcquireAsync(endpoint,default)).DisposeAsync();
        string? name=null;await foreach(var item in h.Container.GetBlobsAsync())name=item.Name;
        // Simulate process death with a storage-owned lease and no application
        // cleanup. A shorter supported duration keeps the real expiry test bounded.
        await h.Container.GetBlobClient(name!).GetBlobLeaseClient().AcquireAsync(TimeSpan.FromSeconds(15));
        var timer=Stopwatch.StartNew();await using var recovered=await h.Coordinator(25).AcquireAsync(endpoint,default);
        Assert.True(timer.Elapsed>=TimeSpan.FromSeconds(14));await recovered.EnsureOwnedAsync(default);
    }

    [Theory]
    [InlineData(0,30)][InlineData(999,30)][InlineData(10001,30)][InlineData(1000,0)][InlineData(1000,61)]
    public async Task Invalid_limits_fail_before_creating_coordination_storage(int interval,int wait)
    {
        await using var h=await Harness.Create();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>new BlobTimestampRequestCoordinator(h.Container,new(){Enabled=true,MinimumIntervalMilliseconds=interval,AcquireTimeoutSeconds=wait},true).AcquireAsync(new("https://tsa.example.invalid/tsr"),default));
        Assert.False((await h.Container.ExistsAsync()).Value);
    }

    [Theory]
    [InlineData("https://freetsa.org/tsr")][InlineData("https://www.freetsa.org/tsr")][InlineData("https://FREETSA.ORG./tsr")]
    public async Task FreeTSA_requires_coordination_and_explicit_trust_before_private_material_or_network(string endpoint)
    {
        await using var f=await SealFixtures.Create();f.Options.TsaUrl=endpoint;var source=PdfFixtures.Create();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source)));
        f.Options.TimestampCoordination.Enabled=true;f.Options.TsaTrustedRootPaths=[];
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source)));
        Assert.Equal(0,f.Certificates.Calls);Assert.Equal(0,f.Requests);
    }

    [Fact]
    public async Task Actual_local_timestamp_requests_are_spaced_and_invalid_nonce_still_fails_with_coordinator_enabled()
    {
        await using var h=await Harness.Create();await using var f=await SealFixtures.Create();f.Options.TimestampCoordination.Enabled=true;
        var starts=new List<long>();f.RequestObserved=()=> {lock(starts)starts.Add(Stopwatch.GetTimestamp());};
        using var authority=new TimestampAuthority(f.Options,f.App.Environment,f.Time,()=>h.Coordinator());
        var engine=new PlatformPdfSeal(f.Options,f.Certificates,authority,f.App.Environment,f.Time);var source=PdfFixtures.Create();var hash=SHA256.HashData(source);
        var executed=await engine.SealAsync(source,hash);f.Mode="nonce";
        await Assert.ThrowsAsync<SealUnavailableException>(()=>engine.SealAsync(source,hash));f.Mode="valid";
        var certificate=await engine.SealAsync(source,hash);Assert.Equal(3,f.Requests);Assert.Equal(3,starts.Count);
        for(var i=1;i<starts.Count;i++)Assert.True(Stopwatch.GetElapsedTime(starts[i-1],starts[i])>=TimeSpan.FromSeconds(1));
        _=await new SealCms(f.Options,authority).VerifyAsync(executed.Bytes,f.Seal,executed.SealedAt,default);
        _=await new SealCms(f.Options,authority).VerifyAsync(certificate.Bytes,f.Seal,certificate.SealedAt,default);Assert.Equal(3,f.Requests);
    }

    [Fact]
    public async Task Lost_coordination_at_the_send_boundary_prevents_the_actual_timestamp_HTTP_request()
    {
        await using var f=await SealFixtures.Create();f.Options.TimestampCoordination.Enabled=true;var gate=new RejectCoordinator();
        using var authority=new TimestampAuthority(f.Options,f.App.Environment,f.Time,()=>gate);
        var engine=new PlatformPdfSeal(f.Options,f.Certificates,authority,f.App.Environment,f.Time);var source=PdfFixtures.Create();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>engine.SealAsync(source,SHA256.HashData(source)));
        Assert.Equal(0,f.Requests);Assert.Equal(1,gate.Disposals);
    }

    [Fact]
    public async Task Offline_verification_does_not_resolve_coordination_or_call_provider()
    {
        await using var f=await SealFixtures.Create();var source=PdfFixtures.Create();var sealedPdf=await f.Engine.SealAsync(source,SHA256.HashData(source));
        f.Options.TsaUrl="https://freetsa.org/tsr";f.Options.TimestampCoordination.Enabled=false;var resolved=0;
        using var authority=new TimestampAuthority(f.Options,f.App.Environment,f.Time,()=> {resolved++;throw new InvalidOperationException();});
        _=await new SealCms(f.Options,authority).VerifyAsync(sealedPdf.Bytes,f.Seal,sealedPdf.SealedAt,default);
        Assert.Equal(0,resolved);Assert.Equal(1,f.Requests);
    }

    private sealed class RejectCoordinator:ITimestampRequestCoordinator {
        public int Disposals;
        public Task<ITimestampRequestLease> AcquireAsync(Uri endpoint,CancellationToken ct)=>Task.FromResult<ITimestampRequestLease>(new Rejected(this));
        private sealed class Rejected(RejectCoordinator owner):ITimestampRequestLease {
            public CancellationToken Token=>CancellationToken.None;
            public Task EnsureOwnedAsync(CancellationToken ct)=>throw new SealUnavailableException("Synthetic coordination loss");
            public ValueTask DisposeAsync() {owner.Disposals++;return ValueTask.CompletedTask;}
        }
    }

    private sealed class Harness(BlobServiceClient service,BlobContainerClient container):IAsyncDisposable
    {
        public BlobServiceClient Service=>service;public BlobContainerClient Container=>container;
        public BlobTimestampRequestCoordinator Coordinator(int wait=10)=>new(container,new(){Enabled=true,AcquireTimeoutSeconds=wait},true);
        public static Task<Harness> Create() {
            var service=new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!,new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
            return Task.FromResult(new Harness(service,service.GetBlobContainerClient("tsacoord-"+Guid.NewGuid().ToString("N"))));
        }
        public async ValueTask DisposeAsync()=>await container.DeleteIfExistsAsync();
    }
}

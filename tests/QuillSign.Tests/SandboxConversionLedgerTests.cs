using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Specialized;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class SandboxConversionLedgerTests
{
    [Fact]
    public async Task Independent_instances_share_one_fence_and_restart_preserves_authenticated_counters()
    {
        await using var h = new Harness();
        await using (var first = await h.Ledger().AcquireAsync(default))
        {
            await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Ledger().AcquireAsync(default));
            await first.SaveAsync(first.State with { Day = "2026-10-18", DailyAttempts = 2, Month = "2026-10", MonthlyAttempts = 7 }, default);
        }
        await using var restarted = await h.Ledger().AcquireAsync(default);
        Assert.Equal(2, restarted.State.DailyAttempts); Assert.Equal(7, restarted.State.MonthlyAttempts);
        var names = await h.Names(); Assert.Single(names);
        var blob = h.Container.GetBlobClient(names[0]); var bytes = (await blob.DownloadContentAsync()).Value.Content.ToArray();
        Assert.DoesNotContain("2026-10-18", System.Text.Encoding.UTF8.GetString(bytes)); Assert.Empty((await blob.GetPropertiesAsync()).Value.Metadata);
    }

    [Fact]
    public async Task Caller_cancellation_keeps_cleanup_ownership_but_an_actual_lost_lease_fences_writes()
    {
        await using var h = new Harness(); using var caller = new CancellationTokenSource();
        await using var owner = await h.Ledger().AcquireAsync(caller.Token); caller.Cancel();
        Assert.False(owner.Token.IsCancellationRequested);
        await owner.SaveAsync(owner.State with { DailyAttempts = 1 }, default);
        var name = Assert.Single(await h.Names()); await h.Container.GetBlobClient(name).GetBlobLeaseClient().BreakAsync(TimeSpan.Zero);
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => owner.EnsureOwnedAsync(default));
        Assert.True(owner.Token.IsCancellationRequested);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => owner.SaveAsync(owner.State with { DailyAttempts = 2 }, default));
    }

    [Fact]
    public async Task Case_aliases_cannot_bypass_group_serialization()
    {
        await using var h = new Harness(); await using var owner = await h.Ledger().AcquireAsync(default);
        var alias = SandboxDocxTransportTests.Configuration(); alias.SubscriptionId = h.Options.SubscriptionId.ToUpperInvariant();
        alias.ResourceGroup = h.Options.ResourceGroup.ToUpperInvariant(); alias.GroupName = h.Options.GroupName.ToUpperInvariant();
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Ledger(alias).AcquireAsync(default));
        Assert.Single(await h.Names());
    }

    [Theory]
    [InlineData("tampered")]
    [InlineData("oversize")]
    [InlineData("phase")]
    public async Task Unverifiable_records_never_reset_cost_or_pending_operation_evidence(string damage)
    {
        await using var h = new Harness();
        await using (var owner = await h.Ledger().AcquireAsync(default))
            if (damage == "phase") await owner.SaveAsync(owner.State with { Phase = "running" }, default);
        var blob = h.Container.GetBlobClient(Assert.Single(await h.Names()));
        if (damage != "phase")
        {
            var bytes = damage == "oversize" ? new byte[20000] : (await blob.DownloadContentAsync()).Value.Content.ToArray();
            bytes[0] ^= 1; await blob.UploadAsync(BinaryData.FromBytes(bytes), overwrite: true);
        }
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Ledger().AcquireAsync(default));
        Assert.True((await blob.ExistsAsync()).Value);
    }

    [Fact]
    public async Task An_authentic_record_from_a_different_scope_is_not_authority()
    {
        await using var h = new Harness();
        await using (var first = await h.Ledger().AcquireAsync(default)) { }
        var firstName = Assert.Single(await h.Names()); var saved = (await h.Container.GetBlobClient(firstName).DownloadContentAsync()).Value.Content;
        var other = SandboxDocxTransportTests.Configuration();
        await using (var second = await h.Ledger(other).AcquireAsync(default)) { }
        var otherName = (await h.Names()).Single(name => name != firstName);
        await h.Container.GetBlobClient(otherName).UploadAsync(saved, overwrite: true);
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Ledger(other).AcquireAsync(default));
    }

    private sealed class Harness : IAsyncDisposable
    {
        public readonly SandboxConversionOptions Options = SandboxDocxTransportTests.Configuration();
        public readonly BlobContainerClient Container = new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03))
            .GetBlobContainerClient("conversion-ledger-" + Guid.NewGuid().ToString("N"));
        private readonly IDataProtectionProvider protection = new EphemeralDataProtectionProvider();
        public BlobSandboxConversionLedger Ledger(SandboxConversionOptions? options = null) => new(Container, protection, options ?? Options, true);
        public async Task<List<string>> Names() { var names = new List<string>(); await foreach (var item in Container.GetBlobsAsync()) names.Add(item.Name); return names; }
        public async ValueTask DisposeAsync() => await Container.DeleteIfExistsAsync();
    }
}

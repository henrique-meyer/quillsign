using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Documents;

public sealed record SandboxConversionState(string Scope, string Day, int DailyAttempts, string Month, int MonthlyAttempts,
    string? Run = null, string Phase = "idle", string? ImageId = null, string? SandboxId = null);
public interface ISandboxConversionLease : IAsyncDisposable
{
    SandboxConversionState State { get; }
    CancellationToken Token { get; }
    Task EnsureOwnedAsync(CancellationToken ct);
    Task SaveAsync(SandboxConversionState state, CancellationToken ct);
}
public interface ISandboxConversionLedger
{
    Task<ISandboxConversionLease> AcquireAsync(CancellationToken ct);
}

// One protected, non-personal ledger remains outside envelope prefixes. It
// fences replicas, survives SQL purge/process death and preserves cost counters.
public sealed class BlobSandboxConversionLedger(BlobContainerClient container, IDataProtectionProvider protection,
    SandboxConversionOptions options, bool local) : ISandboxConversionLedger
{
    private readonly IDataProtector protector = protection.CreateProtector("QuillSign.SandboxConversionLedger.v1");
    public async Task<ISandboxConversionLease> AcquireAsync(CancellationToken ct)
    {
        options.Validate(); ct.ThrowIfCancellationRequested();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            if (local)
            {
                if (!container.Uri.IsLoopback && container.Uri.Host != "azurite") throw SandboxConversionErrors.Unavailable();
                await container.CreateIfNotExistsAsync(PublicAccessType.None, cancellationToken: timeout.Token);
            }
            var blob = container.GetBlobClient("conversion-coordination/" + options.ScopeHash + ".ledger");
            if (!(await blob.ExistsAsync(timeout.Token)).Value)
            {
                var initial = protector.Protect(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new SandboxConversionState(options.ScopeHash, "", 0, "", 0))));
                try { await blob.UploadAsync(BinaryData.FromBytes(initial), new BlobUploadOptions { Conditions = new() { IfNoneMatch = ETag.All } }, timeout.Token); }
                catch (RequestFailedException e) when (e.Status is 409 or 412 && e.ErrorCode is "BlobAlreadyExists" or "ConditionNotMet" or "LeaseIdMissing") { }
                finally { Array.Clear(initial); }
            }
            var lease = blob.GetBlobLeaseClient(Guid.NewGuid().ToString()); var started = Stopwatch.GetTimestamp();
            await lease.AcquireAsync(TimeSpan.FromSeconds(60), cancellationToken: timeout.Token);
            var owned = new Lease(blob, lease, protector, options.ScopeHash, started);
            try { await owned.LoadAsync(timeout.Token); return owned; }
            catch { await owned.DisposeAsync(); throw; }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw SandboxConversionErrors.Unavailable(); }
        catch (Exception e) when (e is RequestFailedException or IOException or CryptographicException or JsonException) { throw SandboxConversionErrors.Unavailable(); }
    }
    private sealed class Lease : ISandboxConversionLease
    {
        private readonly BlobClient blob; private readonly BlobLeaseClient lease; private readonly IDataProtector protector; private readonly string scope;
        private readonly CancellationTokenSource lifetime; private readonly CancellationTokenSource renewalStop = new(); private readonly Task renewals;
        private readonly SemaphoreSlim gate = new(1); private ETag etag; private long lastRenewal; private int disposed;
        public SandboxConversionState State { get; private set; } = null!;
        public CancellationToken Token => lifetime.Token;
        public Lease(BlobClient blob, BlobLeaseClient lease, IDataProtector protector, string scope, long started)
        {
            this.blob = blob; this.lease = lease; this.protector = protector; this.scope = scope; lastRenewal = started;
            // Caller cancellation stops conversion, not ownership of its cleanup.
            lifetime = new(); renewals = RenewAsync();
        }
        public async Task LoadAsync(CancellationToken ct)
        {
            var properties = await blob.GetPropertiesAsync(new BlobRequestConditions { LeaseId = lease.LeaseId }, ct);
            if (properties.Value.ContentLength is <= 0 or > 16384) throw SandboxConversionErrors.Unavailable();
            var result = await blob.DownloadContentAsync(new BlobDownloadOptions { Conditions = new() { LeaseId = lease.LeaseId, IfMatch = properties.Value.ETag } }, ct);
            if (result.Value.Content.ToMemory().Length > 16384) throw SandboxConversionErrors.Unavailable();
            var bytes = protector.Unprotect(result.Value.Content.ToArray());
            try { State = JsonSerializer.Deserialize<SandboxConversionState>(bytes) ?? throw SandboxConversionErrors.Unavailable(); }
            finally { Array.Clear(bytes); }
            if (State.Scope != scope || State.DailyAttempts is < 0 or > 100000 || State.MonthlyAttempts is < 0 or > 100000 ||
                State.Run is not null && (!Guid.TryParseExact(State.Run, "N", out _) || State.Phase == "idle") ||
                State.Run is null && (State.Phase != "idle" || State.ImageId is not null || State.SandboxId is not null) ||
                State.Phase is not ("idle" or "image-create" or "image-ready" or "sandbox-create" or "running")) throw SandboxConversionErrors.Unavailable();
            if (State.Day is null || State.Month is null ||
                State.Day.Length == 0 && State.DailyAttempts != 0 || State.Month.Length == 0 && State.MonthlyAttempts != 0 ||
                State.Day.Length != 0 && !DateOnly.TryParseExact(State.Day, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _) ||
                State.Month.Length != 0 && !DateOnly.TryParseExact(State.Month + "-01", "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _) ||
                State.Day.Length != 0 && !State.Day.StartsWith(State.Month + "-", StringComparison.Ordinal)) throw SandboxConversionErrors.Unavailable();
            if (State.Phase == "image-create" && (State.ImageId is not null || State.SandboxId is not null) ||
                State.Phase is "image-ready" or "sandbox-create" && (State.ImageId is null || State.SandboxId is not null) ||
                State.Phase == "running" && (State.ImageId is null || State.SandboxId is null)) throw SandboxConversionErrors.Unavailable();
            if (State.ImageId is not null) SandboxConversionApi.Id(State.ImageId);
            if (State.SandboxId is not null) SandboxConversionApi.Id(State.SandboxId);
            etag = result.Value.Details.ETag;
        }
        public async Task EnsureOwnedAsync(CancellationToken ct)
        {
            Token.ThrowIfCancellationRequested(); ct.ThrowIfCancellationRequested();
            if (Stopwatch.GetElapsedTime(Interlocked.Read(ref lastRenewal)) >= TimeSpan.FromSeconds(50))
            { lifetime.Cancel(); throw SandboxConversionErrors.Unavailable(); }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, Token); deadline.CancelAfter(TimeSpan.FromSeconds(5));
            try { var started = Stopwatch.GetTimestamp(); await lease.RenewAsync(cancellationToken: deadline.Token); Interlocked.Exchange(ref lastRenewal, started); }
            catch (Exception e) when (e is RequestFailedException or IOException or OperationCanceledException) { lifetime.Cancel(); throw SandboxConversionErrors.Unavailable(); }
        }
        public async Task SaveAsync(SandboxConversionState state, CancellationToken ct)
        {
            await EnsureOwnedAsync(ct); if (state.Scope != scope) throw SandboxConversionErrors.Unavailable();
            await gate.WaitAsync(ct);
            try
            {
                var bytes = protector.Protect(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(state)));
                try
                {
                    var result = await blob.UploadAsync(BinaryData.FromBytes(bytes), new BlobUploadOptions { Conditions = new() { LeaseId = lease.LeaseId, IfMatch = etag } }, ct);
                    etag = result.Value.ETag; State = state;
                }
                finally { Array.Clear(bytes); }
            }
            catch { lifetime.Cancel(); throw; }
            finally { gate.Release(); }
        }
        private async Task RenewAsync()
        {
            try
            {
                using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
                while (await timer.WaitForNextTickAsync(renewalStop.Token))
                {
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(renewalStop.Token); deadline.CancelAfter(TimeSpan.FromSeconds(5));
                    var started = Stopwatch.GetTimestamp(); await lease.RenewAsync(cancellationToken: deadline.Token); Interlocked.Exchange(ref lastRenewal, started);
                }
            }
            catch (Exception e) when (e is RequestFailedException or IOException or OperationCanceledException) { lifetime.Cancel(); }
        }
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            await renewalStop.CancelAsync(); await renewals;
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await lease.ReleaseAsync(cancellationToken: cleanup.Token); }
            catch (Exception e) when (e is RequestFailedException or IOException or OperationCanceledException) { /* finite lease expires */ }
            lifetime.Dispose(); renewalStop.Dispose(); gate.Dispose();
        }
    }
}

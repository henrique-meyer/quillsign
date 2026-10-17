using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;

namespace QuillSign.Sealing;

public sealed class TimestampCoordinationOptions
{
    public bool Enabled { get; set; }
    public int MinimumIntervalMilliseconds { get; set; }=1000;
    public int AcquireTimeoutSeconds { get; set; }=30;
}

public interface ITimestampRequestLease : IAsyncDisposable
{
    CancellationToken Token { get; }
    Task EnsureOwnedAsync(CancellationToken ct);
}
public interface ITimestampRequestCoordinator
{
    Task<ITimestampRequestLease> AcquireAsync(Uri endpoint,CancellationToken ct);
}

// One empty, provider-scoped blob serializes workers; no SQL, document data or
// client-clock metadata is needed. A crashed worker's finite lease expires.
public sealed class BlobTimestampRequestCoordinator(BlobContainerClient container,TimestampCoordinationOptions options,bool local) : ITimestampRequestCoordinator
{
    public async Task<ITimestampRequestLease> AcquireAsync(Uri endpoint,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if(!options.Enabled || options.MinimumIntervalMilliseconds is <1000 or >10000 || options.AcquireTimeoutSeconds is <1 or >60 ||
            !endpoint.IsAbsoluteUri || endpoint.UserInfo.Length!=0 || endpoint.Query.Length!=0 || endpoint.Fragment.Length!=0 ||
            !(endpoint.Scheme=="https" || local && endpoint.Scheme=="http" && endpoint.IsLoopback) ||
            local && !container.Uri.IsLoopback && container.Uri.Host!="azurite")throw Unavailable();
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(options.AcquireTimeoutSeconds));
        try
        {
            if(local)await container.CreateIfNotExistsAsync(PublicAccessType.None,cancellationToken:timeout.Token);
            var origin=SealOptions.IsFreeTsa(endpoint) ? "freetsa.org" : endpoint.Scheme+"://"+endpoint.IdnHost.TrimEnd('.').ToLowerInvariant()+":"+endpoint.Port;
            var name="tsa-coordination-"+Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(origin)))+".lock";
            var blob=container.GetBlobClient(name);
            if(!(await blob.ExistsAsync(timeout.Token)).Value)
            {
                try {await blob.UploadAsync(BinaryData.FromBytes([]),new BlobUploadOptions {Conditions=new BlobRequestConditions {IfNoneMatch=ETag.All}},timeout.Token);}
                catch(RequestFailedException error) when(error.Status is 409 or 412 && error.ErrorCode is "BlobAlreadyExists" or "ConditionNotMet" or "LeaseIdMissing") { }
            }
            if((await blob.GetPropertiesAsync(cancellationToken:timeout.Token)).Value.ContentLength!=0)throw Unavailable();
            while(true)
            {
                timeout.Token.ThrowIfCancellationRequested();
                var lease=blob.GetBlobLeaseClient(Guid.NewGuid().ToString());var elapsed=Stopwatch.StartNew();
                try
                {
                    await lease.AcquireAsync(TimeSpan.FromSeconds(60),cancellationToken:timeout.Token);
                    // Budget from before the storage round-trip, conservatively
                    // reserving the cooldown and five seconds before lease expiry.
                    var remaining=TimeSpan.FromSeconds(55)-elapsed.Elapsed-TimeSpan.FromMilliseconds(options.MinimumIntervalMilliseconds);
                    if(remaining<=TimeSpan.Zero)throw Unavailable();
                    return new RequestLease(lease,options.MinimumIntervalMilliseconds,remaining,ct);
                }
                catch(RequestFailedException error) when(error.Status==409 && error.ErrorCode=="LeaseAlreadyPresent")
                {await Task.Delay(TimeSpan.FromMilliseconds(100),timeout.Token);}
            }
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested) {throw Unavailable();}
        catch(Exception error) when(error is RequestFailedException or IOException or HttpRequestException) {throw Unavailable();}
    }

    private sealed class RequestLease : ITimestampRequestLease
    {
        private readonly BlobLeaseClient lease;
        private readonly int cooldown;
        private readonly CancellationTokenSource lifetime;
        private int disposed;
        public RequestLease(BlobLeaseClient lease,int cooldown,TimeSpan remaining,CancellationToken ct)
        {
            this.lease=lease;this.cooldown=cooldown;lifetime=CancellationTokenSource.CreateLinkedTokenSource(ct);lifetime.CancelAfter(remaining);
        }
        public CancellationToken Token=>lifetime.Token;
        public async Task EnsureOwnedAsync(CancellationToken ct)
        {
            Token.ThrowIfCancellationRequested();using var linked=CancellationTokenSource.CreateLinkedTokenSource(ct,Token);
            try {await lease.RenewAsync(cancellationToken:linked.Token);}
            catch(Exception error) when(error is RequestFailedException or IOException or HttpRequestException) {throw Unavailable();}
            Token.ThrowIfCancellationRequested();
        }
        public async ValueTask DisposeAsync()
        {
            if(Interlocked.Exchange(ref disposed,1)!=0)return;
            try
            {
                // Cancellation after an attempted HTTP request must still preserve
                // the spacing. Process death instead leaves the 60-second lease.
                await Task.Delay(cooldown,CancellationToken.None);
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try {await lease.ReleaseAsync(cancellationToken:timeout.Token);}
                catch(Exception error) when(error is RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { /* finite lease expires */ }
            }
            finally {lifetime.Dispose();}
        }
    }
    private static SealUnavailableException Unavailable()=>new("Timestamp request coordination is unavailable; no uncoordinated request was authorized.");
}

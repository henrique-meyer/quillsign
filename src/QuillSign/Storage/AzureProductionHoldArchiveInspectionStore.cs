using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;

namespace QuillSign.Storage;

// On-demand internal read adapter only. No arbitrary preconfigured SDK client,
// write/release API, provisioning, fallback, redirects or hidden SDK retries.
internal sealed class AzureProductionHoldArchiveInspectionStore : IProductionHoldArchiveInspectionStore, IDisposable
{
    private readonly AzureProductionHoldArchiveReader reader;
    private readonly TimeProvider time;
    private readonly HttpClient? ownedClient;
    internal AzureProductionHoldArchiveInspectionStore(Uri serviceUri, TokenCredential credential, TimeProvider time, HttpPipelineTransport? transport = null)
    {
        if (serviceUri is null || !serviceUri.IsAbsoluteUri || serviceUri.Scheme != "https" || serviceUri.AbsolutePath != "/" ||
            serviceUri.Query.Length != 0 || serviceUri.Fragment.Length != 0 || serviceUri.UserInfo.Length != 0 ||
            serviceUri.Host.Contains("-secondary.", StringComparison.OrdinalIgnoreCase)) throw Invalid();
        ArgumentNullException.ThrowIfNull(credential); ArgumentNullException.ThrowIfNull(time); this.time = time;
        var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false; options.Diagnostics.IsLoggingContentEnabled = false; options.Diagnostics.IsDistributedTracingEnabled = false;
        if (transport is not null) options.Transport = transport;
        else { ownedClient = new(new SocketsHttpHandler { AllowAutoRedirect = false }); options.Transport = new HttpClientTransport(ownedClient); }
        options.AddPolicy(new RefuseRedirectOrChallenge(), HttpPipelinePosition.PerRetry);
        reader = new(new BlobServiceClient(serviceUri, credential, options));
    }
    public async Task<ProductionHoldArchiveStoredObject> InspectAsync(IProductionHoldArchiveReadScope scope, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        try { return (await reader.VerifyAsync(new ReadInterval(scope, time), true, ct)).Stored; }
        catch (Exception error) when (error is RequestFailedException or IOException or HttpRequestException)
        { throw new InvalidDataException("Fresh private archive protection requires reconciliation.", error); }
    }
    // This only rejects a backwards/non-UTC clock during the observation; the
    // original authority and maintenance expiry belong to the private scope.
    private sealed class ReadInterval(IProductionHoldArchiveReadScope scope, TimeProvider time) : IProductionHoldArchiveReadScope
    {
        private readonly DateTimeOffset started = time.GetUtcNow();
        public ProductionHoldArchiveStoredObject Stored => scope.Stored;
        public async Task DemandAsync(CancellationToken ct = default)
        { Check(); await scope.DemandAsync(ct); Check(); }
        private void Check() { var now = time.GetUtcNow(); if (started.Offset != TimeSpan.Zero || now.Offset != TimeSpan.Zero || now < started) throw Invalid(); }
    }
    private sealed class RefuseRedirectOrChallenge : HttpPipelineSynchronousPolicy
    {
        public override void OnReceivedResponse(HttpMessage message)
        {
            if (message.Response.Status is >= 300 and < 400) throw new UnauthorizedAccessException("Private archive inspection cannot redirect.");
            // SDK authentication challenges can otherwise resubmit even with
            // MaxRetries=0. An unexpected authentication refusal ends this read.
            if (message.Response.Status == 401)
                throw new RequestFailedException(message.Response.Status, "Private archive inspection requires authentication reconciliation.",
                    message.Response.Headers.TryGetValue("x-ms-error-code", out var code) ? code : null, null);
        }
    }
    public void Dispose() => ownedClient?.Dispose();
    private static InvalidDataException Invalid() => new("The current private archive inspection scope could not be verified.");
}

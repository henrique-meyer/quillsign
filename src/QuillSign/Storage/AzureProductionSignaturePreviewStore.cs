using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Storage;

// Deliberately unregistered. Existing private containers/versioning must already
// be configured. This client never creates containers, changes protection or
// borrows a connection string/SAS/shared key. Every SDK request has retries off.
internal interface IProductionSignaturePreviewStore
{
    Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope, VerifiedSigner identity,
        ProductionRecordWriteDescriptor item, Stream source, bool mayWrite, ProductionRecordWriteReceipt? saved,
        Func<CancellationToken, Task> demand, CancellationToken ct = default);
}

internal sealed class AzureProductionSignaturePreviewStore : IProductionSignaturePreviewStore, IDisposable
{
    private readonly BlobServiceClient service;
    private const int BufferSize = 256 * 1024;
    private readonly TimeProvider time;
    private readonly HttpClient? ownedClient;

    internal AzureProductionSignaturePreviewStore(Uri serviceUri, TokenCredential credential, TimeProvider time,
        HttpPipelineTransport? transport = null)
    {
        if (serviceUri is null || !serviceUri.IsAbsoluteUri || serviceUri.Scheme != "https" ||
            serviceUri.AbsolutePath != "/" || serviceUri.Query.Length != 0 || serviceUri.Fragment.Length != 0 ||
            serviceUri.UserInfo.Length != 0 || serviceUri.Host.Contains("-secondary.", StringComparison.OrdinalIgnoreCase)) throw Invalid();
        ArgumentNullException.ThrowIfNull(credential); ArgumentNullException.ThrowIfNull(time); this.time = time;
        var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false; options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        if (transport is not null) options.Transport = transport;
        else
        {
            ownedClient = new(new SocketsHttpHandler { AllowAutoRedirect = false });
            options.Transport = new HttpClientTransport(ownedClient);
        }
        options.AddPolicy(new RefuseRedirect(), HttpPipelinePosition.PerRetry);
        service = new(serviceUri, credential, options);
    }

    public async Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope, VerifiedSigner identity,
        ProductionRecordWriteDescriptor item, Stream source, bool mayWrite, ProductionRecordWriteReceipt? saved,
        Func<CancellationToken,Task> demand, CancellationToken ct = default)
    {
        if (scope is null || identity is null || source is null || demand is null || scope.Kind != ProductionRecordPreviewWriteContract.Kind ||
            scope.RecordId != identity.EnvelopeId || scope.OperationId == Guid.Empty || scope.ReservationSequence < 1 ||
            identity.SignerId == Guid.Empty || identity.SessionId == Guid.Empty || identity.DocumentId == item?.Blob.ObjectId ||
            !ProductionRecordPreviewWriteContract.Item(scope.RecordId, item) || saved is not null && (saved.Item != item || mayWrite)) throw Invalid();
        var capability = (SignatureAssetCapability)SignatureAssetCapability.Create(identity, item!.Blob, AssetOperation.Write, time);
        var binding = OwnershipBinding(scope, identity, item);
        async Task Demand(CancellationToken token) { capability.Demand(item.Blob, AssetOperation.Write); await demand(token); capability.Demand(item.Blob, AssetOperation.Write); }
        await Demand(ct);
        var container = service.GetBlobContainerClient("normalized");
        var configuration = (await container.GetPropertiesAsync(cancellationToken: ct)).Value; await Demand(ct);
        if (configuration.PublicAccess is not null && configuration.PublicAccess != PublicAccessType.None) throw Invalid();
        var client = container.GetBlockBlobClient($"{item.Blob.EnvelopeId:N}/{item.Blob.ObjectId:N}");
        if (mayWrite)
        {
            if (await Current(client, Demand, ct) is not null) throw Invalid();
            await StageAndCommit(client, item, source, binding, Demand, ct);
        }
        var current = await Current(client, Demand, ct) ?? throw Invalid();
        return await Verify(client, item, current, saved, binding, Demand, ct);
    }
    private static async Task StageAndCommit(BlockBlobClient client, ProductionRecordWriteDescriptor item, Stream source,
        string binding, Func<CancellationToken, Task> demand, CancellationToken ct)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize); var blocks = new List<string>();
        var attempt = Guid.NewGuid().ToString("N"); long consumed = 0;
        try
        {
            while (consumed < item.Length)
            {
                await demand(ct);
                var count = await source.ReadAtLeastAsync(buffer.AsMemory(0, (int)Math.Min(BufferSize, item.Length - consumed)),
                    (int)Math.Min(BufferSize, item.Length - consumed), false, ct);
                await demand(ct);
                if (count == 0) throw Invalid();
                consumed += count; hash.AppendData(buffer.AsSpan(0, count));
                var blockId = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{attempt}:{blocks.Count:D8}"));
                using var block = new MemoryStream(buffer, 0, count, false);
                await demand(ct); await client.StageBlockAsync(blockId, block, cancellationToken: ct); await demand(ct);
                blocks.Add(blockId);
            }
            await demand(ct);
            if (await source.ReadAsync(buffer.AsMemory(0, 1), ct) != 0 || Convert.ToHexStringLower(hash.GetHashAndReset()) != item.Sha256) throw Invalid();
            await demand(ct);
            try
            {
                await client.CommitBlockListAsync(blocks, new CommitBlockListOptions {
                    Conditions = new() { IfNoneMatch = ETag.All }, HttpHeaders = new() { ContentType = "application/octet-stream" },
                    Metadata = new Dictionary<string,string> { ["quillsign_signature_preview"] = binding }
                }, ct);
            }
            catch (Exception error) when (UncertainCommit(error))
            {
                // No resend. Only the later exact version/bytes readback may
                // reconcile a commit whose acknowledgement was lost.
                ct.ThrowIfCancellationRequested();
            }
            await demand(ct);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }

    private static async Task<BlobProperties?> Current(BlobBaseClient client, Func<CancellationToken, Task> demand, CancellationToken ct)
    {
        await demand(ct);
        try { var value = (await client.GetPropertiesAsync(cancellationToken: ct)).Value; await demand(ct); return value; }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "BlobNotFound")
        { await demand(ct); return null; }
    }

    private static async Task<ProductionRecordWriteReceipt> Verify(BlockBlobClient root, ProductionRecordWriteDescriptor item,
        BlobProperties current, ProductionRecordWriteReceipt? saved, string binding, Func<CancellationToken, Task> demand, CancellationToken ct)
    {
        if (!Opaque(current.VersionId) || !Opaque(current.ETag.ToString("H")) || current.BlobType != BlobType.Block || current.ContentLength != item.Length) throw Invalid();
        var receipt = new ProductionRecordWriteReceipt(item, current.VersionId, current.ETag.ToString("H"));
        if (saved is not null && saved != receipt) throw Invalid();
        DemandProperties(current,receipt,binding);
        var client = root.WithVersion(receipt.VersionId); var conditions = new BlobRequestConditions { IfMatch = new ETag(receipt.ETag) };
        await demand(ct); var properties = (await client.GetPropertiesAsync(conditions, ct)).Value; await demand(ct);
        DemandProperties(properties, receipt,binding);
        await demand(ct); var response = await client.DownloadStreamingAsync(new() { Conditions = conditions }, ct);
        await using var source = response.Value.Content; await demand(ct);
        if (response.Value.Details.VersionId != receipt.VersionId || response.Value.Details.ETag.ToString("H") != receipt.ETag ||
            response.Value.Details.ContentLength != item.Length) throw Invalid();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            long read = 0;
            while (read < item.Length)
            {
                await demand(ct); var count = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(BufferSize, item.Length - read)), ct); await demand(ct);
                if (count == 0) throw Invalid(); hash.AppendData(buffer.AsSpan(0, count)); read += count;
            }
            await demand(ct);
            if (await source.ReadAsync(buffer.AsMemory(0, 1), ct) != 0 || Convert.ToHexStringLower(hash.GetHashAndReset()) != item.Sha256) throw Invalid();
            await demand(ct);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
        await demand(ct); var final = (await root.GetPropertiesAsync(conditions, ct)).Value; await demand(ct);
        DemandProperties(final, receipt,binding);
        return receipt;
    }

    private static void DemandProperties(BlobProperties p, ProductionRecordWriteReceipt receipt,string binding)
    {
        if (p.VersionId != receipt.VersionId || p.ETag.ToString("H") != receipt.ETag || p.ContentLength != receipt.Item.Length || p.BlobType != BlobType.Block ||
            !p.Metadata.TryGetValue("quillsign_signature_preview",out var owner) || owner != binding) throw Invalid();
    }
    internal static string OwnershipBinding(ProductionRecordOperation scope, VerifiedSigner identity, ProductionRecordWriteDescriptor item)
        => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            Version="production-record-signature-preview-owner-v1", scope.RecordId, scope.OperationId, scope.ReservationSequence, Identity=identity, Item=item
        })));
    private static bool UncertainCommit(Exception error) => error is IOException or HttpRequestException ||
        error is RequestFailedException provider && (provider.Status >= 500 ||
            provider.Status == 0 && provider.InnerException is IOException or HttpRequestException ||
            provider.Status == 412 && provider.ErrorCode is "ConditionNotMet" or "BlobAlreadyExists");
    private sealed class RefuseRedirect : HttpPipelineSynchronousPolicy
    {
        public override void OnReceivedResponse(HttpMessage message)
        {
            if (message.Response.Status is >= 300 and < 400) throw new UnauthorizedAccessException("Production upload requests cannot redirect.");
        }
    }
    public void Dispose() => ownedClient?.Dispose();
    private static bool Opaque(string? value) => value is { Length: > 0 and <= 256 } && value != "*" && value.All(c => c is >= ' ' and <= '~');
    private static InvalidDataException Invalid() => new("The exact production signature preview version and bytes could not be verified.");
}

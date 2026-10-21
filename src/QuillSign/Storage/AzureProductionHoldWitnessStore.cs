using System.Globalization;
using System.Security.Cryptography;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using QuillSign.Lifecycle;

namespace QuillSign.Storage;

// Unregistered provider adapter, not lifecycle authority. The operator must
// deliberately opt into indefinitely legally held witness objects. No defaults
// infer a legal retention policy; no container or protection is ever provisioned.
internal sealed class AzureProductionHoldWitnessStore : IProductionHoldWitnessStore
{
    internal const int MaximumEvents = 16384, MaximumPayloadBytes = 64 * 1024;
    internal const long MaximumTotalBytes = 16 * 1024 * 1024;
    private readonly BlobContainerClient container;
    private readonly string installation;
    private readonly bool enabled;
    private sealed record Entry(long Sequence, string Path, string Version, string ETag, long Length);

    internal AzureProductionHoldWitnessStore(Uri containerUri, TokenCredential credential, string installationDigest,
        bool allowIndefiniteLegalHold = false, HttpPipelineTransport? transport = null)
    {
        if (containerUri is null || !containerUri.IsAbsoluteUri || containerUri.Scheme != "https" ||
            containerUri.UserInfo.Length != 0 || containerUri.Query.Length != 0 || containerUri.Fragment.Length != 0 ||
            containerUri.Host.Contains("-secondary.", StringComparison.OrdinalIgnoreCase) ||
            installationDigest is not { Length: 64 } || !installationDigest.All(char.IsAsciiHexDigitLower)) throw Invalid();
        var name = containerUri.AbsolutePath.Trim('/');
        if (name.Length is < 3 or > 63 || name[0] == '-' || name[^1] == '-' || name.Contains("--", StringComparison.Ordinal) ||
            name.Any(c => c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-'))) throw Invalid();
        ArgumentNullException.ThrowIfNull(credential);
        var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false; options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        if (transport is not null) options.Transport = transport;
        container = new(containerUri, credential, options); installation = installationDigest; enabled = allowIndefiniteLegalHold;
    }

    public async Task<IReadOnlyList<ProductionHoldWitnessObject>> ReadAsync(Guid recordId, CancellationToken ct = default)
    {
        Demand(recordId, ct);
        try { return await ReadCore(recordId, ct); }
        catch (Exception error) when (ProviderFailure(error)) { throw Invalid(); }
    }

    public async Task<ProductionHoldWitnessObject> CreateAsync(ProductionHoldWitnessWrite write, CancellationToken ct = default)
    {
        if (write is null) throw Invalid(); Demand(write.RecordId, ct);
        if (write.Sequence is < 1 or > MaximumEvents || write.ProtectedPayload is not { Length: > 0 and <= MaximumPayloadBytes }) throw Invalid();
        // Own bytes before the first await, including during uncertain outcomes.
        var bytes = write.ProtectedPayload.ToArray(); var path = Path(write.RecordId, write.Sequence);
        try
        {
            var prior = await ReadCore(write.RecordId, ct);
            var existing = prior.SingleOrDefault(x => x.Sequence == write.Sequence);
            if (existing is not null) return Same(existing, bytes) ? existing : throw Invalid();
            if (prior.Count >= MaximumEvents || checked(prior.Sum(x => x.Length) + bytes.LongLength) > MaximumTotalBytes) throw Invalid();
            try
            {
                await container.GetBlobClient(path).UploadAsync(new MemoryStream(bytes, false), new BlobUploadOptions {
                    Conditions = new() { IfNoneMatch = ETag.All }, LegalHold = true,
                    HttpHeaders = new() { ContentType = "application/octet-stream" }
                }, ct);
            }
            catch (Exception error) when (error is RequestFailedException or IOException)
            {
                // Never resend. Only a complete exact-version readback resolves
                // an uncertain create, acknowledgement loss or conditional race.
                ct.ThrowIfCancellationRequested();
            }
            var found = (await ReadCore(write.RecordId, ct)).SingleOrDefault(x => x.Sequence == write.Sequence);
            return found is not null && found.Path == path && Same(found, bytes) ? found : throw Invalid();
        }
        catch (Exception error) when (ProviderFailure(error)) { throw Invalid(); }
    }

    private async Task<IReadOnlyList<ProductionHoldWitnessObject>> ReadCore(Guid id, CancellationToken ct)
    {
        await Configuration(ct);
        var entries = await Census(id, ct);
        var objects = new List<ProductionHoldWitnessObject>(entries.Count);
        foreach (var entry in entries) objects.Add(await Read(entry, ct));
        // Detect observed namespace changes, including root overwrites. This is
        // provider evidence, not an atomic transaction or a distributed fence.
        var after = await Census(id, ct);
        if (!entries.SequenceEqual(after)) throw Invalid();
        return objects.AsReadOnly();
    }

    private async Task Configuration(CancellationToken ct)
    {
        var p = (await container.GetPropertiesAsync(cancellationToken: ct)).Value;
        if (p.PublicAccess is not null && p.PublicAccess != PublicAccessType.None || p.HasImmutableStorageWithVersioning != true) throw Invalid();
    }

    private async Task<List<Entry>> Census(Guid id, CancellationToken ct)
    {
        var prefix = Prefix(id); var entries = new Dictionary<string, Entry>(StringComparer.Ordinal); long total = 0;
        var markers = new HashSet<string>(StringComparer.Ordinal); var pages = 0;
        await foreach (var page in container.GetBlobsAsync(new GetBlobsOptions { Prefix = prefix,
            States = BlobStates.Version | BlobStates.Snapshots | BlobStates.Deleted | BlobStates.DeletedWithVersions }, ct).AsPages(pageSizeHint: 128))
        {
            if (++pages > MaximumEvents + 1 || page.Values.Count > 128 || page.ContinuationToken is { Length: > 16384 } ||
                page.ContinuationToken is { Length: > 0 } marker && !markers.Add(Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(marker))))) throw Invalid();
            foreach (var b in page.Values)
            {
                var suffix = b.Name.StartsWith(prefix, StringComparison.Ordinal) ? b.Name[prefix.Length..] : "";
                if (suffix.Length != 10 || !long.TryParse(suffix, NumberStyles.None, CultureInfo.InvariantCulture, out var sequence) ||
                    sequence is < 1 or > MaximumEvents || suffix != sequence.ToString("D10", CultureInfo.InvariantCulture) ||
                    b.Deleted == true || b.HasVersionsOnly == true || !string.IsNullOrEmpty(b.Snapshot) ||
                    b.Properties.BlobType != BlobType.Block || !Opaque(b.VersionId) || b.Properties.ETag is null ||
                    b.Properties.ContentLength is not (>= 1 and <= MaximumPayloadBytes)) throw Invalid();
                var etag = b.Properties.ETag.Value.ToString("H"); if (!Tag(etag)) throw Invalid();
                total = checked(total + b.Properties.ContentLength.Value);
                if (entries.Count >= MaximumEvents || total > MaximumTotalBytes ||
                    !entries.TryAdd(b.Name, new(sequence, b.Name, b.VersionId!, etag, b.Properties.ContentLength.Value))) throw Invalid();
            }
        }
        return entries.Values.OrderBy(x => x.Sequence).ToList();
    }

    private async Task<ProductionHoldWitnessObject> Read(Entry e, CancellationToken ct)
    {
        var client = container.GetBlobClient(e.Path).WithVersion(e.Version); var conditions = new BlobRequestConditions { IfMatch = new ETag(e.ETag) };
        void Check(BlobProperties p)
        {
            if (!p.HasLegalHold || p.VersionId != e.Version || p.ETag.ToString("H") != e.ETag || p.ContentLength != e.Length || p.BlobType != BlobType.Block) throw Invalid();
        }
        Check((await client.GetPropertiesAsync(conditions, ct)).Value);
        var result = (await client.DownloadStreamingAsync(new() { Conditions = conditions }, ct)).Value;
        await using var input = result.Content;
        if (result.Details.VersionId != e.Version || result.Details.ETag.ToString("H") != e.ETag || result.Details.ContentLength != e.Length) throw Invalid();
        var payload = new byte[checked((int)e.Length)];
        await input.ReadExactlyAsync(payload, ct); var extra = new byte[1];
        if (await input.ReadAsync(extra, ct) != 0) throw Invalid();
        // Legal-hold changes need not change ETag. Protection after bytes matters.
        Check((await client.GetPropertiesAsync(conditions, ct)).Value);
        return new(e.Sequence, e.Path, e.Version, e.ETag, e.Length, Convert.ToHexStringLower(SHA256.HashData(payload)), payload, true);
    }

    private string Prefix(Guid id) => $"production-hold-witnesses/{installation}/{id:N}/";
    private string Path(Guid id, long sequence) => Prefix(id) + sequence.ToString("D10", CultureInfo.InvariantCulture);
    private void Demand(Guid id, CancellationToken ct) { ct.ThrowIfCancellationRequested(); if (!enabled || id == Guid.Empty) throw Invalid(); }
    private static bool Same(ProductionHoldWitnessObject o, byte[] bytes) => o.LegalHold && o.Length == bytes.LongLength &&
        CryptographicOperations.FixedTimeEquals(o.ProtectedPayload, bytes) && o.Sha256 == Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static bool Opaque(string? value) => value is { Length: > 0 and <= 256 } && value != "*" && value.All(c => c is >= ' ' and <= '~');
    private static bool Tag(string value) => Opaque(value) && value.Length >= 3 && value[0] == '"' && value[^1] == '"' && !value[1..^1].Contains('"');
    private static bool ProviderFailure(Exception e) => e is RequestFailedException or IOException or FormatException or OverflowException or System.Xml.XmlException;
    private static InvalidDataException Invalid() => new("Private production hold witness storage could not be verified.");
}

using System.Buffers;
using System.Security.Cryptography;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;

namespace QuillSign.Storage;

// Deliberately read-only. Neither this contract nor the inspection adapter can
// clear a hold, create/reconstruct an object or grant a release command.
internal interface IProductionHoldArchiveReadScope
{
    ProductionHoldArchiveStoredObject Stored { get; }
    Task DemandAsync(CancellationToken ct = default);
}
internal interface IProductionHoldArchiveInspectionStore
{
    Task<ProductionHoldArchiveStoredObject> InspectAsync(IProductionHoldArchiveReadScope scope, CancellationToken ct = default);
}
internal sealed record ProductionHoldArchiveReadResult(ProductionHoldArchiveStoredObject Stored, BlobProperties Properties);

// The release adapter uses this exact reader with its concrete release scope.
// New active inspection supplies only a separately authorized read scope.
internal sealed class AzureProductionHoldArchiveReader(BlobServiceClient service)
{
    internal async Task<ProductionHoldArchiveReadResult> VerifyAsync(IProductionHoldArchiveReadScope scope, bool? held, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        var stored = Own(scope.Stored);
        async Task Demand()
        {
            if (scope.Stored != stored) throw Invalid();
            await scope.DemandAsync(ct);
            if (scope.Stored != stored) throw Invalid();
        }
        await Demand();
        var container = service.GetBlobContainerClient("final");
        var configuration = (await container.GetPropertiesAsync(cancellationToken: ct)).Value; await Demand();
        if (configuration.PublicAccess is not null && configuration.PublicAccess != PublicAccessType.None || configuration.HasImmutableStorageWithVersioning != true) throw Invalid();
        var client = Client(service, stored); var condition = new BlobRequestConditions { IfMatch = new ETag(stored.ETag) };
        await Demand(); var before = (await client.GetPropertiesAsync(condition, ct)).Value; await Demand(); Match(before);
        await Demand(); var response = await client.DownloadStreamingAsync(new() { Conditions = condition }, ct);
        await using var input = response.Value.Content; await Demand();
        if (response.Value.Details.VersionId != stored.VersionId || response.Value.Details.ETag.ToString("H") != stored.ETag || response.Value.Details.ContentLength != stored.Length) throw Invalid();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = ArrayPool<byte>.Shared.Rent(256 * 1024);
        try
        {
            long copied = 0;
            while (copied < stored.Length)
            {
                await Demand(); var count = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, stored.Length - copied)), ct); await Demand();
                if (count == 0) throw Invalid(); copied += count; hash.AppendData(buffer.AsSpan(0, count));
            }
            await Demand(); var tail = await input.ReadAsync(buffer.AsMemory(0, 1), ct); await Demand();
            if (tail != 0 || Convert.ToHexStringLower(hash.GetHashAndReset()) != stored.Sha256) throw Invalid();
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
        await Demand(); var after = (await client.GetPropertiesAsync(condition, ct)).Value; await Demand(); Match(after);
        // Clearing legal hold can preserve ETag. Recheck protection after bytes,
        // including an unchanged optional time-policy mode and expiry.
        if (before.HasLegalHold != after.HasLegalHold || before.ImmutabilityPolicy?.PolicyMode != after.ImmutabilityPolicy?.PolicyMode ||
            before.ImmutabilityPolicy?.ExpiresOn != after.ImmutabilityPolicy?.ExpiresOn) throw Invalid();
        return new(stored, after);

        void Match(BlobProperties p)
        {
            if (p.VersionId != stored.VersionId || p.ETag.ToString("H") != stored.ETag || p.ContentLength != stored.Length ||
                p.BlobType != BlobType.Block || held is { } value && p.HasLegalHold != value) throw Invalid();
        }
    }
    internal static ProductionHoldArchiveStoredObject Own(ProductionHoldArchiveStoredObject stored)
    {
        if (stored is null || stored.Path is not { Length: > 0 and <= 1024 } || stored.Length is < 1 or > 64 * 1024 * 1024 ||
            stored.Sha256 is not { Length: 64 } || !stored.Sha256.All(char.IsAsciiHexDigitLower) ||
            stored.VersionId is not { Length: > 0 and <= 256 } || stored.VersionId == "*" || !stored.VersionId.All(x => x is >= '!' and <= '~') ||
            stored.ETag is not { Length: >= 3 and <= 256 } || stored.ETag[0] != '"' || stored.ETag[^1] != '"' ||
            stored.ETag[1..^1].Any(x => x is < '!' or > '~' or '"')) throw Invalid();
        var path = stored.Path.Split('/');
        if (path.Length is < 6 or > 7 || path[0] != "production-holds" ||
            path.Skip(1).Take(3).Any(x => !Guid.TryParseExact(x, "N", out var id) || id == Guid.Empty || x != id.ToString("N")) ||
            path[4] is not ("sql" or "manifests" or "objects") || path.Length != (path[4] == "objects" ? 7 : 6) ||
            path.Skip(5).Any(x => x.Length != 64 || !x.All(char.IsAsciiHexDigitLower)) || path[^1] != stored.Sha256) throw Invalid();
        return stored with { };
    }
    internal static BlobBaseClient Client(BlobServiceClient service, ProductionHoldArchiveStoredObject stored)
        => service.GetBlobContainerClient("final").GetBlobClient(stored.Path).WithVersion(stored.VersionId);
    private static InvalidDataException Invalid() => new("The exact retained private archive bytes and protection could not be verified.");
}

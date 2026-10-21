using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

internal sealed record ProductionHoldObjectLimits(int MaximumObjects = 1024, long MaximumObjectBytes = 64 * 1024 * 1024,
    long MaximumTotalBytes = 256 * 1024 * 1024);
internal sealed record HoldObjectAddress(string Area, string Name, string VersionId, string Snapshot, string ETag, long Length);
internal sealed record HoldObjectPage(IReadOnlyList<HoldObjectAddress> Objects, string? Continuation);
internal sealed record HoldObjectEvidence(HoldObjectAddress Address, string Sha256);
internal sealed record ProductionHoldObjectSnapshot(Guid RecordId, long Revision, string FenceHash, string SqlStateSha256,
    string SqlPayloadSha256, string ManifestSha256, int Objects, long Bytes, byte[] ProtectedManifest, ProductionHoldSqlSnapshot Sql);

// Separate from sender/signer capabilities. Minted only while the caller owns a
// private production-hold transaction; never registered or accepted from HTTP.
internal sealed class ProductionHoldObjectScope
{
    private readonly TimeProvider time;
    private readonly DateTimeOffset issued;
    private readonly DateTimeOffset expires;
    internal Guid RecordId { get; }
    internal string Prefix => $"{RecordId:N}/";
    private ProductionHoldObjectScope(Guid id, TimeProvider time, DateTimeOffset issued, DateTimeOffset expires)
    { RecordId = id; this.time = time; this.issued = issued; this.expires = expires; }
    internal static ProductionHoldObjectScope FromVerified(ProductionHoldSqlSnapshot sql, IDataProtectionProvider keys, TimeProvider time)
    {
        if (sql.AcknowledgementOnly || sql.Revision is < 1 or > 512 || sql.FenceHash is not { Length: 64 } || !sql.FenceHash.All(char.IsAsciiHexDigitLower)) throw Invalid();
        using var verified = ProductionHoldSqlInventory.OpenVerified(sql, keys);
        var now = time.GetUtcNow();
        if (now.Offset != TimeSpan.Zero || sql.CapturedAt.Offset != TimeSpan.Zero || sql.CapturedAt > now || now - sql.CapturedAt >= TimeSpan.FromMinutes(10) ||
            sql.CapturedAt > DateTimeOffset.MaxValue.AddMinutes(-10)) throw Invalid();
        return new(sql.RecordId, time, now, sql.CapturedAt.AddMinutes(10));
    }
    internal void Demand(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); var now = time.GetUtcNow();
        if (now < issued || now >= expires) throw new UnauthorizedAccessException("The private object-inventory scope expired.");
    }
    internal void Demand(HoldObjectAddress value, CancellationToken ct)
    {
        Demand(ct);
        ValidateAddress(RecordId, value);
    }
    internal static void ValidateAddress(Guid recordId, HoldObjectAddress value)
    {
        var prefix = $"{recordId:N}/";
        if (recordId == Guid.Empty || !Areas.Contains(value.Area, StringComparer.Ordinal) || !value.Name.StartsWith(prefix, StringComparison.Ordinal) ||
            value.Name.Length <= prefix.Length || value.Name.Length > 1024 ||
            value.Name[prefix.Length..].Split('/').Any(p => p.Length == 0 || p.Any(c => c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-'))) ||
            !Opaque(value.VersionId, true) || !Opaque(value.Snapshot, true) || value.VersionId.Length > 0 && value.Snapshot.Length > 0 ||
            !Opaque(value.ETag, false) || value.ETag.Length < 3 || value.ETag[0] != '"' || value.ETag[^1] != '"' ||
            value.ETag[1..^1].Any(c => c == '"' || c == ' ') || value.Length is < 1 or > 64 * 1024 * 1024) throw Invalid();
    }
    internal static readonly string[] Areas = ["originals", "normalized", "previews", "final"];
    private static bool Opaque(string value, bool empty) => value is not null && value.Length <= 256 && (empty || value.Length > 0) && value.All(c => c is >= ' ' and <= '~');
    private static InvalidDataException Invalid() => new("The private object-inventory scope could not be verified.");
}

internal interface IProductionHoldObjectSource
{
    Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct);
    Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress address, CancellationToken ct);
}

// A read-only evidence component. Matching two censuses is not a storage lock,
// immutable preservation receipt, or permission to report an effective hold.
internal sealed class ProductionHoldObjectInventory(QuillSignDbContext db, IDataProtectionProvider keys, TimeProvider time, IProductionHoldObjectSource source)
{
    internal const string Version = "production-hold-object-inventory-v1";
    internal static HoldObjectEvidence[] OpenVerified(ProductionHoldObjectSnapshot snapshot, IDataProtectionProvider keys, TimeProvider time)
    {
        if (snapshot.RecordId == Guid.Empty || snapshot.ProtectedManifest is not { Length: > 0 and <= 9 * 1024 * 1024 } ||
            snapshot.Objects is < 0 or > 4096 || snapshot.Bytes is < 0 or > 256 * 1024 * 1024 ||
            snapshot.Sql.RecordId != snapshot.RecordId || snapshot.Sql.Revision != snapshot.Revision || snapshot.Sql.FenceHash != snapshot.FenceHash ||
            snapshot.Sql.StateSha256 != snapshot.SqlStateSha256 || snapshot.Sql.PayloadSha256 != snapshot.SqlPayloadSha256) throw Invalid();
        using var sql = ProductionHoldSqlInventory.OpenVerified(snapshot.Sql, keys);
        var plain = keys.CreateProtector(Version, snapshot.RecordId.ToString("N")).Unprotect(snapshot.ProtectedManifest);
        try
        {
            if (plain.Length > 8 * 1024 * 1024 || Convert.ToHexStringLower(SHA256.HashData(plain)) != snapshot.ManifestSha256) throw Invalid();
            using var document = JsonDocument.Parse(plain); var root = document.RootElement;
            var captured = root.GetProperty("CapturedAt").GetDateTimeOffset();
            if (root.GetProperty("Version").GetString() != Version || root.GetProperty("RecordId").GetGuid() != snapshot.RecordId ||
                root.GetProperty("Revision").GetInt64() != snapshot.Revision || root.GetProperty("FenceHash").GetString() != snapshot.FenceHash ||
                root.GetProperty("SqlStateSha256").GetString() != snapshot.SqlStateSha256 || root.GetProperty("SqlPayloadSha256").GetString() != snapshot.SqlPayloadSha256 ||
                captured.Offset != TimeSpan.Zero || captured < snapshot.Sql.CapturedAt || captured > time.GetUtcNow()) throw Invalid();
            var entries = root.GetProperty("Objects");
            if (entries.GetArrayLength() != snapshot.Objects) throw Invalid();
            var objects = entries.Deserialize<HoldObjectEvidence[]>() ?? throw Invalid();
            if (objects.Sum(x => x.Address.Length) != snapshot.Bytes) throw Invalid();
            var identities = new HashSet<(string, string, string, string)>();
            foreach (var item in objects)
            {
                ProductionHoldObjectScope.ValidateAddress(snapshot.RecordId, item.Address);
                if (item.Sha256 is not { Length: 64 } || !item.Sha256.All(char.IsAsciiHexDigitLower) ||
                    !identities.Add((item.Address.Area, item.Address.Name, item.Address.VersionId, item.Address.Snapshot))) throw Invalid();
            }
            ProductionHoldObjectReferences.Demand(sql.RootElement, objects);
            ProductionHoldAuditChain.Demand(sql.RootElement);
            var documents = ProductionHoldDocumentAuditReferences.ReadVerified(sql.RootElement, objects);
            var fields = ProductionHoldPreparationAuditReferences.ReadVerified(sql.RootElement, documents);
            ProductionHoldFinalizedFieldReferences.Demand(sql.RootElement, objects, fields);
            var adoptions = ProductionHoldAdoptionAuditReferences.ReadVerified(sql.RootElement, objects);
            ProductionHoldFieldAuditReferences.Demand(sql.RootElement, objects, fields, adoptions);
            ProductionHoldConsentAuditReferences.Demand(sql.RootElement, objects);
            ProductionHoldNotificationReferences.Demand(sql.RootElement, objects, keys);
            return objects;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    internal async Task<ProductionHoldObjectSnapshot> CaptureLockedAsync(Guid id, long revision, string fenceHash,
        ProductionHoldObjectLimits? limits = null, CancellationToken ct = default)
    {
        limits ??= new();
        if (limits.MaximumObjects is < 1 or > 4096 || limits.MaximumObjectBytes is < 1 or > 64 * 1024 * 1024 ||
            limits.MaximumTotalBytes is < 1 or > 256 * 1024 * 1024) throw Invalid();
        var sqlService = new ProductionHoldSqlInventory(db, keys, time);
        var sql = await sqlService.CaptureLockedAsync(id, revision, fenceHash, ct: ct);
        var scope = ProductionHoldObjectScope.FromVerified(sql, keys, time);
        var addresses = await Census(scope, limits, ct);
        var evidence = new List<HoldObjectEvidence>();
        foreach (var address in addresses)
        {
            scope.Demand(address, ct); var hash = await source.HashAsync(scope, address, ct); scope.Demand(ct);
            if (hash is not { Length: 64 } || !hash.All(char.IsAsciiHexDigitLower)) throw Invalid();
            evidence.Add(new(address, hash));
        }
        using (var verified = ProductionHoldSqlInventory.OpenVerified(sql, keys))
        {
            ProductionHoldObjectReferences.Demand(verified.RootElement, evidence);
            ProductionHoldAuditChain.Demand(verified.RootElement);
            var documents = ProductionHoldDocumentAuditReferences.ReadVerified(verified.RootElement, evidence);
            var fields = ProductionHoldPreparationAuditReferences.ReadVerified(verified.RootElement, documents);
            ProductionHoldFinalizedFieldReferences.Demand(verified.RootElement, evidence, fields);
            var adoptions = ProductionHoldAdoptionAuditReferences.ReadVerified(verified.RootElement, evidence);
            ProductionHoldFieldAuditReferences.Demand(verified.RootElement, evidence, fields, adoptions);
            ProductionHoldConsentAuditReferences.Demand(verified.RootElement, evidence);
            ProductionHoldNotificationReferences.Demand(verified.RootElement, evidence, keys);
        }
        // Detect observed late additions/replacements/deletions. This deliberately
        // does not claim to fence writes that happen after the second listing.
        var after = await Census(scope, limits, ct);
        if (!addresses.SequenceEqual(after)) throw new DocumentConflictException();
        var current = await sqlService.CaptureLockedAsync(id, revision, fenceHash, ct: ct);
        if (current.StateSha256 != sql.StateSha256) throw new DocumentConflictException();
        scope.Demand(ct);
        var plain = JsonSerializer.SerializeToUtf8Bytes(new { Version, sql.RecordId, sql.Revision, sql.FenceHash,
            SqlStateSha256 = sql.StateSha256, SqlPayloadSha256 = sql.PayloadSha256, CapturedAt = time.GetUtcNow(), Objects = evidence });
        try
        {
            if (plain.Length > 8 * 1024 * 1024) throw Invalid();
            return new(id, revision, fenceHash, sql.StateSha256, sql.PayloadSha256, Convert.ToHexStringLower(SHA256.HashData(plain)),
                addresses.Length, addresses.Sum(x => x.Length), keys.CreateProtector(Version, id.ToString("N")).Protect(plain), sql);
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private async Task<HoldObjectAddress[]> Census(ProductionHoldObjectScope scope, ProductionHoldObjectLimits limits, CancellationToken ct)
    {
        var found = new HashSet<HoldObjectAddress>(); var identities = new HashSet<(string, string, string, string)>(); long total = 0;
        foreach (var area in ProductionHoldObjectScope.Areas)
        {
            string? cursor = null; var cursors = new HashSet<string>(StringComparer.Ordinal); var pages = 0;
            do
            {
                scope.Demand(ct); if (++pages > 4096) throw Invalid();
                // Permit one bounded sentinel beyond the limit to detect overflow.
                var maximum = Math.Min(128, limits.MaximumObjects - found.Count + 1);
                var page = await source.ListAsync(scope, area, cursor, maximum, ct); scope.Demand(ct);
                if (page.Objects.Count > maximum || page.Continuation is { Length: > 16384 }) throw Invalid();
                foreach (var value in page.Objects)
                {
                    scope.Demand(value, ct);
                    if (value.Area != area || !identities.Add((value.Area, value.Name, value.VersionId, value.Snapshot)) || !found.Add(value)) throw Invalid();
                    total = checked(total + value.Length);
                    if (found.Count > limits.MaximumObjects || value.Length > limits.MaximumObjectBytes || total > limits.MaximumTotalBytes) throw Invalid();
                }
                cursor = string.IsNullOrEmpty(page.Continuation) ? null : page.Continuation;
                if (cursor is not null && !cursors.Add(cursor)) throw Invalid();
            } while (cursor is not null);
        }
        return found.OrderBy(x => x.Area, StringComparer.Ordinal).ThenBy(x => x.Name, StringComparer.Ordinal)
            .ThenBy(x => x.VersionId, StringComparer.Ordinal).ThenBy(x => x.Snapshot, StringComparer.Ordinal).ToArray();
    }
    private static InvalidDataException Invalid() => new("The private object evidence could not be verified within its scope and bounds.");
}

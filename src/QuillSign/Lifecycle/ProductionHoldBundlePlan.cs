using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

internal sealed record ProductionHoldArchivePlanItem(string Kind, string Path, long Length, string Sha256, HoldObjectAddress? Source);
internal sealed record ProductionHoldProtectedPlan(Guid RecordId, Guid HoldId, Guid PlanId, string Sha256, byte[] Payload);
internal sealed record ProductionHoldFrozenPlan(string Version, Guid PlanId, Guid HoldId, Guid PlaceCommandId,
    ProductionHoldObjectSnapshot Snapshot, ProductionHoldArchivePlanItem[] Items);

// Codec for the forthcoming private durable control journal. A protected plan is
// not a persisted receipt, provider preservation proof or an effective hold.
internal static class ProductionHoldBundlePlan
{
    internal const string Version = "production-hold-bundle-plan-v1";
    private const int MaximumPlaintext = 40 * 1024 * 1024;

    internal static async Task<ProductionHoldProtectedPlan> FreezeLockedAsync(QuillSignDbContext db, IDataProtectionProvider keys,
        TimeProvider time, Guid holdId, Guid planId, ProductionHoldObjectSnapshot snapshot, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (planId == Guid.Empty) throw Invalid();
        // Own a bounded copy before awaiting SQL. Caller-owned byte arrays or
        // summary lists must not change between authentication and freezing.
        var input = Serialize(new(Version, planId, holdId, Guid.Empty, snapshot, []));
        try { snapshot = JsonSerializer.Deserialize<ProductionHoldFrozenPlan>(input)?.Snapshot ?? throw Invalid(); }
        finally { CryptographicOperations.ZeroMemory(input); }
        var objects = ProductionHoldObjectInventory.OpenVerified(snapshot, keys, time);
        var sql = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(db, keys, time, holdId, snapshot.Sql, ct);
        var body = new ProductionHoldFrozenPlan(Version, planId, holdId, sql.PlaceCommandId, snapshot,
            Items(snapshot, holdId, sql.PlaceCommandId, objects));
        var plain = Serialize(body);
        try
        {
            ct.ThrowIfCancellationRequested(); sql.Demand(ct);
            return new(snapshot.RecordId, holdId, planId, Hash(plain), Protector(keys, snapshot.RecordId, planId).Protect(plain));
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    internal static ProductionHoldFrozenPlan OpenVerified(ProductionHoldProtectedPlan plan, IDataProtectionProvider keys, TimeProvider time)
    {
        if (plan.RecordId == Guid.Empty || plan.HoldId == Guid.Empty || plan.PlanId == Guid.Empty ||
            plan.Sha256 is not { Length: 64 } || !plan.Sha256.All(char.IsAsciiHexDigitLower) ||
            plan.Payload is not { Length: > 0 and <= MaximumPlaintext + 1024 * 1024 }) throw Invalid();
        var plain = Protector(keys, plan.RecordId, plan.PlanId).Unprotect(plan.Payload);
        try
        {
            if (plain.Length > MaximumPlaintext || Hash(plain) != plan.Sha256) throw Invalid();
            var body = JsonSerializer.Deserialize<ProductionHoldFrozenPlan>(plain) ?? throw Invalid();
            if (body.Version != Version || body.PlanId != plan.PlanId || body.HoldId != plan.HoldId ||
                body.PlaceCommandId == Guid.Empty || body.Snapshot is null || body.Snapshot.RecordId != plan.RecordId || body.Items is not { Length: >= 2 and <= 4098 }) throw Invalid();
            var objects = ProductionHoldObjectInventory.OpenVerified(body.Snapshot, keys, time);
            using (var sql = ProductionHoldSqlInventory.OpenVerified(body.Snapshot.Sql, keys))
            {
                var requests = sql.RootElement.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == "ProductionHoldRequests").GetProperty("Rows");
                if (requests.EnumerateArray().Count(x => x.GetProperty("HoldId").GetGuid() == body.HoldId &&
                    x.GetProperty("CommandId").GetGuid() == body.PlaceCommandId && x.GetProperty("Operation").GetInt32() == 0) != 1) throw Invalid();
            }
            if (!body.Items.SequenceEqual(Items(body.Snapshot, body.HoldId, body.PlaceCommandId, objects))) throw Invalid();
            var canonical = Serialize(body);
            try { if (!plain.AsSpan().SequenceEqual(canonical)) throw Invalid(); }
            finally { CryptographicOperations.ZeroMemory(canonical); }
            // Deserialization owns the returned byte arrays. Mutating either the
            // caller's original capture or returned data cannot alter saved bytes.
            return body;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private static ProductionHoldArchivePlanItem[] Items(ProductionHoldObjectSnapshot snapshot, Guid hold, Guid place, HoldObjectEvidence[] objects)
    {
        var sqlHash = Hash(snapshot.Sql.ProtectedPayload); var manifestHash = Hash(snapshot.ProtectedManifest);
        var items = new List<ProductionHoldArchivePlanItem> {
            new("sql", ProductionHoldArchivePaths.Sql(snapshot.RecordId, hold, place, sqlHash), snapshot.Sql.ProtectedPayload.LongLength, sqlHash, null),
            new("manifest", ProductionHoldArchivePaths.Manifest(snapshot.RecordId, hold, place, manifestHash), snapshot.ProtectedManifest.LongLength, manifestHash, null)
        };
        items.AddRange(objects.Select(x => new ProductionHoldArchivePlanItem("object",
            ProductionHoldArchivePaths.Object(snapshot.RecordId, hold, place, x.Address, x.Sha256), x.Address.Length, x.Sha256, x.Address)));
        var result = items.OrderBy(x => x.Path, StringComparer.Ordinal).ToArray();
        if (result.Select(x => x.Path).Distinct(StringComparer.Ordinal).Count() != result.Length) throw Invalid();
        return result;
    }
    private static byte[] Serialize(ProductionHoldFrozenPlan body)
    {
        using var memory = new MemoryStream();
        using (var bounded = new QuillSign.Documents.BoundedDocumentStream(memory, MaximumPlaintext)) JsonSerializer.Serialize(bounded, body);
        return memory.ToArray();
    }
    private static IDataProtector Protector(IDataProtectionProvider keys, Guid record, Guid plan) => keys.CreateProtector(Version, record.ToString("N"), plan.ToString("N"));
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static InvalidDataException Invalid() => new("The private frozen hold bundle plan could not be verified.");
}

internal static class ProductionHoldArchivePaths
{
    private static string Prefix(Guid record, Guid hold, Guid place) => $"production-holds/{record:N}/{hold:N}/{place:N}/";
    internal static string Sql(Guid record, Guid hold, Guid place, string hash) => Prefix(record, hold, place) + "sql/" + hash;
    internal static string Manifest(Guid record, Guid hold, Guid place, string hash) => Prefix(record, hold, place) + "manifests/" + hash;
    internal static string Object(Guid record, Guid hold, Guid place, HoldObjectAddress source, string hash) => Prefix(record, hold, place) + "objects/" +
        Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(source))) + "/" + hash;
}

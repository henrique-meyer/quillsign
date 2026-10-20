using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal sealed record ProductionHoldControlPrefix(long Sequence, string? Hash);
internal sealed record ProductionHoldItemReceipt(Guid EventId, Guid PlanId, string PlanSha256, ProductionHoldArchiveStoredObject Stored);
internal sealed record ProductionHoldControlState(ProductionHoldControlPrefix Prefix,
    IReadOnlyDictionary<Guid, ProductionHoldProtectedPlan> Plans, IReadOnlyList<ProductionHoldItemReceipt> Items);

// Private, unregistered progress journal. Receipts are historical verified provider
// facts, not current protection, complete preservation, release or deletion authority.
internal sealed class ProductionHoldControls(QuillSignDbContext db, IDataProtectionProvider keys, TimeProvider time)
{
    internal const string Version = "production-hold-control-v1";
    internal const int MaximumEvents = 16384;
    private const long MaximumBytes = 128 * 1024 * 1024;
    private sealed record Evidence(string Version, Guid EventId, Guid RecordId, Guid HoldId, Guid PlanId, long Sequence, int Kind,
        DateTimeOffset At, string PolicySha256, string PlanSha256, string? ItemSha256, string? PayloadSha256,
        string? PreviousHash, ProductionHoldArchiveStoredObject? Stored);
    private sealed record Verified(ProductionHoldControlState State, ProductionHoldControlRecord[] Rows, Evidence[] Events);

    internal async Task<ProductionHoldControlState> ReadLockedAsync(Guid id, CancellationToken ct = default) => (await Read(id, ct)).State;

    internal async Task DemandExtendsLockedAsync(Guid id, ProductionHoldControlPrefix captured, CancellationToken ct = default)
    { var read = await Read(id, ct); DemandPrefix(captured, read.Rows); }

    internal async Task<ProductionHoldProtectedPlan> SavePlanLockedAsync(ProductionHoldProtectedPlan plan, CancellationToken ct = default)
    {
        RequireTransaction();
        if (plan.Payload is not { Length: > 0 and <= 41 * 1024 * 1024 }) throw Invalid();
        plan = Copy(plan); // Own the exact ciphertext before the first SQL await.
        var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
        var read = await Read(plan.RecordId, ct);
        DemandPrefix(body.Snapshot.Sql.Control ?? throw Invalid(), read.Rows);
        _ = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(db, keys, time, plan.HoldId, body.Snapshot.Sql, ct);
        if (read.State.Plans.TryGetValue(plan.PlanId, out var saved))
        { if (saved.HoldId != plan.HoldId || saved.Sha256 != plan.Sha256) throw Conflict(); return Copy(saved); }
        if (read.Rows.Any(x => x.EventId == plan.PlanId) || await db.ProductionHoldControls.AnyAsync(x => x.EventId == plan.PlanId, ct)) throw Conflict();
        var row = await NewRow(plan.RecordId, plan.HoldId, plan.PlanId, plan.PlanId, 0, plan.Sha256, null,
            plan.Payload.ToArray(), null, read, ct);
        await Append(row, ct);
        return Copy((await Read(plan.RecordId, ct)).State.Plans[plan.PlanId]);
    }

    // The service invokes the exact verified provider writer itself. A caller
    // cannot turn an arbitrary provider-fact DTO into an authenticated receipt.
    internal async Task<ProductionHoldItemReceipt> PreserveItemLockedAsync(Guid id, Guid planId, string path, Guid eventId,
        AzureProductionHoldArchiveWriter archive, CancellationToken ct = default)
    {
        RequireTransaction(); if (eventId == Guid.Empty || path is null || path.Length > 1024) throw Invalid();
        var read = await Read(id, ct);
        if (!read.State.Plans.TryGetValue(planId, out var plan)) throw Conflict();
        var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
        var item = body.Items.SingleOrDefault(x => x.Path == path) ?? throw Conflict();
        IProductionHoldArchivePayload capability = item.Kind == "sql"
            ? await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(db, keys, time, plan.HoldId, body.Snapshot.Sql, ct)
            : await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(db, keys, time, plan.HoldId, body.Snapshot, item.Source, ct);
        if (capability.Path != item.Path || capability.Length != item.Length || capability.Sha256 != item.Sha256) throw Invalid();
        var replay = read.State.Items.SingleOrDefault(x => x.PlanId == planId && x.Stored.Path == path);
        if (replay is not null && replay.EventId != eventId || read.Rows.Any(x => x.EventId == eventId &&
            (x.PlanId != planId || x.ItemSha256 != Digest(path))) || await db.ProductionHoldControls.AnyAsync(x => x.EventId == eventId && x.EnvelopeId != id, ct)) throw Conflict();
        // Even an exact replay rechecks actual bytes/protection. Saved historical
        // facts alone do not prove that an administrator has left a hold intact.
        var stored = await archive.PreserveAsync(capability, ct); capability.Demand(ct);
        DemandItem(item, stored);
        if (replay is not null)
        { if (replay.Stored != stored) throw Conflict(); return replay; }
        var row = await NewRow(id, plan.HoldId, planId, eventId, 1, plan.Sha256, Digest(path), null, stored, read, ct);
        capability.Demand(ct); await Append(row, ct);
        return (await Read(id, ct)).State.Items.Single(x => x.EventId == eventId);
    }

    private async Task<ProductionHoldControlRecord> NewRow(Guid id, Guid hold, Guid plan, Guid eventId, int kind, string planHash,
        string? itemHash, byte[]? payload, ProductionHoldArchiveStoredObject? stored, Verified prior, CancellationToken ct)
    {
        var enrollment = (await Ledger().ReadLockedAsync(id, ct)).Enrollment ?? throw Invalid();
        var at = time.GetUtcNow();
        if (at.Offset != TimeSpan.Zero || at < prior.Rows.LastOrDefault()?.At || prior.Rows.Length >= MaximumEvents) throw Invalid();
        var row = new ProductionHoldControlRecord { EventId = eventId, EnvelopeId = id, HoldId = hold, PlanId = plan,
            Sequence = prior.State.Prefix.Sequence + 1, Kind = kind, At = at,
            PolicySha256 = ProductionRetentionPolicyContract.Digest(enrollment.Snapshot), PlanSha256 = planHash,
            ItemSha256 = itemHash, PlanPayload = payload, PayloadSha256 = payload is null ? null : Digest(payload),
            PreviousHash = prior.State.Prefix.Hash is null ? null : Convert.FromHexString(prior.State.Prefix.Hash) };
        row.ProtectedEvidence = Protector(id).Protect(JsonSerializer.Serialize(Describe(row, stored)));
        if (row.ProtectedEvidence.Length > 65536) throw Invalid(); row.Hash = Hash(row); return row;
    }

    private async Task Append(ProductionHoldControlRecord row, CancellationToken ct)
    {
        // Count ciphertext, including large frozen plans, before loading or adding
        // a journal entry. The caller owns commit and uncertain-commit recovery.
        var prior = await StoredBytes(row.EnvelopeId, ct);
        if (checked(prior + (row.PlanPayload?.LongLength ?? 0) + 2L * row.ProtectedEvidence.Length) > MaximumBytes) throw Invalid();
        db.ProductionHoldControls.Add(row); await db.SaveChangesAsync(ct);
    }

    private async Task<Verified> Read(Guid id, CancellationToken ct)
    {
        RequireTransaction();
        var covered = new HashSet<string>(StringComparer.Ordinal) {
            nameof(ProductionHoldControlRecord.EventId), nameof(ProductionHoldControlRecord.EnvelopeId), nameof(ProductionHoldControlRecord.HoldId),
            nameof(ProductionHoldControlRecord.PlanId), nameof(ProductionHoldControlRecord.Sequence), nameof(ProductionHoldControlRecord.Kind),
            nameof(ProductionHoldControlRecord.At), nameof(ProductionHoldControlRecord.PolicySha256), nameof(ProductionHoldControlRecord.PlanSha256),
            nameof(ProductionHoldControlRecord.ItemSha256), nameof(ProductionHoldControlRecord.PayloadSha256), nameof(ProductionHoldControlRecord.PlanPayload),
            nameof(ProductionHoldControlRecord.ProtectedEvidence), nameof(ProductionHoldControlRecord.PreviousHash), nameof(ProductionHoldControlRecord.Hash) };
        if (!covered.SetEquals(db.Model.FindEntityType(typeof(ProductionHoldControlRecord))!.GetProperties().Select(x => x.Name))) throw Invalid();
        var enrollment = (await Ledger().ReadLockedAsync(id, ct)).Enrollment ?? throw Invalid();
        var policy = ProductionRetentionPolicyContract.Digest(enrollment.Snapshot);
        var requests = await new ProductionHoldRequests(db, keys, time).ReadLockedAsync(id, ct);
        if (await StoredBytes(id, ct) > MaximumBytes) throw Invalid();
        var rows = await db.ProductionHoldControls.FromSqlInterpolated($"SELECT * FROM [ProductionHoldControls] WITH(HOLDLOCK) WHERE [EnvelopeId]={id}")
            .AsNoTracking().OrderBy(x => x.Sequence).Take(MaximumEvents + 1).ToArrayAsync(ct);
        if (rows.Length > MaximumEvents) throw Invalid();
        var plans = new Dictionary<Guid, ProductionHoldProtectedPlan>(); var events = new List<Evidence>(); var receipts = new List<ProductionHoldItemReceipt>();
        var items = new Dictionary<Guid, Dictionary<string, ProductionHoldArchivePlanItem>>();
        var recordedItems = new HashSet<(Guid Plan, string Path)>();
        byte[]? previous = null; DateTimeOffset? lastAt = null;
        foreach (var row in rows)
        {
            if (row.EnvelopeId != id || row.Sequence != events.Count + 1 || row.At.Offset != TimeSpan.Zero || row.At > time.GetUtcNow() ||
                row.At < lastAt || row.PolicySha256 != policy || row.Hash is not { Length: 32 } ||
                !CryptographicOperations.FixedTimeEquals(row.Hash, Hash(row)) ||
                (previous is null ? row.PreviousHash is not null : !ProductionRetentionLedger.Same(previous, row.PreviousHash)) ||
                row.EventId == Guid.Empty || row.PlanId == Guid.Empty || row.HoldId == Guid.Empty || !Hex(row.PlanSha256) ||
                row.ProtectedEvidence is not { Length: >= 32 and <= 65536 }) throw Invalid();
            Evidence e;
            try
            {
                var plain = Protector(id).Unprotect(row.ProtectedEvidence);
                e = JsonSerializer.Deserialize<Evidence>(plain) ?? throw Invalid();
                if (plain != JsonSerializer.Serialize(e) || e != Describe(row, e.Stored)) throw Invalid();
            }
            catch (Exception error) when (error is CryptographicException or JsonException or ArgumentException)
            { throw new InvalidDataException("Private hold control evidence could not be verified.", error); }
            var hold = requests.Holds.SingleOrDefault(x => x.HoldId == row.HoldId) ?? throw Invalid();
            if (row.Kind == 0)
            {
                if (row.EventId != row.PlanId || row.ItemSha256 is not null || row.PlanPayload is not { Length: > 0 and <= 41 * 1024 * 1024 } ||
                    row.PayloadSha256 != Digest(row.PlanPayload) || e.Stored is not null) throw Invalid();
                var plan = new ProductionHoldProtectedPlan(id, row.HoldId, row.PlanId, row.PlanSha256, row.PlanPayload);
                var body = ProductionHoldBundlePlan.OpenVerified(plan, keys, time);
                if (body.PlaceCommandId != hold.PlacementCommandId || body.Snapshot.Sql.CapturedAt > row.At) throw Invalid();
                DemandPrefix(body.Snapshot.Sql.Control ?? throw Invalid(), rows.Take(events.Count).ToArray());
                if (!plans.TryAdd(row.PlanId, plan)) throw Invalid();
                items.Add(row.PlanId, body.Items.ToDictionary(x => x.Path, StringComparer.Ordinal));
            }
            else if (row.Kind == 1)
            {
                if (row.PlanPayload is not null || row.PayloadSha256 is not null || !Hex(row.ItemSha256) || e.Stored is null ||
                    !plans.TryGetValue(row.PlanId, out var plan) || plan.HoldId != row.HoldId || plan.Sha256 != row.PlanSha256 ||
                    row.ItemSha256 != Digest(e.Stored.Path)) throw Invalid();
                if (!items[row.PlanId].TryGetValue(e.Stored.Path, out var item)) throw Invalid(); DemandItem(item, e.Stored);
                if (!recordedItems.Add((row.PlanId, e.Stored.Path))) throw Invalid();
                receipts.Add(new(row.EventId, row.PlanId, row.PlanSha256, e.Stored));
            }
            else throw Invalid();
            events.Add(e); previous = row.Hash; lastAt = row.At;
        }
        return new(new(new(rows.LongLength, previous is null ? null : Convert.ToHexStringLower(previous)), plans, receipts), rows, events.ToArray());
    }

    private static void DemandItem(ProductionHoldArchivePlanItem item, ProductionHoldArchiveStoredObject stored)
    {
        if (stored.Path != item.Path || stored.Length != item.Length || stored.Sha256 != item.Sha256 ||
            !Opaque(stored.VersionId) || !Opaque(stored.ETag) || stored.ETag[0] != '"' || stored.ETag[^1] != '"') throw Invalid();
    }
    internal static void ValidatePrefix(ProductionHoldControlPrefix prefix)
    { if (prefix.Sequence is < 0 or > MaximumEvents || (prefix.Sequence == 0 ? prefix.Hash is not null : !Hex(prefix.Hash))) throw Invalid(); }
    private static void DemandPrefix(ProductionHoldControlPrefix captured, ProductionHoldControlRecord[] rows)
    {
        ValidatePrefix(captured);
        if (captured.Sequence > rows.LongLength || captured.Sequence > 0 &&
            Convert.ToHexStringLower(rows[checked((int)captured.Sequence - 1)].Hash) != captured.Hash) throw Invalid();
    }
    private async Task<long> StoredBytes(Guid id, CancellationToken ct) => await db.Database.SqlQuery<long>(
        $"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([ProtectedEvidence]))+COALESCE(CONVERT(bigint,DATALENGTH([PlanPayload])),0)),0) AS [Value] FROM [ProductionHoldControls] WITH(HOLDLOCK) WHERE [EnvelopeId]={id}").SingleAsync(ct);
    private static Evidence Describe(ProductionHoldControlRecord row, ProductionHoldArchiveStoredObject? stored) =>
        new(Version, row.EventId, row.EnvelopeId, row.HoldId, row.PlanId, row.Sequence, row.Kind, row.At, row.PolicySha256,
            row.PlanSha256, row.ItemSha256, row.PayloadSha256, row.PreviousHash is null ? null : Convert.ToHexStringLower(row.PreviousHash), stored);
    private static byte[] Hash(ProductionHoldControlRecord row) => SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
        row.EventId, row.EnvelopeId, row.HoldId, row.PlanId, row.Sequence, row.Kind, row.At, row.PolicySha256, row.PlanSha256,
        row.ItemSha256, row.PayloadSha256, row.ProtectedEvidence, row.PreviousHash }));
    private IDataProtector Protector(Guid id) => keys.CreateProtector(Version, id.ToString("N"));
    private ProductionRetentionLedger Ledger() => new(db, new(db, time), time);
    private static ProductionHoldProtectedPlan Copy(ProductionHoldProtectedPlan p) => p with { Payload = p.Payload.ToArray() };
    private static string Digest(byte[] value) => Convert.ToHexStringLower(SHA256.HashData(value));
    private static string Digest(string value) => Digest(Encoding.UTF8.GetBytes(value));
    private static bool Hex(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    private static bool Opaque(string? value) => value is { Length: >= 3 and <= 256 } && value.All(c => c is >= ' ' and <= '~');
    private void RequireTransaction() { if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Hold controls require a clean caller-owned private transaction."); }
    private static InvalidDataException Invalid() => new("The private production hold control journal could not be verified.");
    private static DocumentConflictException Conflict() => new();
}

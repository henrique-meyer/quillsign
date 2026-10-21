using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

internal enum ProductionHoldPendingState { PreservationPending, ReleasePending }
internal sealed record PendingProductionHold(Guid HoldId, Guid PlacementCommandId, Guid? ReleaseCommandId, ProductionHoldPendingState State);
internal sealed record ProductionHoldRequestSnapshot(long Revision, string? FenceHash, IReadOnlyList<PendingProductionHold> Holds)
{
    // A pending release is not permission to delete. Only later verified provider
    // reconciliation can complete a release; that backend is still required.
    internal bool BlocksDeletion => Holds.Count != 0;
}
internal sealed record ProductionHoldRequestReceipt(Guid CommandId, long CommandRevision, ProductionHoldRequestSnapshot Current);

// Private, unregistered metadata backend. Caller owns the privileged SQL context
// and transaction/commit. No storage capability or effective hold is issued here.
internal sealed class ProductionHoldRequests(QuillSignDbContext db, IDataProtectionProvider keys, TimeProvider time)
{
    internal const string Version = "production-hold-request-v1";
    private sealed record Evidence(string Version, ProductionHoldCommand Command, string Issuer, string Subject,
        long Revision, DateTimeOffset At, string PolicySha256, string? PreviousHash);
    private sealed record ReadResult(ProductionHoldRequestSnapshot Snapshot, ProductionHoldRequestRecord[] Rows, Evidence[] Evidence);
    private IDataProtector Protector(Guid id) => keys.CreateProtector(Version, id.ToString("N"));

    internal async Task<ProductionHoldRequestReceipt> PrepareLockedAsync(ProductionOperatorAuthority authority,
        ProductionOperatorPolicy operators, ProductionHoldCommand command, CancellationToken ct = default)
    {
        RequireTransaction();
        authority.Demand(operators, command.Permission, time);
        var digest = command.Digest();
        var read = await Read(command.RecordId, ct);
        var replay = Array.FindIndex(read.Rows, x => x.CommandId == command.CommandId);
        if (replay >= 0)
        {
            var original = read.Evidence[replay];
            if (read.Rows[replay].CommandSha256 != digest || original.Command != command ||
                original.Issuer != authority.Issuer || original.Subject != authority.Subject) throw Conflict();
            authority.Demand(operators, command.Permission, time);
            return new(command.CommandId, read.Rows[replay].Revision, read.Snapshot);
        }
        // Also reject reuse of a command ID across records without disclosing it.
        if (read.Snapshot.Revision != command.ExpectedRevision || read.Rows.Length >= 512 ||
            await db.ProductionHoldRequests.AnyAsync(x => x.CommandId == command.CommandId, ct)) throw Conflict();
        var hold = read.Snapshot.Holds.SingleOrDefault(x => x.HoldId == command.HoldId);
        if (command.Operation == ProductionHoldOperation.Place ? hold is not null : hold is null || hold.ReleaseCommandId is not null) throw Conflict();
        var enrollment = (await Ledger().ReadLockedAsync(command.RecordId, ct)).Enrollment ?? throw Invalid();
        var at = time.GetUtcNow();
        if (at.Offset != TimeSpan.Zero || read.Rows.LastOrDefault()?.At > at) throw Invalid();
        var revision = checked(read.Snapshot.Revision + 1);
        var evidence = new Evidence(Version, command, authority.Issuer, authority.Subject, revision, at,
            ProductionRetentionPolicyContract.Digest(enrollment.Snapshot), read.Snapshot.FenceHash);
        var row = new ProductionHoldRequestRecord
        {
            CommandId = command.CommandId, EnvelopeId = command.RecordId, HoldId = command.HoldId, Revision = revision,
            Operation = (int)command.Operation, At = at, PolicySha256 = evidence.PolicySha256, CommandSha256 = digest,
            ProtectedEvidence = Protector(command.RecordId).Protect(JsonSerializer.Serialize(evidence)),
            PreviousHash = read.Snapshot.FenceHash is null ? null : Convert.FromHexString(read.Snapshot.FenceHash)
        };
        if (row.ProtectedEvidence.Length > 32768) throw Invalid();
        row.Hash = Hash(row);
        authority.Demand(operators, command.Permission, time);
        db.ProductionHoldRequests.Add(row);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException error) when (error.InnerException is SqlException { Number: 2601 or 2627 }) { throw Conflict(); }
        var saved = await Read(command.RecordId, ct);
        authority.Demand(operators, command.Permission, time);
        return new(command.CommandId, revision, saved.Snapshot);
    }

    internal async Task<ProductionHoldRequestSnapshot> ReadLockedAsync(Guid recordId, CancellationToken ct = default)
    {
        RequireTransaction();
        return (await Read(recordId, ct)).Snapshot;
    }

    private async Task<ReadResult> Read(Guid id, CancellationToken ct)
    {
        var enrollment = (await Ledger().ReadLockedAsync(id, ct)).Enrollment ?? throw Invalid();
        var policy = ProductionRetentionPolicyContract.Digest(enrollment.Snapshot);
        var bytes = await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([ProtectedEvidence]))),0) AS [Value] FROM [ProductionHoldRequests] WHERE [EnvelopeId]={id}").SingleAsync(ct);
        if (bytes > 16 * 1024 * 1024) throw Invalid();
        var rows = await db.ProductionHoldRequests.AsNoTracking().Where(x => x.EnvelopeId == id).OrderBy(x => x.Revision).Take(513).ToArrayAsync(ct);
        if (rows.Length > 512) throw Invalid();
        var holds = new Dictionary<Guid, PendingProductionHold>();
        var evidence = new List<Evidence>();
        byte[]? previous = null; DateTimeOffset? lastAt = null;
        foreach (var row in rows)
        {
            if (row.EnvelopeId != id || row.Revision != evidence.Count + 1 || row.At.Offset != TimeSpan.Zero ||
                row.At > time.GetUtcNow() || row.At < lastAt || row.PolicySha256 != policy || row.Hash.Length != 32 ||
                !CryptographicOperations.FixedTimeEquals(row.Hash, Hash(row)) ||
                (previous is null ? row.PreviousHash is not null : !ProductionRetentionLedger.Same(previous, row.PreviousHash))) throw Invalid();
            Evidence value;
            try
            {
                if (row.ProtectedEvidence.Length is < 32 or > 32768) throw Invalid();
                var plain = Protector(id).Unprotect(row.ProtectedEvidence);
                value = JsonSerializer.Deserialize<Evidence>(plain) ?? throw Invalid();
                if (JsonSerializer.Serialize(value) != plain || value.Version != Version || value.Revision != row.Revision || value.At != row.At ||
                    value.PolicySha256 != policy || value.PreviousHash != (previous is null ? null : ProductionRetentionLedger.Hex(previous)) ||
                    !ProductionOperatorAuthority.Text(value.Issuer, 2048) || !ProductionOperatorAuthority.Text(value.Subject, 256) ||
                    value.Command.CommandId != row.CommandId || value.Command.RecordId != id || value.Command.HoldId != row.HoldId ||
                    value.Command.ExpectedRevision != row.Revision - 1 || (int)value.Command.Operation != row.Operation ||
                    value.Command.Digest() != row.CommandSha256) throw Invalid();
            }
            catch (Exception error) when (error is CryptographicException or JsonException or ArgumentException or NullReferenceException)
            { throw new InvalidDataException("Private production hold evidence could not be verified.", error); }
            if (value.Command.Operation == ProductionHoldOperation.Place)
            {
                if (!holds.TryAdd(row.HoldId, new(row.HoldId, row.CommandId, null, ProductionHoldPendingState.PreservationPending))) throw Invalid();
            }
            else
            {
                if (!holds.TryGetValue(row.HoldId, out var hold) || hold.ReleaseCommandId is not null) throw Invalid();
                holds[row.HoldId] = hold with { ReleaseCommandId = row.CommandId, State = ProductionHoldPendingState.ReleasePending };
            }
            evidence.Add(value); previous = row.Hash; lastAt = row.At;
        }
        return new(new(rows.LongLength, previous is null ? null : ProductionRetentionLedger.Hex(previous),
            holds.Values.OrderBy(x => x.HoldId).ToArray()), rows, evidence.ToArray());
    }

    private ProductionRetentionLedger Ledger() => new(db, new(db, time), time);
    private void RequireTransaction()
    {
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges())
            throw new InvalidOperationException("Private hold requests require a clean caller-owned transaction.");
    }
    private static byte[] Hash(ProductionHoldRequestRecord row) => SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
    {
        Version, row.CommandId, row.EnvelopeId, row.HoldId, row.Revision, row.Operation, row.At, row.PolicySha256, row.CommandSha256,
        evidenceSha256 = ProductionRetentionLedger.Hex(SHA256.HashData(Encoding.UTF8.GetBytes(row.ProtectedEvidence))),
        previousHash = row.PreviousHash is null ? null : Convert.ToHexStringLower(row.PreviousHash)
    }));
    private static DocumentConflictException Conflict() => new();
    private static InvalidDataException Invalid() => new("Private production hold evidence could not be verified.");
}

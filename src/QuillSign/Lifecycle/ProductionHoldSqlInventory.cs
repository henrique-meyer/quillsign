using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using QuillSign.Data;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

internal sealed record ProductionHoldSqlLimits(int MaximumRows = 4096, long MaximumDatabaseBytes = 16 * 1024 * 1024,
    long MaximumJsonBytes = 16 * 1024 * 1024);
internal sealed record ProductionHoldSqlTable(string Table, long Rows, string Sha256);
internal sealed record ProductionHoldSqlSnapshot(Guid RecordId, long Revision, string FenceHash, DateTimeOffset CapturedAt,
    string StateSha256, string PayloadSha256, long PlaintextBytes, byte[] ProtectedPayload, IReadOnlyList<ProductionHoldSqlTable> Tables);

// Private worker building block, unregistered. This captures SQL evidence only;
// it is not proof of referenced blob completeness or provider preservation.
internal sealed class ProductionHoldSqlInventory(QuillSignDbContext db, IDataProtectionProvider keys, TimeProvider time)
{
    internal const string Version = "production-hold-sql-inventory-v1";
    private sealed record TableData(string Table, string[] Columns, long Count, string Sha256, JsonElement Rows);
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly HashSet<Type> PilotTypes = [typeof(EmailPilotRunRecord), typeof(EmailPilotSecretRecord),
        typeof(EmailPilotEnrollmentRecord), typeof(EmailPilotReservationRecord), typeof(EmailPilotLookupRequestRecord), typeof(EmailPilotLookupTokenRecord)];
    private static readonly HashSet<Type> KnownTypes = [typeof(Envelope), typeof(Signer), typeof(Recipient), typeof(DocumentField),
        typeof(AuthToken), typeof(AuditEvent), typeof(EmailOutbox), typeof(WorkItem), typeof(Suppression), typeof(SignaturePreview),
        typeof(SignerReviewCandidate), typeof(SignerFinishAcceptance), typeof(CompletionCandidate), typeof(CompletionSealOutput),
        typeof(CompletionPublicationIntent), typeof(CompletionPublicationResult), typeof(DocumentRetentionSnapshot),
        typeof(LookupContactRetentionSnapshot), typeof(SignerContactRevisionRecord), typeof(SignerContactSession),
        typeof(ProductionRetentionPolicyRecord), typeof(ProductionRetentionTerminalRecord), typeof(ProductionHoldRequestRecord),
        typeof(EmailPilotRunRecord), typeof(EmailPilotSecretRecord), typeof(EmailPilotEnrollmentRecord), typeof(EmailPilotReservationRecord),
        typeof(EmailPilotLookupRequestRecord), typeof(EmailPilotLookupTokenRecord)];

    // Private consumers must authenticate persisted bytes rather than trusting the
    // separately stored summary/hash or accepting a caller-supplied table list.
    internal static JsonDocument OpenVerified(ProductionHoldSqlSnapshot snapshot, IDataProtectionProvider keys)
    {
        if (snapshot.RecordId == Guid.Empty || snapshot.ProtectedPayload is not { Length: > 0 and <= 17 * 1024 * 1024 } ||
            snapshot.PlaintextBytes is < 1 or > 16 * 1024 * 1024) throw Invalid();
        var plain = keys.CreateProtector(Version, snapshot.RecordId.ToString("N")).Unprotect(snapshot.ProtectedPayload);
        JsonDocument? document = null;
        try
        {
            if (plain.LongLength != snapshot.PlaintextBytes || Convert.ToHexStringLower(SHA256.HashData(plain)) != snapshot.PayloadSha256) throw Invalid();
            using var input = new MemoryStream(plain, false);
            document = JsonDocument.Parse(input); var root = document.RootElement;
            if (root.GetProperty("Version").GetString() != Version || root.GetProperty("RecordId").GetGuid() != snapshot.RecordId ||
                root.GetProperty("Revision").GetInt64() != snapshot.Revision || root.GetProperty("FenceHash").GetString() != snapshot.FenceHash ||
                root.GetProperty("CapturedAt").GetDateTimeOffset() != snapshot.CapturedAt || root.GetProperty("StateSha256").GetString() != snapshot.StateSha256) throw Invalid();
            var tables = root.GetProperty("Tables");
            if (tables.GetArrayLength() != snapshot.Tables.Count || !tables.EnumerateArray().Select(x => new ProductionHoldSqlTable(
                x.GetProperty("Table").GetString()!, x.GetProperty("Count").GetInt64(), x.GetProperty("Sha256").GetString()!)).SequenceEqual(snapshot.Tables)) throw Invalid();
            var state = SerializeBounded(new { Version, RecordId = snapshot.RecordId, Revision = snapshot.Revision, FenceHash = snapshot.FenceHash,
                PolicySha256 = root.GetProperty("PolicySha256").GetString(), Tables = tables }, 16 * 1024 * 1024);
            try { if (Convert.ToHexStringLower(SHA256.HashData(state)) != snapshot.StateSha256) throw Invalid(); }
            finally { CryptographicOperations.ZeroMemory(state); }
            return document;
        }
        catch { document?.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    internal async Task<ProductionHoldSqlSnapshot> CaptureLockedAsync(Guid id, long revision, string fenceHash,
        ProductionHoldSqlLimits? limits = null, CancellationToken ct = default)
    {
        limits ??= new();
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw new InvalidOperationException("SQL evidence capture requires a clean caller-owned private transaction.");
        if (id == Guid.Empty || revision is < 1 or > 512 || fenceHash is not { Length: 64 } ||
            !fenceHash.All(char.IsAsciiHexDigitLower) || limits.MaximumRows is < 1 or > 4096 ||
            limits.MaximumDatabaseBytes is < 1 or > 16 * 1024 * 1024 || limits.MaximumJsonBytes is < 64 or > 16 * 1024 * 1024) throw Invalid();
        var entities = db.Model.GetEntityTypes().ToArray();
        if (!KnownTypes.SetEquals(entities.Select(x => x.ClrType))) throw Invalid();
        var holds = await new ProductionHoldRequests(db, keys, time).ReadLockedAsync(id, ct);
        if (!holds.BlocksDeletion || holds.Revision != revision || holds.FenceHash != fenceHash) throw new DocumentConflictException();
        var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == id, ct);
        // Verifies enrollment, original source and terminal provenance without granting
        // a participant session or checking/renewing its separate access deadline.
        var retained = await ProductionRecordRetentionAccess.ReadLockedAsync(db, envelope, time, ct);
        if (retained.Enrollment is null || await db.DocumentRetentionSnapshots.AnyAsync(x => x.EnvelopeId == id, ct) ||
            await db.EmailPilotEnrollments.AnyAsync(x => x.SubjectEnvelopeId == id, ct) ||
            await db.EmailPilotReservations.AnyAsync(x => x.SubjectEnvelopeId == id, ct) ||
            await db.EmailPilotLookupRequests.AnyAsync(x => x.SubjectEnvelopeId == id, ct)) throw Invalid();
        var data = new List<TableData>(); long rows = 0, bytes = 0;
        foreach (var entity in entities.OrderBy(x => x.GetTableName(), StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            if (PilotTypes.Contains(entity.ClrType) || entity.ClrType == typeof(Suppression)) continue;
            var table = entity.GetTableName() ?? throw Invalid(); var schema = entity.GetSchema() ?? "dbo";
            var tableId = Identifier(schema) + "." + Identifier(table);
            var store = StoreObjectIdentifier.Table(table, entity.GetSchema());
            var properties = entity.GetProperties().OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
            if (properties.Any(x => x.PropertyInfo is null)) throw Invalid();
            string scope;
            if (entity.ClrType == typeof(Envelope)) scope = "[Id]=@recordId";
            else if (entity.ClrType == typeof(LookupContactRetentionSnapshot))
                scope = "[RequestId] IN (SELECT [Id] FROM [dbo].[EmailOutbox] WITH(HOLDLOCK) WHERE [EnvelopeId]=@recordId)";
            else
            {
                var owner = entity.FindProperty("EnvelopeId");
                if (owner?.ClrType != typeof(Guid) && owner?.ClrType != typeof(Guid?)) throw Invalid();
                scope = Identifier(owner!.GetColumnName(store) ?? throw Invalid()) + "=@recordId";
            }
            var source = tableId + " WITH(HOLDLOCK) WHERE " + scope;
            SqlParameter Parameter() => new("@recordId", id);
            // Identifiers come only from the exhaustive compiled model allowlist and
            // Identifier's strict quoting guard. All record values stay parameters.
#pragma warning disable EF1003
            var count = await db.Database.SqlQueryRaw<long>("SELECT COUNT_BIG(*) AS [Value] FROM " + source, Parameter()).SingleAsync(ct);
            rows = checked(rows + count); if (rows > limits.MaximumRows) throw Invalid();
            var lengths = string.Join("+", properties.Select(x => "COALESCE(CONVERT(bigint,DATALENGTH(" + Identifier(x.GetColumnName(store) ?? throw Invalid()) + ")),0)"));
            bytes = checked(bytes + await db.Database.SqlQueryRaw<long>("SELECT COALESCE(SUM(" + lengths + "),0) AS [Value] FROM " + source, Parameter()).SingleAsync(ct));
#pragma warning restore EF1003
            if (bytes > limits.MaximumDatabaseBytes) throw Invalid();
            var loader = typeof(ProductionHoldSqlInventory).GetMethod(nameof(Load), BindingFlags.NonPublic | BindingFlags.Instance)!.MakeGenericMethod(entity.ClrType);
            var values = await (Task<object[]>)loader.Invoke(this, ["SELECT * FROM " + source, id, checked((int)count + 1), ct])!;
            if (values.LongLength != count) throw Invalid();
            var records = new List<string>();
            long encodedBytes = 0;
            foreach (var value in values)
            {
                var fields = new SortedDictionary<string, object?>(StringComparer.Ordinal);
                foreach (var property in properties) fields.Add(property.Name, property.PropertyInfo!.GetValue(value));
                var record = JsonSerializer.Serialize(fields, Json);
                encodedBytes = checked(encodedBytes + System.Text.Encoding.UTF8.GetByteCount(record));
                if (encodedBytes > limits.MaximumJsonBytes) throw Invalid();
                records.Add(record);
            }
            records.Sort(StringComparer.Ordinal);
            using var document = JsonDocument.Parse("[" + string.Join(",", records) + "]");
            var encoded = SerializeBounded(document.RootElement, limits.MaximumJsonBytes);
            var hash = Convert.ToHexStringLower(SHA256.HashData(encoded)); CryptographicOperations.ZeroMemory(encoded);
            data.Add(new(table, properties.Select(x => x.Name + ":" + x.GetColumnType() + ":" + x.ClrType.FullName).ToArray(), count, hash, document.RootElement.Clone()));
        }
        var policy = ProductionRetentionPolicyContract.Digest(retained.Enrollment.Snapshot);
        var state = SerializeBounded(new { Version, RecordId = id, Revision = revision, FenceHash = fenceHash, PolicySha256 = policy, Tables = data }, limits.MaximumJsonBytes);
        var stateHash = Convert.ToHexStringLower(SHA256.HashData(state)); CryptographicOperations.ZeroMemory(state);
        var at = time.GetUtcNow();
        var plain = SerializeBounded(new { Version, RecordId = id, Revision = revision, FenceHash = fenceHash, PolicySha256 = policy,
            CapturedAt = at, StateSha256 = stateHash, Tables = data }, limits.MaximumJsonBytes);
        try
        {
            var payloadHash = Convert.ToHexStringLower(SHA256.HashData(plain));
            var protectedPayload = keys.CreateProtector(Version, id.ToString("N")).Protect(plain);
            return new(id, revision, fenceHash, at, stateHash, payloadHash, plain.LongLength, protectedPayload,
                data.Select(x => new ProductionHoldSqlTable(x.Table, x.Count, x.Sha256)).ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private async Task<object[]> Load<T>(string sql, Guid id, int take, CancellationToken ct) where T : class
        => (await db.Set<T>().FromSqlRaw(sql, new SqlParameter("@recordId", id)).AsNoTracking().Take(take).ToArrayAsync(ct)).Cast<object>().ToArray();
    private static string Identifier(string value)
    {
        if (value.Length is < 1 or > 128 || value.Any(x => !char.IsAsciiLetterOrDigit(x) && x != '_')) throw Invalid();
        return "[" + value + "]";
    }
    private static byte[] SerializeBounded<T>(T value, long maximum)
    {
        using var memory = new MemoryStream();
        try
        {
            using var bounded = new BoundedDocumentStream(memory, maximum);
            using (var writer = new Utf8JsonWriter(bounded)) { JsonSerializer.Serialize(writer, value, Json); writer.Flush(); }
            return memory.ToArray();
        }
        catch (DocumentRejectedException error) { throw new InvalidDataException("The private SQL evidence snapshot exceeds its bound.", error); }
        finally { if (memory.TryGetBuffer(out var buffer)) CryptographicOperations.ZeroMemory(buffer.AsSpan(0, checked((int)memory.Length))); }
    }
    private static InvalidDataException Invalid() => new("Private SQL evidence inventory could not be verified within its scope and bounds.");
}

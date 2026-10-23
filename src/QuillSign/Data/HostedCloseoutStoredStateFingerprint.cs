using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace QuillSign.Data;

public sealed record HostedCloseoutStoredStateColumn(string Name, string SqlType, bool Nullable, int? ExactBytes);
public sealed record HostedCloseoutStoredStateSchema(int Index, string Table,
    ImmutableArray<HostedCloseoutStoredStateColumn> Columns, ImmutableArray<string> KeyColumns);
public sealed record HostedCloseoutStoredStateRowFingerprint(string Key, string Sha256);
public sealed record HostedCloseoutStoredStateSetFingerprint(int Index, string Table, string SchemaSha256,
    string Sha256, ImmutableArray<HostedCloseoutStoredStateRowFingerprint> Rows);

/// <summary>
/// Factual fingerprints of a closed set of stored SQL rows, including opaque ciphertext.
/// These digests confer no decrypted-manifest, delivery, policy, or mutation authority.
/// Version changes are required for any change to schemas, nullability, ordering, bounds or encoding.
/// </summary>
public static class HostedCloseoutStoredStateFingerprint
{
    public const string Version = "closeout-stored-state-v1";
    public const int MaximumRows = 4096;
    public const int MaximumCellBytes = 4 * 1024 * 1024;
    public const int MaximumEncodedBytes = 64 * 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    private static readonly ImmutableDictionary<int, HostedCloseoutStoredStateSchema> Schemas = new[]
    {
        S(1, "__EFMigrationsHistory", "MigrationId",
            C("MigrationId", "nvarchar", false, null),
            C("ProductVersion", "nvarchar", false, null)),
        S(2, "EmailPilotRuns", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("CreatedAt", "datetimeoffset", false, null),
            C("ExpiresAt", "datetimeoffset", false, null),
            C("ManifestSha256", "varbinary", false, 32),
            C("CapabilitySha256", "varbinary", false, 32)),
        S(3, "EmailPilotSecrets", "RunId",
            C("RunId", "uniqueidentifier", false, null),
            C("ProtectedManifest", "nvarchar", false, null),
            C("DeleteAfter", "datetimeoffset", false, null)),
        S(4, "EmailPilotEnrollments", "SubjectEnvelopeId",
            C("SubjectEnvelopeId", "uniqueidentifier", false, null),
            C("RunId", "uniqueidentifier", false, null),
            C("Scenario", "nvarchar", false, null),
            C("EnrolledAt", "datetimeoffset", false, null),
            C("ProtectedBinding", "nvarchar", false, null)),
        S(5, "EmailPilotReservations", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("RunId", "uniqueidentifier", false, null),
            C("SubjectEnvelopeId", "uniqueidentifier", true, null),
            C("OperationId", "uniqueidentifier", false, null),
            C("Kind", "nvarchar", false, null),
            C("Role", "nvarchar", false, null),
            C("EncodedBytes", "int", false, null),
            C("RequestSha256", "varbinary", false, 32),
            C("ReservedAt", "datetimeoffset", false, null),
            C("ProtectedReceipt", "nvarchar", false, null)),
        S(7, "Envelopes", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("PublicId", "nvarchar", false, null),
            C("Status", "nvarchar", false, null),
            C("SenderEmail", "nvarchar", false, null),
            C("SenderName", "nvarchar", true, null),
            C("SenderVerifiedAt", "datetimeoffset", true, null),
            C("Title", "nvarchar", true, null),
            C("Message", "nvarchar", true, null),
            C("ReminderDaysJson", "nvarchar", false, null),
            C("ExpiresAt", "datetimeoffset", true, null),
            C("ErsdVersion", "nvarchar", true, null),
            C("ErsdSha256", "varbinary", true, 32),
            C("ExclusionsAckAt", "datetimeoffset", true, null),
            C("OriginalBlob", "nvarchar", true, null),
            C("OriginalSha256", "varbinary", true, 32),
            C("OriginalMime", "nvarchar", true, null),
            C("PdfBlob", "nvarchar", true, null),
            C("PdfSha256", "varbinary", true, 32),
            C("PageCount", "int", true, null),
            C("PageSizesJson", "nvarchar", true, null),
            C("PreviewConfirmedAt", "datetimeoffset", true, null),
            C("SentPdfBlob", "nvarchar", true, null),
            C("SentPdfSha256", "varbinary", true, 32),
            C("FinalBlob", "nvarchar", true, null),
            C("FinalSha256", "varbinary", true, 32),
            C("CertificateBlob", "nvarchar", true, null),
            C("CertificateSha256", "varbinary", true, 32),
            C("SealCertThumbprint", "nvarchar", true, null),
            C("SealProvider", "nvarchar", true, null),
            C("TsaUrl", "nvarchar", true, null),
            C("AiRolesJson", "nvarchar", true, null),
            C("AiModel", "nvarchar", true, null),
            C("CreatedAt", "datetimeoffset", false, null),
            C("SentAt", "datetimeoffset", true, null),
            C("CompletedAt", "datetimeoffset", true, null),
            C("PurgeAfter", "datetimeoffset", true, null),
            C("IsDemo", "bit", false, null),
            C("RowVersion", "timestamp", false, 8),
            C("ErsdText", "nvarchar", true, null),
            C("CurrentCopyVersion", "int", false, null),
            C("CurrentFinishId", "uniqueidentifier", true, null)),
        S(8, "Signers", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("EnvelopeId", "uniqueidentifier", false, null),
            C("Order", "int", false, null),
            C("FullName", "nvarchar", false, null),
            C("Email", "nvarchar", false, null),
            C("Role", "nvarchar", true, null),
            C("Color", "nvarchar", true, null),
            C("Status", "nvarchar", false, null),
            C("ConsentAt", "datetimeoffset", true, null),
            C("ConsentIp", "nvarchar", true, null),
            C("ConsentUa", "nvarchar", true, null),
            C("SignedAt", "datetimeoffset", true, null),
            C("SignedIp", "nvarchar", true, null),
            C("SignedUa", "nvarchar", true, null),
            C("DeclineReason", "nvarchar", true, null),
            C("SignatureImageBlob", "nvarchar", true, null),
            C("InitialsImageBlob", "nvarchar", true, null),
            C("SignatureMethod", "nvarchar", true, null),
            C("RowVersion", "timestamp", false, 8),
            C("InitialsImageSha256", "varbinary", true, 32),
            C("SignatureAdoptedAt", "datetimeoffset", true, null),
            C("SignatureAdoptionId", "uniqueidentifier", true, null),
            C("SignatureAdoptionVersion", "nvarchar", true, null),
            C("SignatureImageSha256", "varbinary", true, 32),
            C("SignatureNormalizationVersion", "nvarchar", true, null),
            C("SignatureTypedInitials", "nvarchar", true, null),
            C("SignatureTypedName", "nvarchar", true, null)),
        S(9, "Recipients", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("EnvelopeId", "uniqueidentifier", false, null),
            C("Name", "nvarchar", false, null),
            C("Email", "nvarchar", false, null),
            C("RowVersion", "timestamp", false, 8)),
        S(10, "EmailOutbox", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("EnvelopeId", "uniqueidentifier", true, null),
            C("To", "nvarchar", false, null),
            C("Template", "nvarchar", false, null),
            C("PayloadJson", "nvarchar", false, null),
            C("AttachmentsJson", "nvarchar", false, null),
            C("Status", "nvarchar", false, null),
            C("Provider", "nvarchar", true, null),
            C("ProviderMessageId", "nvarchar", true, null),
            C("Attempts", "int", false, null),
            C("LastError", "nvarchar", true, null),
            C("AvailableAt", "datetimeoffset", false, null),
            C("LeaseOwner", "uniqueidentifier", true, null),
            C("LeaseExpiresAt", "datetimeoffset", true, null),
            C("RowVersion", "timestamp", false, 8),
            C("SubmissionStartedAt", "datetimeoffset", true, null)),
        S(11, "WorkItems", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("EnvelopeId", "uniqueidentifier", true, null),
            C("Kind", "nvarchar", false, null),
            C("Status", "nvarchar", false, null),
            C("PayloadJson", "nvarchar", false, null),
            C("Attempts", "int", false, null),
            C("LastError", "nvarchar", true, null),
            C("AvailableAt", "datetimeoffset", false, null),
            C("LeaseOwner", "uniqueidentifier", true, null),
            C("LeaseExpiresAt", "datetimeoffset", true, null),
            C("RowVersion", "timestamp", false, 8)),
        S(13, "CompletionPublicationIntents", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("EnvelopeId", "uniqueidentifier", false, null),
            C("CandidateId", "uniqueidentifier", false, null),
            C("ExecutedOutputId", "uniqueidentifier", false, null),
            C("CertificateOutputId", "uniqueidentifier", false, null),
            C("ExecutedObjectId", "uniqueidentifier", false, null),
            C("CertificateObjectId", "uniqueidentifier", false, null),
            C("BeforeEnvelopeJson", "nvarchar", false, null),
            C("StageBindingsJson", "nvarchar", false, null),
            C("RetentionDays", "int", false, null),
            C("DevelopmentWriteOnce", "bit", false, null),
            C("PreparedAt", "datetimeoffset", false, null),
            C("RecipeSha256", "varbinary", false, 32),
            C("RowVersion", "timestamp", false, 8)),
        S(14, "CompletionPublicationResults", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("EnvelopeId", "uniqueidentifier", false, null),
            C("IntentId", "uniqueidentifier", false, null),
            C("FinalDocumentsJson", "nvarchar", false, null),
            C("CompletedAt", "datetimeoffset", false, null),
            C("AfterEnvelopeSha256", "varbinary", false, 32),
            C("IntentRecipeSha256", "varbinary", false, 32),
            C("RecipeSha256", "varbinary", false, 32),
            C("AuditSequence", "bigint", false, null),
            C("RowVersion", "timestamp", false, 8)),
        S(15, "CompletionCandidates", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("EnvelopeId", "uniqueidentifier", false, null),
            C("FinishId", "uniqueidentifier", false, null),
            C("CopyVersion", "int", false, null),
            C("SourceObjectId", "uniqueidentifier", false, null),
            C("SourceSha256", "varbinary", false, 32),
            C("PdfObjectId", "uniqueidentifier", false, null),
            C("PdfLength", "bigint", false, null),
            C("PdfSha256", "varbinary", false, 32),
            C("DocumentPages", "int", false, null),
            C("CertificatePages", "int", false, null),
            C("GeometryJson", "nvarchar", false, null),
            C("EvidenceJson", "nvarchar", false, null),
            C("EvidenceSha256", "varbinary", false, 32),
            C("FrozenStateSha256", "varbinary", false, 32),
            C("AuditSequence", "bigint", false, null),
            C("AuditAnchor", "varbinary", false, 32),
            C("RecipeSha256", "varbinary", false, 32),
            C("RendererVersion", "nvarchar", false, null),
            C("SnapshotVersion", "nvarchar", false, null),
            C("PreparedAt", "datetimeoffset", false, null),
            C("RowVersion", "timestamp", false, 8)),
        S(16, "CompletionSealOutputs", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("EnvelopeId", "uniqueidentifier", false, null),
            C("CandidateId", "uniqueidentifier", false, null),
            C("Kind", "nvarchar", false, null),
            C("SourceObjectId", "uniqueidentifier", false, null),
            C("SourceLength", "bigint", false, null),
            C("SourceSha256", "varbinary", false, 32),
            C("PdfObjectId", "uniqueidentifier", false, null),
            C("PdfLength", "bigint", false, null),
            C("PdfSha256", "varbinary", false, 32),
            C("PageCount", "int", false, null),
            C("EvidenceSha256", "varbinary", false, 32),
            C("CandidateRecipeSha256", "varbinary", false, 32),
            C("ExecutedSha256", "varbinary", true, 32),
            C("MetadataJson", "nvarchar", false, null),
            C("RecipeVersion", "nvarchar", false, null),
            C("RecipeSha256", "varbinary", false, 32),
            C("RowVersion", "timestamp", false, 8)),
        S(17, "AuditEvents", "Id",
            C("Id", "bigint", false, null),
            C("EnvelopeId", "uniqueidentifier", false, null),
            C("Sequence", "bigint", false, null),
            C("At", "datetimeoffset", false, null),
            C("ActorType", "nvarchar", false, null),
            C("ActorId", "uniqueidentifier", true, null),
            C("ActorEmail", "nvarchar", true, null),
            C("Event", "nvarchar", false, null),
            C("Ip", "nvarchar", true, null),
            C("UserAgent", "nvarchar", true, null),
            C("DataJson", "nvarchar", false, null),
            C("PrevHash", "varbinary", true, 32),
            C("Hash", "varbinary", false, 32)),
        S(18, "AuthTokens", "Id",
            C("Id", "uniqueidentifier", false, null),
            C("TokenSha256", "varbinary", false, 32),
            C("Purpose", "nvarchar", false, null),
            C("EnvelopeId", "uniqueidentifier", true, null),
            C("PartyType", "nvarchar", false, null),
            C("PartyId", "uniqueidentifier", true, null),
            C("Email", "nvarchar", false, null),
            C("ExpiresAt", "datetimeoffset", false, null),
            C("UsedAt", "datetimeoffset", true, null),
            C("Ip", "nvarchar", true, null),
            C("RowVersion", "timestamp", false, 8),
            C("DisclosureSha256", "varbinary", true, 32),
            C("DocumentId", "uniqueidentifier", true, null),
            C("DocumentSha256", "varbinary", true, 32),
            C("CompletionPartySha256", "varbinary", true, 32),
            C("CompletionPublicationId", "uniqueidentifier", true, null),
            C("CompletionRecipeSha256", "varbinary", true, 32),
            C("SignerContactRevisionId", "uniqueidentifier", true, null),
            C("EmailPilotLookupRequestId", "uniqueidentifier", true, null)),
        S(19, "Suppressions", "Email",
            C("Email", "nvarchar", false, null),
            C("Reason", "nvarchar", false, null),
            C("CreatedAt", "datetimeoffset", false, null),
            C("RowVersion", "timestamp", false, 8)),
    }.ToImmutableDictionary(x => x.Index);

    public static HostedCloseoutStoredStateSchema Schema(int savedSetIndex) =>
        Schemas.TryGetValue(savedSetIndex, out var schema) ? schema : throw Refused();

    /// <summary>Accepts exact CLR SqlDataReader values; DBNull and null are SQL NULL. No type coercion.</summary>
    public static HostedCloseoutStoredStateSetFingerprint Compute(int savedSetIndex,
        IEnumerable<IReadOnlyList<object?>> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var schema = Schema(savedSetIndex);
        var schemaHash = SchemaHash(schema);
        var encoded = new List<EncodedRow>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        long total = 0;
        foreach (var row in rows)
        {
            if (row is null || row.Count != schema.Columns.Length || encoded.Count >= MaximumRows) throw Refused();
            using var body = Header("row", schemaHash);
            using var key = Header("key", schemaHash);
            body.Integer(row.Count);
            for (var i = 0; i < row.Count; i++)
            {
                var column = schema.Columns[i];
                var value = row[i] is DBNull ? null : row[i];
                var payload = Encode(column, value);
                var tag = Tag(column.SqlType);
                body.Cell(tag, payload);
                if (schema.KeyColumns.Contains(column.Name, StringComparer.Ordinal))
                {
                    if (value is null) throw Refused();
                    key.Cell(tag, payload);
                }
            }
            total = checked(total + body.Length);
            if (total > MaximumEncodedBytes) throw Refused();
            var keyBytes = key.Bytes();
            var order = Convert.ToHexString(keyBytes);
            if (!keys.Add(order)) throw Refused();
            encoded.Add(new EncodedRow(order, Hex(keyBytes), Hex(body.Bytes())));
        }
        encoded.Sort((a, b) => StringComparer.Ordinal.Compare(a.Order, b.Order));
        using var result = Header("set", schemaHash);
        result.Integer(encoded.Count);
        foreach (var row in encoded)
        {
            result.Block(Convert.FromHexString(row.Key));
            result.Block(Convert.FromHexString(row.Sha256));
        }
        return new(schema.Index, schema.Table, Convert.ToHexString(schemaHash), Hex(result.Bytes()),
            encoded.Select(x => new HostedCloseoutStoredStateRowFingerprint(x.Key, x.Sha256)).ToImmutableArray());
    }

    /// <summary>Parses exactly the historical typed reader's one-result-set format, never a whole raw export.</summary>
    public static HostedCloseoutStoredStateSetFingerprint ComputeSaved(JsonElement rawResultSet)
    {
        try
        {
            Properties(rawResultSet, "Index", "Columns", "Rows");
            var index = rawResultSet.GetProperty("Index").GetInt32();
            var schema = Schema(index);
            var columns = rawResultSet.GetProperty("Columns");
            var rows = rawResultSet.GetProperty("Rows");
            if (columns.ValueKind != JsonValueKind.Array || columns.GetArrayLength() != schema.Columns.Length ||
                rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > MaximumRows) throw Refused();
            var ordinal = 0;
            foreach (var column in columns.EnumerateArray())
            {
                Properties(column, "Name", "SqlType");
                var expected = schema.Columns[ordinal++];
                if (column.GetProperty("Name").GetString() != expected.Name ||
                    column.GetProperty("SqlType").GetString() != expected.SqlType) throw Refused();
            }
            return Compute(index, ReadRows());

            IEnumerable<IReadOnlyList<object?>> ReadRows()
            {
                foreach (var row in rows.EnumerateArray())
                {
                    if (row.ValueKind != JsonValueKind.Array || row.GetArrayLength() != schema.Columns.Length) throw Refused();
                    var values = new object?[schema.Columns.Length];
                    var n = 0;
                    foreach (var cell in row.EnumerateArray())
                    {
                        values[n] = SavedValue(schema.Columns[n], cell);
                        n++;
                    }
                    yield return values;
                }
            }
        }
        catch (Exception error) when (error is JsonException or FormatException or InvalidOperationException or
            ArgumentException or OverflowException)
        {
            throw Refused();
        }
    }

    private static object? SavedValue(HostedCloseoutStoredStateColumn column, JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Null) return null;
        switch (column.SqlType)
        {
            case "nvarchar": return value.GetString() ?? throw Refused();
            case "uniqueidentifier":
                var guidText = value.GetString();
                if (!Guid.TryParseExact(guidText, "D", out var guid) || guid.ToString("D") != guidText) throw Refused();
                return guid;
            case "datetimeoffset":
                var dateText = value.GetString();
                if (!DateTimeOffset.TryParseExact(dateText, "O", CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var date) || date.ToString("O", CultureInfo.InvariantCulture) != dateText) throw Refused();
                return date;
            case "varbinary":
            case "timestamp":
                var binaryText = value.GetString() ?? throw Refused();
                if (binaryText.Length > MaximumCellBytes * 2) throw Refused();
                var bytes = Convert.FromBase64String(binaryText);
                if (Convert.ToBase64String(bytes) != binaryText) throw Refused();
                return bytes;
            case "int":
                var integer = value.GetInt32();
                if (integer.ToString(CultureInfo.InvariantCulture) != value.GetRawText()) throw Refused();
                return integer;
            case "bigint":
                var bigInteger = value.GetInt64();
                if (bigInteger.ToString(CultureInfo.InvariantCulture) != value.GetRawText()) throw Refused();
                return bigInteger;
            case "bit": return value.GetBoolean();
            default: throw Refused();
        }
    }

    private static byte[]? Encode(HostedCloseoutStoredStateColumn column, object? value)
    {
        if (value is null)
        {
            if (!column.Nullable) throw Refused();
            return null;
        }
        switch (column.SqlType)
        {
            case "nvarchar" when value is string text:
                try
                {
                    if (Utf8.GetByteCount(text) > MaximumCellBytes) throw Refused();
                    return Utf8.GetBytes(text);
                }
                catch (EncoderFallbackException) { throw Refused(); }
            case "uniqueidentifier" when value is Guid guid: return Utf8.GetBytes(guid.ToString("N"));
            case "datetimeoffset" when value is DateTimeOffset date:
                var clock = new byte[12];
                BinaryPrimitives.WriteInt64BigEndian(clock, date.Ticks);
                BinaryPrimitives.WriteInt32BigEndian(clock.AsSpan(8), checked((int)date.Offset.TotalMinutes));
                return clock;
            case "varbinary" or "timestamp" when value is byte[] binary:
                if (binary.Length != column.ExactBytes || binary.Length > MaximumCellBytes) throw Refused();
                return binary.ToArray();
            case "int" when value is int integer:
                var number = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(number, integer);
                return number;
            case "bigint" when value is long bigInteger:
                var bigNumber = new byte[8];
                BinaryPrimitives.WriteInt64BigEndian(bigNumber, bigInteger);
                return bigNumber;
            case "bit" when value is bool bit: return [(byte)(bit ? 1 : 0)];
            default: throw Refused();
        }
    }

    private static byte[] SchemaHash(HostedCloseoutStoredStateSchema schema)
    {
        using var writer = new Canonical();
        writer.Text(Version);
        writer.Text("schema");
        writer.Integer(schema.Index);
        writer.Text(schema.Table);
        writer.Integer(MaximumRows);
        writer.Integer(MaximumCellBytes);
        writer.Integer(MaximumEncodedBytes);
        writer.Integer(schema.Columns.Length);
        foreach (var column in schema.Columns)
        {
            writer.Text(column.Name);
            writer.Text(column.SqlType);
            writer.Integer(column.Nullable ? 1 : 0);
            writer.Integer(column.ExactBytes ?? -1);
        }
        writer.Integer(schema.KeyColumns.Length);
        foreach (var key in schema.KeyColumns) writer.Text(key);
        return SHA256.HashData(writer.Bytes());
    }

    private static Canonical Header(string purpose, byte[] schemaHash)
    {
        var writer = new Canonical();
        writer.Text(Version);
        writer.Text(purpose);
        writer.Block(schemaHash);
        return writer;
    }

    private static byte Tag(string sqlType) => sqlType switch
    {
        "nvarchar" => 1, "uniqueidentifier" => 2, "datetimeoffset" => 3,
        "varbinary" => 4, "timestamp" => 5, "int" => 6, "bigint" => 7, "bit" => 8,
        _ => throw Refused()
    };
    private static string Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    private static InvalidDataException Refused() => new("Stored-state fingerprint refused.");
    private static HostedCloseoutStoredStateColumn C(string name, string type, bool nullable, int? exactBytes) =>
        new(name, type, nullable, exactBytes);
    private static HostedCloseoutStoredStateSchema S(int index, string table, string key,
        params HostedCloseoutStoredStateColumn[] columns) => new(index, table, columns.ToImmutableArray(), [key]);
    private sealed record EncodedRow(string Order, string Key, string Sha256);

    private static void Properties(JsonElement value, params string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Refused();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name)) throw Refused();
        if (seen.Count != expected.Length) throw Refused();
    }

    // All numbers and lengths are signed big-endian. A cell is type-tag + length (-1 for NULL) + exact bytes.
    // Strings are strict UTF-8 with no Unicode normalization, trimming, case folding or JSON interpretation.
    private sealed class Canonical : IDisposable
    {
        private readonly MemoryStream stream = new();
        public long Length => stream.Length;
        public void Integer(int value)
        {
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(bytes, value);
            Write(bytes);
        }
        public void Text(string value) => Block(Utf8.GetBytes(value));
        public void Block(byte[] value) { Integer(value.Length); Write(value); }
        public void Cell(byte tag, byte[]? payload)
        {
            Span<byte> value = stackalloc byte[1];
            value[0] = tag;
            Write(value);
            if (payload is null) Integer(-1); else Block(payload);
        }
        private void Write(ReadOnlySpan<byte> value)
        {
            if (stream.Length + value.Length > MaximumEncodedBytes) throw Refused();
            stream.Write(value);
        }
        public byte[] Bytes() => stream.ToArray();
        public void Dispose() => stream.Dispose();
    }
}
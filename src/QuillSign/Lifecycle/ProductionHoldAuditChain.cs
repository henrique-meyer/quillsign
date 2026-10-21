using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Lifecycle;

// Structural integrity of the entire retained chain, including the operational
// tail after completion. Event-specific actor roles and reference codecs remain
// separate requirements; a valid hash alone does not verify those semantics.
internal static class ProductionHoldAuditChain
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    internal static void Demand(JsonElement sql)
    {
        try { Verify(sql); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException or OverflowException)
        { throw Invalid(); }
    }

    private static void Verify(JsonElement sql)
    {
        var id = sql.GetProperty("RecordId").GetGuid();
        var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var encoded = sql.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == "AuditEvents").GetProperty("Rows");
        if (id == Guid.Empty || captured.Offset != TimeSpan.Zero || encoded.GetArrayLength() is < 1 or > 4096) throw Invalid();
        // Bound all decoded payloads before materializing any audit entities. The
        // containing SQL envelope has its own authenticated 16 MiB bound as well.
        long bytes = 0;
        foreach (var row in encoded.EnumerateArray())
        {
            var raw = row.GetProperty("DataJson").GetString();
            if (raw is null || raw.Length > 16 * 1024 * 1024 || (bytes += Encoding.UTF8.GetByteCount(raw)) > 16 * 1024 * 1024) throw Invalid();
        }
        var rows = encoded.Deserialize<AuditEvent[]>(Rows) ?? throw Invalid();
        var identities = new HashSet<long>(); byte[]? previous = null; DateTimeOffset? at = null; long sequence = 0;
        // SQL inventory sorts serialized rows, not sequence. Never trust that
        // transport order, nor use the global database identity as a sequence.
        foreach (var row in rows.OrderBy(x => x.Sequence))
        {
            if (row.Id < 1 || !identities.Add(row.Id) || row.EnvelopeId != id || row.Sequence != ++sequence ||
                row.At.Offset != TimeSpan.Zero || row.At == default || row.At > captured || row.At < at || !Enum.IsDefined(row.ActorType) ||
                row.ActorId == Guid.Empty || row.ActorEmail is not null && EmailAddress.Normalize(row.ActorEmail) != row.ActorEmail ||
                row.Event is not { Length: > 0 and <= 512 } || row.Event.Any(char.IsControl) ||
                row.Ip is { Length: > 45 } || row.UserAgent is { Length: > 2048 } ||
                row.Hash is not { Length: 32 } ||
                (previous is null ? row.PrevHash is not null : row.PrevHash is not { Length: 32 } || !CryptographicOperations.FixedTimeEquals(previous, row.PrevHash))) throw Invalid();
            using var data = JsonDocument.Parse(row.DataJson, new() { MaxDepth = 64 });
            if (data.RootElement.ValueKind != JsonValueKind.Object) throw Invalid();
            UniqueProperties(data.RootElement);
            if (!CryptographicOperations.FixedTimeEquals(row.Hash, AuditHash.Compute(row))) throw Invalid();
            previous = row.Hash; at = row.At;
        }
    }

    private static void UniqueProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw Invalid();
                UniqueProperties(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) UniqueProperties(item);
    }
    private static InvalidDataException Invalid() => new("The complete retained audit chain could not be verified.");
}

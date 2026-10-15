using System.Security.Cryptography;
using System.Text.Json;

namespace QuillSign.Data;

public static class AuditHash
{
    // v1: ordinal property ordering, compact UTF-8 JSON, UTC timestamps, and preserved
    // numeric JSON lexemes. Prefix the canonical event with its predecessor's 32 bytes
    // (all zero for the first event). Database-generated Id and Hash are excluded.
    public static byte[] Compute(AuditEvent value)
    {
        using var data = JsonDocument.Parse(value.DataJson);
        var payload = JsonSerializer.SerializeToElement(new
        {
            value.EnvelopeId, value.Sequence,
            At = value.At.ToUniversalTime().ToString("O"),
            ActorType = value.ActorType.ToString(), value.ActorId, value.ActorEmail,
            value.Event, value.Ip, value.UserAgent, Data = data.RootElement
        });
        using var stream = new MemoryStream();
        stream.Write(value.PrevHash ?? new byte[32]);
        using (var writer = new Utf8JsonWriter(stream)) WriteCanonical(writer, payload);
        return SHA256.HashData(stream.ToArray());
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            writer.WriteStartObject();
            foreach (var property in value.EnumerateObject().OrderBy(x => x.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(property.Name);
                WriteCanonical(writer, property.Value);
            }
            writer.WriteEndObject();
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            writer.WriteStartArray();
            foreach (var element in value.EnumerateArray()) WriteCanonical(writer, element);
            writer.WriteEndArray();
        }
        else value.WriteTo(writer);
    }
}

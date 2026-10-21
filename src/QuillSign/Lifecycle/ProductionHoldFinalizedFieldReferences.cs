using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Lifecycle;

// The Send producer has used this same three-property proof since its first
// version. This binds its field snapshot, not the complete Send/acceptance graph.
internal static class ProductionHoldFinalizedFieldReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly JsonSerializerOptions Strict = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 4 };
    private sealed record Evidence(string fieldSnapshotSha256, int fieldCount, string documentSha256);

    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IReadOnlyList<FieldInput> prepared)
    {
        try { Verify(sql, objects, prepared); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException)
        { throw Invalid(); }
    }

    private static void Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IReadOnlyList<FieldInput> prepared)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        if (tables["AuditEvents"].GetArrayLength() > 4096 || tables["Fields"].GetArrayLength() > 200 || prepared.Count > 200) throw Invalid();
        var e = tables["Envelopes"].EnumerateArray().Single().Deserialize<Envelope>(Rows) ?? throw Invalid();
        var selected = tables["AuditEvents"].EnumerateArray().Where(x => x.GetProperty("Event").GetString() is "fields_finalized" or "sent").ToArray();
        if (selected.Length == 0)
        {
            if (e.SentAt is not null || e.SentPdfBlob is not null || e.SentPdfSha256 is not null) throw Invalid();
            return;
        }
        if (selected.Length != 2 || e.Id != sql.GetProperty("RecordId").GetGuid() || e.Id == Guid.Empty || e.Status == EnvelopeStatus.Draft ||
            e.SenderVerifiedAt is null || e.SentAt is null || e.SentAt < e.SenderVerifiedAt || e.ExclusionsAckAt != e.SentAt ||
            e.SentPdfSha256 is not { Length: 32 } || e.PdfSha256 is not { Length: 32 }) throw Invalid();
        var events = selected.Select(x => x.Deserialize<AuditEvent>(Rows) ?? throw Invalid()).ToArray();
        var finalized = events.Single(x => x.Event == "fields_finalized"); var sent = events.Single(x => x.Event == "sent");
        var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        foreach (var row in events)
            if (row.EnvelopeId != e.Id || row.ActorType != PartyType.Sender || row.ActorId is not null || row.ActorEmail != e.SenderEmail ||
                row.At.Offset != TimeSpan.Zero || row.At < e.SentAt || row.At > captured || row.Sequence < 1 || row.Hash is not { Length: 32 } ||
                !CryptographicOperations.FixedTimeEquals(row.Hash, AuditHash.Compute(row))) throw Invalid();
        if (finalized.Sequence != sent.Sequence - 1 || finalized.At > sent.At || sent.PrevHash is not { Length: 32 } ||
            !CryptographicOperations.FixedTimeEquals(finalized.Hash, sent.PrevHash) || finalized.DataJson.Length > 512) throw Invalid();
        var proof = JsonSerializer.Deserialize<Evidence>(finalized.DataJson, Strict) ?? throw Invalid();
        if (JsonSerializer.Serialize(proof) != finalized.DataJson) throw Invalid();
        var fields = tables["Fields"].Deserialize<DocumentField[]>(Rows) ?? throw Invalid();
        if (fields.Length != prepared.Count || fields.Select(x => x.Id).Distinct().Count() != fields.Length || prepared.Select(x => x.Id).Distinct().Count() != prepared.Count) throw Invalid();
        foreach (var field in fields)
        {
            var old = prepared.Single(x => x.Id == field.Id);
            if (field.EnvelopeId != e.Id || field.Id == Guid.Empty || !Enum.IsDefined(field.Type) ||
                old != new FieldInput(field.Id, field.SignerId, field.Type.ToString(), field.Page, field.X, field.Y, field.Width, field.Height,
                    field.Required, field.Label, field.SignerId is null ? field.Value : old.Value) || field.SignerId is not null && old.Value is not null) throw Invalid();
        }
        // Send reads decimal(10,8) from SQL. Use that retained numeric scale and
        // SQL uniqueidentifier ordering, not JSON's earlier fields_saved scale or
        // Guid.CompareTo. Preserve the producer's numeric enum representation.
        var snapshot = JsonSerializer.SerializeToUtf8Bytes(fields.OrderBy(x => new SqlGuid(x.Id)).Select(x => new {
            x.Id, x.SignerId, x.Type, x.Page, x.X, x.Y, x.Width, x.Height, x.Required, x.Label,
            Value = prepared.Single(f => f.Id == x.Id).Value
        }));
        if (proof.fieldCount != fields.Length || proof.fieldSnapshotSha256 != Convert.ToHexStringLower(SHA256.HashData(snapshot)) ||
            proof.documentSha256 != Convert.ToHexStringLower(e.SentPdfSha256)) throw Invalid();
        Match(e.PdfBlob, e.PdfSha256); Match(e.SentPdfBlob, e.SentPdfSha256);

        void Match(string? raw, byte[] hash)
        {
            if (!Guid.TryParseExact(raw, "N", out var id) || id == Guid.Empty || !objects.Any(x => x.Address.Area == "normalized" &&
                x.Address.Name == $"{e.Id:N}/{id:N}" && x.Address.Length > 0 && x.Sha256 == Convert.ToHexStringLower(hash))) throw Invalid();
        }
    }
    private static InvalidDataException Invalid() => new("The historical finalized-field evidence could not be verified.");
}

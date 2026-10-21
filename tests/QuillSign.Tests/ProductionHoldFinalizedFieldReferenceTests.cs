using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldFinalizedFieldReferenceTests
{
    [Fact]
    public void Original_snapshot_uses_SQL_order_numeric_enums_and_saved_decimal_scale_despite_later_signing()
    {
        var f = new Frame();
        Assert.NotEqual(f.Fields.OrderBy(x => x.Id).First().Id, f.Fields.OrderBy(x => new SqlGuid(x.Id)).First().Id);
        f.Fields[0].Value = Guid.NewGuid().ToString("N"); // A later assigned signature is not the frozen value.
        using var sql = f.Sql(); f.Demand(sql);
        using var reordered = f.Sql(reverse: true); f.Demand(reordered);
    }

    [Fact]
    public void An_unsent_draft_requires_no_finalized_snapshot_and_empty_snapshot_is_valid()
    {
        var f = new Frame(); f.Audits.Clear(); f.Envelope.SentAt = null; f.Envelope.SentPdfBlob = null; f.Envelope.SentPdfSha256 = null;
        using (var sql = f.Sql()) f.Demand(sql);
        f = new Frame(); f.Fields.Clear(); f.Prepared = []; f.Freeze(); using var empty = f.Sql(); f.Demand(empty);
    }

    [Theory]
    [InlineData("missing-finalized")][InlineData("missing-sent")][InlineData("missing-both")][InlineData("duplicate-finalized")]
    [InlineData("unknown-property")][InlineData("duplicate-property")][InlineData("lexical-number")][InlineData("wrong-count")]
    [InlineData("wrong-snapshot")][InlineData("wrong-document")][InlineData("uppercase-digest")][InlineData("foreign-record")]
    [InlineData("actor-mailbox")][InlineData("actor-type")][InlineData("actor-id")][InlineData("unverified-sender")]
    [InlineData("before-send")][InlineData("after-capture")][InlineData("non-UTC")][InlineData("sequence-gap")]
    [InlineData("reversed-time")][InlineData("wrong-predecessor")][InlineData("wrong-audit-hash")][InlineData("no-ack")]
    [InlineData("draft")][InlineData("missing-source")][InlineData("missing-sent-bytes")][InlineData("foreign-bytes")]
    [InlineData("wrong-byte-hash")][InlineData("empty-bytes")][InlineData("altered-preparation")][InlineData("assigned-prefill")]
    [InlineData("generic-text-changed")][InlineData("foreign-field")][InlineData("duplicate-field")][InlineData("missing-field")]
    [InlineData("field-bound")][InlineData("unknown-type")][InlineData("GUID-order")][InlineData("decimal-scale")]
    public void Rehashed_inconsistent_or_unknown_finalization_is_rejected(string fault)
    {
        var f = new Frame();
        switch (fault)
        {
            case "missing-finalized": f.Audits.RemoveAt(0); break;
            case "missing-sent": f.Audits.RemoveAt(1); break;
            case "missing-both": f.Audits.Clear(); break;
            case "duplicate-finalized": f.Audits.Add(f.Audits[0]); break;
            case "unknown-property": f.Edit(x => x["hiddenObject"] = Guid.NewGuid()); break;
            case "duplicate-property": f.Audits[0].DataJson = f.Audits[0].DataJson[..^1] + ",\"fieldCount\":2}"; break;
            case "lexical-number": f.Audits[0].DataJson = f.Audits[0].DataJson.Replace("\"fieldCount\":2", "\"fieldCount\":2e0"); break;
            case "wrong-count": f.Edit(x => x["fieldCount"] = 1); break;
            case "wrong-snapshot": f.Edit(x => x["fieldSnapshotSha256"] = new string('a', 64)); break;
            case "wrong-document": f.Edit(x => x["documentSha256"] = new string('b', 64)); break;
            case "uppercase-digest": f.Edit(x => x["fieldSnapshotSha256"] = x["fieldSnapshotSha256"]!.GetValue<string>().ToUpperInvariant()); break;
            case "foreign-record": f.Audits[0].EnvelopeId = Guid.NewGuid(); break;
            case "actor-mailbox": f.Audits[0].ActorEmail = "other@example.invalid"; break;
            case "actor-type": f.Audits[0].ActorType = PartyType.Signer; break;
            case "actor-id": f.Audits[0].ActorId = Guid.NewGuid(); break;
            case "unverified-sender": f.Envelope.SenderVerifiedAt = null; break;
            case "before-send": f.Audits[0].At = f.Envelope.SentAt!.Value.AddTicks(-1); break;
            case "after-capture": f.Audits[1].At = f.Captured.AddSeconds(1); break;
            case "non-UTC": f.Audits[0].At = f.Audits[0].At.ToOffset(TimeSpan.FromHours(1)); break;
            case "sequence-gap": f.Audits[1].Sequence++; break;
            case "reversed-time": f.Audits[0].At = f.Audits[1].At.AddTicks(1); break;
            case "wrong-predecessor": break;
            case "wrong-audit-hash": break;
            case "no-ack": f.Envelope.ExclusionsAckAt = null; break;
            case "draft": f.Envelope.Status = EnvelopeStatus.Draft; break;
            case "missing-source": f.Objects.RemoveAt(0); break;
            case "missing-sent-bytes": f.Objects.RemoveAt(1); break;
            case "foreign-bytes": f.Objects[1] = f.Objects[1] with { Address = f.Objects[1].Address with { Name = $"{Guid.NewGuid():N}/{f.Envelope.SentPdfBlob}" } }; break;
            case "wrong-byte-hash": f.Objects[1] = f.Objects[1] with { Sha256 = new string('c', 64) }; break;
            case "empty-bytes": f.Objects[1] = f.Objects[1] with { Address = f.Objects[1].Address with { Length = 0 } }; break;
            case "altered-preparation": f.Prepared[0] = f.Prepared[0] with { X = .2m }; break;
            case "assigned-prefill": f.Prepared[0] = f.Prepared[0] with { Value = "fabricated" }; break;
            case "generic-text-changed": f.Fields[1].Value = "changed"; break;
            case "foreign-field": f.Fields[0].EnvelopeId = Guid.NewGuid(); break;
            case "duplicate-field": f.Fields.Add(f.Fields[0]); break;
            case "missing-field": f.Fields.RemoveAt(0); break;
            case "field-bound": while (f.Fields.Count < 201) f.Fields.Add(f.Fields[0]); break;
            case "unknown-type": f.Fields[0].Type = (FieldType)999; break;
            case "GUID-order": f.Freeze(orderByGuid: true); break;
            case "decimal-scale": f.Fields[0].X = .100m; break;
        }
        f.Rehash();
        if (fault == "wrong-predecessor") { f.Audits[1].PrevHash = new byte[32]; f.Audits[1].Hash = AuditHash.Compute(f.Audits[1]); }
        if (fault == "wrong-audit-hash") f.Audits[0].Hash = new byte[32];
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    private sealed class Frame
    {
        private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
        public DateTimeOffset Captured = new(2026, 5, 3, 12, 0, 0, TimeSpan.Zero);
        public Envelope Envelope = new() { Id = Guid.NewGuid(), SenderEmail = "sender@example.invalid", Status = EnvelopeStatus.Sent,
            SenderVerifiedAt = new(2026, 5, 1, 0, 0, 0, TimeSpan.Zero), SentAt = new(2026, 5, 2, 0, 0, 0, TimeSpan.Zero),
            ExclusionsAckAt = new(2026, 5, 2, 0, 0, 0, TimeSpan.Zero), PdfBlob = Guid.NewGuid().ToString("N"), PdfSha256 = SHA256.HashData([1]),
            SentPdfBlob = Guid.NewGuid().ToString("N"), SentPdfSha256 = SHA256.HashData([2]) };
        public List<DocumentField> Fields = [];
        public FieldInput[] Prepared = [];
        public List<AuditEvent> Audits = [];
        public List<HoldObjectEvidence> Objects = [];
        public Frame()
        {
            Fields.Add(new() { Id = Guid.Parse("00000001-0000-0000-0000-000000000000"), EnvelopeId = Envelope.Id, SignerId = Guid.NewGuid(),
                Type = FieldType.Signature, Page = 1, X = .10000000m, Y = .20000000m, Width = .30000000m, Height = .10000000m, Required = true });
            Fields.Add(new() { Id = Guid.Parse("00000000-0000-0000-0000-000000000001"), EnvelopeId = Envelope.Id, Type = FieldType.Text,
                Page = 1, X = .10000000m, Y = .40000000m, Width = .30000000m, Height = .10000000m, Label = "Synthetic text", Value = Guid.NewGuid().ToString("N") });
            Prepared = Fields.Select(x => new FieldInput(x.Id, x.SignerId, x.Type.ToString(), x.Page, x.X, x.Y, x.Width, x.Height, x.Required, x.Label, x.Value)).ToArray();
            Audits = [new() { Id = 11, EnvelopeId = Envelope.Id, Sequence = 7, Event = "fields_finalized", ActorType = PartyType.Sender, ActorEmail = Envelope.SenderEmail, At = Envelope.SentAt.Value.AddSeconds(1) },
                new() { Id = 15, EnvelopeId = Envelope.Id, Sequence = 8, Event = "sent", ActorType = PartyType.Sender, ActorEmail = Envelope.SenderEmail, At = Envelope.SentAt.Value.AddSeconds(2), DataJson = "{}" }];
            Objects = [Object(Envelope.PdfBlob!, Envelope.PdfSha256!), Object(Envelope.SentPdfBlob!, Envelope.SentPdfSha256!)]; Freeze();
        }
        private HoldObjectEvidence Object(string id, byte[] hash) => new(new("normalized", $"{Envelope.Id:N}/{id}", "version", "", "\"etag\"", 10), Convert.ToHexStringLower(hash));
        public void Freeze(bool orderByGuid = false)
        {
            var rows = orderByGuid ? Fields.OrderBy(x => x.Id) : Fields.OrderBy(x => new SqlGuid(x.Id));
            var bytes = JsonSerializer.SerializeToUtf8Bytes(rows.Select(x => new { x.Id, x.SignerId, x.Type, x.Page, x.X, x.Y, x.Width, x.Height, x.Required, x.Label, x.Value }));
            Audits[0].DataJson = JsonSerializer.Serialize(new { fieldSnapshotSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)), fieldCount = Fields.Count, documentSha256 = Convert.ToHexStringLower(Envelope.SentPdfSha256!) }); Rehash();
        }
        public void Edit(Action<JsonObject> edit) { var root = JsonNode.Parse(Audits[0].DataJson)!.AsObject(); edit(root); Audits[0].DataJson = root.ToJsonString(new() { WriteIndented = false }); }
        public void Rehash() { if (Audits.Count == 0) return; Audits[0].Hash = AuditHash.Compute(Audits[0]); if (Audits.Count > 1) { Audits[1].PrevHash = Audits[0].Hash; Audits[1].Hash = AuditHash.Compute(Audits[1]); } }
        public JsonDocument Sql(bool reverse = false) => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, CapturedAt = Captured, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "AuditEvents", Rows = reverse ? Audits.AsEnumerable().Reverse().ToArray() : Audits.ToArray() },
            new { Table = "Fields", Rows = Fields.ToArray() }
        } }, Rows));
        public void Demand(JsonDocument sql) => ProductionHoldFinalizedFieldReferences.Demand(sql.RootElement, Objects, Prepared);
    }
}

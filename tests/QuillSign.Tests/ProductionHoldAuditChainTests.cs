using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionHoldAuditChainTests
{
    private readonly Guid id = Guid.NewGuid();
    private readonly DateTimeOffset at = new(2025, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public void Transport_order_and_global_identity_gaps_do_not_change_the_complete_chain()
    {
        var rows = Chain(); using var sql = Sql(rows.Reverse().ToArray());
        ProductionHoldAuditChain.Demand(sql.RootElement);
        Assert.Equal(21, rows[1].Id - rows[0].Id);
        Assert.NotEqual(rows[0].Id, rows[0].Sequence);
    }

    [Theory]
    [InlineData("missing-first")][InlineData("missing-middle")][InlineData("duplicate-sequence")][InlineData("duplicate-id")]
    [InlineData("zero-id")][InlineData("foreign-owner")][InlineData("missing-predecessor")][InlineData("foreign-predecessor")]
    [InlineData("first-predecessor")][InlineData("changed-hash")][InlineData("short-hash")][InlineData("undefined-actor")]
    [InlineData("empty-actor-id")][InlineData("noncanonical-mailbox")][InlineData("invalid-mailbox")]
    [InlineData("future")][InlineData("non-utc")][InlineData("backwards")][InlineData("zero-time")]
    [InlineData("empty-event")][InlineData("event-limit")][InlineData("event-control")][InlineData("ip-limit")][InlineData("ua-limit")]
    public void Missing_tampered_or_rehashed_structurally_invalid_chain_is_rejected(string fault)
    {
        var rows = Chain().ToList(); var rehash = true;
        switch (fault)
        {
            case "missing-first": rows.RemoveAt(0); rehash = false; break;
            case "missing-middle": rows.RemoveAt(1); rehash = false; break;
            case "duplicate-sequence": rows[1].Sequence = 1; break;
            case "duplicate-id": rows[1].Id = rows[0].Id; break;
            case "zero-id": rows[1].Id = 0; break;
            case "foreign-owner": rows[1].EnvelopeId = Guid.NewGuid(); break;
            case "missing-predecessor": rows[1].PrevHash = null; rehash = false; break;
            case "foreign-predecessor": rows[1].PrevHash = new byte[32]; rehash = false; break;
            case "first-predecessor": rows[0].PrevHash = new byte[32]; rehash = false; break;
            case "changed-hash": rows[1].Hash = new byte[32]; rehash = false; break;
            case "short-hash": rows[1].Hash = [1]; rehash = false; break;
            case "undefined-actor": rows[1].ActorType = (PartyType)99; break;
            case "empty-actor-id": rows[1].ActorId = Guid.Empty; break;
            case "noncanonical-mailbox": rows[1].ActorEmail = "Sender@example.invalid"; break;
            case "invalid-mailbox": rows[1].ActorEmail = "not a mailbox"; break;
            case "future": rows[2].At = at.AddMinutes(2); break;
            case "non-utc": rows[1].At = at.ToOffset(TimeSpan.FromHours(-4)); break;
            case "backwards": rows[1].At = at.AddSeconds(-1); break;
            case "zero-time": rows[0].At = default; break;
            case "empty-event": rows[1].Event = ""; break;
            case "event-limit": rows[1].Event = new('e', 513); break;
            case "event-control": rows[1].Event = "bad\nevent"; break;
            case "ip-limit": rows[1].Ip = new('i', 46); break;
            case "ua-limit": rows[1].UserAgent = new('u', 2049); break;
        }
        if (rehash) Rehash(rows);
        using var sql = Sql(rows); Assert.Throws<InvalidDataException>(() => ProductionHoldAuditChain.Demand(sql.RootElement));
    }

    [Theory]
    [InlineData("{\"same\":1,\"same\":2}")]
    [InlineData("{\"nested\":[{\"x\":1,\"x\":2}]}")]
    [InlineData("{\"nested\":{\"a\":{},\"\\u0061\":{}}}")]
    [InlineData("[]")][InlineData("null")][InlineData("17")]
    public void Even_correctly_hashed_duplicate_or_nonobject_payloads_are_ambiguous(string json)
    {
        var rows = Chain(); rows[1].DataJson = json; Rehash(rows);
        using var sql = Sql(rows); Assert.Throws<InvalidDataException>(() => ProductionHoldAuditChain.Demand(sql.RootElement));
    }

    [Fact]
    public void Legacy_json_property_order_numbers_and_whitespace_are_preserved()
    {
        var rows = Chain(); const string raw = "{ \"z\": 1e2, \"A\": [{\"a\":1,\"A\":2}], \"n\": -0.00 }";
        rows[1].DataJson = raw; Rehash(rows); using var sql = Sql(rows);
        ProductionHoldAuditChain.Demand(sql.RootElement); Assert.Equal(raw, rows[1].DataJson);
    }

    [Fact]
    public void Empty_or_excessive_chain_and_payload_allocation_are_bounded()
    {
        using var empty = Sql([]); Assert.Throws<InvalidDataException>(() => ProductionHoldAuditChain.Demand(empty.RootElement));
        using var excess = Sql(Enumerable.Repeat(Chain()[0], 4097));
        Assert.Throws<InvalidDataException>(() => ProductionHoldAuditChain.Demand(excess.RootElement));
        var rows = Chain(); rows[0].DataJson = new('x', 16 * 1024 * 1024 + 1);
        using var oversized = Sql(rows); Assert.Throws<InvalidDataException>(() => ProductionHoldAuditChain.Demand(oversized.RootElement));
        rows[0].DataJson = new('界', 6 * 1024 * 1024);
        using var encoded = Sql(rows); Assert.Throws<InvalidDataException>(() => ProductionHoldAuditChain.Demand(encoded.RootElement));
    }

    [Theory]
    [InlineData("future-owned-template")][InlineData("document-lookup")][InlineData("pilot-ses-simulator-v1")]
    [InlineData("SIGNER-INVITATION")][InlineData("")]
    public void Unknown_owned_templates_and_global_templates_misclassified_as_owned_are_rejected(string template)
    {
        using var sql = Sql(Chain(), [new() { EnvelopeId = id, Template = template }]);
        Assert.Throws<InvalidDataException>(() => ProductionHoldNotificationReferences.Demand(sql.RootElement, [], new EphemeralDataProtectionProvider()));
    }

    [Theory]
    [InlineData("foreign")][InlineData("null")][InlineData("empty-id")][InlineData("duplicate")]
    public void Template_registry_rejects_foreign_or_ambiguous_mail_before_payload_read(string fault)
    {
        var mail = new EmailOutbox { EnvelopeId = fault == "foreign" ? Guid.NewGuid() : fault == "null" ? null : id, Template = "sender-verification" };
        if (fault == "empty-id") mail.Id = Guid.Empty;
        using var sql = Sql(Chain(), fault == "duplicate" ? [mail, mail] : [mail]);
        Assert.Throws<InvalidDataException>(() => ProductionHoldNotificationReferences.Demand(sql.RootElement, [], new EphemeralDataProtectionProvider()));
    }

    private AuditEvent[] Chain()
    {
        var rows = Enumerable.Range(0, 3).Select(n => new AuditEvent { Id = 100 + 21 * n, EnvelopeId = id, Sequence = n + 1,
            At = at.AddSeconds(n), ActorType = PartyType.Sender, ActorEmail = "sender@example.invalid", Event = "draft_created" }).ToArray();
        Rehash(rows); return rows;
    }
    private static void Rehash(IReadOnlyList<AuditEvent> rows)
    {
        byte[]? previous = null;
        foreach (var row in rows) { row.PrevHash = previous; row.Hash = AuditHash.Compute(row); previous = row.Hash; }
    }
    private JsonDocument Sql(IEnumerable<AuditEvent> audits, EmailOutbox[]? mail = null) => JsonDocument.Parse(JsonSerializer.Serialize(new
    {
        RecordId = id, CapturedAt = at.AddMinutes(1), Tables = new object[] {
            new { Table = "AuditEvents", Rows = audits }, new { Table = "EmailOutbox", Rows = mail ?? [] } }
    }, Json));
}

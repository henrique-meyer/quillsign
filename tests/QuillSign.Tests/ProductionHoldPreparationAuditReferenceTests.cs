using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldPreparationAuditReferenceTests
{
    [Fact]
    public void Removed_parties_and_assigned_fields_bind_the_then_current_roster_and_generic_UUID_text_stays_text()
    {
        var f = new Frame(); using var sql = f.Sql(); f.Demand(sql);
        Assert.DoesNotContain(f.Signers, x => x.Id == f.Removed); Assert.Single(f.Fields); Assert.True(Guid.TryParse(f.Fields[0].Value, out _));
        Assert.DoesNotContain(f.Recipients, x => x.Name == "Removed recipient");
    }

    [Theory]
    [InlineData("owner")][InlineData("actor")][InlineData("role")][InlineData("actor-id")][InlineData("unconfirmed")][InlineData("late-preview")]
    [InlineData("late-preparation")][InlineData("hidden")][InlineData("nested-hidden")][InlineData("missing-roster")][InlineData("selected")]
    [InlineData("added-changes-other")][InlineData("removed-has-fields")][InlineData("reorder-not-adjacent")][InlineData("duplicate-mailbox")]
    [InlineData("signer-name")][InlineData("signer-role")][InlineData("recipient-name")][InlineData("recipient-selected")]
    [InlineData("recipient-unknown")][InlineData("current-signers")][InlineData("current-recipients")][InlineData("current-fields")]
    [InlineData("foreign-current")][InlineData("field-owner")][InlineData("field-source")][InlineData("field-type")][InlineData("field-page")]
    [InlineData("field-geometry")][InlineData("field-precision")][InlineData("assigned-value")][InlineData("field-label")][InlineData("checkbox")][InlineData("date")]
    [InlineData("current-message")][InlineData("current-title")][InlineData("details-control")]
    public void Rehashed_unknown_or_inconsistent_preparation_history_is_rejected(string fault)
    {
        var f = new Frame();
        switch (fault)
        {
            case "owner": f.Audits[0].EnvelopeId = Guid.NewGuid(); break;
            case "actor": f.Audits[0].ActorEmail = "other@example.invalid"; break;
            case "role": f.Audits[0].ActorType = PartyType.Signer; break;
            case "actor-id": f.Audits[0].ActorId = Guid.NewGuid(); break;
            case "unconfirmed": f.Documents[0] = f.Documents[0] with { PreviewSequence = null }; break;
            case "late-preview": f.Documents[0] = f.Documents[0] with { PreviewSequence = 999 }; break;
            case "late-preparation": f.Sent(4); break;
            case "hidden": f.Edit(0, x => x["newObject"] = Guid.NewGuid().ToString("N")); break;
            case "nested-hidden": f.Edit(0, x => x["signers"]![0]!["newObject"] = Guid.NewGuid().ToString("N")); break;
            case "missing-roster": f.Audits.RemoveAt(0); break;
            case "selected": f.Edit(0, x => x["signerId"] = Guid.NewGuid()); break;
            case "added-changes-other": f.Edit(1, x => x["signers"]![0]!["FullName"] = "Changed other signer"); break;
            case "removed-has-fields": f.Audits.RemoveAt(3); break;
            case "reorder-not-adjacent": f.Edit(8, x => { var items = x["signers"]!.AsArray(); var a = items[0]!.DeepClone(); var b = items[2]!.DeepClone(); a["Order"] = 3; b["Order"] = 1; items[0] = b; items[2] = a; }); break;
            case "duplicate-mailbox": f.Edit(1, x => x["signers"]![1]!["Email"] = x["signers"]![0]!["Email"]!.DeepClone()); break;
            case "signer-name": f.Edit(0, x => x["signers"]![0]!["FullName"] = " untrimmed "); break;
            case "signer-role": f.Edit(0, x => x["signers"]![0]!["Role"] = " "); break;
            case "recipient-name": f.Edit(9, x => x["recipients"]![0]!["Name"] = "bad\nname"); break;
            case "recipient-selected": f.Edit(9, x => x["recipientId"] = Guid.NewGuid()); break;
            case "recipient-unknown": f.Edit(9, x => x["recipients"]![0]!["Hidden"] = "not covered"); break;
            case "current-signers": f.Signers.RemoveAt(0); break;
            case "current-recipients": f.Recipients.Clear(); break;
            case "current-fields": f.Fields.Clear(); break;
            case "foreign-current": f.ForeignCurrent = true; break;
            case "field-owner": f.Edit(2, x => x["fields"]![0]!["SignerId"] = Guid.NewGuid()); break;
            case "field-source": f.Edit(2, x => x["documentId"] = Guid.NewGuid().ToString("N")); break;
            case "field-type": f.Edit(2, x => x["fields"]![1]!["Type"] = "FutureMark"); break;
            case "field-page": f.Edit(2, x => x["fields"]![0]!["Page"] = 3); break;
            case "field-geometry": f.Edit(2, x => x["fields"]![0]!["Width"] = 2); break;
            case "field-precision": f.Edit(2, x => x["fields"]![0]!["X"] = .123456789m); break;
            case "assigned-value": f.Edit(2, x => x["fields"]![0]!["Value"] = "sender prefilled signer"); break;
            case "field-label": f.Edit(2, x => x["fields"]![0]!["Label"] = " "); break;
            case "checkbox": f.Edit(2, x => x["fields"]![1]!["Type"] = "Checkbox"); break;
            case "date": f.Edit(2, x => { x["fields"]![1]!["Type"] = "Date"; x["fields"]![1]!["Value"] = "2025-02-29"; }); break;
            case "current-message": f.Envelope.Message = "changed"; break;
            case "current-title": f.Envelope.Title = "changed"; break;
            case "details-control": f.Edit(13, x => x["title"] = "bad\nname"); break;
        }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Theory]
    [InlineData("signers", 101)][InlineData("recipients", 101)][InlineData("fields", 201)]
    public void Arrays_are_bounded_before_materializing_empty_entities(string property, int count)
    {
        var f = new Frame(); var index = property == "signers" ? 0 : property == "recipients" ? 9 : 2;
        f.Edit(index, x => x[property] = new JsonArray(Enumerable.Range(0, count).Select(_ => (JsonNode)new JsonObject()).ToArray()));
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Fact]
    public void Full_supported_Unicode_field_payload_and_explicit_empty_field_save_remain_readable()
    {
        var f = new Frame(); f.Fields = Enumerable.Range(0, 200).Select(_ => new FieldInput(Guid.NewGuid(), null, "Text", 1, .1m, .1m, .2m, .1m, false, new('界', 512), new('界', 4000))).ToList();
        f.Add("fields_saved", new { documentId = f.Documents[0].ObjectId.ToString("N"), fields = f.Fields }); f.Rehash();
        using (var sql = f.Sql()) f.Demand(sql);
        f.Fields.Clear(); f.Add("fields_saved", new { documentId = f.Documents[0].ObjectId.ToString("N"), fields = f.Fields }); f.Rehash();
        using var empty = f.Sql(); f.Demand(empty);
    }

    [Fact]
    public void Post_send_mailbox_projection_uses_saved_contact_history_without_renewing_expired_authority()
    {
        var f = new Frame(); f.Correct(); using var sql = f.Sql(); f.Demand(sql);
        Assert.True(f.Revisions[0].ChangedAt.AddMinutes(10) < DateTimeOffset.UtcNow);
        f.Revisions.Clear(); using var omitted = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(omitted));
    }

    [Fact]
    public void A_later_uploaded_document_clears_old_field_state_without_erasing_historical_fields()
    {
        var f = new Frame(); var previous = f.Fields[0];
        f.Documents = [.. f.Documents, new(100, Guid.NewGuid(), new('b', 64), 1, 101)];
        f.Fields.Clear(); f.Envelope.Title = "replacement.pdf";
        using (var cleared = f.Sql()) f.Demand(cleared);
        f.Fields.Add(previous); using var resurrected = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(resurrected));
    }

    private sealed class Frame
    {
        internal Envelope Envelope = new() { SenderEmail = "sender@example.invalid", CreatedAt = DateTimeOffset.Parse("2025-01-01T00:00:00Z"), SenderVerifiedAt = DateTimeOffset.Parse("2025-01-01T00:00:00Z"), Title = "Prepared", Message = "Synthetic message" };
        internal List<AuditEvent> Audits = []; internal List<SignerListItem> Signers = []; internal List<RecipientItem> Recipients = []; internal List<FieldInput> Fields = [];
        internal List<SignerContactRevisionRecord> Revisions = []; internal bool ForeignCurrent;
        private string? correctedEmail; private Guid correctedSigner;
        internal readonly Guid Removed = Guid.NewGuid();
        internal HoldUploadedDocument[] Documents = [new(1, Guid.NewGuid(), new string('a', 64), 2, 2)];
        internal Frame()
        {
            void Roster(string name, Guid selected) => Add(name, new { signerId = (Guid?)selected, signers = Signers });
            var second = Guid.NewGuid(); var third = Guid.NewGuid(); var fourth = Guid.NewGuid();
            Signers.Add(new(Removed, 1, "Removed signer", "removed@example.invalid", null)); Roster("signer_added", Removed);
            Signers.Add(new(second, 2, "Second signer", "second@example.invalid", null)); Roster("signer_added", second);
            Fields = [new(Guid.NewGuid(), Removed, "Signature", 1, .1m, .1m, .2m, .1m, true), new(Guid.NewGuid(), null, "Text", 1, .1m, .2m, .2m, .1m, false, Value: Guid.NewGuid().ToString("N"))];
            Add("fields_saved", new { documentId = Documents[0].ObjectId.ToString("N"), fields = Fields }); Fields.RemoveAt(0);
            Add("fields_saved", new { documentId = Documents[0].ObjectId.ToString("N"), fields = Fields }); Signers.RemoveAt(0); Signers[0] = Signers[0] with { Order = 1 }; Roster("signer_removed", Removed);
            Signers[0] = Signers[0] with { FullName = "Updated second", Email = "updated@example.invalid" }; Roster("signer_updated", second);
            Signers.Add(new(third, 2, "Third signer", "third@example.invalid", null)); Roster("signer_added", third);
            Signers.Add(new(fourth, 3, "Fourth signer", "fourth@example.invalid", null)); Roster("signer_added", fourth);
            (Signers[0], Signers[1]) = (Signers[1] with { Order = 1 }, Signers[0] with { Order = 2 }); Roster("signers_reordered", third);
            var removedRecipient = Guid.NewGuid(); Recipients.Add(new(removedRecipient, "Removed recipient", "removed-recipient@example.invalid")); Add("recipient_added", new { recipientId = removedRecipient, recipients = Recipients });
            Recipients[0] = Recipients[0] with { Email = "updated-recipient@example.invalid" }; Add("recipient_updated", new { recipientId = removedRecipient, recipients = Recipients });
            var recipient = Guid.NewGuid(); Recipients.Add(new(recipient, "Current recipient", "recipient@example.invalid")); Add("recipient_added", new { recipientId = recipient, recipients = Recipients });
            Recipients.RemoveAt(0); Add("recipient_removed", new { recipientId = removedRecipient, recipients = Recipients });
            Add("envelope_details_updated", new { title = Envelope.Title, message = Envelope.Message }); Rehash();
        }
        internal void Add(string name, object data) => Audits.Add(new() { Id = 100 + Audits.Count, EnvelopeId = Envelope.Id, Sequence = Audits.Count + 3, At = Envelope.SenderVerifiedAt!.Value.AddSeconds(Audits.Count + 3),
            ActorEmail = Envelope.SenderEmail, Event = name, DataJson = JsonSerializer.Serialize(data) });
        internal void Edit(int n, Action<JsonObject> change) { var json = JsonNode.Parse(Audits[n].DataJson)!.AsObject(); change(json); Audits[n].DataJson = json.ToJsonString(); }
        internal void Sent(long sequence) { Envelope.Status = EnvelopeStatus.Sent; Envelope.SentAt = Envelope.SenderVerifiedAt; Audits.Add(new() { EnvelopeId = Envelope.Id, Sequence = sequence, Event = "sent", At = Envelope.SenderVerifiedAt!.Value }); }
        internal void Correct()
        {
            Add("sent", new { }); Envelope.SentAt = Audits[^1].At; Envelope.Status = EnvelopeStatus.Sent;
            var party = Signers[0]; correctedSigner = party.Id; correctedEmail = "corrected@example.invalid";
            var at = Audits[^1].At.AddSeconds(1); var revision = new SignerContactRevision(SignerContactHistory.Version, Guid.NewGuid(), Envelope.Id, party.Id, Guid.Empty, 1, party.Email, correctedEmail,
                at, at.AddMinutes(5), Convert.ToBase64String(new byte[8]), Convert.ToBase64String(new byte[8]), Documents[0].ObjectId, Documents[0].Sha256, new('b', 64), new('c', 64), null,
                SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
            Add(SignerContactHistory.Event, new { }); Audits[^1].DataJson = SignerContactHistory.Canonical(revision);
            Revisions.Add(new() { Id = revision.Id, EnvelopeId = Envelope.Id, SignerId = party.Id, Number = 1, ChangedAt = at, EvidenceJson = Audits[^1].DataJson }); Rehash();
        }
        internal void Rehash() { byte[]? previous = null; for (var n = 0; n < Audits.Count; n++) { var a = Audits[n]; if (a.Event != "sent") a.Sequence = n + 3; a.PrevHash = previous; a.Hash = AuditHash.Compute(a); previous = a.Hash; } }
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, CapturedAt = DateTimeOffset.Parse("2025-02-01T00:00:00Z"), Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "AuditEvents", Rows = Audits }, new { Table = "SignerContactRevisions", Rows = Revisions },
            new { Table = "Signers", Rows = Signers.Select(x => new Signer { Id = x.Id, EnvelopeId = ForeignCurrent ? Guid.NewGuid() : Envelope.Id, Order = x.Order, FullName = x.FullName, Email = x.Id == correctedSigner ? correctedEmail! : x.Email, Role = x.Role }) },
            new { Table = "Recipients", Rows = Recipients.Select(x => new Recipient { Id = x.Id, EnvelopeId = Envelope.Id, Name = x.Name, Email = x.Email }) },
            new { Table = "Fields", Rows = Fields.Select(x => new DocumentField { Id = x.Id, EnvelopeId = Envelope.Id, SignerId = x.SignerId, Type = Enum.Parse<FieldType>(x.Type), Page = x.Page,
                X = x.X, Y = x.Y, Width = x.Width, Height = x.Height, Required = x.Required, Label = x.Label, Value = x.Value, DateFormat = x.Type is "Date" or "DateSigned" ? "yyyy-MM-dd" : null }) }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        internal void Demand(JsonDocument sql) => ProductionHoldPreparationAuditReferences.Demand(sql.RootElement, Documents);
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldFieldAuditReferenceTests
{
    [Fact]
    public void Old_applied_mark_remains_historical_after_replacement_and_UUID_text_is_not_an_asset()
    { var f = new Frame(); using var sql = f.Sql(); f.Demand(sql); Assert.Equal(f.Adoptions[0].Id, f.Fields[0].SignatureAdoptionId); Assert.True(Guid.TryParse(f.Fields[1].Value, out _)); }

    [Theory]
    [InlineData("unknown")][InlineData("missing")][InlineData("actor")][InlineData("role")][InlineData("actor-id")][InlineData("owner")]
    [InlineData("field")][InlineData("type")][InlineData("readonly")][InlineData("source")][InlineData("disclosure")][InlineData("input")]
    [InlineData("old-value")][InlineData("old-adoption")][InlineData("old-hash")][InlineData("value-hash")][InlineData("old-mark-missing")]
    [InlineData("adoption")][InlineData("image")][InlineData("object")][InlineData("future-mark")][InlineData("name")][InlineData("date")]
    [InlineData("checkbox")][InlineData("text-adoption")][InlineData("text-image")][InlineData("normalization")][InlineData("format")]
    [InlineData("clear-value")][InlineData("clear-adoption")][InlineData("clear-image")][InlineData("current-value")][InlineData("current-adoption")]
    [InlineData("current-metadata")][InlineData("filled-by")][InlineData("filled-at")][InlineData("before-fill")][InlineData("omit-fill-time")]
    public void Correctly_rehashed_ambiguous_or_changed_field_history_fails(string fault)
    {
        var f = new Frame();
        switch (fault)
        {
            case "unknown": f.Edit(2, x => x["hiddenObjectId"] = Guid.NewGuid()); break;
            case "missing": f.Edit(2, x => x.Remove("previousImageSha256")); break;
            case "actor": f.Audits[2].ActorEmail = "other@example.invalid"; break;
            case "role": f.Audits[2].ActorType = PartyType.Sender; break;
            case "actor-id": f.Audits[2].ActorId = Guid.NewGuid(); break;
            case "owner": f.Audits[2].EnvelopeId = Guid.NewGuid(); break;
            case "field": f.Edit(2, x => x["fieldId"] = Guid.NewGuid()); break;
            case "type": f.Edit(2, x => x["type"] = "Initials"); break;
            case "readonly": f.Edit(2, x => { x["fieldId"] = f.Fields[5].Id; x["type"] = "DateSigned"; }); break;
            case "source": f.Edit(2, x => x["documentSha256"] = new string('b', 64)); break;
            case "disclosure": f.Edit(2, x => x["disclosureSha256"] = new string('c', 64)); break;
            case "input": f.Edit(2, x => x["input"] = "client_identity"); break;
            case "old-value": f.Edit(8, x => x["previousValue"] = "false"); break;
            case "old-adoption": f.Edit(8, x => x["previousAdoptionId"] = Guid.NewGuid()); break;
            case "old-hash": f.Edit(8, x => x["previousImageSha256"] = new string('a', 64)); break;
            case "value-hash": f.Edit(2, x => x["valueSha256"] = new string('d', 64)); break;
            case "old-mark-missing": f.Objects.RemoveAll(x => x.Address.Name.EndsWith(f.Adoptions[0].SignatureObjectId.ToString("N"))); break;
            case "adoption": f.Edit(2, x => x["adoptionId"] = Guid.NewGuid()); break;
            case "image": f.Edit(2, x => x["imageSha256"] = new string('e', 64)); break;
            case "object": f.EditValue(2, Guid.NewGuid().ToString("N")); break;
            case "future-mark": f.Edit(2, x => x["adoptionId"] = f.Adoptions[1].Id); break;
            case "name": f.EditValue(5, "Arbitrary person"); break;
            case "date": f.EditValue(6, "2025-02-29"); break;
            case "checkbox": f.EditValue(7, "yes"); break;
            case "text-adoption": f.Edit(4, x => x["adoptionId"] = f.Adoptions[0].Id); break;
            case "text-image": f.Edit(4, x => x["imageSha256"] = new string('e', 64)); break;
            case "normalization": f.EditValue(4, "e\u0301"); break;
            case "format": f.EditValue(4, "bad\u200dtext"); break;
            case "clear-value": f.EditValue(8, "false"); break;
            case "clear-adoption": f.Edit(8, x => x["adoptionId"] = f.Adoptions[0].Id); break;
            case "clear-image": f.Edit(8, x => x["imageSha256"] = new string('a', 64)); break;
            case "current-value": f.Fields[0].Value = f.Adoptions[1].SignatureObjectId.ToString("N"); break;
            case "current-adoption": f.Fields[0].SignatureAdoptionId = f.Adoptions[1].Id; break;
            case "current-metadata": f.Fields[0].Page = 2; break;
            case "filled-by": f.Fields[0].FilledBy = PartyType.Sender; break;
            case "filled-at": f.Fields[0].FilledAt = f.Captured; break;
            case "before-fill": f.Fields[0].FilledAt = f.At.AddDays(-1); break;
            case "omit-fill-time": f.Fields[0].FilledAt = null; break;
        }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Fact]
    public void Stale_mark_can_be_cleared_then_deliberately_reapplied_with_the_new_adoption()
    {
        var f = new Frame(); f.Change(f.Fields[0], null); f.ApplyMark(f.Fields[0], f.Adoptions[1]);
        using var sql = f.Sql(); f.Demand(sql);
    }

    [Fact]
    public void Initials_select_the_exact_initials_pair_and_full_length_Unicode_values_keep_both_sides()
    {
        var f = new Frame(); f.Fields[0].Type = FieldType.Initials; f.Definitions[0] = f.Definitions[0] with { Type = "Initials" };
        f.Edit(2, x => { x["type"] = "Initials"; x["value"] = f.Adoptions[0].InitialsObjectId.ToString("N"); x["imageSha256"] = f.Adoptions[0].InitialsSha256;
            x["valueSha256"] = Convert.ToHexStringLower(Frame.Hash(f.Adoptions[0].InitialsObjectId.ToString("N"))); });
        f.Fields[0].Value = f.Adoptions[0].InitialsObjectId.ToString("N"); f.Fields[0].ImageSha256 = Convert.FromHexString(f.Adoptions[0].InitialsSha256);
        f.Change(f.Fields[1], new string('界', 4000)); f.Change(f.Fields[1], new string('語', 4000)); f.Rehash();
        using var sql = f.Sql(); f.Demand(sql);
    }

    [Fact]
    public void Retirement_binds_old_fields_then_resets_before_new_mailbox_entries()
    {
        var f = new Frame(); f.Correct(); using (var cleared = f.Sql()) f.Demand(cleared);
        f.Change(f.Fields[1], "Corrected mailbox text"); using (var applied = f.Sql()) f.Demand(applied);
        var retired = JsonNode.Parse(f.Contacts[0].RetirementJson)!; retired["Fields"]![0]!["Value"] = Guid.NewGuid().ToString("N");
        f.Contacts[0].RetirementJson = retired.ToJsonString(); using var changed = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(changed));
    }

    [Fact]
    public void Accepted_snapshot_binds_editable_state_without_inventing_DateSigned_field_events()
    {
        var f = new Frame(); f.Accept(); using (var accepted = f.Sql()) f.Demand(accepted);
        var fields = JsonSerializer.Deserialize<DocumentField[]>(f.Finishes[0].FieldsJson)!; fields[0].Value = Guid.NewGuid().ToString("N");
        f.Finishes[0].FieldsJson = JsonSerializer.Serialize(fields); f.Finishes[0].FieldsSha256 = Frame.Hash(f.Finishes[0].FieldsJson);
        f.Audits[^1].DataJson = SignerFinish.EvidenceJson(f.Finishes[0]); f.Rehash(); using var changed = f.Sql();
        Assert.Throws<InvalidDataException>(() => f.Demand(changed));
    }

    [Theory]
    [InlineData("e\u0301", "é")][InlineData("a\r\nb\rc", "a\nb\nc")][InlineData("", "")][InlineData("bad\u200dtext", null)]
    public void Historical_text_uses_the_original_pure_producer_canonicalizer(string input, string? expected) => Assert.Equal(expected, SignerFields.Canonical(input));

    [Theory]
    [InlineData("noop")][InlineData("server-date-without-finish")][InlineData("server-date-changed")][InlineData("future-finish-audit")]
    public void Noop_events_and_fabricated_server_dates_are_rejected(string fault)
    {
        var f = new Frame();
        if (fault == "noop") f.Change(f.Fields[1], f.Fields[1].Value);
        else if (fault == "future-finish-audit") { f.Accept(); f.Audits[^1].At = f.Captured.AddSeconds(1); f.Rehash(); }
        else { if (fault == "server-date-changed") f.Accept(); f.Fields[5].Value = "2030-01-01"; }
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    private sealed class Frame
    {
        internal readonly DateTimeOffset At = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), Captured = new(2020, 2, 1, 0, 0, 0, TimeSpan.Zero);
        internal Envelope Envelope; internal Signer Signer; internal List<AuditEvent> Audits = [];
        internal List<HoldObjectEvidence> Objects = []; internal List<HoldAdoptedMark> Adoptions = []; internal List<FieldInput> Definitions = [];
        internal List<DocumentField> Fields = []; internal List<SignerContactRevisionRecord> Contacts = []; internal List<SignerFinishAcceptance> Finishes = [];
        internal Frame()
        {
            var source = Guid.NewGuid(); Envelope = new() { Status = EnvelopeStatus.Sent, SentAt = At, SenderEmail = "sender@example.invalid", SentPdfBlob = source.ToString("N"), SentPdfSha256 = Hash("source"), ErsdSha256 = Hash("disclosure") };
            Signer = new() { EnvelopeId = Envelope.Id, Email = "signer@example.invalid", FullName = "Synthetic signer", RowVersion = new byte[8] };
            Object(source, Convert.ToHexStringLower(Envelope.SentPdfSha256)); Add("sent", "{}", PartyType.Sender, null, Envelope.SenderEmail);
            foreach (var kind in new[] { FieldType.Signature, FieldType.Text, FieldType.FullName, FieldType.Date, FieldType.Checkbox, FieldType.DateSigned })
            {
                var field = new DocumentField { EnvelopeId = Envelope.Id, SignerId = Signer.Id, Type = kind, Page = 1, X = .1m, Y = .1m, Width = .2m, Height = .1m };
                Fields.Add(field); Definitions.Add(new(field.Id, Signer.Id, kind.ToString(), field.Page, field.X, field.Y, field.Width, field.Height, field.Required));
            }
            var old = Adoption(); ApplyMark(Fields[0], old); _ = Adoption();
            Change(Fields[1], Guid.NewGuid().ToString("N")); Change(Fields[2], Signer.FullName); Change(Fields[3], "2020-01-01"); Change(Fields[4], "true"); Change(Fields[4], null); Change(Fields[4], "false");
        }
        internal HoldAdoptedMark Adoption()
        {
            Add("signature_adopted", "{}", PartyType.Signer, Signer.Id, Signer.Email);
            var mark = new HoldAdoptedMark(Audits.Count, Guid.NewGuid(), Signer.Id, Guid.NewGuid(), Guid.NewGuid(), Convert.ToHexStringLower(Hash("signature" + Adoptions.Count)), Convert.ToHexStringLower(Hash("initials" + Adoptions.Count)));
            Adoptions.Add(mark); Object(mark.SignatureObjectId, mark.SignatureSha256); Object(mark.InitialsObjectId, mark.InitialsSha256); return mark;
        }
        internal void ApplyMark(DocumentField field, HoldAdoptedMark mark) => Change(field, mark.SignatureObjectId.ToString("N"), mark.Id, mark.SignatureSha256);
        internal void Change(DocumentField field, string? value, Guid? adoption = null, string? image = null)
        {
            var raw = JsonSerializer.Serialize(new { fieldId = field.Id, type = field.Type.ToString(), previousValue = field.Value, value, previousAdoptionId = field.SignatureAdoptionId,
                adoptionId = adoption, previousImageSha256 = field.ImageSha256 is null ? null : Convert.ToHexStringLower(field.ImageSha256), imageSha256 = image,
                valueSha256 = value is null ? null : Convert.ToHexStringLower(Hash(value)), documentSha256 = Convert.ToHexStringLower(Envelope.SentPdfSha256!), disclosureSha256 = Convert.ToHexStringLower(Envelope.ErsdSha256!),
                input = field.Type == FieldType.FullName ? "server_signer_record" : "explicit_owned_field_request" });
            Add(value is null ? "field_cleared" : "field_filled", raw, PartyType.Signer, Signer.Id, Signer.Email);
            field.Value = value; field.SignatureAdoptionId = adoption; field.ImageSha256 = image is null ? null : Convert.FromHexString(image);
            field.FilledAt = value is null ? null : Audits[^1].At; field.FilledBy = value is null ? null : PartyType.Signer;
        }
        internal void Correct()
        {
            var retirement = SignerContactState.RetirementJson(Signer, Fields); var at = At.AddSeconds(Audits.Count + 1);
            var revision = new SignerContactRevision(SignerContactHistory.Version, Guid.NewGuid(), Envelope.Id, Signer.Id, Guid.Empty, 1, Signer.Email, "corrected@example.invalid", at,
                at.AddMinutes(5), Convert.ToBase64String(new byte[8]), Convert.ToBase64String(Signer.RowVersion), Guid.ParseExact(Envelope.SentPdfBlob!, "N"), Convert.ToHexStringLower(Envelope.SentPdfSha256!),
                Convert.ToHexStringLower(Envelope.ErsdSha256!), SignerContactState.RetirementDigest(retirement), null, SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
            var raw = SignerContactHistory.Canonical(revision); Contacts.Add(new() { Id = revision.Id, EnvelopeId = Envelope.Id, SignerId = Signer.Id, Number = 1, ChangedAt = at, EvidenceJson = raw, RetirementJson = retirement });
            Add(SignerContactHistory.Event, raw, PartyType.Sender, null, Envelope.SenderEmail); Signer.Email = revision.NewEmail;
            foreach (var field in Fields) { field.Value = null; field.SignatureAdoptionId = null; field.ImageSha256 = null; field.FilledAt = null; field.FilledBy = null; }
        }
        internal void Accept()
        {
            var at = At.AddSeconds(Audits.Count + 1); Fields[5].Value = "2020-01-01"; Fields[5].FilledAt = at; Fields[5].FilledBy = PartyType.Signer;
            var finish = new SignerFinishAcceptance { EnvelopeId = Envelope.Id, SignerId = Signer.Id, FinishedAt = at, ProspectiveDate = new(2020, 1, 1), FieldsJson = JsonSerializer.Serialize(Fields) };
            finish.FieldsSha256 = Hash(finish.FieldsJson); Finishes.Add(finish); Add("signer_finish_accepted", SignerFinish.EvidenceJson(finish), PartyType.Signer, Signer.Id, Signer.Email);
        }
        internal void Object(Guid id, string hash) => Objects.Add(new(new("normalized", $"{Envelope.Id:N}/{id:N}", "", "", "\"etag\"", 200), hash));
        internal static byte[] Hash(string text) => SHA256.HashData(Encoding.UTF8.GetBytes(text));
        internal void Add(string name, string data, PartyType type, Guid? actor, string email)
        { Audits.Add(new() { EnvelopeId = Envelope.Id, Event = name, DataJson = data, ActorType = type, ActorId = actor, ActorEmail = email, At = At.AddSeconds(Audits.Count + 1) }); Rehash(); }
        internal void Rehash() { byte[]? previous = null; for (var n = 0; n < Audits.Count; n++) { var a = Audits[n]; a.Sequence = n + 1; a.Id = n + 100; a.PrevHash = previous; a.Hash = AuditHash.Compute(a); previous = a.Hash; } }
        internal void Edit(int n, Action<JsonObject> edit) { var j = JsonNode.Parse(Audits[n].DataJson)!.AsObject(); edit(j); Audits[n].DataJson = j.ToJsonString(); }
        internal void EditValue(int n, string value) => Edit(n, x => { x["value"] = value; x["valueSha256"] = Convert.ToHexStringLower(Hash(value)); });
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, CapturedAt = Captured, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "Signers", Rows = new[] { Signer } }, new { Table = "AuditEvents", Rows = Audits }, new { Table = "Fields", Rows = Fields },
            new { Table = "SignerContactRevisions", Rows = Contacts }, new { Table = "SignerFinishAcceptances", Rows = Finishes }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        internal void Demand(JsonDocument sql) => ProductionHoldFieldAuditReferences.Demand(sql.RootElement, Objects, Definitions, Adoptions);
    }
}

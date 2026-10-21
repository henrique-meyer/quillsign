using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldAdoptionAuditReferenceTests
{
    [Theory]
    [InlineData(SignatureMethod.Typed)][InlineData(SignatureMethod.Drawn)][InlineData(SignatureMethod.Uploaded)]
    public void Expired_replaced_and_current_used_previews_preserve_exact_history_without_renewal(SignatureMethod method)
    {
        var f = new Frame(method); var expiry = f.Previews[0].ExpiresAt;
        using var sql = f.Sql(); f.Demand(sql); Assert.Equal(expiry, f.Previews[0].ExpiresAt);
        Assert.True(expiry < f.Captured); Assert.Equal(2, f.Previews.Count);
    }

    [Theory]
    [InlineData("owner")][InlineData("actor")][InlineData("role")][InlineData("actor-id")][InlineData("unknown")][InlineData("statement")]
    [InlineData("ack")][InlineData("identity")][InlineData("server")][InlineData("previous")][InlineData("preview-missing")][InlineData("audit-missing")]
    [InlineData("unused")][InlineData("double-use")][InlineData("foreign-preview")][InlineData("foreign-signer")][InlineData("source")]
    [InlineData("source-hash")][InlineData("disclosure")][InlineData("signature-hash")][InlineData("initials-hash")][InlineData("signature-object")]
    [InlineData("initials-object")][InlineData("missing-old-mark")][InlineData("changed-old-mark")][InlineData("missing-current-mark")]
    [InlineData("created-after-use")][InlineData("used-at-expiry")][InlineData("used-after-audit")][InlineData("extended-expiry")]
    [InlineData("future-audit")][InlineData("dimensions")][InlineData("normalizer")][InlineData("method")][InlineData("descriptor")]
    [InlineData("session-hash")][InlineData("baseline")][InlineData("current-projection")][InlineData("current-cleared")]
    public void Rehashed_unknown_missing_or_changed_adoption_evidence_fails(string fault)
    {
        var f = new Frame(SignatureMethod.Typed); var p = f.Previews[0];
        switch (fault)
        {
            case "owner": f.Audits[1].EnvelopeId = Guid.NewGuid(); break;
            case "actor": f.Audits[1].ActorEmail = "foreign@example.invalid"; break;
            case "role": f.Audits[1].ActorType = PartyType.Sender; break;
            case "actor-id": f.Audits[1].ActorId = Guid.NewGuid(); break;
            case "unknown": f.Edit(1, x => x["newObjectId"] = Guid.NewGuid()); break;
            case "statement": f.Edit(1, x => x["statement"] = "Different statement"); break;
            case "ack": f.Edit(1, x => x["acknowledged"] = false); break;
            case "identity": f.Edit(1, x => x["identityEvidence"] = "invented"); break;
            case "server": f.Edit(1, x => x["serverEvidence"] = "invented"); break;
            case "previous": f.Edit(2, x => x["replacedAdoptionId"] = null); break;
            case "preview-missing": f.Previews.RemoveAt(0); break;
            case "audit-missing": f.Audits.RemoveAt(1); break;
            case "unused": p.UsedAt = null; break;
            case "double-use": f.Audits.Add(JsonSerializer.Deserialize<AuditEvent>(JsonSerializer.Serialize(f.Audits[1]))!); break;
            case "foreign-preview": p.EnvelopeId = Guid.NewGuid(); break;
            case "foreign-signer": p.SignerId = Guid.NewGuid(); break;
            case "source": p.DocumentId = Guid.NewGuid(); f.Object(p.DocumentId, p.DocumentSha256); break;
            case "source-hash": p.DocumentSha256 = Frame.Hash("changed"); break;
            case "disclosure": p.DisclosureSha256 = Frame.Hash("changed"); break;
            case "signature-hash": p.SignatureSha256 = Frame.Hash("changed"); break;
            case "initials-hash": p.InitialsSha256 = Frame.Hash("changed"); break;
            case "signature-object": f.Edit(1, x => x["signatureObjectId"] = Guid.NewGuid()); break;
            case "initials-object": f.Edit(1, x => x["initialsObjectId"] = Guid.NewGuid()); break;
            case "missing-old-mark": f.Objects.RemoveAll(x => x.Address.Name.EndsWith(p.SignatureObjectId.ToString("N"))); break;
            case "changed-old-mark": f.Objects[1] = f.Objects[1] with { Sha256 = new('c', 64) }; break;
            case "missing-current-mark": f.Objects.RemoveAt(f.Objects.Count - 1); break;
            case "created-after-use": p.CreatedAt = p.UsedAt!.Value.AddSeconds(1); break;
            case "used-at-expiry": p.ExpiresAt = p.UsedAt!.Value; break;
            case "used-after-audit": p.UsedAt = f.Audits[1].At.AddSeconds(1); break;
            case "extended-expiry": p.ExpiresAt = p.CreatedAt.AddMinutes(11); break;
            case "future-audit": f.Audits[1].At = f.Captured.AddSeconds(1); break;
            case "dimensions": p.SignatureWidth = 0; break;
            case "normalizer": p.NormalizationVersion = "future"; break;
            case "method": p.Method = (SignatureMethod)123; break;
            case "descriptor": p.TypedName = "bad\nname"; break;
            case "session-hash": p.SessionSha256 = []; break;
            case "baseline": p.BaselineSignerVersion = []; break;
            case "current-projection": f.Signer.SignatureImageBlob = p.SignatureObjectId.ToString("N"); break;
            case "current-cleared": f.Signer.SignatureAdoptionId = null; break;
        }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Fact]
    public void Exact_contact_retirement_resets_the_chain_and_never_resurrects_prior_marks()
    {
        var f = new Frame(SignatureMethod.Drawn); f.Correct();
        using (var reset = f.Sql()) f.Demand(reset);
        f.Adopt(SignatureMethod.Uploaded); using (var resumed = f.Sql()) f.Demand(resumed);
        f.Revisions.Clear(); using var missing = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(missing));
    }

    [Fact]
    public void Prepared_unused_preview_is_not_an_adoption_and_omitting_all_adoption_audits_is_rejected()
    {
        var f = new Frame(SignatureMethod.Drawn); f.Prepare(SignatureMethod.Uploaded);
        using (var valid = f.Sql()) f.Demand(valid);
        f.Audits.RemoveAll(x => x.Event == "signature_adopted"); f.Clear(); f.Rehash();
        using var omitted = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(omitted));
    }

    [Theory]
    [InlineData("valid")][InlineData("pending")][InlineData("later")][InlineData("foreign")][InlineData("unsigned")]
    public void Later_signer_adoption_requires_its_preceding_processed_checkpoint_not_the_envelope_latest_copy(string fault)
    {
        var f = new Frame(SignatureMethod.Drawn); f.Signer.Order = 2;
        var previous = new Signer { EnvelopeId = f.Envelope.Id, Order = 1, Status = SignerStatus.Signed, SignedAt = f.At.AddSeconds(10) };
        f.Others.Add(previous);
        var finish = new SignerFinishAcceptance { EnvelopeId = f.Envelope.Id, SignerId = previous.Id, PdfObjectId = Guid.NewGuid(), PdfSha256 = Frame.Hash("checkpoint"),
            FinishedAt = previous.SignedAt.Value, ProcessedAt = f.At.AddSeconds(20), DisclosureSha256 = f.Envelope.ErsdSha256! };
        f.Finishes.Add(finish); f.Object(finish.PdfObjectId, finish.PdfSha256);
        for (var n = 0; n < f.Previews.Count; n++)
        { f.Previews[n].DocumentId = finish.PdfObjectId; f.Previews[n].DocumentSha256 = finish.PdfSha256; f.Edit(n + 1, x => x["documentSha256"] = Convert.ToHexStringLower(finish.PdfSha256)); }
        switch (fault)
        {
            case "pending": finish.ProcessedAt = null; break;
            case "later": finish.ProcessedAt = f.Captured; break;
            case "foreign": finish.EnvelopeId = Guid.NewGuid(); break;
            case "unsigned": previous.Status = SignerStatus.Pending; break;
        }
        f.Rehash(); using var sql = f.Sql();
        if (fault == "valid") f.Demand(sql); else Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    private sealed class Frame
    {
        internal readonly DateTimeOffset At = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        internal readonly DateTimeOffset Captured = new(2020, 2, 1, 0, 0, 0, TimeSpan.Zero);
        internal Envelope Envelope; internal Signer Signer;
        internal List<AuditEvent> Audits = []; internal List<SignaturePreview> Previews = []; internal List<HoldObjectEvidence> Objects = [];
        internal List<SignerContactRevisionRecord> Revisions = [];
        internal List<Signer> Others = []; internal List<SignerFinishAcceptance> Finishes = [];
        internal Frame(SignatureMethod method)
        {
            var source = Guid.NewGuid(); Envelope = new() { SentAt = At, SenderEmail = "sender@example.invalid", SentPdfBlob = source.ToString("N"), SentPdfSha256 = Hash("source"), ErsdSha256 = Hash("disclosure") };
            Signer = new() { EnvelopeId = Envelope.Id, Email = "signer@example.invalid", FullName = "Synthetic signer", RowVersion = new byte[8] };
            Object(source, Envelope.SentPdfSha256); Add("sent", "{}", PartyType.Sender, null, Envelope.SenderEmail, At);
            Adopt(method); Adopt(method);
        }
        internal SignaturePreview Prepare(SignatureMethod method)
        {
            var now = At.AddMinutes(Previews.Count + 1); var p = new SignaturePreview { EnvelopeId = Envelope.Id, SignerId = Signer.Id,
                DocumentId = Guid.ParseExact(Envelope.SentPdfBlob!, "N"), DocumentSha256 = Envelope.SentPdfSha256!, DisclosureSha256 = Envelope.ErsdSha256!,
                SignatureObjectId = Guid.NewGuid(), InitialsObjectId = Guid.NewGuid(), SignatureSha256 = Hash("signature" + Previews.Count), InitialsSha256 = Hash("initials" + Previews.Count),
                SessionSha256 = Hash("session"), BaselineSignerVersion = new byte[8], SignatureWidth = 30, SignatureHeight = 20, InitialsWidth = 20, InitialsHeight = 20,
                Method = method, TypedName = method == SignatureMethod.Typed ? "Synthetic signer" : null, TypedInitials = method == SignatureMethod.Typed ? "SS" : null,
                NormalizationVersion = SignaturePng.Version, AdoptionVersion = SignatureAdoptionStatement.Version, CreatedAt = now, ExpiresAt = now.AddMinutes(10) };
            Previews.Add(p); Object(p.SignatureObjectId, p.SignatureSha256); Object(p.InitialsObjectId, p.InitialsSha256); return p;
        }
        internal void Adopt(SignatureMethod method)
        {
            var p = Prepare(method); p.UsedAt = p.CreatedAt.AddSeconds(2); var replaced = Signer.SignatureAdoptionId;
            var raw = JsonSerializer.Serialize(new { adoptionId = p.Id, replacedAdoptionId = replaced, statementVersion = p.AdoptionVersion,
                statement = SignatureAdoptionStatement.Text, statementSha256 = Convert.ToHexStringLower(SignatureAdoptionStatement.Sha256), acknowledged = true,
                method = p.Method.ToString(), reportedTypedName = p.TypedName, reportedTypedInitials = p.TypedInitials, normalizationVersion = p.NormalizationVersion,
                signatureObjectId = p.SignatureObjectId, initialsObjectId = p.InitialsObjectId, signatureSha256 = Convert.ToHexStringLower(p.SignatureSha256),
                initialsSha256 = Convert.ToHexStringLower(p.InitialsSha256), documentSha256 = Convert.ToHexStringLower(p.DocumentSha256), disclosureSha256 = Convert.ToHexStringLower(p.DisclosureSha256),
                serverEvidence = "previewed_assets_bound_to_explicit_adoption_request", identityEvidence = "email_link_session_with_prior_consent" });
            Signer.SignatureAdoptionId = p.Id; Signer.SignatureAdoptedAt = p.UsedAt; Signer.SignatureImageBlob = p.SignatureObjectId.ToString("N"); Signer.InitialsImageBlob = p.InitialsObjectId.ToString("N");
            Signer.SignatureImageSha256 = p.SignatureSha256; Signer.InitialsImageSha256 = p.InitialsSha256; Signer.SignatureMethod = p.Method;
            Signer.SignatureTypedName = p.TypedName; Signer.SignatureTypedInitials = p.TypedInitials; Signer.SignatureNormalizationVersion = p.NormalizationVersion; Signer.SignatureAdoptionVersion = p.AdoptionVersion;
            Add("signature_adopted", raw, PartyType.Signer, Signer.Id, Signer.Email, p.UsedAt.Value.AddSeconds(1)); Rehash();
        }
        internal void Correct()
        {
            var retirement = SignerContactState.RetirementJson(Signer, [new() { EnvelopeId = Envelope.Id, SignerId = Signer.Id, Type = FieldType.Signature }]);
            var at = At.AddMinutes(2).AddSeconds(10);
            var r = new SignerContactRevision(SignerContactHistory.Version, Guid.NewGuid(), Envelope.Id, Signer.Id, Guid.Empty, 1, Signer.Email, "corrected@example.invalid", at,
                at.AddMinutes(5), Convert.ToBase64String(new byte[8]), Convert.ToBase64String(Signer.RowVersion), Guid.ParseExact(Envelope.SentPdfBlob!, "N"), Convert.ToHexStringLower(Envelope.SentPdfSha256!),
                Convert.ToHexStringLower(Envelope.ErsdSha256!), SignerContactState.RetirementDigest(retirement), null, SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
            var raw = SignerContactHistory.Canonical(r); Revisions.Add(new() { Id = r.Id, EnvelopeId = Envelope.Id, SignerId = Signer.Id, Number = 1, ChangedAt = at, EvidenceJson = raw, RetirementJson = retirement });
            Add(SignerContactHistory.Event, raw, PartyType.Sender, null, Envelope.SenderEmail, at); Signer.Email = r.NewEmail; Clear(); Rehash();
        }
        internal void Clear() { Signer.SignatureAdoptionId = null; Signer.SignatureAdoptedAt = null; Signer.SignatureImageBlob = null; Signer.InitialsImageBlob = null; Signer.SignatureImageSha256 = null; Signer.InitialsImageSha256 = null;
            Signer.SignatureMethod = null; Signer.SignatureTypedName = null; Signer.SignatureTypedInitials = null; Signer.SignatureNormalizationVersion = null; Signer.SignatureAdoptionVersion = null; }
        internal void Add(string name, string raw, PartyType actor, Guid? actorId, string email, DateTimeOffset at) => Audits.Add(new() { EnvelopeId = Envelope.Id, Event = name, DataJson = raw, ActorType = actor, ActorId = actorId, ActorEmail = email, At = at });
        internal void Object(Guid id, byte[] hash) => Objects.Add(new(new("normalized", $"{Envelope.Id:N}/{id:N}", "", "", "\"etag\"", 200), Convert.ToHexStringLower(hash)));
        internal static byte[] Hash(string value) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
        internal void Edit(int n, Action<JsonObject> action) { var j = JsonNode.Parse(Audits[n].DataJson)!.AsObject(); action(j); Audits[n].DataJson = j.ToJsonString(); }
        internal void Rehash() { byte[]? previous = null; for (var n = 0; n < Audits.Count; n++) { var a = Audits[n]; a.Id = 100 + n; a.Sequence = n + 1; a.PrevHash = previous; a.Hash = AuditHash.Compute(a); previous = a.Hash; } }
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, CapturedAt = Captured, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "Signers", Rows = Others.Append(Signer).ToArray() }, new { Table = "AuditEvents", Rows = Audits },
            new { Table = "SignaturePreviews", Rows = Previews }, new { Table = "SignerContactRevisions", Rows = Revisions }, new { Table = "SignerFinishAcceptances", Rows = Finishes }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        internal void Demand(JsonDocument sql) => ProductionHoldAdoptionAuditReferences.Demand(sql.RootElement, Objects);
    }
}

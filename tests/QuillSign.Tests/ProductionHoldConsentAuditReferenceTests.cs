using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Legal;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldConsentAuditReferenceTests
{
    [Fact]
    public void Expired_used_links_and_original_consent_remain_evidence_without_invented_legacy_sessions()
    {
        var f = new Frame(); var old = JsonSerializer.Serialize(f.Tokens); using var sql = f.Sql(); f.Demand(sql);
        Assert.Empty(f.Sessions); Assert.Equal(old, JsonSerializer.Serialize(f.Tokens)); Assert.True(f.Tokens[0].ExpiresAt < f.Captured);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Original_link_shape_binds_saved_source_without_fabricating_missing_token_columns(bool scoped)
    {
        var f = new Frame(); f.Edit(1, x => x.Remove("documentId"));
        if (!scoped) { f.Tokens[0].DocumentId = null; f.Tokens[0].DocumentSha256 = null; f.Tokens[0].DisclosureSha256 = null; }
        f.Rehash(); using var sql = f.Sql(); f.Demand(sql);
    }

    [Theory]
    [InlineData("owner")][InlineData("actor")][InlineData("actor-id")][InlineData("role")][InlineData("link-hidden")][InlineData("consent-hidden")]
    [InlineData("token")][InlineData("token-owner")][InlineData("token-party")][InlineData("token-purpose")][InlineData("token-email")]
    [InlineData("token-unused")][InlineData("token-time")][InlineData("token-expired")][InlineData("token-document")][InlineData("token-scope-missing")]
    [InlineData("source")][InlineData("source-missing")][InlineData("disclosure")][InlineData("disclosure-text")][InlineData("version")]
    [InlineData("authentication")][InlineData("receipt")][InlineData("method")][InlineData("agreement")][InlineData("retention")]
    [InlineData("server")][InlineData("client")][InlineData("consent-time")][InlineData("consent-ip")][InlineData("consent-ua")]
    [InlineData("preview-before-consent")][InlineData("consent-omitted")][InlineData("link-omitted")][InlineData("action-before-consent")]
    [InlineData("duplicate-consent")][InlineData("missing-used-token-audit")]
    public void Rehashed_missing_unknown_or_inconsistent_identity_and_consent_evidence_is_rejected(string fault)
    {
        var f = new Frame();
        switch (fault)
        {
            case "owner": f.Audits[1].EnvelopeId = Guid.NewGuid(); break;
            case "actor": f.Audits[1].ActorEmail = "foreign@example.invalid"; break;
            case "actor-id": f.Audits[1].ActorId = Guid.NewGuid(); break;
            case "role": f.Audits[2].ActorType = PartyType.Sender; break;
            case "link-hidden": f.Edit(1, x => x["newObject"] = Guid.NewGuid()); break;
            case "consent-hidden": f.Edit(2, x => x["newProof"] = "unknown"); break;
            case "token": f.Edit(1, x => x["tokenId"] = Guid.NewGuid()); break;
            case "token-owner": f.Tokens[0].EnvelopeId = Guid.NewGuid(); break;
            case "token-party": f.Tokens[0].PartyType = PartyType.Recipient; break;
            case "token-purpose": f.Tokens[0].Purpose = TokenPurpose.Lookup; break;
            case "token-email": f.Tokens[0].Email = "foreign@example.invalid"; break;
            case "token-unused": f.Tokens[0].UsedAt = null; break;
            case "token-time": f.Tokens[0].UsedAt = f.Captured; break;
            case "token-expired": f.Tokens[0].ExpiresAt = f.Tokens[0].UsedAt!.Value; break;
            case "token-document": f.Tokens[0].DocumentId = Guid.NewGuid(); break;
            case "token-scope-missing": f.Tokens[0].DisclosureSha256 = null; break;
            case "source": f.Edit(1, x => x["documentId"] = Guid.NewGuid()); break;
            case "source-missing": f.Objects.Clear(); break;
            case "disclosure": f.Edit(2, x => x["disclosureSha256"] = new string('c', 64)); break;
            case "disclosure-text": f.Envelope.ErsdText += "Changed frozen text"; break;
            case "version": f.Edit(2, x => x["disclosureVersion"] = "future"); break;
            case "authentication": f.Edit(1, x => x["authentication"] = "invented_identity"); break;
            case "receipt": f.Edit(2, x => x["accessReceiptId"] = Guid.Empty); break;
            case "method": f.Edit(2, x => x["accessMethod"] = "read_every_word"); break;
            case "agreement": f.Edit(2, x => x["agreement"] = false); break;
            case "retention": f.Edit(2, x => x["canRetain"] = false); break;
            case "server": f.Edit(2, x => x["serverEvidence"] = "identity_verified"); break;
            case "client": f.Edit(2, x => x["clientEvidence"] = "server_observed_reading"); break;
            case "consent-time": f.Signer.ConsentAt = f.Captured; break;
            case "consent-ip": f.Signer.ConsentIp = "different synthetic IP"; break;
            case "consent-ua": f.Signer.ConsentUa = "changed synthetic agent"; break;
            case "preview-before-consent": f.Previews[0].CreatedAt = f.At; break;
            case "consent-omitted": f.Audits.RemoveAt(2); break;
            case "link-omitted": f.Audits.RemoveAt(1); break;
            case "action-before-consent": (f.Audits[2], f.Audits[3]) = (f.Audits[3], f.Audits[2]); break;
            case "duplicate-consent": f.Add("consent_given", f.Audits[2].DataJson); break;
            case "missing-used-token-audit": f.Tokens.Add(new() { EnvelopeId = f.Envelope.Id, PartyId = f.Signer.Id, Purpose = TokenPurpose.SignerAccess, UsedAt = f.At }); break;
        }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Theory]
    [InlineData("signature_adopted")][InlineData("field_filled")][InlineData("field_cleared")][InlineData("signer_review_prepared")][InlineData("signer_finish_accepted")][InlineData("signer_completed")]
    public void Protected_actions_require_prior_same_epoch_consent(string action)
    {
        var f = new Frame(); f.Previews.Clear(); f.Audits[^1].Event = action;
        f.Rehash(); using (var valid = f.Sql()) f.Demand(valid);
        f.Audits.RemoveAt(2); f.Signer.ConsentAt = null; f.Signer.ConsentIp = null; f.Signer.ConsentUa = null; f.Rehash();
        using var omitted = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(omitted));
    }

    [Fact]
    public void Correction_retires_old_consent_and_requires_new_link_consent_and_bound_preview_session()
    {
        var f = new Frame(); f.Correct(); using (var reset = f.Sql()) f.Demand(reset);
        f.Link(); f.Consent(); f.Preview(); using (var corrected = f.Sql()) f.Demand(corrected);
        f.Sessions.Clear(); using var missing = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(missing));
    }

    [Fact]
    public void Declining_after_consent_does_not_revoke_the_saved_consent_graph()
    {
        var f = new Frame(); f.Add("declined", "{}"); f.Envelope.Status = EnvelopeStatus.Declined; f.Signer.Status = SignerStatus.Declined;
        using var sql = f.Sql(); f.Demand(sql);
    }

    [Theory]
    [InlineData("consent")][InlineData("token")][InlineData("preview")]
    public void Omitting_all_link_consent_and_action_audits_cannot_hide_persisted_evidence(string kind)
    {
        var f = new Frame(); f.Audits.RemoveRange(1, f.Audits.Count - 1);
        if (kind != "preview") f.Previews.Clear();
        if (kind != "token") f.Tokens.Clear();
        if (kind != "consent") { f.Signer.ConsentAt = null; f.Signer.ConsentIp = null; f.Signer.ConsentUa = null; }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    private sealed class Frame
    {
        internal readonly DateTimeOffset At = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), Captured = new(2020, 2, 1, 0, 0, 0, TimeSpan.Zero);
        internal Envelope Envelope; internal Signer Signer; internal List<AuditEvent> Audits = []; internal List<AuthToken> Tokens = [];
        internal List<HoldObjectEvidence> Objects = []; internal List<SignaturePreview> Previews = []; internal List<SignerContactSession> Sessions = [];
        internal List<SignerContactRevisionRecord> Contacts = []; private Guid epoch;
        internal Frame()
        {
            Envelope = new() { Status = EnvelopeStatus.Sent, SenderEmail = "sender@example.invalid", Title = "Synthetic NO AGREEMENT", SentAt = At, SentPdfBlob = Guid.NewGuid().ToString("N"), SentPdfSha256 = Hash("source") };
            var disclosure = new ElectronicRecordDisclosure(ElectronicRecordDisclosureTests.Policy()).Build(Envelope.PublicId, Envelope.Title, Envelope.SenderEmail);
            Envelope.ErsdText = disclosure.Text; Envelope.ErsdVersion = disclosure.Version; Envelope.ErsdSha256 = disclosure.Sha256;
            Signer = new() { EnvelopeId = Envelope.Id, Email = "signer@example.invalid", FullName = "Synthetic signer", RowVersion = new byte[8] };
            Objects.Add(new(new("normalized", $"{Envelope.Id:N}/{Envelope.SentPdfBlob}", "", "", "\"etag\"", 200), Convert.ToHexStringLower(Envelope.SentPdfSha256)));
            Add("sent", "{}", false); Link(); Consent(); Preview();
        }
        internal void Link()
        {
            var token = new AuthToken { EnvelopeId = Envelope.Id, PartyId = Signer.Id, PartyType = PartyType.Signer, Purpose = TokenPurpose.SignerAccess, Email = Signer.Email,
                UsedAt = At.AddSeconds(Audits.Count + .5), ExpiresAt = At.AddHours(1), TokenSha256 = Hash("synthetic token " + Tokens.Count), DocumentId = Guid.ParseExact(Envelope.SentPdfBlob!, "N"),
                DocumentSha256 = Envelope.SentPdfSha256, DisclosureSha256 = Envelope.ErsdSha256, SignerContactRevisionId = epoch == Guid.Empty ? null : epoch };
            Tokens.Add(token); Add("link_opened", JsonSerializer.Serialize(new { signerId = Signer.Id, tokenId = token.Id, documentId = token.DocumentId!.Value,
                documentSha256 = Convert.ToHexStringLower(token.DocumentSha256!), disclosureSha256 = Convert.ToHexStringLower(token.DisclosureSha256!), authentication = "single_use_email_link" }));
            if (epoch != Guid.Empty) Sessions.Add(new() { EnvelopeId = Envelope.Id, SignerId = Signer.Id, RevisionId = epoch, SessionId = Guid.NewGuid(),
                SessionSha256 = Hash("session " + epoch), CreatedAt = Audits[^1].At, ExpiresAt = At.AddHours(1) });
        }
        internal void Consent()
        {
            Signer.ConsentAt = At.AddSeconds(Audits.Count + .5); Signer.ConsentIp = "127.0.0.1"; Signer.ConsentUa = "Synthetic user agent";
            Add("consent_given", JsonSerializer.Serialize(new { disclosureVersion = Envelope.ErsdVersion, disclosureSha256 = Convert.ToHexStringLower(Envelope.ErsdSha256!),
                documentSha256 = Convert.ToHexStringLower(Envelope.SentPdfSha256!), accessReceiptId = Guid.NewGuid(), accessMethod = "preview", agreement = true, canRetain = true,
                serverEvidence = "hash_verified_pdf_prepared", clientEvidence = "signer_reported_access_and_retention" }));
        }
        internal void Preview()
        {
            var p = new SignaturePreview { EnvelopeId = Envelope.Id, SignerId = Signer.Id, CreatedAt = At.AddSeconds(Audits.Count + .25), UsedAt = At.AddSeconds(Audits.Count + .5),
                ExpiresAt = At.AddMinutes(10), SessionSha256 = Hash("session " + epoch) }; Previews.Add(p); Add("signature_adopted", JsonSerializer.Serialize(new { adoptionId = p.Id }));
        }
        internal void Correct()
        {
            var retirement = SignerContactState.RetirementJson(Signer, [new() { EnvelopeId = Envelope.Id, SignerId = Signer.Id, Type = FieldType.Signature }]);
            var at = At.AddSeconds(Audits.Count + 1); epoch = Guid.NewGuid();
            var r = new SignerContactRevision(SignerContactHistory.Version, epoch, Envelope.Id, Signer.Id, Guid.Empty, 1, Signer.Email, "corrected@example.invalid", at, at.AddMinutes(5),
                Convert.ToBase64String(new byte[8]), Convert.ToBase64String(Signer.RowVersion), Guid.ParseExact(Envelope.SentPdfBlob!, "N"), Convert.ToHexStringLower(Envelope.SentPdfSha256!),
                Convert.ToHexStringLower(Envelope.ErsdSha256!), SignerContactState.RetirementDigest(retirement), null, SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
            var raw = SignerContactHistory.Canonical(r); Contacts.Add(new() { Id = r.Id, EnvelopeId = Envelope.Id, SignerId = Signer.Id, Number = 1, ChangedAt = at, EvidenceJson = raw, RetirementJson = retirement });
            Add(SignerContactHistory.Event, raw, false); Signer.Email = r.NewEmail; Signer.ConsentAt = null; Signer.ConsentIp = null; Signer.ConsentUa = null;
        }
        internal void Add(string name, string raw, bool signer = true)
        { Audits.Add(new() { EnvelopeId = Envelope.Id, Event = name, DataJson = raw, At = At.AddSeconds(Audits.Count + 1), ActorType = signer ? PartyType.Signer : PartyType.Sender,
            ActorId = signer ? Signer.Id : null, ActorEmail = signer ? Signer.Email : Envelope.SenderEmail, Ip = "127.0.0.1", UserAgent = "Synthetic user agent" }); Rehash(); }
        internal void Edit(int n, Action<JsonObject> edit) { var j = JsonNode.Parse(Audits[n].DataJson)!.AsObject(); edit(j); Audits[n].DataJson = j.ToJsonString(); }
        internal void Rehash() { byte[]? prior = null; for (var n = 0; n < Audits.Count; n++) { var a = Audits[n]; a.Id = 100 + n; a.Sequence = n + 1; a.PrevHash = prior; a.Hash = AuditHash.Compute(a); prior = a.Hash; } }
        private static byte[] Hash(string raw) => SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, CapturedAt = Captured, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "Signers", Rows = new[] { Signer } }, new { Table = "AuditEvents", Rows = Audits },
            new { Table = "AuthTokens", Rows = Tokens }, new { Table = "SignaturePreviews", Rows = Previews }, new { Table = "SignerContactRevisions", Rows = Contacts },
            new { Table = "SignerContactSessions", Rows = Sessions }, new { Table = "SignerFinishAcceptances", Rows = Array.Empty<SignerFinishAcceptance>() }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        internal void Demand(JsonDocument sql) => ProductionHoldConsentAuditReferences.Demand(sql.RootElement, Objects);
    }
}

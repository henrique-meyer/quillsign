using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldInvitationReferenceTests
{
    [Theory]
    [InlineData("initial")][InlineData("resend")][InlineData("successor")]
    public void Historical_invitation_requires_original_document_even_after_its_access_deadline(string kind)
    {
        var model = new Frame(kind); using var sql = model.Sql();
        ProductionHoldInvitationReferences.Demand(sql.RootElement, model.Objects, model.Keys);
        Assert.True(model.At.AddDays(1) < DateTimeOffset.UtcNow);
        Assert.NotEqual(model.Document, model.Envelope.SentPdfBlob);
        Assert.Throws<InvalidDataException>(() => ProductionHoldInvitationReferences.Demand(sql.RootElement, [], model.Keys));
        // A newer current source cannot replace the historical exact path/hash.
        var newer = model.Objects[0] with { Address = model.Objects[0].Address with { Name = $"{model.Id:N}/{model.Envelope.SentPdfBlob}" } };
        Assert.Throws<InvalidDataException>(() => ProductionHoldInvitationReferences.Demand(sql.RootElement, [newer], model.Keys));
    }

    [Theory]
    [InlineData("initial", "owner")][InlineData("resend", "owner")][InlineData("successor", "owner")]
    [InlineData("initial", "recipient")][InlineData("resend", "recipient")][InlineData("successor", "recipient")]
    [InlineData("initial", "disclosure")][InlineData("resend", "disclosure")][InlineData("successor", "disclosure")]
    [InlineData("initial", "ciphertext")][InlineData("resend", "ciphertext")][InlineData("successor", "ciphertext")]
    [InlineData("initial", "hash")][InlineData("resend", "area")][InlineData("successor", "prefix")]
    [InlineData("initial", "attachment")][InlineData("resend", "large")][InlineData("successor", "status")]
    [InlineData("initial", "signer")][InlineData("resend", "sender")][InlineData("successor", "sender")]
    public void Cross_scope_corruption_or_partial_evidence_cannot_be_preserved_as_verified(string kind, string fault)
    {
        var m = new Frame(kind);
        switch (fault)
        {
            case "owner": m.Mail.EnvelopeId = Guid.NewGuid(); break;
            case "recipient": m.Mail.To = "other-synthetic@example.invalid"; break;
            case "disclosure": m.Envelope.ErsdSha256 = new byte[32]; break;
            case "ciphertext": m.Mail.PayloadJson += "!"; break;
            case "hash": m.Objects[0] = m.Objects[0] with { Sha256 = new string('0', 64) }; break;
            case "area": m.Objects[0] = m.Objects[0] with { Address = m.Objects[0].Address with { Area = "originals" } }; break;
            case "prefix": m.Objects[0] = m.Objects[0] with { Address = m.Objects[0].Address with { Name = $"{Guid.NewGuid():N}/{m.Document}" } }; break;
            case "attachment": m.Mail.AttachmentsJson = "[{}]"; break;
            case "large": m.Mail.PayloadJson = new string('x', 12001); break;
            case "status": m.Mail.Status = (EmailStatus)999; break;
            case "signer": m.Signer.Id = Guid.NewGuid(); break;
            case "sender": m.Envelope.SenderEmail = "different-sender@example.invalid"; break;
        }
        using var sql = m.Sql();
        Assert.Throws<InvalidDataException>(() => ProductionHoldInvitationReferences.Demand(sql.RootElement, m.Objects, m.Keys));
    }

    [Fact]
    public void A_different_key_ring_or_template_purpose_does_not_authenticate_a_saved_invitation()
    {
        var m = new Frame("initial"); using var original = m.Sql();
        Assert.Throws<InvalidDataException>(() => ProductionHoldInvitationReferences.Demand(original.RootElement, m.Objects, new EphemeralDataProtectionProvider()));
        m.Mail.Template = InvitationSuccessorProtection.Template; using var moved = m.Sql();
        Assert.Throws<InvalidDataException>(() => ProductionHoldInvitationReferences.Demand(moved.RootElement, m.Objects, m.Keys));
    }

    [Theory]
    [InlineData("initial", "hidden-field")][InlineData("resend", "hidden-field")][InlineData("successor", "hidden-field")]
    [InlineData("initial", "wrapper")][InlineData("resend", "wrapper")][InlineData("successor", "wrapper")]
    [InlineData("initial", "noncanonical")][InlineData("resend", "noncanonical")][InlineData("successor", "noncanonical")]
    public void Authenticated_unknown_or_noncanonical_payloads_cannot_hide_uncovered_object_references(string kind, string fault)
    {
        var m = new Frame(kind);
        if (fault == "wrapper") m.Mail.PayloadJson = m.Mail.PayloadJson[..^1] + ",\"UncoveredObject\":\"synthetic\"}";
        else
        {
            var purpose = kind switch { "initial" => "QuillSign.SignerInvitationPayload.v1", "resend" => "QuillSign.InvitationResend.Payload.v1", _ => "QuillSign.InvitationSuccessor.Payload.v1" };
            var protector = m.Keys.CreateProtector(purpose);
            var wrapped = JsonSerializer.Deserialize<ProtectedWorkPayload>(m.Mail.PayloadJson)!;
            var raw = protector.Unprotect(wrapped.Protected);
            var changed = fault == "hidden-field" ? raw[..^1] + ",\"UncoveredObjectId\":\"" + Guid.NewGuid() + "\"}" : " " + raw;
            m.Mail.PayloadJson = JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(changed)));
        }
        using var sql = m.Sql();
        Assert.Throws<InvalidDataException>(() => ProductionHoldInvitationReferences.Demand(sql.RootElement, m.Objects, m.Keys));
    }

    [Theory]
    [InlineData("initial")][InlineData("successor")]
    public void Original_contact_epoch_remains_preservable_after_contact_correction_but_cannot_be_readdressed(string kind)
    {
        var m = new Frame(kind); m.CorrectContact(); using var sql = m.Sql();
        ProductionHoldInvitationReferences.Demand(sql.RootElement, m.Objects, m.Keys);
        m.Mail.To = m.Signer.Email; using var readdressed = m.Sql();
        Assert.Throws<InvalidDataException>(() => ProductionHoldInvitationReferences.Demand(readdressed.RootElement, m.Objects, m.Keys));
    }

    [Theory]
    [InlineData("missing")][InlineData("number")][InlineData("owner")][InlineData("chain")]
    public void Missing_or_moved_contact_epoch_history_is_not_inferred_from_a_current_signer(string fault)
    {
        var m = new Frame("initial"); m.CorrectContact();
        switch (fault)
        {
            case "missing": m.History.Clear(); break;
            case "number": m.History[0].Number = 2; break;
            case "owner": m.History[0].EnvelopeId = Guid.NewGuid(); break;
            case "chain": m.Signer.Email = "unexplained-current@example.invalid"; break;
        }
        using var sql = m.Sql();
        Assert.Throws<InvalidDataException>(() => ProductionHoldInvitationReferences.Demand(sql.RootElement, m.Objects, m.Keys));
    }

    private sealed class Frame
    {
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider();
        internal readonly Guid Id = Guid.NewGuid();
        internal readonly string Document = Guid.NewGuid().ToString("N");
        internal readonly DateTimeOffset At = new(2020, 1, 1, 12, 0, 0, TimeSpan.Zero);
        internal readonly List<HoldObjectEvidence> Objects = [];
        internal readonly List<SignerContactRevisionRecord> History = [];
        internal readonly Envelope Envelope;
        internal readonly Signer Signer;
        internal readonly EmailOutbox Mail;
        private readonly string hash = Convert.ToHexStringLower(SHA256.HashData("Synthetic historical invitation - NO AGREEMENT"u8));
        internal Frame(string kind)
        {
            Envelope = new() { Id = Id, SenderEmail = "sender@example.invalid", SentPdfBlob = Guid.NewGuid().ToString("N"), ErsdSha256 = Convert.FromHexString(hash) };
            Signer = new() { EnvelopeId = Id, Email = "signer@example.invalid" };
            Mail = new() { EnvelopeId = Id, To = Signer.Email, AvailableAt = At };
            Objects.Add(new(new("normalized", $"{Id:N}/{Document}", "historical-version", "", "\"old-etag\"", 45), hash));
            switch (kind)
            {
                case "initial":
                    Mail.Template = "signer-invitation";
                    Mail.PayloadJson = new SignerInvitationProtection(Keys).Protect(new(Signer.Id, DocumentId: Guid.Parse(Document), DocumentSha256: hash, DisclosureSha256: hash));
                    break;
                case "resend":
                    Mail.Template = InvitationResendProtection.Template;
                    var request = new ResendRequest("resend-request-v1", Mail.Id, Id, Signer.Id, Guid.NewGuid(), Mail.To, Envelope.SenderEmail,
                        hash, Convert.ToBase64String(new byte[8]), Guid.Parse(Document), hash, hash, At, At.AddMinutes(5), At.AddMinutes(10), InvitationResendProtection.DayEnd(At));
                    Mail.PayloadJson = new InvitationResendProtection(Keys).Protect(new(request));
                    break;
                default:
                    Mail.Template = InvitationSuccessorProtection.Template;
                    var scope = new InvitationSuccessorScope(InvitationSuccessorProtection.Version, Mail.Id, Id, Signer.Id, Guid.NewGuid(), SignerContactEpoch.Legacy,
                        InvitationSuccessorReason.ManualResend, Mail.To, Envelope.SenderEmail, Guid.Parse(Document), hash, hash, hash, At, At.AddMinutes(10));
                    Mail.PayloadJson = new InvitationSuccessorProtection(Keys).Protect(new(scope));
                    break;
            }
        }
        internal void CorrectContact()
        {
            var revision = new SignerContactRevision(SignerContactHistory.Version, Guid.NewGuid(), Id, Signer.Id, Guid.Empty, 1,
                Signer.Email, "corrected@example.invalid", At.AddMinutes(20), At.AddMinutes(25), Convert.ToBase64String(new byte[8]), Convert.ToBase64String(new byte[8]),
                Guid.Parse(Document), hash, hash, hash, null, SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
            History.Add(new() { Id = revision.Id, EnvelopeId = Id, SignerId = Signer.Id, Number = 1, ChangedAt = revision.ChangedAt, EvidenceJson = SignerContactHistory.Canonical(revision) });
            Signer.Email = revision.NewEmail;
        }
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Id, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "Signers", Rows = new[] { Signer } },
            new { Table = "EmailOutbox", Rows = new[] { Mail } }, new { Table = "SignerContactRevisions", Rows = History }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
    }
}

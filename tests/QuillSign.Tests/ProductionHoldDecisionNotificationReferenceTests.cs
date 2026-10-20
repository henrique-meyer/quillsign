using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldDecisionNotificationReferenceTests
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Queued_verification_precedes_token_issuance_and_expired_used_issued_evidence_remains_readable(bool issued)
    {
        var f = new Frame(false);
        if (issued) f.Issue();
        using var sql = f.Sql(); f.Demand(sql);
        Assert.True(f.At.AddDays(1) < DateTimeOffset.UtcNow);
        Assert.Equal(issued ? 1 : 0, f.Tokens.Count);
        if (issued) { Assert.Equal(f.At, f.Tokens[0].UsedAt); Assert.Equal(f.At.AddMinutes(15), f.Tokens[0].ExpiresAt); }
    }

    [Theory]
    [InlineData("missing")][InlineData("owner")][InlineData("party")][InlineData("purpose")][InlineData("mailbox")]
    [InlineData("hash")][InlineData("document")][InlineData("completion")][InlineData("duplicate")][InlineData("token-id")]
    [InlineData("short-token")][InlineData("noncanonical-token")]
    public void Issued_verification_requires_exact_saved_token_scope_without_creating_replacement(string fault)
    {
        var f = new Frame(false); f.Issue();
        switch (fault)
        {
            case "missing": f.Tokens.Clear(); break;
            case "owner": f.Tokens[0].EnvelopeId = Guid.NewGuid(); break;
            case "party": f.Tokens[0].PartyId = Guid.NewGuid(); break;
            case "purpose": f.Tokens[0].Purpose = TokenPurpose.SignerAccess; break;
            case "mailbox": f.Tokens[0].Email = "other@example.invalid"; break;
            case "hash": f.Tokens[0].TokenSha256 = new byte[32]; break;
            case "document": f.Tokens[0].DocumentId = Guid.NewGuid(); break;
            case "completion": f.Tokens[0].CompletionPublicationId = Guid.NewGuid(); break;
            case "duplicate": f.Tokens.Add(f.Tokens[0]); break;
            case "token-id": f.Verification = f.Verification with { TokenId = Guid.Empty }; f.Protect(); break;
            case "short-token": f.Verification = f.Verification with { Token = "short" }; f.Protect(); break;
            case "noncanonical-token": f.Verification = f.Verification with { Token = new string('A', 42) + "B" }; f.Protect(); break;
        }
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Theory]
    [InlineData(false, "mailbox")][InlineData(true, "mailbox")]
    [InlineData(false, "owner")][InlineData(true, "owner")]
    [InlineData(false, "ciphertext")][InlineData(true, "ciphertext")]
    [InlineData(false, "key")][InlineData(true, "key")]
    [InlineData(false, "purpose")][InlineData(true, "purpose")]
    [InlineData(false, "attachment")][InlineData(true, "attachment")]
    [InlineData(false, "large")][InlineData(true, "large")]
    [InlineData(false, "hidden")][InlineData(true, "hidden")]
    [InlineData(false, "wrapper")][InlineData(true, "wrapper")]
    [InlineData(false, "duplicate-field")][InlineData(true, "duplicate-field")]
    public void Protected_payloads_cannot_hide_unknown_references_or_change_owner_recipient_or_purpose(bool decline, string fault)
    {
        var f = new Frame(decline); IDataProtectionProvider keys = f.Keys;
        switch (fault)
        {
            case "mailbox": f.Mail.To = "other@example.invalid"; break;
            case "owner": f.Mail.EnvelopeId = Guid.NewGuid(); break;
            case "ciphertext": f.Mail.PayloadJson += "!"; break;
            case "key": keys = new EphemeralDataProtectionProvider(); break;
            case "purpose": f.Mail.Template = decline ? "sender-verification" : "signer-declined"; break;
            case "attachment": f.Mail.AttachmentsJson = "[{}]"; break;
            case "large": f.Mail.PayloadJson = new string('x', 16385); break;
            case "wrapper": f.Mail.PayloadJson = f.Mail.PayloadJson[..^1] + ",\"HiddenObject\":\"synthetic\"}"; break;
            default:
                var p = f.Keys.CreateProtector(decline ? "QuillSign.DeclineNotification.v1" : "QuillSign.EmailPayload.v1");
                var body = p.Unprotect(JsonSerializer.Deserialize<ProtectedWorkPayload>(f.Mail.PayloadJson)!.Protected);
                body = body[..^1] + (fault == "hidden" ? ",\"HiddenObject\":\"synthetic\"}" : "," + body[1..]);
                f.Mail.PayloadJson = JsonSerializer.Serialize(new ProtectedWorkPayload(p.Protect(body))); break;
        }
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => ProductionHoldDecisionNotificationReferences.Demand(sql.RootElement, f.Objects, keys));
    }

    [Fact]
    public void Decline_requires_original_hash_referenced_only_by_its_audit_not_a_newer_current_document()
    {
        var f = new Frame(true); using var sql = f.Sql(); f.Demand(sql);
        Assert.NotEqual(f.Document.ToString("N"), f.Envelope.SentPdfBlob);
        f.Objects.Clear(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Fact]
    public void Full_length_unicode_decline_evidence_fits_the_bounded_protected_payload()
    {
        var f = new Frame(true);
        f.Envelope.Title = new string('界', 512); f.Signer.FullName = new string('界', 512); f.Signer.DeclineReason = new string('界', 512);
        f.Protect();
        f.Audits[0].DataJson = JsonSerializer.Serialize(new { reason = f.Signer.DeclineReason, notificationId = f.Mail.Id,
            documentSha256 = f.Objects[0].Sha256, disclosureSha256 = Convert.ToHexStringLower(f.Envelope.ErsdSha256!) });
        f.Audits[0].Hash = AuditHash.Compute(f.Audits[0]);
        Assert.True(Encoding.UTF8.GetByteCount(f.Mail.PayloadJson) > 12000);
        using var sql = f.Sql(); f.Demand(sql);
    }

    [Theory]
    [InlineData("missing-audit")][InlineData("duplicate-audit")][InlineData("audit-hash")][InlineData("audit-owner")]
    [InlineData("audit-actor")][InlineData("audit-mailbox")][InlineData("audit-reason")][InlineData("audit-hidden")]
    [InlineData("audit-predecessor")]
    [InlineData("disclosure")][InlineData("signer-name")][InlineData("signer-owner")][InlineData("signer-status")]
    [InlineData("signer-reason")][InlineData("title")][InlineData("source-hash")][InlineData("source-area")][InlineData("source-prefix")]
    public void Decline_requires_canonical_audit_party_reason_disclosure_and_exact_owned_historical_bytes(string fault)
    {
        var f = new Frame(true);
        switch (fault)
        {
            case "missing-audit": f.Audits.Clear(); break;
            case "duplicate-audit": f.Audits.Add(f.Audits[0]); break;
            case "audit-hash": f.Audits[0].Hash = new byte[32]; break;
            case "audit-owner": f.Audits[0].EnvelopeId = Guid.NewGuid(); break;
            case "audit-actor": f.Audits[0].ActorId = Guid.NewGuid(); break;
            case "audit-mailbox": f.Audits[0].ActorEmail = "other@example.invalid"; break;
            case "audit-reason": f.Audits[0].DataJson = f.Audits[0].DataJson.Replace("Synthetic refusal", "Changed refusal"); break;
            case "audit-hidden": f.Audits[0].DataJson = f.Audits[0].DataJson[..^1] + ",\"hiddenObject\":\"synthetic\"}"; break;
            case "audit-predecessor": f.Audits[0].Sequence = 2; break;
            case "disclosure": f.Envelope.ErsdSha256 = new byte[32]; break;
            case "signer-name": f.Signer.FullName = "Different signer"; break;
            case "signer-owner": f.Signer.EnvelopeId = Guid.NewGuid(); break;
            case "signer-status": f.Signer.Status = SignerStatus.Signed; break;
            case "signer-reason": f.Signer.DeclineReason = "Changed reason"; break;
            case "title": f.Envelope.Title = "Changed title"; break;
            case "source-hash": f.Objects[0] = f.Objects[0] with { Sha256 = new string('0', 64) }; break;
            case "source-area": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Area = "originals" } }; break;
            case "source-prefix": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Name = $"{Guid.NewGuid():N}/{f.Document:N}" } }; break;
        }
        // Recomputed unkeyed audit hashes cannot excuse mismatched typed scope.
        if (fault is "audit-owner" or "audit-actor" or "audit-mailbox" or "audit-reason" or "audit-hidden" or "audit-predecessor") f.Audits[0].Hash = AuditHash.Compute(f.Audits[0]);
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    private sealed class Frame
    {
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider();
        internal readonly DateTimeOffset At = new(2020, 1, 1, 12, 0, 0, TimeSpan.Zero);
        internal readonly Envelope Envelope = new() { SenderEmail = "sender@example.invalid", Title = "Synthetic - NO AGREEMENT", SentPdfBlob = Guid.NewGuid().ToString("N") };
        internal readonly Guid Document = Guid.NewGuid();
        internal readonly Signer Signer;
        internal readonly EmailOutbox Mail;
        internal readonly List<AuthToken> Tokens = [];
        internal readonly List<AuditEvent> Audits = [];
        internal readonly List<HoldObjectEvidence> Objects = [];
        internal VerificationPayload Verification = new(WebEncoders.Base64UrlEncode(SHA256.HashData("Synthetic - NO AGREEMENT"u8)), Guid.NewGuid());
        private readonly bool decline;
        internal Frame(bool decline)
        {
            this.decline = decline;
            Signer = new() { EnvelopeId = Envelope.Id, Email = "signer@example.invalid", FullName = "Synthetic signer", Status = SignerStatus.Declined, DeclineReason = "Synthetic refusal" };
            Mail = new() { EnvelopeId = Envelope.Id, To = Envelope.SenderEmail, Template = decline ? "signer-declined" : "sender-verification", AvailableAt = At };
            if (decline)
            {
                Envelope.Status = EnvelopeStatus.Declined; Envelope.ErsdSha256 = SHA256.HashData("Synthetic disclosure"u8);
                var hash = Convert.ToHexStringLower(SHA256.HashData("Synthetic historical source - NO AGREEMENT"u8));
                Objects.Add(new(new("normalized", $"{Envelope.Id:N}/{Document:N}", "historical", "", "\"etag\"", 47), hash));
                var audit = new AuditEvent { Id = 12, EnvelopeId = Envelope.Id, Sequence = 1, At = At, ActorType = PartyType.Signer, ActorId = Signer.Id,
                    ActorEmail = Signer.Email, Event = "declined", DataJson = JsonSerializer.Serialize(new { reason = Signer.DeclineReason, notificationId = Mail.Id,
                        documentSha256 = hash, disclosureSha256 = Convert.ToHexStringLower(Envelope.ErsdSha256) }) };
                audit.Hash = AuditHash.Compute(audit); Audits.Add(audit);
            }
            Protect();
        }
        internal void Protect() => Mail.PayloadJson = decline ? new DeclinePayloadProtection(Keys).Protect(new(Envelope.Title!, Signer.FullName, Signer.Email, Signer.DeclineReason)) :
            new EmailPayloadProtection(Keys).Protect(Verification);
        internal void Issue()
        {
            Mail.Status = EmailStatus.Sent; Mail.SubmissionStartedAt = At;
            Tokens.Add(new() { Id = Verification.TokenId, EnvelopeId = Envelope.Id, Email = Mail.To, Purpose = TokenPurpose.SenderVerify, PartyType = PartyType.Sender,
                ExpiresAt = At.AddMinutes(15), UsedAt = At, TokenSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(Verification.Token)) });
        }
        internal void Demand(JsonDocument sql) => ProductionHoldDecisionNotificationReferences.Demand(sql.RootElement, Objects, Keys);
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "Signers", Rows = new[] { Signer } },
            new { Table = "EmailOutbox", Rows = new[] { Mail } }, new { Table = "AuthTokens", Rows = Tokens }, new { Table = "AuditEvents", Rows = Audits }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
    }
}

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionHoldAdmissionAuditReferenceTests
{
    [Fact]
    public void Normal_original_admission_and_elapsed_verification_bind_without_renewal()
    {
        var f = new Frame(); using var sql = f.Sql(); var before = sql.RootElement.GetRawText();
        ProductionHoldAuditChain.Demand(sql.RootElement); ProductionHoldAdmissionAuditReferences.Demand(sql.RootElement);
        Assert.Equal(before, sql.RootElement.GetRawText()); Assert.True(f.Token.ExpiresAt < f.Captured);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Unverified_queued_or_expired_unused_token_does_not_invent_verification(bool tokenIssued)
    {
        var f = new Frame(); f.Unverified(); if (!tokenIssued) f.Tokens.Clear();
        using var sql = f.Sql(); ProductionHoldAdmissionAuditReferences.Demand(sql.RootElement);
        Assert.Null(f.Envelope.SenderVerifiedAt); Assert.All(f.Tokens, x => Assert.Null(x.UsedAt));
    }
    [Fact]
    public void Later_operational_tail_does_not_rewrite_original_admission_or_token_deadlines()
    {
        var f = new Frame(); f.Add("synthetic-later-tail", f.Captured.AddSeconds(-1), PartyType.System, null, "{}");
        f.Rehash(); using var sql = f.Sql(); ProductionHoldAdmissionAuditReferences.Demand(sql.RootElement);
        Assert.Equal(f.Verified, f.Token.UsedAt);
    }
    [Theory]
    [InlineData("draft-missing")][InlineData("request-missing")][InlineData("verified-missing")][InlineData("draft-duplicate")]
    [InlineData("request-duplicate")][InlineData("verified-duplicate")][InlineData("future-shape")][InlineData("whitespace")]
    [InlineData("array")][InlineData("actor")][InlineData("actor-id")][InlineData("mailbox")][InlineData("foreign-audit")]
    [InlineData("clock")][InlineData("creation-after-audit")][InlineData("capture-before")][InlineData("request-metadata")]
    [InlineData("request-order")][InlineData("verification-before-use")][InlineData("verification-reordered")]
    [InlineData("used-without-verified")][InlineData("missing-token")][InlineData("foreign-token")][InlineData("token-mailbox")]
    [InlineData("token-role")][InlineData("token-party")][InlineData("token-document")][InlineData("token-disclosure")]
    [InlineData("token-contact")][InlineData("token-completion")][InlineData("token-hash")][InlineData("token-ip")]
    [InlineData("expired-at-use")][InlineData("use-before-request")][InlineData("use-after-capture")][InlineData("use-offset")]
    [InlineData("used-twice")][InlineData("unmatched-verified")][InlineData("policy-owner")][InlineData("policy-created")]
    [InlineData("policy-origin")][InlineData("policy-json")][InlineData("policy-audit")][InlineData("enrollment-shape")]
    [InlineData("enrollment-role")][InlineData("enrollment-clock")][InlineData("demo")][InlineData("unbounded-audits")]
    public void Rehashed_actor_shape_owner_clock_token_or_enrollment_substitutions_fail_closed(string fault)
    {
        var f = new Frame(); var draft = f.Audits[1]; var requested = f.Audits[2]; var verified = f.Audits[3];
        switch (fault)
        {
            case "draft-missing": f.Audits.Remove(draft); break;
            case "request-missing": f.Audits.Remove(requested); break;
            case "verified-missing": f.Audits.Remove(verified); break;
            case "draft-duplicate": f.Add(draft.Event, f.Captured, PartyType.Sender, f.Envelope.SenderEmail, "{}"); break;
            case "request-duplicate": f.Add(requested.Event, f.Captured, PartyType.Sender, f.Envelope.SenderEmail, "{}"); break;
            case "verified-duplicate": f.Add(verified.Event, f.Captured, PartyType.Sender, f.Envelope.SenderEmail, "{}"); break;
            case "future-shape": draft.DataJson = "{\"future\":{\"objectId\":\"not-owned\"}}"; break;
            case "whitespace": requested.DataJson = "{ }"; break;
            case "array": verified.DataJson = "[]"; break;
            case "actor": draft.ActorType = PartyType.System; break;
            case "actor-id": requested.ActorId = Guid.NewGuid(); break;
            case "mailbox": verified.ActorEmail = "other@example.invalid"; break;
            case "foreign-audit": requested.EnvelopeId = Guid.NewGuid(); break;
            case "clock": draft.At = draft.At.ToOffset(TimeSpan.FromHours(1)); break;
            case "creation-after-audit": f.Envelope.CreatedAt = f.Verified.AddDays(1); break;
            case "capture-before": f.Captured = f.Envelope.CreatedAt.AddTicks(-1); break;
            case "request-metadata": requested.UserAgent = "Changed original request browser"; break;
            case "request-order": (f.Audits[1], f.Audits[2]) = (f.Audits[2], f.Audits[1]); break;
            case "verification-before-use": verified.At = f.Verified.AddTicks(-1); break;
            case "verification-reordered": (f.Audits[2], f.Audits[3]) = (f.Audits[3], f.Audits[2]); break;
            case "used-without-verified": f.Envelope.SenderVerifiedAt = null; break;
            case "missing-token": f.Tokens.Clear(); break;
            case "foreign-token": f.Token.EnvelopeId = Guid.NewGuid(); break;
            case "token-mailbox": f.Token.Email = "other@example.invalid"; break;
            case "token-role": f.Token.PartyType = PartyType.Signer; break;
            case "token-party": f.Token.PartyId = Guid.NewGuid(); break;
            case "token-document": f.Token.DocumentId = Guid.NewGuid(); break;
            case "token-disclosure": f.Token.DisclosureSha256 = new byte[32]; break;
            case "token-contact": f.Token.SignerContactRevisionId = Guid.NewGuid(); break;
            case "token-completion": f.Token.CompletionPublicationId = Guid.NewGuid(); break;
            case "token-hash": f.Token.TokenSha256 = [1]; break;
            case "token-ip": f.Token.Ip = "127.0.0.1"; break;
            case "expired-at-use": f.Token.ExpiresAt = f.Verified; break;
            case "use-before-request": f.Token.UsedAt = f.Envelope.CreatedAt; break;
            case "use-after-capture": f.Token.UsedAt = f.Captured.AddSeconds(1); break;
            case "use-offset": f.Token.UsedAt = f.Verified.ToOffset(TimeSpan.FromHours(1)); break;
            case "used-twice": f.Tokens.Add(new() { EnvelopeId = f.Envelope.Id, Email = f.Envelope.SenderEmail, Purpose = TokenPurpose.SenderVerify,
                PartyType = PartyType.Sender, TokenSha256 = SHA256.HashData("other-token"u8), UsedAt = f.Verified, ExpiresAt = f.Token.ExpiresAt }); break;
            case "unmatched-verified": f.Envelope.SenderVerifiedAt = f.Verified.AddTicks(1); break;
            case "policy-owner": f.Policy.EnvelopeId = Guid.NewGuid(); break;
            case "policy-created": f.Policy.OriginalCreatedAt = f.Policy.OriginalCreatedAt.AddTicks(1); break;
            case "policy-origin": f.Policy.OriginSha256[0] ^= 1; break;
            case "policy-json": f.Policy.PolicyJson += " "; break;
            case "policy-audit": f.Policy.AuditSequence = 2; break;
            case "enrollment-shape": f.Audits[0].DataJson += " "; break;
            case "enrollment-role": f.Audits[0].ActorType = PartyType.Sender; break;
            case "enrollment-clock": f.Audits[0].At = f.Envelope.CreatedAt; break;
            case "demo": f.Envelope.IsDemo = true; break;
            case "unbounded-audits": for (var n = 0; n < 4097; n++) f.Add("tail", f.Captured, PartyType.System, null, "{}"); break;
        }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => ProductionHoldAdmissionAuditReferences.Demand(sql.RootElement));
    }
    private sealed class Frame
    {
        private static readonly JsonSerializerOptions Options = new() { Converters = { new JsonStringEnumConverter() } };
        internal readonly Envelope Envelope = new() { SenderEmail = "synthetic-admission@example.invalid", CreatedAt = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero).AddMilliseconds(123) };
        internal readonly ProductionRetentionPolicyRecord Policy;
        internal readonly List<AuditEvent> Audits = [];
        internal readonly AuthToken Token;
        internal readonly List<AuthToken> Tokens;
        internal readonly DateTimeOffset Verified;
        internal DateTimeOffset Captured = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        internal Frame()
        {
            var policy = ProductionRetentionPolicyContract.Freeze(Envelope.Id, ProductionRetentionLedger.Seconds(Envelope.CreatedAt), ProductionRetentionLedgerTests.Policy());
            Policy = new() { EnvelopeId = Envelope.Id, OriginalCreatedAt = Envelope.CreatedAt, EnrolledAt = Envelope.CreatedAt.AddMilliseconds(1),
                PolicyJson = ProductionRetentionPolicyContract.Serialize(policy), PolicySha256 = ProductionRetentionPolicyContract.Digest(policy), AuditSequence = 1,
                OriginSha256 = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { Envelope.Id, Envelope.PublicId, Envelope.SenderEmail, Envelope.CreatedAt, Envelope.IsDemo })) };
            Add(ProductionRetentionLedger.EnrollmentEvent, Envelope.CreatedAt.AddMilliseconds(2), PartyType.System, null,
                JsonSerializer.Serialize(new { version = "production-retention-enrollment-v1", Policy.EnvelopeId, Policy.OriginalCreatedAt,
                    Policy.EnrolledAt, Policy.PolicySha256, originSha256 = Convert.ToHexStringLower(Policy.OriginSha256) }));
            Add("draft_created", Envelope.CreatedAt.AddMilliseconds(3), PartyType.Sender, Envelope.SenderEmail, "{}");
            Add("sender_verification_requested", Envelope.CreatedAt.AddMilliseconds(4), PartyType.Sender, Envelope.SenderEmail, "{}");
            Audits[1].UserAgent = Audits[2].UserAgent = "Synthetic request browser";
            Verified = Envelope.CreatedAt.AddSeconds(5); Envelope.SenderVerifiedAt = Verified;
            Token = new() { EnvelopeId = Envelope.Id, Email = Envelope.SenderEmail, Purpose = TokenPurpose.SenderVerify, PartyType = PartyType.Sender,
                TokenSha256 = SHA256.HashData("synthetic-token"u8), ExpiresAt = Envelope.CreatedAt.AddMinutes(15), UsedAt = Verified };
            Tokens = [Token]; Add("sender_email_verified", Verified.AddTicks(1), PartyType.Sender, Envelope.SenderEmail, "{}"); Rehash();
        }
        internal void Unverified() { Envelope.SenderVerifiedAt = null; Token.UsedAt = null; Audits.RemoveAt(3); Rehash(); }
        internal void Add(string name, DateTimeOffset at, PartyType role, string? email, string data) => Audits.Add(new() {
            Id = 50 + Audits.Count * 11, EnvelopeId = Envelope.Id, Sequence = Audits.Count + 1, Event = name, At = at, ActorType = role, ActorEmail = email, DataJson = data });
        internal void Rehash()
        {
            byte[]? previous = null;
            for (var n = 0; n < Audits.Count; n++) { var a = Audits[n]; a.Sequence = n + 1; a.PrevHash = previous; a.Hash = AuditHash.Compute(a); previous = a.Hash; }
            Policy.AuditHash = Audits[0].Hash.ToArray();
        }
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, CapturedAt = Captured, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "AuditEvents", Rows = Audits.OrderByDescending(x => x.Id).ToArray() },
            new { Table = "ProductionRetentionPolicies", Rows = new[] { Policy } }, new { Table = "AuthTokens", Rows = Tokens } } }, Options));
    }
}

using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class InvitationSuccessorProtectionTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static InvitationSuccessorScope Scope(InvitationSuccessorReason reason = InvitationSuccessorReason.Reminder) => new(
        InvitationSuccessorProtection.Version, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
        reason == InvitationSuccessorReason.ContactCorrection ? new(Guid.NewGuid(), 1) : SignerContactEpoch.Legacy,
        reason, "signer@example.invalid", "sender@example.invalid", Guid.NewGuid(), new('a', 64), new('b', 64), new('c', 64), Now, Now.AddHours(1));
    private static EmailOutbox Row(InvitationSuccessorProtection protection, InvitationSuccessorScope p, InvitationSuccessorToken? token = null) => new() {
        Id = p.Id, EnvelopeId = p.EnvelopeId, To = p.Recipient, Template = InvitationSuccessorProtection.Template,
        AvailableAt = p.AdmittedAt, PayloadJson = protection.Protect(new(p, token)),
        SubmissionStartedAt = token is null ? null : p.AdmittedAt.AddMinutes(1), Attempts = token is null ? 0 : 1
    };
    private static AuditEvent Evidence(InvitationSuccessorScope p)
    {
        var row = new AuditEvent { EnvelopeId = p.EnvelopeId, Event = InvitationSuccessorProtection.Event, Sequence = 2,
            ActorType = p.Reason == InvitationSuccessorReason.Reminder ? PartyType.System : PartyType.Sender,
            ActorEmail = p.Reason == InvitationSuccessorReason.Reminder ? null : p.SenderEmail,
            At = p.AdmittedAt, DataJson = InvitationSuccessorProtection.Canonical(p) };
        row.Hash = AuditHash.Compute(row); return row;
    }

    [Theory]
    [InlineData(InvitationSuccessorReason.ManualResend)][InlineData(InvitationSuccessorReason.Reminder)][InlineData(InvitationSuccessorReason.ContactCorrection)]
    public void Each_reason_roundtrips_audit_and_protected_outbox_with_exact_scope(InvitationSuccessorReason reason)
    {
        var protection = new InvitationSuccessorProtection(new EphemeralDataProtectionProvider()); var p = Scope(reason);
        Assert.Equal(p, protection.Read(Row(protection, p)).Scope);
        Assert.Equal(p, InvitationSuccessorProtection.ReadEvidence(Evidence(p)));
        var token = new InvitationSuccessorToken(Guid.NewGuid(), new('d', 64), Now.AddDays(2));
        Assert.Equal(token, protection.Read(Row(protection, p, token)).Issued);
        Assert.DoesNotContain(p.Recipient, Row(protection, p).PayloadJson);
    }

    [Theory]
    [InlineData("id")][InlineData("envelope")][InlineData("recipient")][InlineData("template")][InlineData("attachments")]
    [InlineData("available")][InlineData("intent")][InlineData("negative-attempt")]
    public void Moving_a_protected_payload_to_another_outbox_scope_fails(string change)
    {
        var protection = new InvitationSuccessorProtection(new EphemeralDataProtectionProvider()); var row = Row(protection, Scope());
        if (change == "id") row.Id = Guid.NewGuid(); if (change == "envelope") row.EnvelopeId = Guid.NewGuid();
        if (change == "recipient") row.To = "other@example.invalid"; if (change == "template") row.Template = "signer-invitation";
        if (change == "attachments") row.AttachmentsJson = "[{}]"; if (change == "available") row.AvailableAt = Now.AddTicks(1);
        if (change == "intent") row.SubmissionStartedAt = Now; if (change == "negative-attempt") row.Attempts = -1;
        Assert.Throws<InvalidDataException>(() => protection.Read(row));
    }

    [Fact]
    public void Purpose_separation_and_ciphertext_tampering_cannot_reuse_another_payload()
    {
        var provider = new EphemeralDataProtectionProvider(); var protection = new InvitationSuccessorProtection(provider);
        var row = Row(protection, Scope());
        var foreign = new InvitationSuccessorProtection(new EphemeralDataProtectionProvider());
        Assert.Throws<CryptographicException>(() => foreign.Read(row));
        row.PayloadJson = System.Text.Json.JsonSerializer.Serialize(new ProtectedWorkPayload(
            provider.CreateProtector("QuillSign.InvitationResend.Payload.v1").Protect("foreign")));
        Assert.Throws<CryptographicException>(() => protection.Read(row));
        row.PayloadJson = "{\"Protected\":\"invalid\"}";
        Assert.Throws<CryptographicException>(() => protection.Read(row));
    }

    [Theory][InlineData("attempt")][InlineData("offset")][InlineData("expired-token")][InlineData("deadline")]
    public void Issued_intent_requires_actual_attempt_and_unexpired_exact_utc_scope(string change)
    {
        var protection = new InvitationSuccessorProtection(new EphemeralDataProtectionProvider()); var p = Scope();
        var token = new InvitationSuccessorToken(Guid.NewGuid(), new('d', 64), Now.AddMinutes(30));
        var row = Row(protection, p, token);
        if (change == "attempt") row.Attempts = 0;
        if (change == "offset") row.SubmissionStartedAt = row.SubmissionStartedAt!.Value.ToOffset(TimeSpan.FromHours(1));
        if (change == "expired-token") row.SubmissionStartedAt = token.ExpiresAt;
        if (change == "deadline") row.SubmissionStartedAt = p.Deadline;
        Assert.Throws<InvalidDataException>(() => protection.Read(row));
    }

    [Theory]
    [InlineData("id")][InlineData("previous")][InlineData("self")][InlineData("contact-id")][InlineData("contact-number")]
    [InlineData("correction-legacy")][InlineData("recipient")][InlineData("sender")][InlineData("source")]
    [InlineData("disclosure")][InlineData("authorization")][InlineData("deadline")][InlineData("day-end")][InlineData("non-utc")]
    public void Invalid_metadata_is_rejected_before_any_protection_or_evidence_claim(string change)
    {
        var p = Scope(); p = change switch {
            "id" => p with { Id = Guid.Empty }, "previous" => p with { PreviousId = Guid.Empty }, "self" => p with { PreviousId = p.Id },
            "contact-id" => p with { Contact = new(Guid.Empty, 1) }, "contact-number" => p with { Contact = new(Guid.NewGuid(), 0) },
            "correction-legacy" => p with { Reason = InvitationSuccessorReason.ContactCorrection },
            "recipient" => p with { Recipient = "SIGNER@example.invalid" }, "sender" => p with { SenderEmail = "Other <sender@example.invalid>" },
            "source" => p with { DocumentSha256 = new('A', 64) }, "disclosure" => p with { DisclosureSha256 = "short" },
            "authorization" => p with { AuthorizationSha256 = "" }, "deadline" => p with { Deadline = Now },
            "day-end" => p with { Deadline = Now.AddDays(1) }, _ => p with { AdmittedAt = Now.ToOffset(TimeSpan.FromHours(1)) }
        };
        Assert.Throws<InvalidDataException>(() => InvitationSuccessorProtection.Canonical(p));
        Assert.Throws<InvalidDataException>(() => new InvitationSuccessorProtection(new EphemeralDataProtectionProvider()).Protect(new(p)));
    }

    [Theory]
    [InlineData("actor")][InlineData("email")][InlineData("id")][InlineData("envelope")][InlineData("event")]
    [InlineData("before")][InlineData("after")][InlineData("noncanonical")][InlineData("hash")]
    public void Rehashed_audit_metadata_still_cannot_change_admission_authority_or_scope(string change)
    {
        var p = Scope(); var row = Evidence(p);
        if (change == "actor") row.ActorType = PartyType.Sender; if (change == "email") row.ActorEmail = p.SenderEmail;
        if (change == "id") row.ActorId = Guid.NewGuid(); if (change == "envelope") row.EnvelopeId = Guid.NewGuid();
        if (change == "event") row.Event = "reminder_submitted"; if (change == "before") row.At = Now.AddTicks(-1);
        if (change == "after") row.At = p.Deadline; if (change == "noncanonical") row.DataJson = " " + row.DataJson;
        row.Hash = AuditHash.Compute(row); if (change == "hash") row.Hash[0] ^= 1;
        Assert.Throws<InvalidDataException>(() => InvitationSuccessorProtection.ReadEvidence(row));
    }
}

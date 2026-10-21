using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Data;
using QuillSign.Legal;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldSentAuditReferenceTests
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Closed_initial_production_Send_preserves_exact_saved_evidence_with_optional_deadline(bool deadline)
    {
        var f = new Frame(deadline); using var sql = f.Sql(); f.Demand(sql);
        Assert.True(f.Token.ExpiresAt < f.Captured); // Historical proof does not renew an expired verification token.
        Assert.NotEqual(Convert.ToBase64String(f.Envelope.RowVersion), f.SentJson()["reviewedVersion"]!.GetValue<string>());
        using var reversed = f.Sql(reverse: true); f.Demand(reversed);
    }

    [Fact]
    public void Draft_is_left_to_its_existing_complete_registry_and_private_controls_are_not_reinterpreted()
    {
        var f = new Frame(); f.Envelope.Status = EnvelopeStatus.Draft; f.Other["ProductionHoldControls"] = [new { protectedPayload = "opaque-private-control" }];
        using var sql = f.Sql(); f.Demand(sql);
    }

    [Fact]
    public void Explicit_indefinite_signing_deadline_and_empty_fields_or_recipient_sets_are_supported()
    {
        var f = new Frame(); f.Fields.Clear(); f.Recipients.Clear(); f.FreezeFields(); using var sql = f.Sql(); f.Demand(sql);
    }

    [Theory]
    [InlineData("Dispatched", false)][InlineData("Opened", false)]
    [InlineData("Consented", false)][InlineData("Dispatched", true)]
    [InlineData("Opened", true)][InlineData("Consented", true)]
    public void Exact_first_invitation_opening_and_consent_preserve_frozen_Send_and_original_expired_proof(string stage, bool deadline)
    {
        var f = new Frame(deadline); f.Progress(Enum.Parse<HoldInitialSignerStage>(stage)); f.Captured = f.Captured.AddDays(2);
        f.Signers.Add(new() { EnvelopeId = f.Envelope.Id, Order = 2, Email = "later@example.invalid", FullName = "Synthetic later signer" });
        var expiry = f.Tokens[1].ExpiresAt; var used = f.Tokens[1].UsedAt; var consent = f.Signers[0].ConsentAt;
        using var sql = f.Sql(); f.Demand(sql); using var reverse = f.Sql(reverse: true); f.Demand(reverse);
        Assert.Equal(expiry, f.Tokens[1].ExpiresAt); Assert.Equal(used, f.Tokens[1].UsedAt); Assert.Equal(consent, f.Signers[0].ConsentAt);
        Assert.True(expiry < f.Captured);
    }

    [Theory]
    [InlineData("dispatch-unknown")][InlineData("dispatch-duplicate-property")][InlineData("dispatch-missing-property")][InlineData("dispatch-reordered")]
    [InlineData("dispatch-actor")][InlineData("dispatch-actor-id")][InlineData("dispatch-mailbox")][InlineData("dispatch-ip")][InlineData("dispatch-ua")]
    [InlineData("dispatch-parent")][InlineData("dispatch-email")][InlineData("dispatch-token")][InlineData("dispatch-signer")][InlineData("dispatch-recipient")]
    [InlineData("dispatch-source")][InlineData("dispatch-disclosure")][InlineData("dispatch-provider")][InlineData("dispatch-provider-id")][InlineData("dispatch-meaning")]
    [InlineData("dispatch-duplicate")][InlineData("dispatch-before-sent")][InlineData("dispatch-sequence-before-sent")][InlineData("dispatch-after-capture")][InlineData("dispatch-no-receipt")]
    [InlineData("mail-attempt")][InlineData("mail-status")][InlineData("mail-submission-clock")][InlineData("mail-provider")][InlineData("mail-provider-id")]
    [InlineData("work-status")][InlineData("work-owner")][InlineData("work-lease")][InlineData("work-attempt")][InlineData("work-before-receipt")][InlineData("work-after-capture")]
    [InlineData("token-missing")][InlineData("token-foreign")][InlineData("token-party")][InlineData("token-purpose")][InlineData("token-mailbox")]
    [InlineData("token-source")][InlineData("token-disclosure")][InlineData("token-hash")][InlineData("token-contact")][InlineData("token-expiry-offset")]
    [InlineData("token-expiry-before-submission")][InlineData("token-expiry-beyond-signing")][InlineData("token-hidden-completion")]
    [InlineData("used-without-link")][InlineData("unused-with-link")][InlineData("used-before-submission")][InlineData("link-unknown")][InlineData("link-token")][InlineData("link-duplicate")]
    [InlineData("link-before-dispatch")][InlineData("link-wrong-actor")][InlineData("consent-without-link")][InlineData("consent-unknown")]
    [InlineData("consent-receipt")][InlineData("consent-method")][InlineData("consent-agreement")][InlineData("consent-retention")][InlineData("consent-source")]
    [InlineData("consent-disclosure")][InlineData("consent-attribution")][InlineData("consent-time")][InlineData("consent-duplicate")]
    [InlineData("first-pending-after-dispatch")][InlineData("first-viewed-without-consent")][InlineData("later-notified")][InlineData("later-consent")]
    [InlineData("later-token")][InlineData("future-event")][InlineData("signature-progress")][InlineData("field-progress")][InlineData("resend-event")]
    public void Rehashed_dispatch_or_progress_substitutions_remain_outside_complete_acceptance(string fault)
    {
        var f = new Frame(deadline: true); f.Progress(HoldInitialSignerStage.Consented);
        var dispatch = f.Audits.Single(x => x.Event == "invitation_submitted"); var link = f.Audits.Single(x => x.Event == "link_opened");
        var consent = f.Audits.Single(x => x.Event == "consent_given"); var token = f.Tokens[1];
        switch (fault)
        {
            case "dispatch-unknown": f.EditEvent(dispatch, x => x["hiddenObject"] = Guid.NewGuid()); break;
            case "dispatch-duplicate-property": dispatch.DataJson = dispatch.DataJson[..^1] + ",\"meaning\":\"provider_accepted_not_proof_of_delivery\"}"; break;
            case "dispatch-missing-property": f.EditEvent(dispatch, x => x.Remove("meaning")); break;
            case "dispatch-reordered": var parts = JsonNode.Parse(dispatch.DataJson)!.AsObject().Reverse(); dispatch.DataJson = "{" + string.Join(",", parts.Select(x => JsonSerializer.Serialize(x.Key) + ":" + x.Value!.ToJsonString())) + "}"; break;
            case "dispatch-actor": dispatch.ActorType = PartyType.Sender; break;
            case "dispatch-actor-id": dispatch.ActorId = f.Signers[0].Id; break;
            case "dispatch-mailbox": dispatch.ActorEmail = f.Envelope.SenderEmail; break;
            case "dispatch-ip": dispatch.Ip = "127.0.0.1"; break;
            case "dispatch-ua": dispatch.UserAgent = "synthetic"; break;
            case "dispatch-parent": dispatch.EnvelopeId = Guid.NewGuid(); break;
            case "dispatch-email": f.EditEvent(dispatch, x => x["emailId"] = Guid.NewGuid()); break;
            case "dispatch-token": f.EditEvent(dispatch, x => x["tokenId"] = Guid.NewGuid()); break;
            case "dispatch-signer": f.EditEvent(dispatch, x => x["signerId"] = Guid.NewGuid()); break;
            case "dispatch-recipient": f.EditEvent(dispatch, x => x["recipient"] = "other@example.invalid"); break;
            case "dispatch-source": f.EditEvent(dispatch, x => x["documentSha256"] = new string('a', 64)); break;
            case "dispatch-disclosure": f.EditEvent(dispatch, x => x["disclosureSha256"] = new string('a', 64)); break;
            case "dispatch-provider": f.EditEvent(dispatch, x => x["provider"] = "DifferentSyntheticProvider"); break;
            case "dispatch-provider-id": f.EditEvent(dispatch, x => x["providerMessageId"] = "different-synthetic-id"); break;
            case "dispatch-meaning": f.EditEvent(dispatch, x => x["meaning"] = "delivered"); break;
            case "dispatch-duplicate": f.Audits.Insert(7, Clone(dispatch)); break;
            case "dispatch-before-sent": dispatch.At = f.Sent.At.AddTicks(-1); break;
            case "dispatch-sequence-before-sent": f.Audits.Remove(dispatch); dispatch.At = f.Sent.At; f.Audits.Insert(5, dispatch); break;
            case "dispatch-after-capture": dispatch.At = f.Captured.AddDays(1); break;
            case "dispatch-no-receipt": f.Audits.Remove(dispatch); break;
            case "mail-attempt": f.Invitation.Attempts = 2; break;
            case "mail-status": f.Invitation.Status = EmailStatus.Bounced; break;
            case "mail-submission-clock": f.Invitation.SubmissionStartedAt = dispatch.At.AddSeconds(1); break;
            case "mail-provider": f.Invitation.Provider = "DifferentSyntheticProvider"; break;
            case "mail-provider-id": f.Invitation.ProviderMessageId = null; break;
            case "work-status": f.InvitationWork.Status = WorkStatus.Leased; break;
            case "work-owner": f.InvitationWork.EnvelopeId = Guid.NewGuid(); break;
            case "work-lease": f.InvitationWork.LeaseOwner = Guid.NewGuid(); break;
            case "work-attempt": f.InvitationWork.Attempts = 2; break;
            case "work-before-receipt": f.InvitationWork.AvailableAt = dispatch.At.AddTicks(-1); break;
            case "work-after-capture": f.InvitationWork.AvailableAt = f.Captured.AddDays(1); break;
            case "token-missing": f.Tokens.Remove(token); break;
            case "token-foreign": token.EnvelopeId = Guid.NewGuid(); break;
            case "token-party": token.PartyId = Guid.NewGuid(); break;
            case "token-purpose": token.Purpose = TokenPurpose.CompletionAccess; break;
            case "token-mailbox": token.Email = "other@example.invalid"; break;
            case "token-source": token.DocumentId = Guid.Parse(f.Envelope.PdfBlob!); break;
            case "token-disclosure": token.DisclosureSha256 = SHA256.HashData([9]); break;
            case "token-hash": token.TokenSha256 = new byte[31]; break;
            case "token-contact": token.SignerContactRevisionId = Guid.NewGuid(); break;
            case "token-expiry-offset": token.ExpiresAt = token.ExpiresAt.ToOffset(TimeSpan.FromHours(1)); break;
            case "token-expiry-before-submission": token.ExpiresAt = f.Invitation.SubmissionStartedAt!.Value; break;
            case "token-expiry-beyond-signing": token.ExpiresAt = f.Envelope.ExpiresAt!.Value.AddDays(1); break;
            case "token-hidden-completion": token.CompletionPublicationId = Guid.NewGuid(); break;
            case "used-without-link": f.Audits.Remove(link); f.Audits.Remove(consent); f.Signers[0].ConsentAt = null; f.Signers[0].ConsentIp = null; f.Signers[0].ConsentUa = null; f.Signers[0].Status = SignerStatus.Notified; break;
            case "unused-with-link": token.UsedAt = null; break;
            case "used-before-submission": token.UsedAt = f.Invitation.SubmissionStartedAt!.Value.AddTicks(-1); break;
            case "link-unknown": f.EditEvent(link, x => x["futureFile"] = Guid.NewGuid()); break;
            case "link-token": f.EditEvent(link, x => x["tokenId"] = Guid.NewGuid()); break;
            case "link-duplicate": f.Audits.Insert(8, Clone(link)); break;
            case "link-before-dispatch": f.Audits.Remove(link); f.Audits.Insert(6, link); link.At = f.Sent.At.AddTicks(1); break;
            case "link-wrong-actor": link.ActorId = Guid.NewGuid(); break;
            case "consent-without-link": f.Audits.Remove(link); break;
            case "consent-unknown": f.EditEvent(consent, x => x["futureObject"] = Guid.NewGuid()); break;
            case "consent-receipt": f.EditEvent(consent, x => x["accessReceiptId"] = Guid.Empty); break;
            case "consent-method": f.EditEvent(consent, x => x["accessMethod"] = "future"); break;
            case "consent-agreement": f.EditEvent(consent, x => x["agreement"] = false); break;
            case "consent-retention": f.EditEvent(consent, x => x["canRetain"] = false); break;
            case "consent-source": f.EditEvent(consent, x => x["documentSha256"] = new string('b', 64)); break;
            case "consent-disclosure": f.EditEvent(consent, x => x["disclosureSha256"] = new string('b', 64)); break;
            case "consent-attribution": f.Signers[0].ConsentUa = "different synthetic client"; break;
            case "consent-time": f.Signers[0].ConsentAt = consent.At.AddSeconds(1); break;
            case "consent-duplicate": f.Audits.Add(Clone(consent)); break;
            case "first-pending-after-dispatch": f.Signers[0].Status = SignerStatus.Pending; break;
            case "first-viewed-without-consent": f.Audits.Remove(consent); f.Signers[0].ConsentAt = null; f.Signers[0].ConsentIp = null; f.Signers[0].ConsentUa = null; break;
            case "later-notified": f.Signers.Add(new() { EnvelopeId = f.Envelope.Id, Order = 2, Email = "later@example.invalid", FullName = "Synthetic later", Status = SignerStatus.Notified }); break;
            case "later-consent": f.Signers.Add(new() { EnvelopeId = f.Envelope.Id, Order = 2, Email = "later@example.invalid", FullName = "Synthetic later", ConsentAt = consent.At }); break;
            case "later-token": f.Tokens.Add(new() { EnvelopeId = f.Envelope.Id, Purpose = TokenPurpose.SignerAccess }); break;
            case "future-event": f.Audits.Add(new() { EnvelopeId = f.Envelope.Id, Event = "future_event", ActorType = PartyType.System, At = consent.At }); break;
            case "signature-progress": f.Signers[0].SignatureAdoptionId = Guid.NewGuid(); break;
            case "field-progress": f.Fields.Add(new() { EnvelopeId = f.Envelope.Id, SignerId = f.Signers[0].Id, Type = FieldType.Signature, Value = Guid.NewGuid().ToString("N") }); break;
            case "resend-event": f.Audits.Add(new() { EnvelopeId = f.Envelope.Id, Event = "invitation_resent", ActorType = PartyType.Sender, ActorEmail = f.Envelope.SenderEmail, At = consent.At }); break;
        }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    private static AuditEvent Clone(AuditEvent audit) => JsonSerializer.Deserialize<AuditEvent>(JsonSerializer.Serialize(audit))!;

    [Theory]
    [InlineData("unknown-sent-field")][InlineData("duplicate-sent-field")][InlineData("missing-sent-field")][InlineData("reordered-sent")]
    [InlineData("legacy7")][InlineData("legacy16")][InlineData("noncanonical-guid")][InlineData("false-exclusions")][InlineData("false-confirmation")]
    [InlineData("dispatch")][InlineData("statement-version")][InlineData("statement-text")][InlineData("statement-hash")][InlineData("review-version")]
    [InlineData("document-hash")][InlineData("source-hash")][InlineData("disclosure-hash")][InlineData("disclosure-version")]
    [InlineData("missing-original")][InlineData("missing-source")][InlineData("missing-frozen")][InlineData("foreign-object")][InlineData("changed-object-hash")]
    [InlineData("empty-object")][InlineData("same-frozen-UUID")][InlineData("wrong-actor")][InlineData("actor-id")][InlineData("actor-mailbox")]
    [InlineData("after-capture")][InlineData("sent-before-preview")][InlineData("unverified")][InlineData("preview-missing")][InlineData("non-UTC")]
    [InlineData("at-draft-deadline")][InlineData("nonproduction")][InlineData("terminal")][InlineData("final-fields")][InlineData("current-checkpoint")][InlineData("ack-offset")]
    [InlineData("disclosure-text")][InlineData("changed-retention-notice")][InlineData("policy-row")][InlineData("field-snapshot")]
    [InlineData("no-signers")][InlineData("signer-bound")][InlineData("signer-order")][InlineData("foreign-signer")][InlineData("duplicate-signer")]
    [InlineData("duplicate-signer-mailbox")][InlineData("signer-progress")][InlineData("consent")][InlineData("adoption")][InlineData("decline")]
    [InlineData("assigned-value")][InlineData("field-adoption")][InlineData("foreign-recipient")][InlineData("field-bound")][InlineData("generic-attribution")][InlineData("generic-time")]
    [InlineData("invitation-id")][InlineData("invitation-template")][InlineData("invitation-recipient")][InlineData("invitation-at")]
    [InlineData("invitation-submitted")][InlineData("invitation-attempt")][InlineData("invitation-provider")][InlineData("invitation-lease")]
    [InlineData("invitation-attachments")][InlineData("payload-signer")][InlineData("payload-token")][InlineData("payload-contact")]
    [InlineData("payload-source")][InlineData("payload-disclosure")][InlineData("payload-extra")][InlineData("wrapper-extra")]
    [InlineData("work-owner")][InlineData("work-kind")][InlineData("work-payload")][InlineData("work-status")][InlineData("work-attempt")]
    [InlineData("work-due")][InlineData("unknown-work")][InlineData("unknown-mail")][InlineData("verification-not-completed")]
    [InlineData("verification-attempt")][InlineData("verification-submission")][InlineData("verification-token")][InlineData("extra-token")][InlineData("verification-due")]
    [InlineData("expiry-id")][InlineData("expiry-time")][InlineData("expiry-missing")][InlineData("expiry-payload")][InlineData("expiry-work-due")]
    [InlineData("enabled-reminders")][InlineData("future-reminder-version")][InlineData("unknown-event-tail")]
    public void Rehashed_unknown_inconsistent_progressed_or_out_of_scope_Send_cannot_be_complete(string fault)
    {
        var f = new Frame(fault.StartsWith("expiry-", StringComparison.Ordinal));
        switch (fault)
        {
            case "unknown-sent-field": f.Edit(x => x["hiddenObject"] = Guid.NewGuid()); break;
            case "duplicate-sent-field": f.Sent.DataJson = f.Sent.DataJson[..^1] + ",\"dispatch\":\"queued\"}"; break;
            case "missing-sent-field": f.Edit(x => x.Remove("senderConfirmed")); break;
            case "reordered-sent": f.Sent.DataJson = "{" + string.Join(",", f.SentJson().Reverse().Select(x => JsonSerializer.Serialize(x.Key) + ":" + (x.Value?.ToJsonString() ?? "null"))) + "}"; break;
            case "legacy7": f.Sent.DataJson = "{" + string.Join(",", f.SentJson().Take(7).Select(x => JsonSerializer.Serialize(x.Key) + ":" + x.Value!.ToJsonString())) + "}"; break;
            case "legacy16": f.Edit(x => x.Remove("reminderSchedulingVersion")); break;
            case "noncanonical-guid": f.Sent.DataJson = f.Sent.DataJson.Replace(f.Invitation.Id.ToString(), f.Invitation.Id.ToString().ToUpperInvariant()); break;
            case "false-exclusions": f.Edit(x => x["exclusionsAcknowledged"] = false); break;
            case "false-confirmation": f.Edit(x => x["senderConfirmed"] = false); break;
            case "dispatch": f.Edit(x => x["dispatch"] = "submitted"); break;
            case "statement-version": f.Edit(x => x["senderStatementVersion"] = "future"); break;
            case "statement-text": f.Edit(x => x["senderStatement"] = "Different statement."); break;
            case "statement-hash": f.Edit(x => x["senderStatementSha256"] = new string('c', 64)); break;
            case "review-version": f.Edit(x => x["reviewedVersion"] = Convert.ToBase64String(new byte[7])); break;
            case "document-hash": f.Edit(x => x["documentSha256"] = new string('a', 64)); break;
            case "source-hash": f.Edit(x => x["sourceSha256"] = new string('a', 64)); break;
            case "disclosure-hash": f.Edit(x => x["disclosureSha256"] = new string('a', 64)); break;
            case "disclosure-version": f.Edit(x => x["disclosureVersion"] = ElectronicRecordDisclosure.CurrentVersion); break;
            case "missing-original": f.Objects.RemoveAt(0); break;
            case "missing-source": f.Objects.RemoveAt(1); break;
            case "missing-frozen": f.Objects.RemoveAt(2); break;
            case "foreign-object": f.Objects[2] = f.Objects[2] with { Address = f.Objects[2].Address with { Name = $"{Guid.NewGuid():N}/{f.Envelope.SentPdfBlob}" } }; break;
            case "changed-object-hash": f.Objects[2] = f.Objects[2] with { Sha256 = new string('d', 64) }; break;
            case "empty-object": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Length = 0 } }; break;
            case "same-frozen-UUID": f.Envelope.SentPdfBlob = f.Envelope.PdfBlob; break;
            case "wrong-actor": f.Sent.ActorType = PartyType.System; break;
            case "actor-id": f.Sent.ActorId = Guid.NewGuid(); break;
            case "actor-mailbox": f.Sent.ActorEmail = "other@example.invalid"; break;
            case "after-capture": f.Sent.At = f.Captured.AddSeconds(1); break;
            case "sent-before-preview": f.Envelope.SentAt = f.Envelope.PreviewConfirmedAt!.Value.AddTicks(-1); break;
            case "unverified": f.Envelope.SenderVerifiedAt = null; break;
            case "preview-missing": f.Envelope.PreviewConfirmedAt = null; break;
            case "non-UTC": f.Envelope.SentAt = f.Envelope.SentAt!.Value.ToOffset(TimeSpan.FromHours(1)); break;
            case "ack-offset": f.Envelope.ExclusionsAckAt = f.Envelope.ExclusionsAckAt!.Value.ToOffset(TimeSpan.FromHours(1)); break;
            case "at-draft-deadline": f.Envelope.SentAt = f.Envelope.CreatedAt.AddDays(3); f.Envelope.ExclusionsAckAt = f.Envelope.SentAt; f.Invitation.AvailableAt = f.Envelope.SentAt.Value; f.InvitationWork.AvailableAt = f.Invitation.AvailableAt; f.Audits[^2].At = f.Envelope.SentAt.Value; f.Sent.At = f.Envelope.SentAt.Value; f.Captured = f.Sent.At.AddDays(1); break;
            case "nonproduction": f.Envelope.IsDemo = true; break;
            case "terminal": f.Envelope.Status = EnvelopeStatus.Completed; break;
            case "final-fields": f.Envelope.CertificateBlob = Guid.NewGuid().ToString("N"); break;
            case "current-checkpoint": f.Envelope.CurrentCopyVersion = 1; f.Envelope.CurrentFinishId = Guid.NewGuid(); break;
            case "disclosure-text": f.Envelope.ErsdText += "Changed."; break;
            case "changed-retention-notice": f.Envelope.ErsdText = f.Envelope.ErsdText!.Replace("365 days", "366 days"); f.Envelope.ErsdSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(f.Envelope.ErsdText)); f.Edit(x => x["disclosureSha256"] = Convert.ToHexStringLower(f.Envelope.ErsdSha256)); break;
            case "policy-row": f.Policy.OriginalCreatedAt = f.Policy.OriginalCreatedAt.AddSeconds(1); break;
            case "field-snapshot": f.Fields[0].Value = "Changed."; break;
            case "no-signers": f.Signers.Clear(); break;
            case "signer-bound": while (f.Signers.Count < 101) f.Signers.Add(f.Signers[0]); break;
            case "signer-order": f.Signers[0].Order = 2; break;
            case "foreign-signer": f.Signers[0].EnvelopeId = Guid.NewGuid(); break;
            case "duplicate-signer": f.Signers.Add(f.Signers[0]); break;
            case "duplicate-signer-mailbox": f.Signers.Add(new() { EnvelopeId = f.Envelope.Id, Order = 2, FullName = "Synthetic second", Email = f.Signers[0].Email }); break;
            case "signer-progress": f.Signers[0].Status = SignerStatus.Notified; break;
            case "consent": f.Signers[0].ConsentAt = f.Envelope.SentAt; break;
            case "adoption": f.Signers[0].SignatureAdoptionId = Guid.NewGuid(); break;
            case "decline": f.Signers[0].DeclineReason = "Synthetic reason."; break;
            case "assigned-value": f.Fields.Add(new() { EnvelopeId = f.Envelope.Id, SignerId = f.Signers[0].Id, Type = FieldType.Signature, Value = Guid.NewGuid().ToString("N") }); break;
            case "field-adoption": f.Fields[0].SignatureAdoptionId = Guid.NewGuid(); break;
            case "generic-attribution": f.Fields[0].FilledBy = PartyType.Signer; break;
            case "generic-time": f.Fields[0].FilledAt = f.Envelope.SentAt!.Value.AddSeconds(1); break;
            case "foreign-recipient": f.Recipients[0].EnvelopeId = Guid.NewGuid(); break;
            case "field-bound": while (f.Fields.Count < 201) f.Fields.Add(f.Fields[0]); break;
            case "invitation-id": f.Edit(x => x["invitationWorkId"] = Guid.NewGuid()); break;
            case "invitation-template": f.Invitation.Template = "future-template"; break;
            case "invitation-recipient": f.Invitation.To = f.Envelope.SenderEmail; break;
            case "invitation-at": f.Invitation.AvailableAt = f.Sent.At.AddDays(1); break;
            case "invitation-submitted": f.Invitation.SubmissionStartedAt = f.Envelope.SentAt; break;
            case "invitation-attempt": f.Invitation.Attempts = 1; break;
            case "invitation-provider": f.Invitation.Provider = "SyntheticProvider"; break;
            case "invitation-lease": f.Invitation.LeaseOwner = Guid.NewGuid(); break;
            case "invitation-attachments": f.Invitation.AttachmentsJson = "[{}]"; break;
            case "payload-signer": f.Reprotect(p => p with { SignerId = Guid.NewGuid() }); break;
            case "payload-token": f.Reprotect(p => p with { LastTokenId = Guid.NewGuid() }); break;
            case "payload-contact": f.Reprotect(p => p with { ContactRevisionId = Guid.NewGuid(), ContactRevisionNumber = 1 }); break;
            case "payload-source": f.Reprotect(p => p with { DocumentId = Guid.Parse(f.Envelope.PdfBlob!) }); break;
            case "payload-disclosure": f.Reprotect(p => p with { DisclosureSha256 = new string('e', 64) }); break;
            case "payload-extra": f.Invitation.PayloadJson = JsonSerializer.Serialize(new ProtectedWorkPayload(f.Keys.CreateProtector("QuillSign.SignerInvitationPayload.v1").Protect(JsonSerializer.Serialize(f.Payload)[..^1] + ",\"futureFile\":\"hidden\"}"))); break;
            case "wrapper-extra": f.Invitation.PayloadJson = f.Invitation.PayloadJson[..^1] + ",\"future\":true}"; break;
            case "work-owner": f.InvitationWork.EnvelopeId = Guid.NewGuid(); break;
            case "work-kind": f.InvitationWork.Kind = WorkKind.Sealing; break;
            case "work-payload": f.InvitationWork.PayloadJson = "{\"hidden\":true}"; break;
            case "work-status": f.InvitationWork.Status = WorkStatus.Leased; break;
            case "work-attempt": f.InvitationWork.Attempts = 1; break;
            case "work-due": f.InvitationWork.AvailableAt = f.InvitationWork.AvailableAt.AddSeconds(1); break;
            case "unknown-work": f.Work.Add(new() { EnvelopeId = f.Envelope.Id, Kind = WorkKind.Ai }); break;
            case "unknown-mail": f.Mail.Add(new() { EnvelopeId = f.Envelope.Id, Template = "future" }); break;
            case "verification-not-completed": f.VerificationWork.Status = WorkStatus.Queued; break;
            case "verification-attempt": f.VerificationWork.Attempts++; break;
            case "verification-submission": f.Verification.SubmissionStartedAt = null; break;
            case "verification-token": f.Token.UsedAt = f.Envelope.SenderVerifiedAt!.Value.AddSeconds(1); break;
            case "verification-due": f.VerificationWork.AvailableAt = f.Captured.AddDays(1); break;
            case "extra-token": f.Tokens.Add(new() { EnvelopeId = f.Envelope.Id, Purpose = TokenPurpose.SignerAccess }); break;
            case "expiry-id": f.Edit(x => x["expiryWorkId"] = Guid.NewGuid()); break;
            case "expiry-time": f.Edit(x => x["signingDeadline"] = f.Envelope.ExpiresAt!.Value.AddSeconds(1)); break;
            case "expiry-missing": f.Work.RemoveAt(2); break;
            case "expiry-payload": f.Work[2].PayloadJson = "{}"; break;
            case "expiry-work-due": f.Work[2].AvailableAt = f.Work[2].AvailableAt.AddSeconds(1); break;
            case "enabled-reminders": var policy = SignerReminderPolicy.FromDays([3, 7]); f.Edit(x => { x["reminderPolicy"] = policy.CanonicalJson; x["reminderPolicySha256"] = policy.Sha256; }); break;
            case "future-reminder-version": f.Edit(x => x["reminderSchedulingVersion"] = "future"); break;
            case "unknown-event-tail": f.Audits.Add(new() { EnvelopeId = f.Envelope.Id, Event = "future_event", ActorType = PartyType.System, At = f.Sent.At.AddSeconds(1) }); break;
        }
        f.Rehash(); using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Theory]
    [InlineData("SignaturePreviews")][InlineData("SignerReviewCandidates")][InlineData("SignerFinishAcceptances")]
    [InlineData("SignerContactRevisions")][InlineData("SignerContactSessions")][InlineData("CompletionCandidates")]
    [InlineData("CompletionSealOutputs")][InlineData("CompletionPublicationIntents")][InlineData("CompletionPublicationResults")]
    [InlineData("ProductionRetentionTerminals")][InlineData("DocumentRetentionSnapshots")]
    public void Explicitly_deferred_owned_progress_cannot_enter_initial_Sent_acceptance(string table)
    {
        var f = new Frame(); f.Other[table] = [new { Id = Guid.NewGuid() }]; using var sql = f.Sql();
        Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    private sealed class Frame
    {
        private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider();
        internal readonly Envelope Envelope;
        internal DateTimeOffset Captured;
        internal readonly ProductionRetentionPolicyRecord Policy;
        internal readonly List<Signer> Signers = [];
        internal readonly List<Recipient> Recipients = [];
        internal readonly List<DocumentField> Fields = [];
        internal readonly List<AuditEvent> Audits = [];
        internal readonly List<HoldObjectEvidence> Objects = [];
        internal readonly List<EmailOutbox> Mail = [];
        internal readonly List<WorkItem> Work = [];
        internal readonly List<AuthToken> Tokens = [];
        internal readonly Dictionary<string, object[]> Other = new(StringComparer.Ordinal);
        internal EmailOutbox Invitation => Mail[1]; internal EmailOutbox Verification => Mail[0];
        internal WorkItem InvitationWork => Work[1]; internal WorkItem VerificationWork => Work[0];
        internal AuthToken Token => Tokens[0]; internal AuditEvent Sent => Audits[5];
        internal SignerInvitationPayload Payload => new SignerInvitationProtection(Keys).Read(Invitation.PayloadJson);
        internal Frame(bool deadline = false)
        {
            var created = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero); Captured = created.AddDays(1);
            Envelope = new() { CreatedAt = created, SenderEmail = "sender@example.invalid", Title = "Synthetic NO AGREEMENT", Status = EnvelopeStatus.Sent,
                SenderVerifiedAt = created.AddMinutes(5), PreviewConfirmedAt = created.AddMinutes(6), SentAt = created.AddMinutes(10), ExclusionsAckAt = created.AddMinutes(10),
                OriginalBlob = Guid.NewGuid().ToString("N"), OriginalSha256 = SHA256.HashData([1]), OriginalMime = "application/pdf",
                PdfBlob = Guid.NewGuid().ToString("N"), PdfSha256 = SHA256.HashData([2]), SentPdfBlob = Guid.NewGuid().ToString("N"), SentPdfSha256 = SHA256.HashData([3]),
                PageCount = 1, PageSizesJson = "[]", RowVersion = Enumerable.Repeat((byte)2, 8).ToArray(), ExpiresAt = deadline ? created.AddDays(30) : null };
            var frozen = ProductionRetentionPolicyContract.Freeze(Envelope.Id, created, ProductionRetentionAdmissionContractTests.Settings().Production);
            Policy = new() { EnvelopeId = Envelope.Id, OriginalCreatedAt = created, EnrolledAt = created, PolicyJson = ProductionRetentionPolicyContract.Serialize(frozen),
                PolicySha256 = ProductionRetentionPolicyContract.Digest(frozen), AuditSequence = 1, AuditHash = new byte[32],
                OriginSha256 = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { Envelope.Id, Envelope.PublicId, Envelope.SenderEmail, Envelope.CreatedAt, Envelope.IsDemo })) };
            var disclosure = new ElectronicRecordDisclosure(ProductionRetentionAdmissionContractTests.Policies()).BuildProduction(Envelope, Envelope.Title,
                new(frozen, created, created, 1, new string('a', 64)));
            Envelope.ErsdVersion = disclosure.Version; Envelope.ErsdText = disclosure.Text; Envelope.ErsdSha256 = disclosure.Sha256;
            Signers.Add(new() { EnvelopeId = Envelope.Id, Order = 1, FullName = "Synthetic signer", Email = "signer@example.invalid" });
            Recipients.Add(new() { EnvelopeId = Envelope.Id, Name = "Synthetic recipient", Email = "recipient@example.invalid" });
            Fields.Add(new() { EnvelopeId = Envelope.Id, Type = FieldType.Text, Value = Guid.NewGuid().ToString("N"), FilledBy = PartyType.Sender,
                FilledAt = created.AddMinutes(7), Page = 1, X = .10000000m, Y = .20000000m, Width = .30000000m, Height = .10000000m });
            foreach (var name in new[] { ProductionRetentionLedger.EnrollmentEvent, "draft_created", "sender_verification_requested", "sender_email_verified", "fields_finalized", "sent" })
                Audits.Add(new() { EnvelopeId = Envelope.Id, Event = name, ActorType = name == ProductionRetentionLedger.EnrollmentEvent ? PartyType.System : PartyType.Sender,
                    ActorEmail = name == ProductionRetentionLedger.EnrollmentEvent ? null : Envelope.SenderEmail,
                    At = name == "sender_email_verified" ? Envelope.SenderVerifiedAt.Value : name is "fields_finalized" or "sent" ? Envelope.SentAt.Value.AddSeconds(name == "sent" ? 2 : 1) : created });
            Audits[0].DataJson = JsonSerializer.Serialize(new { version = "production-retention-enrollment-v1", Policy.EnvelopeId, Policy.OriginalCreatedAt,
                Policy.EnrolledAt, Policy.PolicySha256, originSha256 = Convert.ToHexStringLower(Policy.OriginSha256) });
            var raw = WebEncoders.Base64UrlEncode(Enumerable.Repeat((byte)7, 32).ToArray());
            Tokens.Add(new() { EnvelopeId = Envelope.Id, Purpose = TokenPurpose.SenderVerify, PartyType = PartyType.Sender, Email = Envelope.SenderEmail,
                TokenSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(raw)), UsedAt = Envelope.SenderVerifiedAt, ExpiresAt = created.AddMinutes(18) });
            Mail.Add(new() { EnvelopeId = Envelope.Id, Template = "sender-verification", To = Envelope.SenderEmail, AvailableAt = created, Status = EmailStatus.Sent,
                Attempts = 1, SubmissionStartedAt = created.AddMinutes(3), Provider = "SyntheticCapture", ProviderMessageId = "synthetic-receipt",
                PayloadJson = new EmailPayloadProtection(Keys).Protect(new(raw, Token.Id)) });
            Mail.Add(new() { Id = Guid.Parse("abcdef01-2345-6789-abcd-ef0123456789"), EnvelopeId = Envelope.Id, Template = "signer-invitation", To = Signers[0].Email, AvailableAt = Envelope.SentAt.Value,
                PayloadJson = new SignerInvitationProtection(Keys).Protect(new(Signers[0].Id, DocumentId: Guid.Parse(Envelope.SentPdfBlob),
                    DocumentSha256: Convert.ToHexStringLower(Envelope.SentPdfSha256), DisclosureSha256: Convert.ToHexStringLower(Envelope.ErsdSha256))) });
            Work.Add(new() { Id = Verification.Id, EnvelopeId = Envelope.Id, Kind = WorkKind.Email, Status = WorkStatus.Completed, Attempts = 1,
                AvailableAt = created.AddMinutes(4), PayloadJson = JsonSerializer.Serialize(new { emailId = Verification.Id }) });
            Work.Add(new() { Id = Invitation.Id, EnvelopeId = Envelope.Id, Kind = WorkKind.Email, AvailableAt = Invitation.AvailableAt });
            if (Envelope.ExpiresAt is { } due) Work.Add(new() { Id = SigningExpiryJobs.WorkId(Envelope.Id), EnvelopeId = Envelope.Id, Kind = WorkKind.Expiry,
                AvailableAt = due, PayloadJson = SigningExpiryJobs.Bind(Envelope) });
            foreach (var table in new[] { "SignaturePreviews", "SignerReviewCandidates", "SignerFinishAcceptances", "SignerContactRevisions", "SignerContactSessions",
                "CompletionCandidates", "CompletionSealOutputs", "CompletionPublicationIntents", "CompletionPublicationResults", "ProductionRetentionTerminals", "DocumentRetentionSnapshots",
                "ProductionHoldRequests", "ProductionHoldControls" }) Other[table] = [];
            Objects.Add(Object("originals", Envelope.OriginalBlob, Envelope.OriginalSha256)); Objects.Add(Object("normalized", Envelope.PdfBlob, Envelope.PdfSha256));
            Objects.Add(Object("normalized", Envelope.SentPdfBlob, Envelope.SentPdfSha256));
            FreezeFields();
            var reminder = SignerReminderPolicy.FromDays([]);
            Sent.DataJson = JsonSerializer.Serialize(new { documentSha256 = Convert.ToHexStringLower(Envelope.SentPdfSha256), sourceSha256 = Convert.ToHexStringLower(Envelope.PdfSha256),
                disclosureVersion = Envelope.ErsdVersion, disclosureSha256 = Convert.ToHexStringLower(Envelope.ErsdSha256), invitationWorkId = Invitation.Id, dispatch = "queued", exclusionsAcknowledged = true,
                expiryWorkId = Envelope.ExpiresAt is null ? (Guid?)null : SigningExpiryJobs.WorkId(Envelope.Id), signingDeadline = Envelope.ExpiresAt,
                reviewedVersion = Convert.ToBase64String(Enumerable.Repeat((byte)1, 8).ToArray()), senderConfirmed = true,
                senderStatementVersion = SenderSendStatement.Version, senderStatement = SenderSendStatement.Text, senderStatementSha256 = SenderSendStatement.Sha256,
                reminderPolicy = reminder.CanonicalJson, reminderPolicySha256 = reminder.Sha256, reminderSchedulingVersion = SignerReminderEvidence.Version });
            Rehash();
        }
        private HoldObjectEvidence Object(string area, string id, byte[] hash) => new(new(area, $"{Envelope.Id:N}/{id}", "synthetic-version", "", "\"synthetic-etag\"", 10), Convert.ToHexStringLower(hash));
        internal void FreezeFields()
        {
            var snapshot = JsonSerializer.SerializeToUtf8Bytes(Fields.OrderBy(x => new SqlGuid(x.Id)).Select(x => new { x.Id, x.SignerId, x.Type, x.Page, x.X, x.Y, x.Width, x.Height, x.Required, x.Label, x.Value }));
            Audits[4].DataJson = JsonSerializer.Serialize(new { fieldSnapshotSha256 = Convert.ToHexStringLower(SHA256.HashData(snapshot)), fieldCount = Fields.Count, documentSha256 = Convert.ToHexStringLower(Envelope.SentPdfSha256!) });
            Rehash();
        }
        internal JsonObject SentJson() => JsonNode.Parse(Sent.DataJson)!.AsObject();
        internal void Edit(Action<JsonObject> edit) { var p = SentJson(); edit(p); Sent.DataJson = p.ToJsonString(); }
        internal void Reprotect(Func<SignerInvitationPayload, SignerInvitationPayload> edit) => Invitation.PayloadJson = new SignerInvitationProtection(Keys).Protect(edit(Payload));
        internal void EditEvent(AuditEvent audit, Action<JsonObject> edit)
        { var p = JsonNode.Parse(audit.DataJson)!.AsObject(); edit(p); audit.DataJson = p.ToJsonString(); }
        internal void Progress(HoldInitialSignerStage stage)
        {
            if (stage == HoldInitialSignerStage.Queued) return;
            var at = Sent.At.AddMinutes(1); var first = Signers[0]; first.Status = SignerStatus.Notified;
            var token = new AuthToken { EnvelopeId = Envelope.Id, PartyId = first.Id, PartyType = PartyType.Signer, Purpose = TokenPurpose.SignerAccess,
                Email = first.Email, DocumentId = Guid.Parse(Envelope.SentPdfBlob!), DocumentSha256 = Envelope.SentPdfSha256!, DisclosureSha256 = Envelope.ErsdSha256!,
                TokenSha256 = SHA256.HashData("Synthetic first invitation link"u8), ExpiresAt = at.AddHours(24) };
            Tokens.Add(token); Reprotect(p => p with { LastTokenId = token.Id });
            Invitation.SubmissionStartedAt = at; Invitation.Attempts = 1; Invitation.Status = EmailStatus.Sent;
            Invitation.Provider = "SyntheticCapture"; Invitation.ProviderMessageId = "synthetic-invitation-receipt";
            InvitationWork.Status = WorkStatus.Completed; InvitationWork.Attempts = 1; InvitationWork.AvailableAt = at.AddSeconds(2);
            Audits.Add(new() { EnvelopeId = Envelope.Id, Event = "invitation_submitted", ActorType = PartyType.System, At = at.AddSeconds(1),
                DataJson = JsonSerializer.Serialize(new { emailId = Invitation.Id, tokenId = token.Id, documentSha256 = Payload.DocumentSha256,
                    disclosureSha256 = Payload.DisclosureSha256, signerId = first.Id, recipient = first.Email, provider = Invitation.Provider,
                    providerMessageId = Invitation.ProviderMessageId, meaning = "provider_accepted_not_proof_of_delivery" }) });
            if (stage != HoldInitialSignerStage.Dispatched)
            {
                token.UsedAt = at.AddMinutes(1);
                Audits.Add(new() { EnvelopeId = Envelope.Id, Event = "link_opened", ActorType = PartyType.Signer, ActorId = first.Id, ActorEmail = first.Email,
                    At = token.UsedAt.Value.AddTicks(1), Ip = "127.0.0.1", UserAgent = "synthetic-link",
                    DataJson = JsonSerializer.Serialize(new { signerId = first.Id, tokenId = token.Id, documentId = token.DocumentId!.Value,
                        documentSha256 = Payload.DocumentSha256, disclosureSha256 = Payload.DisclosureSha256, authentication = "single_use_email_link" }) });
            }
            if (stage == HoldInitialSignerStage.Consented)
            {
                first.Status = SignerStatus.Viewed; first.ConsentAt = at.AddMinutes(2); first.ConsentIp = "127.0.0.1"; first.ConsentUa = "synthetic-consent";
                Audits.Add(new() { EnvelopeId = Envelope.Id, Event = "consent_given", ActorType = PartyType.Signer, ActorId = first.Id, ActorEmail = first.Email,
                    At = first.ConsentAt.Value.AddTicks(1), Ip = first.ConsentIp, UserAgent = first.ConsentUa,
                    DataJson = JsonSerializer.Serialize(new { disclosureVersion = Envelope.ErsdVersion, disclosureSha256 = Payload.DisclosureSha256,
                        documentSha256 = Payload.DocumentSha256, accessReceiptId = Guid.NewGuid(), accessMethod = "preview", agreement = true, canRetain = true,
                        serverEvidence = "hash_verified_pdf_prepared", clientEvidence = "signer_reported_access_and_retention" }) });
            }
            Rehash();
        }
        internal void Rehash()
        {
            byte[]? previous = null;
            for (var i = 0; i < Audits.Count; i++) { var row = Audits[i]; row.Id = 100 + i * 7; row.Sequence = i + 1; row.PrevHash = previous; row.Hash = AuditHash.Compute(row); previous = row.Hash; }
            Policy.AuditHash = Audits[0].Hash;
        }
        internal JsonDocument Sql(bool reverse = false)
        {
            var data = new Dictionary<string, object> { ["Envelopes"] = new[] { Envelope }, ["AuditEvents"] = reverse ? Audits.AsEnumerable().Reverse().ToArray() : Audits.ToArray(),
                ["ProductionRetentionPolicies"] = new[] { Policy }, ["Signers"] = Signers.ToArray(), ["Recipients"] = Recipients.ToArray(), ["Fields"] = Fields.ToArray(),
                ["AuthTokens"] = Tokens.ToArray(), ["EmailOutbox"] = Mail.ToArray(), ["WorkItems"] = Work.ToArray() };
            foreach (var pair in Other) data[pair.Key] = pair.Value;
            return JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, CapturedAt = Captured,
                Tables = (reverse ? data.Reverse() : data).Select(x => new { Table = x.Key, Rows = x.Value }) }, Rows));
        }
        internal void Demand(JsonDocument sql) => ProductionHoldSentAuditReferences.Demand(sql.RootElement, Objects, Keys);
    }
}

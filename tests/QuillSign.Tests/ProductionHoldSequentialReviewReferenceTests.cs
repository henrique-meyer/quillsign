using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldSequentialReviewReferenceTests
{
    [Theory]
    [InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)][InlineData(5)]
    public void Every_original_party_stays_exact_through_second_dispatch_consent_marks_review_acceptance_and_last_checkpoint(int stage)
    {
        var f = new SequentialFrame(); f.First(); var old = f.Frame.Inputs.Single().Body.OriginalSnapshotJson;
        f.Dispatch(1, stage == 0 ? HoldInitialSignerStage.Dispatched : HoldInitialSignerStage.Consented);
        if (stage >= 2) f.Marks(1);
        if (stage >= 3) f.Frame.Review(party: 1);
        if (stage >= 4) f.Frame.Accept();
        if (stage >= 5) f.Frame.Process();
        var history = f.Frame.Demand(); Assert.Equal(stage >= 3 ? 2 : 1, history.Reviews.Count);
        Assert.Equal(stage >= 2 ? 2 : 1, history.Previews.Count);
        Assert.Equal(old, history.Reviews.Single(x => x.SignerId == f.F.Signers[0].Id).Input.Body.OriginalSnapshotJson);
        Assert.Equal(stage >= 5 ? 2 : 1, f.F.Envelope.CurrentCopyVersion);
        Assert.Equal(stage >= 5 ? 1 : 0, f.F.Work.Count(x => x.Kind == WorkKind.Sealing));
    }

    [Theory]
    [InlineData(1)][InlineData(3)]
    public void Product_is_bounded_sequential_not_exactly_two_parties(int count)
    {
        var f = new SequentialFrame(count);
        for (var party = 0; party < count; party++)
        {
            if (party > 0) { f.Dispatch(party, HoldInitialSignerStage.Consented); f.Marks(party); }
            f.Frame.Review(party: party); f.Frame.Accept(); f.Frame.Process();
            Assert.Equal(party + 1, f.Frame.Demand().Reviews.Count);
        }
        Assert.Equal(count, f.F.Envelope.CurrentCopyVersion); Assert.Single(f.F.Work, x => x.Kind == WorkKind.Sealing);
    }

    [Fact]
    public void Two_original_large_Unicode_inputs_keep_the_global_200_field_bound_without_inlining_witness_payloads()
    {
        var f = new SequentialFrame(additionalTextFields: 189); f.First(); f.Dispatch(1, HoldInitialSignerStage.Consented); f.Marks(1, large: true);
        f.Frame.Review(party: 1); f.Frame.Accept(); f.Frame.Process(); var history = f.Frame.Demand();
        Assert.Equal(200, f.F.Fields.Count); Assert.Equal(2, history.Reviews.Count);
        Assert.All(history.Reviews, x => Assert.True(Encoding.UTF8.GetByteCount(x.Input.Body.OriginalSnapshotJson) > 65536));
        Assert.Equal(191, history.Reviews.Sum(x => x.Input.Snapshot.fields.Count(y => y.Type == FieldType.Text)));
    }

    [Theory]
    [InlineData("old-review-missing")][InlineData("old-review-actor")][InlineData("old-date")][InlineData("old-field-time")]
    [InlineData("old-source")][InlineData("next-id")][InlineData("second-preview-source")][InlineData("second-token-source")]
    [InlineData("second-token-expiry")][InlineData("second-submitted-schema")][InlineData("second-provider")][InlineData("second-order")]
    [InlineData("second-consent-source")][InlineData("second-review-source")][InlineData("second-review-cut")][InlineData("second-prepared-actor")]
    [InlineData("second-used")][InlineData("second-finish-statement")][InlineData("second-copy")][InlineData("current-head")]
    [InlineData("last-next-id")][InlineData("sealing-payload")][InlineData("sealing-attempt")][InlineData("sealing-kind")]
    [InlineData("sealing-lease")][InlineData("sealing-time")][InlineData("extra-mail")][InlineData("extra-token")][InlineData("unknown-tail")]
    public void Rehashed_old_and_new_party_substitutions_never_become_complete_preservation(string fault)
    {
        var f = new SequentialFrame(); f.First(); f.Dispatch(1, HoldInitialSignerStage.Consented); f.Marks(1); f.Frame.Review(party: 1); f.Frame.Accept(); f.Frame.Process();
        var first = f.Frame.Finishes[0]; var second = f.Frame.Finishes[1]; var later = f.F.Signers[1];
        var mail = f.F.Mail.Single(x => x.Id == first.NextInvitationId); var token = f.F.Tokens.Single(x => x.PartyId == later.Id);
        var sealing = f.F.Work.Single(x => x.Kind == WorkKind.Sealing);
        switch (fault)
        {
            case "old-review-missing": f.Frame.Inputs.RemoveAt(0); break;
            case "old-review-actor": f.F.Audits.First(x => x.Event == "signer_review_prepared").ActorId = later.Id; break;
            case "old-date": f.F.Fields.Single(x => x.SignerId == first.SignerId && x.Type == FieldType.DateSigned).Value = "2031-01-01"; break;
            case "old-field-time": f.F.Fields.First(x => x.SignerId == first.SignerId && x.Type == FieldType.Signature).FilledAt = first.FinishedAt; break;
            case "old-source": first.PdfSha256 = SHA256.HashData([9]); break;
            case "next-id": first.NextInvitationId = Guid.NewGuid(); break;
            case "second-preview-source": f.Frame.M.Previews[^1].DocumentId = Guid.Parse(f.F.Envelope.SentPdfBlob!); break;
            case "second-token-source": token.DocumentId = Guid.Parse(f.F.Envelope.SentPdfBlob!); break;
            case "second-token-expiry": token.ExpiresAt = token.UsedAt!.Value; break;
            case "second-submitted-schema": f.F.EditEvent(f.F.Audits.Last(x => x.Event == "invitation_submitted"), x => x["future"] = true); break;
            case "second-provider": mail.ProviderMessageId = "changed"; break;
            case "second-order": later.Order = 3; break;
            case "second-consent-source": f.F.EditEvent(f.F.Audits.Last(x => x.Event == "consent_given"), x => x["documentSha256"] = Hex(f.F.Envelope.SentPdfSha256!)); break;
            case "second-review-source": f.Frame.Candidates[^1].SourceObjectId = Guid.Parse(f.F.Envelope.SentPdfBlob!); break;
            case "second-review-cut": f.F.Audits.Last(x => x.Event == "signer_review_prepared").DataJson = "{}"; break;
            case "second-prepared-actor": f.F.Audits.Last(x => x.Event == "signer_review_prepared").ActorEmail = f.F.Envelope.SenderEmail; break;
            case "second-used": f.Frame.Candidates[^1].UsedAt = null; break;
            case "second-finish-statement": second.Statement = "different"; break;
            case "second-copy": f.F.Envelope.CurrentCopyVersion = 1; break;
            case "current-head": f.F.Envelope.CurrentFinishId = first.Id; break;
            case "last-next-id": second.NextInvitationId = Guid.NewGuid(); break;
            case "sealing-payload": sealing.PayloadJson = JsonSerializer.Serialize(new CompletionWorkPayload(CompletionJobs.Version, first.Id, 2, Hex(first.PdfSha256), Hex(first.DisclosureSha256))); break;
            case "sealing-attempt": sealing.Attempts = 1; break;
            case "sealing-kind": sealing.Kind = WorkKind.Rendering; break;
            case "sealing-lease": sealing.LeaseOwner = Guid.NewGuid(); break;
            case "sealing-time": sealing.AvailableAt = second.ProcessedAt!.Value.AddTicks(-1); break;
            case "extra-mail": f.F.Mail.Add(new() { EnvelopeId = f.F.Envelope.Id, Template = "signer-invitation", To = later.Email }); break;
            case "extra-token": f.F.Tokens.Add(new() { EnvelopeId = f.F.Envelope.Id, Purpose = TokenPurpose.SignerAccess, PartyId = later.Id }); break;
            case "unknown-tail": f.Frame.PartyEvent(later, "future_stage", "{}", f.F.Audits.Last().At.AddTicks(1)); break;
        }
        f.Frame.Sync(); Assert.Throws<InvalidDataException>(() => f.Frame.Demand());
    }

    [Fact]
    public void Exact_missing_completion_job_repair_uses_original_processed_time_without_a_new_deadline()
    {
        var f = new SequentialFrame(); f.First(); f.Dispatch(1, HoldInitialSignerStage.Consented); f.Marks(1); f.Frame.Review(party: 1); f.Frame.Accept(); f.Frame.Process();
        var last = f.Frame.Finishes[^1]; var job = f.F.Work.Single(x => x.Kind == WorkKind.Sealing); job.AvailableAt = last.ProcessedAt!.Value;
        Assert.True(f.Frame.Demand().Processed); Assert.Equal(last.ProcessedAt, job.AvailableAt);
    }

    [Fact]
    public void Prepared_unused_previews_are_bounded_per_party_with_the_same_global_SQL_limit()
    {
        var f = new SequentialFrame(3);
        for (var party = 0; party < 3; party++)
        {
            if (party > 0) { f.Dispatch(party, HoldInitialSignerStage.Consented); f.Marks(party); }
            f.Frame.Review(party: party); f.Frame.Accept(); f.Frame.Process();
        }
        foreach (var used in f.Frame.M.Previews.ToArray())
            for (var index = 0; index < 2; index++)
            {
                var p = Clone(used); p.Id = Guid.NewGuid(); p.SignatureObjectId = Guid.NewGuid(); p.InitialsObjectId = Guid.NewGuid();
                p.CreatedAt = used.CreatedAt.AddTicks(index + 1); p.UsedAt = null; f.Frame.M.Previews.Add(p);
                foreach (var (id, hash) in new[] { (p.SignatureObjectId, p.SignatureSha256), (p.InitialsObjectId, p.InitialsSha256) })
                    f.F.Objects.Add(new(new("normalized", $"{f.F.Envelope.Id:N}/{id:N}", "synthetic-mark-version", "", "\"synthetic-mark-etag\"", 100), Hex(hash)));
            }
        f.Frame.Sync(); Assert.Equal(9, f.Frame.Demand().Previews.Count);
    }
    [Theory]
    [InlineData("candidate-columns")][InlineData("per-party-candidates")][InlineData("total-rows")][InlineData("late-preview")]
    public void Unknown_shapes_and_original_per_owner_or_total_limits_do_not_expand_with_roster_size(string fault)
    {
        var f = new SequentialFrame(); f.First(); f.Dispatch(1, HoldInitialSignerStage.Consented); f.Marks(1); f.Frame.Review(party: 1); f.Frame.Accept(); f.Frame.Process();
        if (fault == "candidate-columns")
        {
            using var original = f.F.Sql(); var body = System.Text.Json.Nodes.JsonNode.Parse(original.RootElement.GetRawText())!;
            body["Tables"]!.AsArray().Single(x => x!["Table"]!.GetValue<string>() == "SignerReviewCandidates")!["Rows"]![0]!["future"] = true;
            using var altered = JsonDocument.Parse(body.ToJsonString());
            Assert.Throws<InvalidDataException>(() => ProductionHoldReviewCheckpointReferences.ReadVerified(altered.RootElement, f.F.Objects, f.F.Keys, f.Frame.Inputs)); return;
        }
        if (fault == "per-party-candidates")
            for (var index = 0; index < SignerReviewCandidates.MaximumCandidatesPerSigner; index++)
            {
                var row = Clone(f.Frame.Candidates[^1]); row.Id = Guid.NewGuid(); row.PdfObjectId = Guid.NewGuid(); f.Frame.Candidates.Add(row);
            }
        else if (fault == "total-rows")
            while (f.F.Work.Count < 4096) f.F.Work.Add(Clone(f.F.Work[0]));
        else f.Frame.M.Previews[0].CreatedAt = f.Frame.Finishes[0].FinishedAt.AddTicks(1);
        f.Frame.Sync(); Assert.Throws<InvalidDataException>(() => f.Frame.Demand());
    }

    [Theory]
    [InlineData(1, false)][InlineData(1, true)][InlineData(2, false)][InlineData(2, true)][InlineData(3, true)]
    public void Accepted_before_frozen_deadline_may_drain_at_or_after_it_without_a_new_party_invitation(int parties, bool later)
    {
        var f = new SequentialFrame(parties); var deadline = Deadline(f); f.Frame.Review(); f.Frame.Accept();
        Assert.True(f.Frame.Acceptance!.FinishedAt < deadline); Assert.Equal(deadline, f.Frame.Candidates[0].ExpiresAt);
        f.Frame.Process(later ? deadline.AddMinutes(1) : deadline); var history = f.Frame.Demand();
        Assert.True(history.Processed); Assert.Null(history.NextInvitationId); Assert.Single(history.Reviews);
        Assert.Equal(1, f.F.Envelope.CurrentCopyVersion); Assert.Equal(2, f.F.Mail.Count);
        Assert.Equal(parties == 1 ? 1 : 0, f.F.Work.Count(x => x.Kind == WorkKind.Sealing));
        Assert.All(f.F.Signers.Skip(1), x => { Assert.Equal(SignerStatus.Pending, x.Status); Assert.Null(x.ConsentAt); Assert.Null(x.SignatureAdoptionId); });
    }
    [Fact]
    public void Late_drain_cannot_manufacture_a_new_initial_invitation_after_original_deadline()
    {
        var f = new SequentialFrame(); var deadline = Deadline(f); f.Frame.Review(); f.Frame.Accept(); f.Frame.Process(deadline);
        var finish = f.Frame.Acceptance!; finish.NextInvitationId = Guid.NewGuid(); var due = deadline.AddTicks(2); var target = f.F.Signers[1];
        f.F.Mail.Add(new() { Id = finish.NextInvitationId.Value, EnvelopeId = f.F.Envelope.Id, Template = "signer-invitation", To = target.Email, AvailableAt = due,
            PayloadJson = new SignerInvitationProtection(f.F.Keys).Protect(new(target.Id, DocumentId: finish.PdfObjectId, DocumentSha256: Hex(finish.PdfSha256), DisclosureSha256: Hex(finish.DisclosureSha256))) });
        f.F.Work.Add(new() { Id = finish.NextInvitationId.Value, EnvelopeId = f.F.Envelope.Id, Kind = WorkKind.Email, AvailableAt = due });
        f.F.Audits.Single(x => x.Event == "signer_completed").DataJson = SignerCheckpointState.PublishedJson(finish); f.Frame.Sync();
        Assert.Throws<InvalidDataException>(() => f.Frame.Demand());
    }
    [Fact]
    public void Late_processing_does_not_excuse_a_Finish_accepted_at_the_expired_deadline()
    {
        var f = new SequentialFrame(); var deadline = Deadline(f); f.Frame.Review(); f.Frame.Accept(); var finish = f.Frame.Acceptance!;
        finish.FinishedAt = deadline; f.Frame.Candidates[0].UsedAt = deadline;
        f.F.Audits.Single(x => x.Event == "signer_finish_accepted").DataJson = SignerFinish.EvidenceJson(finish); f.Frame.Process(deadline.AddMinutes(1));
        Assert.Throws<InvalidDataException>(() => f.Frame.Demand());
    }
    private static DateTimeOffset Deadline(SequentialFrame f)
    {
        var deadline = f.F.Audits.Last().At.AddMinutes(2); var e = f.F.Envelope; e.ExpiresAt = deadline;
        foreach (var token in f.F.Tokens.Where(x => x.Purpose == TokenPurpose.SignerAccess)) token.ExpiresAt = deadline;
        foreach (var preview in f.Frame.M.Previews.Where(x => x.ExpiresAt > deadline)) preview.ExpiresAt = deadline;
        var work = SigningExpiryJobs.WorkId(e.Id); f.F.Edit(x => { x["expiryWorkId"] = work; x["signingDeadline"] = System.Text.Json.Nodes.JsonValue.Create(deadline); });
        f.F.Work.Add(new() { Id = work, EnvelopeId = e.Id, Kind = WorkKind.Expiry, AvailableAt = deadline, PayloadJson = SigningExpiryJobs.Bind(e) });
        f.Frame.Sync(); return deadline;
    }

    private sealed class SequentialFrame
    {
        internal readonly ProductionHoldReviewCheckpointReferenceTests.Frame Frame;
        internal ProductionHoldSentAuditReferenceTests.Frame F => Frame.F;
        internal SequentialFrame(int count = 2, int additionalTextFields = 0) => Frame = new(parties: count, laterFields: true, additionalTextFields: additionalTextFields);
        internal void First() { Frame.Review(); Frame.Accept(); Frame.Process(); }
        internal void Dispatch(int party, HoldInitialSignerStage stage)
        {
            var signer = F.Signers[party]; var previous = Frame.Finishes.Single(x => x.SignerId == F.Signers[party - 1].Id);
            var mail = F.Mail.Single(x => x.Id == previous.NextInvitationId); var work = F.Work.Single(x => x.Id == mail.Id);
            var at = F.Audits.Last().At.AddSeconds(1); signer.Status = SignerStatus.Notified;
            var payload = new SignerInvitationProtection(F.Keys).Read(mail.PayloadJson);
            var token = new AuthToken { EnvelopeId = F.Envelope.Id, PartyId = signer.Id, PartyType = PartyType.Signer, Purpose = TokenPurpose.SignerAccess,
                Email = signer.Email, DocumentId = previous.PdfObjectId, DocumentSha256 = previous.PdfSha256, DisclosureSha256 = previous.DisclosureSha256,
                TokenSha256 = SHA256.HashData("Synthetic later initial token"u8), ExpiresAt = at.AddHours(24) };
            F.Tokens.Add(token); mail.PayloadJson = new SignerInvitationProtection(F.Keys).Protect(payload with { LastTokenId = token.Id });
            mail.Status = EmailStatus.Sent; mail.Attempts = 1; mail.SubmissionStartedAt = at; mail.Provider = "SyntheticCapture"; mail.ProviderMessageId = $"synthetic-party-{party}";
            work.Status = WorkStatus.Completed; work.Attempts = 1; work.AvailableAt = at.AddTicks(2);
            F.Audits.Add(new() { EnvelopeId = F.Envelope.Id, Event = "invitation_submitted", ActorType = PartyType.System, At = at.AddTicks(1),
                DataJson = JsonSerializer.Serialize(new { emailId = mail.Id, tokenId = token.Id, documentSha256 = payload.DocumentSha256, disclosureSha256 = payload.DisclosureSha256,
                    signerId = signer.Id, recipient = signer.Email, provider = mail.Provider, providerMessageId = mail.ProviderMessageId, meaning = "provider_accepted_not_proof_of_delivery" }) });
            if (stage != HoldInitialSignerStage.Dispatched)
            {
                token.UsedAt = at.AddSeconds(1); Frame.PartyEvent(signer, "link_opened", JsonSerializer.Serialize(new { signerId = signer.Id, tokenId = token.Id,
                    documentId = previous.PdfObjectId, documentSha256 = payload.DocumentSha256, disclosureSha256 = payload.DisclosureSha256, authentication = "single_use_email_link" }), token.UsedAt.Value.AddTicks(1));
                F.Audits[^1].Ip = "127.0.0.1"; F.Audits[^1].UserAgent = "synthetic-link";
            }
            if (stage == HoldInitialSignerStage.Consented)
            {
                signer.Status = SignerStatus.Viewed; signer.ConsentAt = at.AddSeconds(2); signer.ConsentIp = "127.0.0.1"; signer.ConsentUa = "synthetic-consent";
                Frame.PartyEvent(signer, "consent_given", JsonSerializer.Serialize(new { disclosureVersion = F.Envelope.ErsdVersion, disclosureSha256 = payload.DisclosureSha256,
                    documentSha256 = payload.DocumentSha256, accessReceiptId = Guid.NewGuid(), accessMethod = "preview", agreement = true, canRetain = true,
                    serverEvidence = "hash_verified_pdf_prepared", clientEvidence = "signer_reported_access_and_retention" }), signer.ConsentAt.Value.AddTicks(1));
                F.Audits[^1].Ip = signer.ConsentIp; F.Audits[^1].UserAgent = signer.ConsentUa;
            }
            Frame.Sync();
        }
        internal void Marks(int party, bool large = false)
        {
            var signer = F.Signers[party]; var prior = Frame.Finishes.Single(x => x.SignerId == F.Signers[party - 1].Id);
            var p = Clone(Frame.M.Previews[0]); p.Id = Guid.NewGuid(); p.SignerId = signer.Id; p.DocumentId = prior.PdfObjectId; p.DocumentSha256 = prior.PdfSha256;
            p.SignatureObjectId = Guid.NewGuid(); p.InitialsObjectId = Guid.NewGuid(); p.CreatedAt = F.Audits.Last().At.AddSeconds(1); p.ExpiresAt = p.CreatedAt.AddMinutes(10);
            p.UsedAt = p.CreatedAt.AddSeconds(1); p.BaselineSignerVersion = signer.RowVersion.ToArray(); Frame.M.Previews.Add(p);
            foreach (var (id, hash) in new[] { (p.SignatureObjectId, p.SignatureSha256), (p.InitialsObjectId, p.InitialsSha256) })
                F.Objects.Add(new(new("normalized", $"{F.Envelope.Id:N}/{id:N}", "synthetic-mark-version", "", "\"synthetic-mark-etag\"", F.Objects.First(x => x.Address.Name.EndsWith('/' + Frame.M.Previews[0].SignatureObjectId.ToString("N"), StringComparison.Ordinal)).Address.Length), Hex(hash)));
            signer.SignatureAdoptionId = p.Id; signer.SignatureAdoptedAt = p.UsedAt; signer.SignatureMethod = p.Method; signer.SignatureImageBlob = p.SignatureObjectId.ToString("N");
            signer.InitialsImageBlob = p.InitialsObjectId.ToString("N"); signer.SignatureImageSha256 = p.SignatureSha256; signer.InitialsImageSha256 = p.InitialsSha256;
            signer.SignatureTypedName = p.TypedName; signer.SignatureTypedInitials = p.TypedInitials; signer.SignatureNormalizationVersion = p.NormalizationVersion; signer.SignatureAdoptionVersion = p.AdoptionVersion;
            signer.RowVersion = Enumerable.Repeat((byte)9, 8).ToArray();
            Frame.PartyEvent(signer, "signature_adopted", JsonSerializer.Serialize(new { adoptionId = p.Id, replacedAdoptionId = (Guid?)null, statementVersion = p.AdoptionVersion,
                statement = SignatureAdoptionStatement.Text, statementSha256 = Hex(SignatureAdoptionStatement.Sha256), acknowledged = true, method = p.Method.ToString(),
                reportedTypedName = p.TypedName, reportedTypedInitials = p.TypedInitials, normalizationVersion = p.NormalizationVersion, signatureObjectId = p.SignatureObjectId,
                initialsObjectId = p.InitialsObjectId, signatureSha256 = Hex(p.SignatureSha256), initialsSha256 = Hex(p.InitialsSha256), documentSha256 = Hex(p.DocumentSha256),
                disclosureSha256 = Hex(p.DisclosureSha256), serverEvidence = "previewed_assets_bound_to_explicit_adoption_request", identityEvidence = "email_link_session_with_prior_consent" }), p.UsedAt.Value.AddTicks(1));
            foreach (var field in F.Fields.Where(x => x.SignerId == signer.Id && (x.Type == FieldType.Signature || large && x.Type == FieldType.Text)))
            {
                var at = F.Audits.Last().At.AddTicks(2); field.Value = field.Type == FieldType.Signature ? p.SignatureObjectId.ToString("N") : new string('é', 4000);
                field.SignatureAdoptionId = field.Type == FieldType.Signature ? p.Id : null; field.ImageSha256 = field.Type == FieldType.Signature ? p.SignatureSha256 : null;
                field.FilledAt = at; field.FilledBy = PartyType.Signer;
                Frame.PartyEvent(signer, "field_filled", JsonSerializer.Serialize(new { fieldId = field.Id, type = field.Type.ToString(), previousValue = (string?)null, value = field.Value,
                    previousAdoptionId = (Guid?)null, adoptionId = field.SignatureAdoptionId, previousImageSha256 = (string?)null, imageSha256 = field.ImageSha256 is null ? null : Hex(field.ImageSha256),
                    valueSha256 = Hex(SHA256.HashData(Encoding.UTF8.GetBytes(field.Value))), documentSha256 = Hex(p.DocumentSha256), disclosureSha256 = Hex(p.DisclosureSha256), input = "explicit_owned_field_request" }), at.AddTicks(1));
            }
            Frame.Sync();
        }
    }
    private static T Clone<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value))!;
    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
}

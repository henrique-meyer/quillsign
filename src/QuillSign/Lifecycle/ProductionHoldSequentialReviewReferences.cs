using System.Data.SqlTypes;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// CLOSED bounded sequential prefix. Every original review input remains an
// authenticated sidecar; historical fields are folded at its exact audit cut.
// This graph does not render, issue tokens, renew clocks or admit Sealing.
internal static class ProductionHoldSequentialReviewReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    internal static HoldReviewCheckpointHistory ReadVerified(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects,
        IDataProtectionProvider keys, IReadOnlyList<VerifiedReviewInput> inputs)
    {
        try { return Verify(sql, objects, keys, inputs); }
        catch (Exception error) when (error is JsonException or CryptographicException or KeyNotFoundException or InvalidOperationException or
            ArgumentException or FormatException or OverflowException or NullReferenceException) { throw Invalid(); }
    }
    private static HoldReviewCheckpointHistory Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects,
        IDataProtectionProvider keys, IReadOnlyList<VerifiedReviewInput> inputs)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        if (tables.Values.Any(x => x.ValueKind != JsonValueKind.Array || x.GetArrayLength() > 4096) || tables.Values.Sum(x => x.GetArrayLength()) > 4096) throw Invalid();
        T[] Table<T>(string name, int maximum) { var raw = tables[name]; if (raw.GetArrayLength() > maximum) throw Invalid(); return raw.Deserialize<T[]>(Rows) ?? throw Invalid(); }
        ProductionHoldAuditChain.Demand(sql); ProductionHoldSentAuditReferences.DemandFrozenSequentialBaseline(sql, objects, keys);
        var id = sql.GetProperty("RecordId").GetGuid(); var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var e = Table<Envelope>("Envelopes", 1).Single(); var signers = Table<Signer>("Signers", 100).OrderBy(x => x.Order).ToArray();
        var candidates = Table<SignerReviewCandidate>("SignerReviewCandidates", 4096); var finishes = Table<SignerFinishAcceptance>("SignerFinishAcceptances", 100);
        var previews = Table<SignaturePreview>("SignaturePreviews", 4096); var fields = Table<DocumentField>("Fields", 200);
        var audits = Table<AuditEvent>("AuditEvents", 4096).OrderBy(x => x.Sequence).ToArray();
        if (signers.Length == 0 || e.Status != EnvelopeStatus.Sent || e.Id != id || e.IsDemo || !Utc(captured) ||
            candidates.GroupBy(x => x.SignerId).Any(x => x.Count() > SignerReviewCandidates.MaximumCandidatesPerSigner) ||
            candidates.Select(x => x.Id).Distinct().Count() != candidates.Length || candidates.Select(x => x.PdfObjectId).Distinct().Count() != candidates.Length ||
            candidates.Any(x => x.RowVersion.Length != 8 || !signers.Any(s => s.Id == x.SignerId)) ||
            finishes.Select(x => x.SignerId).Distinct().Count() != finishes.Length || finishes.Select(x => x.Id).Distinct().Count() != finishes.Length ||
            inputs.Count != candidates.Length || inputs.Select(x => x.CandidateId).Distinct().Count() != inputs.Count) throw Invalid();
        Columns(tables["SignerReviewCandidates"], CandidateColumns); Columns(tables["SignerFinishAcceptances"], FinishColumns);
        var sent = audits.Single(x => x.Event == "sent");
        if (audits.Where(x => x.Sequence > sent.Sequence).Any(x => x.Event is not ("invitation_submitted" or "link_opened" or "consent_given" or
            "signature_adopted" or "field_filled" or "field_cleared" or "signer_review_prepared" or "signer_finish_accepted" or "signer_completed"))) throw Invalid();
        var definitions = ProductionHoldPreparationAuditReferences.ReadVerified(sql, ProductionHoldDocumentAuditReferences.ReadVerified(sql, objects));
        ProductionHoldFinalizedFieldReferences.Demand(sql, objects, definitions); ProductionHoldConsentAuditReferences.Demand(sql, objects);
        var adopted = ProductionHoldAdoptionAuditReferences.ReadVerified(sql, objects); ProductionHoldFieldAuditReferences.Demand(sql, objects, definitions, adopted);
        var marks = ProductionHoldSignaturePreviewReferences.ReadVerifiedSequential(sql, objects);
        var prepared = audits.Where(x => x.Event == "signer_review_prepared").ToArray();
        if (prepared.Length != candidates.Length) throw Invalid();
        var result = new List<HoldVerifiedReviewCandidate>();
        foreach (var candidate in candidates.OrderBy(x => x.PreparedAt).ThenBy(x => x.Id))
        {
            var signer = signers.Single(x => x.Id == candidate.SignerId);
            var (source, sourceHash) = ProductionHoldAdoptionAuditReferences.Source(e, signer, signers, finishes, candidate.PreparedAt);
            var verified = inputs.Single(x => x.CandidateId == candidate.Id); var input = verified.Body;
            var original = ProductionRecordReviewWriteContract.ReadRow(input.CandidateRowJson);
            var current = Clone(candidate); current.UsedAt = null; current.SupersededAt = null;
            var identity = input.Identity;
            var evidence = prepared.Single(x => x.DataJson == PreparedJson(candidate));
            var cut = audits.Single(x => x.Id == input.AuditId && x.Sequence == input.AuditSequence && Hex(x.Hash) == input.AuditSha256);
            var mark = previews.Single(x => x.Id == candidate.AdoptionId);
            if (input.RecordId != id || input.CandidateId != candidate.Id || input.OperationId == Guid.Empty ||
                ProductionRecordReviewWriteContract.Row(current) != input.CandidateRowJson || original.UsedAt is not null || original.SupersededAt is not null ||
                candidate.Id == Guid.Empty || candidate.EnvelopeId != id || candidate.SignerId != signer.Id || candidate.SourceObjectId != source ||
                candidate.PdfObjectId == Guid.Empty || candidate.PdfObjectId == candidate.SourceObjectId || candidate.PdfLength is < 16 or > 64 * 1024 * 1024 ||
                new[] { e.OriginalBlob, e.PdfBlob }.Contains(candidate.PdfObjectId.ToString("N")) || previews.Any(x => x.SignatureObjectId == candidate.PdfObjectId || x.InitialsObjectId == candidate.PdfObjectId) ||
                candidate.RendererVersion != "signer-pdf-v1" || candidate.SnapshotVersion != "signer-review-v1" ||
                identity.EnvelopeId != id || identity.PublicId != e.PublicId || identity.SignerId != signer.Id || identity.Email != signer.Email ||
                identity.DocumentId != candidate.SourceObjectId || identity.DocumentHash != Hex(candidate.SourceSha256) || identity.DisclosureHash != Hex(candidate.DisclosureSha256) ||
                identity.SessionId == Guid.Empty || !Same(candidate.SessionSha256, SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity))) ||
                !Same(candidate.SourceSha256, sourceHash) || !Same(candidate.DisclosureSha256, e.ErsdSha256!) ||
                !Utc(candidate.PreparedAt) || candidate.PreparedAt < signer.ConsentAt || candidate.PreparedAt > captured || !Utc(input.AccessExpiresAt) ||
                input.AccessExpiresAt > identity.SessionExpiresAt || candidate.ExpiresAt != new[] { candidate.PreparedAt.AddMinutes(10), input.AccessExpiresAt,
                    e.ExpiresAt ?? DateTimeOffset.MaxValue, new DateTimeOffset(candidate.PreparedAt.UtcDateTime.Date.AddDays(1), TimeSpan.Zero) }.Min() ||
                !Utc(candidate.ExpiresAt) || candidate.ExpiresAt <= candidate.PreparedAt || candidate.ProspectiveDate != DateOnly.FromDateTime(candidate.PreparedAt.UtcDateTime) ||
                cut.Sequence + 1 != evidence.Sequence || cut.At > candidate.PreparedAt || evidence.At < candidate.PreparedAt ||
                mark.UsedAt is null || mark.UsedAt > candidate.PreparedAt || !Actor(evidence, signer, id, captured) ||
                input.Render.Marks is not { } images || images.SignatureObjectId != mark.SignatureObjectId || images.InitialsObjectId != mark.InitialsObjectId ||
                !Same(images.SignatureSha256, mark.SignatureSha256) || !Same(images.InitialsSha256, mark.InitialsSha256) || images.NormalizationVersion != mark.NormalizationVersion ||
                !objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == $"{id:N}/{candidate.PdfObjectId:N}" &&
                    x.Address.Length == candidate.PdfLength && x.Sha256 == Hex(candidate.PdfSha256))) throw Invalid();
            // The authenticated sidecar contains the exact original field rows,
            // not a guess at overwritten FilledAt or SQL row versions. Fold the
            // existing typed histories at that exact original audit cut.
            using var snapshot = JsonDocument.Parse(input.OriginalSnapshotJson);
            var saved = snapshot.RootElement.GetProperty("fields").Deserialize<DocumentField[]>() ?? throw Invalid();
            if (saved.Length is < 1 or > 200 || saved.Any(x => x.EnvelopeId != id || x.SignerId != signer.Id) ||
                !saved.Select(x => x.Id).SequenceEqual(saved.OrderBy(x => new SqlGuid(x.Id)).Select(x => x.Id)) ||
                !saved.Any(x => x.Type == FieldType.Signature && x.Value is not null && x.FilledAt is not null && x.FilledBy == PartyType.Signer) ||
                saved.Select(x => x.Id).Distinct().Count() != saved.Length || snapshot.RootElement.GetProperty("FullName").GetString() != signer.FullName ||
                snapshot.RootElement.GetProperty("ConsentAt").GetDateTimeOffset() != signer.ConsentAt || snapshot.RootElement.GetProperty("PageCount").GetInt32() != e.PageCount ||
                snapshot.RootElement.GetProperty("PageSizesJson").GetString() != e.PageSizesJson) throw Invalid();
            if (snapshot.RootElement.GetProperty("RowVersion").GetBytesFromBase64().Length != 8 ||
                snapshot.RootElement.GetProperty("signerVersion").GetBytesFromBase64().Length != 8 ||
                adopted.Where(x => x.SignerId == signer.Id && x.Sequence <= cut.Sequence).OrderBy(x => x.Sequence).LastOrDefault()?.Id != mark.Id) throw Invalid();
            ProductionHoldFieldAuditReferences.DemandSnapshot(sql, objects, definitions, adopted, signer.Id, cut.Sequence, saved, candidate.PreparedAt);
            result.Add(new(candidate.Id, candidate.SignerId, candidate.PdfObjectId, candidate.PdfLength, Hex(candidate.PdfSha256),
                candidate.PreparedAt, candidate.ExpiresAt, candidate.UsedAt, candidate.SupersededAt, verified));
        }
        // Superseding is exactly the next successful preparation's original
        // clock and only changes live, unused, different snapshots.
        var prepareSequences = candidates.ToDictionary(x => x.Id, x => prepared.Single(a => a.DataJson == PreparedJson(x)).Sequence);
        var supersedeSequences = new Dictionary<Guid, long>();
        foreach (var old in candidates)
        {
            var next = candidates.Where(x => x.SignerId == old.SignerId && prepareSequences[x.Id] > prepareSequences[old.Id] && x.PreparedAt < old.ExpiresAt &&
                !Same(x.SnapshotSha256, old.SnapshotSha256)).OrderBy(x => prepareSequences[x.Id]).FirstOrDefault();
            supersedeSequences.Add(old.Id, next is null ? long.MaxValue : prepareSequences[next.Id]);
            if (old.SupersededAt != next?.PreparedAt || old.SupersededAt is not null && old.UsedAt is not null ||
                old.SupersededAt is { } superseded && (!Utc(superseded) || superseded > captured) ||
                old.UsedAt is { } used && (!Utc(used) || !finishes.Any(x => x.ReviewCandidateId == old.Id && x.FinishedAt == used))) throw Invalid();
        }
        // Audit order also disambiguates equal UTC samples. Every preparation
        // precedes its own party acceptance (checked below), so a later UsedAt
        // cannot excuse a third simultaneous candidate at an earlier cut.
        foreach (var row in candidates)
            if (candidates.Count(x => x.SignerId == row.SignerId && prepareSequences[x.Id] <= prepareSequences[row.Id] && x.ExpiresAt > row.PreparedAt &&
                supersedeSequences[x.Id] > prepareSequences[row.Id]) > SignerReviewCandidates.MaximumActiveCandidates) throw Invalid();

        var accepted = audits.Where(x => x.Event == "signer_finish_accepted").ToArray();
        var completed = audits.Where(x => x.Event == "signer_completed").ToArray();
        if (accepted.Length != finishes.Length || completed.Length != finishes.Count(x => x.ProcessedAt is not null) ||
            candidates.Any(x => x.UsedAt is not null && !finishes.Any(f => f.ReviewCandidateId == x.Id && f.FinishedAt == x.UsedAt))) throw Invalid();
        foreach (var finish in finishes)
        {
            var signer = signers.Single(x => x.Id == finish.SignerId); var candidate = candidates.Single(x => x.Id == finish.ReviewCandidateId);
            var proof = inputs.Single(x => x.CandidateId == candidate.Id).Body; var a = accepted.Single(x => x.ActorId == signer.Id);
            if (finish.Id == Guid.Empty || finish.EnvelopeId != id || finish.RowVersion.Length != 8 || finish.AdoptionId != signer.SignatureAdoptionId ||
                !SignerFinish.MatchesCandidate(finish, candidate) || !Utc(finish.FinishedAt) || finish.FinishedAt > captured ||
                finish.FinishedAt >= proof.AccessExpiresAt || e.ExpiresAt is { } finishDeadline && finish.FinishedAt >= finishDeadline || a.DataJson != SignerFinish.EvidenceJson(finish) || !Actor(a, signer, id, captured) ||
                a.At < finish.FinishedAt || a.Ip != finish.Ip || a.UserAgent != finish.UserAgent || finish.Ip is { Length: > 45 } || finish.UserAgent is { Length: > 2048 } ||
                a.Sequence <= prepared.Single(x => x.DataJson == PreparedJson(candidate)).Sequence ||
                audits.Any(x => x.ActorId == signer.Id && x.Sequence > a.Sequence && x.Event != "signer_completed") ||
                candidates.Any(x => x.SignerId == signer.Id && x.PreparedAt > finish.FinishedAt)) throw Invalid();
            var original = proof.OriginalSnapshotJson; using var snapshot = JsonDocument.Parse(original);
            var restore = snapshot.RootElement.GetProperty("fields").Deserialize<DocumentField[]>() ?? throw Invalid();
            var frozen = ProductionHoldObjectReferences.ReadFinishFields(JsonSerializer.SerializeToElement(finish));
            if (!frozen.Select(x => x.Id).SequenceEqual(frozen.OrderBy(x => new SqlGuid(x.Id)).Select(x => x.Id)) || frozen.Length != restore.Length ||
                JsonSerializer.Serialize(frozen.OrderBy(x => x.Id)) != JsonSerializer.Serialize(fields.Where(x => x.SignerId == signer.Id).OrderBy(x => x.Id))) throw Invalid();
            foreach (var old in restore)
            {
                var current = Clone(frozen.Single(x => x.Id == old.Id));
                if (old.Type == FieldType.DateSigned)
                {
                    if (current.Value != finish.ProspectiveDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) || current.FilledAt != finish.FinishedAt ||
                        current.FilledBy != PartyType.Signer || current.RowVersion.Length != 8 || current.RowVersion.AsSpan().SequenceEqual(old.RowVersion)) throw Invalid();
                    current.Value = old.Value; current.FilledAt = old.FilledAt; current.FilledBy = old.FilledBy; current.RowVersion = old.RowVersion;
                }
                if (JsonSerializer.Serialize(current) != JsonSerializer.Serialize(old)) throw Invalid();
            }
        }
        DemandPrefixAndJobs(sql, tables, e, signers, audits, finishes, captured, keys, objects);
        var latest = finishes.OrderBy(x => signers.Single(s => s.Id == x.SignerId).Order).LastOrDefault();
        return new(marks, result.AsReadOnly(), latest?.Id, latest?.NextInvitationId, latest?.ProcessedAt is not null);
    }

    private static readonly JsonSerializerOptions Strict = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 4 };
    private sealed record Submitted(Guid emailId, Guid tokenId, string documentSha256, string disclosureSha256, Guid signerId,
        string recipient, string provider, string providerMessageId, string meaning);
    private static void DemandPrefixAndJobs(JsonElement sql, Dictionary<string, JsonElement> tables, Envelope e, Signer[] parties,
        AuditEvent[] audits, SignerFinishAcceptance[] finishes, DateTimeOffset captured, IDataProtectionProvider keys, IReadOnlyList<HoldObjectEvidence> objects)
    {
        var processed = parties.TakeWhile(x => x.Status == SignerStatus.Signed).ToArray();
        if (parties.Skip(processed.Length).Any(x => x.Status == SignerStatus.Signed) || e.CurrentCopyVersion != processed.Length ||
            finishes.Count(x => x.ProcessedAt is not null) != processed.Length ||
            e.CurrentFinishId != (processed.Length == 0 ? null : finishes.Single(x => x.SignerId == processed[^1].Id).Id) ||
            finishes.Any(x => parties.Single(s => s.Id == x.SignerId).Order > processed.Length + 1)) throw Invalid();
        var mail = tables["EmailOutbox"].Deserialize<EmailOutbox[]>(Rows)!; var work = tables["WorkItems"].Deserialize<WorkItem[]>(Rows)!;
        var tokens = tables["AuthTokens"].Deserialize<AuthToken[]>(Rows)!;
        var sent = audits.Single(x => x.Event == "sent"); using var sentBody = JsonDocument.Parse(sent.DataJson);
        var firstInvitation = sentBody.RootElement.GetProperty("invitationWorkId").GetGuid();
        var verification = mail.Single(x => x.Template == "sender-verification");
        var expectedMail = new HashSet<Guid> { verification.Id }; var expectedWork = new HashSet<Guid> { verification.Id };
        var expectedTokens = new HashSet<Guid> { tokens.Single(x => x.Purpose == TokenPurpose.SenderVerify).Id };
        ProductionHoldInvitationReferences.Demand(sql, objects, keys);
        var source = Guid.ParseExact(e.SentPdfBlob!, "N"); var sourceHash = e.SentPdfSha256!; AuditEvent prior = sent;
        for (var n = 0; n < parties.Length; n++)
        {
            var signer = parties[n]; var f = finishes.SingleOrDefault(x => x.SignerId == signer.Id);
            var blockedAfterDrain = n == processed.Length && n > 0 && finishes.Single(x => x.SignerId == parties[n - 1].Id).NextInvitationId is null;
            if (blockedAfterDrain)
            {
                var previous = finishes.Single(x => x.SignerId == parties[n - 1].Id);
                if (e.ExpiresAt is not { } cutoff || previous.ProcessedAt < cutoff) throw Invalid();
            }
            if (n > processed.Length || blockedAfterDrain)
            {
                if (signer.Status != SignerStatus.Pending || signer.DeclineReason is not null || signer.ConsentAt is not null || signer.ConsentIp is not null || signer.ConsentUa is not null ||
                    signer.SignedAt is not null || signer.SignedIp is not null || signer.SignedUa is not null || f is not null ||
                    tokens.Any(x => x.PartyId == signer.Id) || audits.Any(x => x.Sequence > sent.Sequence && x.ActorId == signer.Id)) throw Invalid();
                continue;
            }
            var invitationId = n == 0 ? firstInvitation : finishes.Single(x => x.SignerId == parties[n - 1].Id).NextInvitationId ?? throw Invalid();
            if (!expectedMail.Add(invitationId) || !expectedWork.Add(invitationId)) throw Invalid();
            var stage = DemandInvitation(e, signer, source, sourceHash, invitationId, prior, captured, mail, work, tokens, audits, keys, expectedTokens);
            var signed = f?.ProcessedAt is not null;
            var wanted = signed ? SignerStatus.Signed : stage == HoldInitialSignerStage.Queued ? SignerStatus.Pending :
                stage == HoldInitialSignerStage.Consented ? SignerStatus.Viewed : SignerStatus.Notified;
            if (signer.Status != wanted || signer.DeclineReason is not null ||
                (stage == HoldInitialSignerStage.Consented ? signer.ConsentAt is null : signer.ConsentAt is not null || signer.ConsentIp is not null || signer.ConsentUa is not null) ||
                !signed && (signer.SignedAt is not null || signer.SignedIp is not null || signer.SignedUa is not null)) throw Invalid();
            if (f is null) continue;
            if (stage != HoldInitialSignerStage.Consented || f.SourceObjectId != source || !Same(f.SourceSha256, sourceHash) || !Same(f.DisclosureSha256, e.ErsdSha256)) throw Invalid();
            var a = audits.Single(x => x.Event == "signer_finish_accepted" && x.ActorId == signer.Id);
            var job = work.Single(x => x.Id == f.Id); if (!expectedWork.Add(f.Id) || job.EnvelopeId != e.Id || job.Kind != WorkKind.Rendering ||
                job.PayloadJson != JsonSerializer.Serialize(new SignerCheckpointPayload(SignerCheckpointJobs.Version, f.Id)) ||
                job.LastError is not null || job.LeaseOwner is not null || job.LeaseExpiresAt is not null || !Utc(job.AvailableAt)) throw Invalid();
            if (!signed)
            {
                if (n != processed.Length || f.NextInvitationId is not null || job.Status != WorkStatus.Queued || job.Attempts != 0 ||
                    job.AvailableAt < a.At || job.AvailableAt > captured) throw Invalid();
                continue;
            }
            var published = audits.Single(x => x.Event == "signer_completed" && x.ActorId == signer.Id);
            var expiredDuringDrain = e.ExpiresAt is { } frozenDeadline && f.ProcessedAt >= frozenDeadline;
            if (!Utc(f.ProcessedAt) || f.ProcessedAt < a.At || f.ProcessedAt > captured ||
                signer.SignedAt != f.FinishedAt || signer.SignedIp != f.Ip || signer.SignedUa != f.UserAgent ||
                published.DataJson != SignerCheckpointState.PublishedJson(f) || !Actor(published, signer, e.Id, captured) ||
                published.At < f.ProcessedAt || published.Sequence <= a.Sequence || published.Ip != f.Ip || published.UserAgent != f.UserAgent ||
                job.Status != WorkStatus.Completed || job.Attempts != 1 || job.AvailableAt < published.At || job.AvailableAt > captured ||
                (n == parties.Length - 1 || expiredDuringDrain ? f.NextInvitationId is not null : f.NextInvitationId is null || f.NextInvitationId == Guid.Empty)) throw Invalid();
            source = f.PdfObjectId; sourceHash = f.PdfSha256; prior = published;
        }
        if (processed.Length == parties.Length)
        {
            var last = finishes.Single(x => x.SignerId == parties[^1].Id); var id = CompletionJobs.WorkId(e.Id); var completion = work.Single(x => x.Id == id);
            if (!expectedWork.Add(id) || completion.EnvelopeId != e.Id || completion.Kind != WorkKind.Sealing || completion.Status != WorkStatus.Queued ||
                completion.Attempts != 0 || completion.LeaseOwner is not null || completion.LeaseExpiresAt is not null || completion.LastError is not null ||
                !Utc(completion.AvailableAt) || (completion.AvailableAt != last.ProcessedAt && completion.AvailableAt < prior.At) || completion.AvailableAt > captured ||
                completion.PayloadJson != JsonSerializer.Serialize(new CompletionWorkPayload(CompletionJobs.Version, last.Id, parties.Length, Hex(last.PdfSha256), Hex(e.ErsdSha256!)))) throw Invalid();
        }
        if (e.ExpiresAt is not null) expectedWork.Add(SigningExpiryJobs.WorkId(e.Id));
        if (mail.Length != expectedMail.Count || !expectedMail.SetEquals(mail.Select(x => x.Id)) ||
            work.Length != expectedWork.Count || !expectedWork.SetEquals(work.Select(x => x.Id)) ||
            tokens.Length != expectedTokens.Count || !expectedTokens.SetEquals(tokens.Select(x => x.Id)) ||
            audits.Count(x => x.Event == "invitation_submitted") != tokens.Count(x => x.Purpose == TokenPurpose.SignerAccess)) throw Invalid();
    }
    private static HoldInitialSignerStage DemandInvitation(Envelope e, Signer signer, Guid source, byte[] sourceHash, Guid invitationId,
        AuditEvent prior, DateTimeOffset captured, EmailOutbox[] allMail, WorkItem[] allWork, AuthToken[] tokens, AuditEvent[] audits,
        IDataProtectionProvider keys, HashSet<Guid> expectedTokens)
    {
        var mail = allMail.Single(x => x.Id == invitationId); var work = allWork.Single(x => x.Id == invitationId);
        if (mail.EnvelopeId != e.Id || mail.Template != "signer-invitation" || mail.To != signer.Email || mail.AttachmentsJson != "[]" ||
            mail.LastError is not null || mail.LeaseOwner is not null || mail.LeaseExpiresAt is not null || !Utc(mail.AvailableAt) ||
            mail.AvailableAt < (signer.Order == 1 ? e.SentAt : prior.At) || mail.AvailableAt > (signer.Order == 1 ? prior.At : captured) ||
            work.EnvelopeId != e.Id || work.Kind != WorkKind.Email || work.PayloadJson != "{}" || work.LastError is not null ||
            work.LeaseOwner is not null || work.LeaseExpiresAt is not null || !Utc(work.AvailableAt)) throw Invalid();
        var wrapper = JsonSerializer.Deserialize<ProtectedWorkPayload>(mail.PayloadJson, Strict) ?? throw Invalid();
        var payload = new SignerInvitationProtection(keys).Read(mail.PayloadJson);
        if (JsonSerializer.Serialize(wrapper) != mail.PayloadJson || keys.CreateProtector("QuillSign.SignerInvitationPayload.v1").Unprotect(wrapper.Protected) != JsonSerializer.Serialize(payload) ||
            payload.SignerId != signer.Id || payload.DocumentId != source || payload.DocumentSha256 != Hex(sourceHash) || payload.DisclosureSha256 != Hex(e.ErsdSha256!) ||
            payload.ContactRevisionId != Guid.Empty || payload.ContactRevisionNumber != 0) throw Invalid();
        var submitted = audits.Where(x => x.Event == "invitation_submitted").Select(x => (Audit: x, Proof: ReadSubmitted(x))).Where(x => x.Proof.signerId == signer.Id).ToArray();
        var links = audits.Where(x => x.Event == "link_opened" && x.ActorId == signer.Id).ToArray();
        var consents = audits.Where(x => x.Event == "consent_given" && x.ActorId == signer.Id).ToArray();
        if (submitted.Length == 0)
        {
            if (links.Length != 0 || consents.Length != 0 || tokens.Any(x => x.PartyId == signer.Id) || payload.LastTokenId is not null ||
                mail.Status != EmailStatus.Queued || mail.Attempts != 0 || mail.SubmissionStartedAt is not null || mail.Provider is not null || mail.ProviderMessageId is not null ||
                work.Status != WorkStatus.Queued || work.Attempts != 0 || work.AvailableAt != mail.AvailableAt) throw Invalid();
            return HoldInitialSignerStage.Queued;
        }
        var (row, proof) = submitted.Single();
        if (row.EnvelopeId != e.Id || row.ActorType != PartyType.System || row.ActorId is not null || row.ActorEmail is not null || row.Ip is not null || row.UserAgent is not null ||
            !Utc(row.At) || row.At < prior.At || row.At > captured || row.Sequence <= prior.Sequence || !Same(row.Hash, AuditHash.Compute(row)) ||
            proof.emailId != invitationId || proof.tokenId == Guid.Empty || proof.tokenId != payload.LastTokenId || proof.recipient != signer.Email ||
            proof.documentSha256 != Hex(sourceHash) || proof.disclosureSha256 != Hex(e.ErsdSha256!) || proof.meaning != "provider_accepted_not_proof_of_delivery" ||
            !ProviderText(proof.provider) || !ProviderText(proof.providerMessageId) || mail.Provider != proof.provider || mail.ProviderMessageId != proof.providerMessageId ||
            mail.Status != EmailStatus.Sent || mail.Attempts != 1 || mail.SubmissionStartedAt is not { } at || !Utc(at) || at < prior.At || at > row.At ||
            work.Status != WorkStatus.Completed || work.Attempts != 1 || work.AvailableAt < row.At || work.AvailableAt > captured) throw Invalid();
        var token = tokens.Single(x => x.Id == proof.tokenId);
        if (!expectedTokens.Add(token.Id) || token.EnvelopeId != e.Id || token.PartyType != PartyType.Signer || token.PartyId != signer.Id || token.Purpose != TokenPurpose.SignerAccess ||
            token.Email != signer.Email || token.TokenSha256 is not { Length: 32 } || token.DocumentId != source || !Same(token.DocumentSha256, sourceHash) || !Same(token.DisclosureSha256, e.ErsdSha256) ||
            token.SignerContactRevisionId is not null || token.EmailPilotLookupRequestId is not null || token.CompletionPublicationId is not null || token.CompletionRecipeSha256 is not null ||
            token.CompletionPartySha256 is not null || token.Ip is not null || !Utc(token.ExpiresAt) || token.ExpiresAt <= at ||
            token.UsedAt is { } used && (used < at || !Utc(used)) || e.ExpiresAt is { } deadline && token.ExpiresAt > deadline ||
            links.Length > 1 || consents.Length > 1 || links.Length == 0 && (consents.Length != 0 || token.UsedAt is not null) ||
            links.Length == 1 && (links[0].Sequence <= row.Sequence || token.UsedAt is null) ||
            consents.Length == 1 && consents[0].Sequence <= links.Single().Sequence) throw Invalid();
        return consents.Length == 1 ? HoldInitialSignerStage.Consented : links.Length == 1 ? HoldInitialSignerStage.Opened : HoldInitialSignerStage.Dispatched;
    }
    private static Submitted ReadSubmitted(AuditEvent row)
    {
        if (row.DataJson.Length > 8192 || System.Text.Encoding.UTF8.GetByteCount(row.DataJson) > 8192) throw Invalid();
        var value = JsonSerializer.Deserialize<Submitted>(row.DataJson, Strict) ?? throw Invalid();
        return JsonSerializer.Serialize(value) == row.DataJson ? value : throw Invalid();
    }
    private static bool ProviderText(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);

    private static readonly string[] CandidateColumns = ["Id", "EnvelopeId", "SignerId", "AdoptionId", "SourceObjectId", "PdfObjectId", "PdfLength",
        "SourceSha256", "DisclosureSha256", "SessionSha256", "SnapshotSha256", "PdfSha256", "RecipeSha256", "RendererVersion", "SnapshotVersion",
        "ProspectiveDate", "PreparedAt", "ExpiresAt", "UsedAt", "SupersededAt", "RowVersion"];
    private static readonly string[] FinishColumns = ["Id", "EnvelopeId", "SignerId", "ReviewCandidateId", "AdoptionId", "SourceObjectId", "PdfObjectId", "PdfLength",
        "SourceSha256", "DisclosureSha256", "SessionSha256", "SnapshotSha256", "PdfSha256", "RecipeSha256", "FieldsJson", "FieldsSha256", "SnapshotVersion",
        "StatementVersion", "Statement", "StatementSha256", "ProspectiveDate", "ReviewPreparedAt", "ReviewExpiresAt", "FinishedAt", "Ip", "UserAgent", "ProcessedAt", "NextInvitationId", "RowVersion"];

    internal static string PreparedJson(SignerReviewCandidate p) => JsonSerializer.Serialize(new { candidateId = p.Id, p.PdfObjectId, p.SourceObjectId, p.PdfLength, p.AdoptionId,
        sourceSha256 = Hex(p.SourceSha256), disclosureSha256 = Hex(p.DisclosureSha256), sessionSha256 = Hex(p.SessionSha256), snapshotSha256 = Hex(p.SnapshotSha256),
        pdfSha256 = Hex(p.PdfSha256), recipeSha256 = Hex(p.RecipeSha256), p.RendererVersion, p.SnapshotVersion, p.ProspectiveDate, p.PreparedAt, p.ExpiresAt,
        serverEvidence = "exact_review_pdf_prepared_not_user_review_or_finish" });
    private static bool Actor(AuditEvent x, Signer s, Guid id, DateTimeOffset captured) => x.EnvelopeId == id && x.ActorType == PartyType.Signer && x.ActorId == s.Id &&
        x.ActorEmail == s.Email && Utc(x.At) && x.At <= captured && x.Ip is not { Length: > 64 } && x.UserAgent is not { Length: > 2048 } && Same(x.Hash, AuditHash.Compute(x));
    private static T Clone<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value, Rows), Rows)!;
    private static void Columns(JsonElement rows, string[] expected)
    {
        foreach (var row in rows.EnumerateArray())
        {
            var names = row.EnumerateObject().Select(x => x.Name).ToArray();
            if (names.Length != expected.Length || !names.ToHashSet(StringComparer.Ordinal).SetEquals(expected)) throw Invalid();
        }
    }
    private static bool Utc(DateTimeOffset? value) => value is { Offset: var offset } && offset == TimeSpan.Zero;
    private static bool Same(byte[]? a, byte[]? b) => a is { Length: 32 } && b is { Length: 32 } && CryptographicOperations.FixedTimeEquals(a, b);
    private static string Hex(byte[] value) => value is { Length: 32 } ? Convert.ToHexStringLower(value) : throw Invalid();
    private static InvalidDataException Invalid() => new("The closed sequential review and checkpoint evidence could not be verified.");
}

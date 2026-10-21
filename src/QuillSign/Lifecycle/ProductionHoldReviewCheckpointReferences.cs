using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Factual historical projections only. The caller authenticates each input's
// settled two-object plan and EXACT provider receipts before opening its body.
internal sealed record HoldVerifiedReviewCandidate(Guid Id, Guid SignerId, Guid PdfObjectId, long PdfLength,
    string PdfSha256, DateTimeOffset PreparedAt, DateTimeOffset ExpiresAt, DateTimeOffset? UsedAt,
    DateTimeOffset? SupersededAt, VerifiedReviewInput Input);
internal sealed record HoldReviewCheckpointHistory(IReadOnlyList<HoldVerifiedSignaturePreview> Previews,
    IReadOnlyList<HoldVerifiedReviewCandidate> Reviews, Guid? FinishId, Guid? NextInvitationId, bool Processed);

// CLOSED first-party review/acceptance/checkpoint graph. Later parties may only
// have their original Pending rows and the second initial QUEUED notification.
internal static class ProductionHoldReviewCheckpointReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly string[] CandidateColumns = ["Id", "EnvelopeId", "SignerId", "AdoptionId", "SourceObjectId", "PdfObjectId", "PdfLength",
        "SourceSha256", "DisclosureSha256", "SessionSha256", "SnapshotSha256", "PdfSha256", "RecipeSha256", "RendererVersion", "SnapshotVersion",
        "ProspectiveDate", "PreparedAt", "ExpiresAt", "UsedAt", "SupersededAt", "RowVersion"];
    private static readonly string[] FinishColumns = ["Id", "EnvelopeId", "SignerId", "ReviewCandidateId", "AdoptionId", "SourceObjectId", "PdfObjectId", "PdfLength",
        "SourceSha256", "DisclosureSha256", "SessionSha256", "SnapshotSha256", "PdfSha256", "RecipeSha256", "FieldsJson", "FieldsSha256", "SnapshotVersion",
        "StatementVersion", "Statement", "StatementSha256", "ProspectiveDate", "ReviewPreparedAt", "ReviewExpiresAt", "FinishedAt", "Ip", "UserAgent", "ProcessedAt", "NextInvitationId", "RowVersion"];
    private static bool Added(string name) => name is "signer_review_prepared" or "signer_finish_accepted" or "signer_completed";

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
        T[] Table<T>(string name, int maximum) { var rows = tables[name]; if (rows.GetArrayLength() > maximum) throw Invalid(); return rows.Deserialize<T[]>(Rows) ?? throw Invalid(); }
        var candidates = Table<SignerReviewCandidate>("SignerReviewCandidates", SignerReviewCandidates.MaximumCandidatesPerSigner);
        var finishes = Table<SignerFinishAcceptance>("SignerFinishAcceptances", 1);
        Columns(tables["SignerReviewCandidates"], CandidateColumns); Columns(tables["SignerFinishAcceptances"], FinishColumns);
        if (candidates.Length == 0)
        {
            if (inputs.Count != 0 || finishes.Length != 0) throw Invalid();
            return new(ProductionHoldSentAuditReferences.ReadVerified(sql, objects, keys), [], null, null, false);
        }
        if (inputs.Count != candidates.Length || inputs.Select(x => x.CandidateId).Distinct().Count() != inputs.Count) throw Invalid();
        ProductionHoldAuditChain.Demand(sql);
        var id = sql.GetProperty("RecordId").GetGuid(); var captured = sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var e = Table<Envelope>("Envelopes", 1).Single(); var signers = Table<Signer>("Signers", 100).OrderBy(x => x.Order).ToArray();
        if (signers.Length < 2 || e.Status != EnvelopeStatus.Sent || e.IsDemo || e.Id != id || !Utc(captured)) throw Invalid();
        var first = signers[0]; var audits = Table<AuditEvent>("AuditEvents", 4096).OrderBy(x => x.Sequence).ToArray();
        var previews = Table<SignaturePreview>("SignaturePreviews", SignatureAdoption.MaximumPreviewsPerSigner);
        var fields = Table<DocumentField>("Fields", 200);
        var prepared = audits.Where(x => x.Event == "signer_review_prepared").ToArray();
        if (prepared.Length != candidates.Length || candidates.Select(x => x.Id).Distinct().Count() != candidates.Length ||
            candidates.Select(x => x.PdfObjectId).Distinct().Count() != candidates.Length || candidates.Any(x => x.RowVersion.Length != 8)) throw Invalid();
        var definitions = ProductionHoldPreparationAuditReferences.ReadVerified(sql, ProductionHoldDocumentAuditReferences.ReadVerified(sql, objects));
        ProductionHoldFinalizedFieldReferences.Demand(sql, objects, definitions);
        ProductionHoldConsentAuditReferences.Demand(sql, objects);
        var adopted = ProductionHoldAdoptionAuditReferences.ReadVerified(sql, objects);
        ProductionHoldFieldAuditReferences.Demand(sql, objects, definitions, adopted);
        var result = new List<HoldVerifiedReviewCandidate>();
        foreach (var candidate in candidates.OrderBy(x => x.PreparedAt).ThenBy(x => x.Id))
        {
            var verified = inputs.Single(x => x.CandidateId == candidate.Id); var input = verified.Body;
            var original = ProductionRecordReviewWriteContract.ReadRow(input.CandidateRowJson);
            var current = Clone(candidate); current.UsedAt = null; current.SupersededAt = null;
            var identity = input.Identity;
            var evidence = prepared.Single(x => x.DataJson == PreparedJson(candidate));
            var cut = audits.Single(x => x.Id == input.AuditId && x.Sequence == input.AuditSequence && Hex(x.Hash) == input.AuditSha256);
            var mark = previews.Single(x => x.Id == candidate.AdoptionId);
            if (input.RecordId != id || input.CandidateId != candidate.Id || input.OperationId == Guid.Empty ||
                ProductionRecordReviewWriteContract.Row(current) != input.CandidateRowJson || original.UsedAt is not null || original.SupersededAt is not null ||
                candidate.Id == Guid.Empty || candidate.EnvelopeId != id || candidate.SignerId != first.Id || candidate.SourceObjectId.ToString("N") != e.SentPdfBlob ||
                candidate.PdfObjectId == Guid.Empty || candidate.PdfObjectId == candidate.SourceObjectId || candidate.PdfLength is < 16 or > 64 * 1024 * 1024 ||
                new[] { e.OriginalBlob, e.PdfBlob }.Contains(candidate.PdfObjectId.ToString("N")) || previews.Any(x => x.SignatureObjectId == candidate.PdfObjectId || x.InitialsObjectId == candidate.PdfObjectId) ||
                candidate.RendererVersion != "signer-pdf-v1" || candidate.SnapshotVersion != "signer-review-v1" ||
                identity.EnvelopeId != id || identity.PublicId != e.PublicId || identity.SignerId != first.Id || identity.Email != first.Email ||
                identity.DocumentId != candidate.SourceObjectId || identity.DocumentHash != Hex(candidate.SourceSha256) || identity.DisclosureHash != Hex(candidate.DisclosureSha256) ||
                identity.SessionId == Guid.Empty || !Same(candidate.SessionSha256, SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity))) ||
                !Same(candidate.SourceSha256, e.SentPdfSha256!) || !Same(candidate.DisclosureSha256, e.ErsdSha256!) ||
                !Utc(candidate.PreparedAt) || candidate.PreparedAt < first.ConsentAt || candidate.PreparedAt > captured || !Utc(input.AccessExpiresAt) ||
                input.AccessExpiresAt > identity.SessionExpiresAt || candidate.ExpiresAt != new[] { candidate.PreparedAt.AddMinutes(10), input.AccessExpiresAt,
                    e.ExpiresAt ?? DateTimeOffset.MaxValue, new DateTimeOffset(candidate.PreparedAt.UtcDateTime.Date.AddDays(1), TimeSpan.Zero) }.Min() ||
                !Utc(candidate.ExpiresAt) || candidate.ExpiresAt <= candidate.PreparedAt || candidate.ProspectiveDate != DateOnly.FromDateTime(candidate.PreparedAt.UtcDateTime) ||
                cut.Sequence + 1 != evidence.Sequence || cut.At > candidate.PreparedAt || evidence.At < candidate.PreparedAt ||
                mark.UsedAt is null || mark.UsedAt > candidate.PreparedAt || !Actor(evidence, first, id, captured) ||
                input.Render.Marks is not { } images || images.SignatureObjectId != mark.SignatureObjectId || images.InitialsObjectId != mark.InitialsObjectId ||
                !Same(images.SignatureSha256, mark.SignatureSha256) || !Same(images.InitialsSha256, mark.InitialsSha256) || images.NormalizationVersion != mark.NormalizationVersion ||
                !objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == $"{id:N}/{candidate.PdfObjectId:N}" &&
                    x.Address.Length == candidate.PdfLength && x.Sha256 == Hex(candidate.PdfSha256))) throw Invalid();
            // The authenticated sidecar contains the exact original field rows,
            // not a guess at overwritten FilledAt or SQL row versions. Fold the
            // existing typed histories at that exact original audit cut.
            using var snapshot = JsonDocument.Parse(input.OriginalSnapshotJson);
            var saved = snapshot.RootElement.GetProperty("fields").Deserialize<DocumentField[]>() ?? throw Invalid();
            if (saved.Length is < 1 or > 200 || saved.Any(x => x.EnvelopeId != id || x.SignerId != first.Id) ||
                !saved.Any(x => x.Type == FieldType.Signature && x.Value is not null && x.FilledAt is not null && x.FilledBy == PartyType.Signer) ||
                saved.Select(x => x.Id).Distinct().Count() != saved.Length || snapshot.RootElement.GetProperty("FullName").GetString() != first.FullName ||
                snapshot.RootElement.GetProperty("ConsentAt").GetDateTimeOffset() != first.ConsentAt || snapshot.RootElement.GetProperty("PageCount").GetInt32() != e.PageCount ||
                snapshot.RootElement.GetProperty("PageSizesJson").GetString() != e.PageSizesJson) throw Invalid();
            using var before = Projection(sql, tables, e, signers, fields, audits, previews, finishes.SingleOrDefault(), input.AuditSequence, saved,
                snapshot.RootElement.GetProperty("RowVersion").GetBytesFromBase64(), snapshot.RootElement.GetProperty("signerVersion").GetBytesFromBase64(), mark, candidate.PreparedAt);
            using var originalHistory = Projection(sql, tables, e, signers, fields, audits, previews, finishes.SingleOrDefault(), input.AuditSequence, saved,
                snapshot.RootElement.GetProperty("RowVersion").GetBytesFromBase64(), snapshot.RootElement.GetProperty("signerVersion").GetBytesFromBase64(), mark, candidate.PreparedAt, false);
            _ = ProductionHoldSentAuditReferences.ReadVerifiedReviewProjection(before.RootElement, objects, keys, originalHistory.RootElement);
            result.Add(new(candidate.Id, candidate.SignerId, candidate.PdfObjectId, candidate.PdfLength, Hex(candidate.PdfSha256),
                candidate.PreparedAt, candidate.ExpiresAt, candidate.UsedAt, candidate.SupersededAt, verified));
        }
        // Superseding is exactly the next successful preparation's original
        // clock and only changes live, unused, different snapshots.
        var prepareSequences = candidates.ToDictionary(x => x.Id, x => prepared.Single(a => a.DataJson == PreparedJson(x)).Sequence);
        var supersedeSequences = new Dictionary<Guid, long>();
        foreach (var old in candidates)
        {
            var next = candidates.Where(x => prepareSequences[x.Id] > prepareSequences[old.Id] && x.PreparedAt < old.ExpiresAt &&
                !Same(x.SnapshotSha256, old.SnapshotSha256)).OrderBy(x => prepareSequences[x.Id]).FirstOrDefault();
            supersedeSequences.Add(old.Id, next is null ? long.MaxValue : prepareSequences[next.Id]);
            if (old.SupersededAt != next?.PreparedAt || old.SupersededAt is not null && old.UsedAt is not null ||
                old.SupersededAt is { } superseded && (!Utc(superseded) || superseded > captured) ||
                old.UsedAt is { } used && (!Utc(used) || !finishes.Any(x => x.ReviewCandidateId == old.Id && x.FinishedAt == used))) throw Invalid();
        }
        // Audit order also disambiguates equal UTC samples. Every preparation
        // precedes the single acceptance (checked below), so a later UsedAt
        // cannot excuse a third simultaneous candidate at an earlier cut.
        foreach (var row in candidates)
            if (candidates.Count(x => prepareSequences[x.Id] <= prepareSequences[row.Id] && x.ExpiresAt > row.PreparedAt &&
                supersedeSequences[x.Id] > prepareSequences[row.Id]) > SignerReviewCandidates.MaximumActiveCandidates) throw Invalid();

        var finish = finishes.SingleOrDefault(); var accepted = audits.Where(x => x.Event == "signer_finish_accepted").ToArray();
        var completed = audits.Where(x => x.Event == "signer_completed").ToArray();
        if (finish is null ? accepted.Length != 0 || completed.Length != 0 || candidates.Any(x => x.UsedAt is not null) : accepted.Length != 1) throw Invalid();
        DocumentField[]? restore = null;
        if (finish is not null)
        {
            var candidate = candidates.Single(x => x.Id == finish.ReviewCandidateId); var proof = inputs.Single(x => x.CandidateId == candidate.Id).Body;
            var a = accepted.Single();
            if (finish.Id == Guid.Empty || finish.EnvelopeId != id || finish.SignerId != first.Id || finish.RowVersion.Length != 8 || finish.AdoptionId != first.SignatureAdoptionId ||
                !SignerFinish.MatchesCandidate(finish, candidate) || !Utc(finish.FinishedAt) || finish.FinishedAt > captured ||
                finish.FinishedAt >= proof.AccessExpiresAt || a.DataJson != SignerFinish.EvidenceJson(finish) || !Actor(a, first, id, captured) ||
                a.At < finish.FinishedAt || a.Ip != finish.Ip || a.UserAgent != finish.UserAgent || finish.Ip is { Length: > 45 } || finish.UserAgent is { Length: > 2048 } ||
                a.Sequence <= prepared.Single(x => x.DataJson == PreparedJson(candidate)).Sequence ||
                audits.Any(x => x.Sequence > a.Sequence && x.Event != "signer_completed") || candidates.Any(x => x.PreparedAt > finish.FinishedAt)) throw Invalid();
            using var snapshot = JsonDocument.Parse(proof.OriginalSnapshotJson);
            restore = snapshot.RootElement.GetProperty("fields").Deserialize<DocumentField[]>() ?? throw Invalid();
            var frozen = ProductionHoldObjectReferences.ReadFinishFields(JsonSerializer.SerializeToElement(finish));
            if (frozen.Length != restore.Length || JsonSerializer.Serialize(frozen.OrderBy(x => x.Id)) != JsonSerializer.Serialize(fields.Where(x => x.SignerId == first.Id).OrderBy(x => x.Id))) throw Invalid();
            foreach (var old in restore)
            {
                var current = Clone(frozen.Single(x => x.Id == old.Id));
                if (old.Type == FieldType.DateSigned)
                {
                    if (current.Value != finish.ProspectiveDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) || current.FilledAt != finish.FinishedAt || current.FilledBy != PartyType.Signer ||
                        current.RowVersion.Length != 8 || current.RowVersion.AsSpan().SequenceEqual(old.RowVersion)) throw Invalid();
                    current.Value = old.Value; current.FilledAt = old.FilledAt; current.FilledBy = old.FilledBy; current.RowVersion = old.RowVersion;
                }
                if (JsonSerializer.Serialize(current) != JsonSerializer.Serialize(old)) throw Invalid();
            }
            DemandCheckpoint(tables, e, signers, audits, finish, a, captured, keys);
        }
        else if (first.Status != SignerStatus.Viewed || e.CurrentFinishId is not null || e.CurrentCopyVersion != 0 ||
            first.SignedAt is not null || first.SignedIp is not null || first.SignedUa is not null) throw Invalid();
        using var preceding = Projection(sql, tables, e, signers, fields, audits, previews, finish, long.MaxValue, restore, null, null, null, captured);
        var marks = ProductionHoldSentAuditReferences.ReadVerifiedReviewProjection(preceding.RootElement, objects, keys, sql);
        return new(marks, result.AsReadOnly(), finish?.Id, finish?.NextInvitationId, finish?.ProcessedAt is not null);
    }

    private static void DemandCheckpoint(Dictionary<string, JsonElement> tables, Envelope e, Signer[] parties, AuditEvent[] audits,
        SignerFinishAcceptance f, AuditEvent accepted, DateTimeOffset captured, IDataProtectionProvider keys)
    {
        var first = parties[0]; var work = tables["WorkItems"].Deserialize<WorkItem[]>(Rows)!.Single(x => x.Id == f.Id);
        if (work.EnvelopeId != e.Id || work.Kind != WorkKind.Rendering || work.PayloadJson != JsonSerializer.Serialize(new SignerCheckpointPayload("signer-checkpoint-v1", f.Id)) ||
            work.LastError is not null || work.LeaseOwner is not null || work.LeaseExpiresAt is not null || !Utc(work.AvailableAt)) throw Invalid();
        var published = audits.Where(x => x.Event == "signer_completed").ToArray();
        if (f.ProcessedAt is null)
        {
            if (published.Length != 0 || f.NextInvitationId is not null || first.Status != SignerStatus.Viewed || first.SignedAt is not null || first.SignedIp is not null || first.SignedUa is not null ||
                e.CurrentFinishId is not null || e.CurrentCopyVersion != 0 || work.Status != WorkStatus.Queued || work.Attempts != 0 || work.AvailableAt < accepted.At || work.AvailableAt > captured) throw Invalid();
            return;
        }
        var completed = published.Single();
        if (!Utc(f.ProcessedAt) || f.ProcessedAt < accepted.At || f.ProcessedAt > captured || f.NextInvitationId is null || f.NextInvitationId == Guid.Empty ||
            e.ExpiresAt is { } deadline && f.ProcessedAt >= deadline || first.Status != SignerStatus.Signed || first.SignedAt != f.FinishedAt || first.SignedIp != f.Ip || first.SignedUa != f.UserAgent ||
            e.CurrentFinishId != f.Id || e.CurrentCopyVersion != 1 || completed.DataJson != SignerCheckpointState.PublishedJson(f) ||
            !Actor(completed, first, e.Id, captured) || completed.At < f.ProcessedAt || completed.Sequence <= accepted.Sequence || completed.Ip != f.Ip || completed.UserAgent != f.UserAgent ||
            work.Status != WorkStatus.Completed || work.Attempts != 1 || work.AvailableAt < completed.At || work.AvailableAt > captured) throw Invalid();
        var second = parties[1]; var next = tables["EmailOutbox"].Deserialize<EmailOutbox[]>(Rows)!.Single(x => x.Id == f.NextInvitationId);
        var nextWork = tables["WorkItems"].Deserialize<WorkItem[]>(Rows)!.Single(x => x.Id == f.NextInvitationId);
        if (next.EnvelopeId != e.Id || next.Template != "signer-invitation" || next.To != second.Email || next.AttachmentsJson != "[]" ||
            next.Status != EmailStatus.Queued || next.Attempts != 0 || next.SubmissionStartedAt is not null || next.Provider is not null || next.ProviderMessageId is not null ||
            next.LeaseOwner is not null || next.LeaseExpiresAt is not null || next.LastError is not null || !Utc(next.AvailableAt) || next.AvailableAt < completed.At || next.AvailableAt > captured ||
            nextWork.EnvelopeId != e.Id || nextWork.Kind != WorkKind.Email || nextWork.PayloadJson != "{}" || nextWork.Status != WorkStatus.Queued || nextWork.Attempts != 0 ||
            nextWork.AvailableAt != next.AvailableAt || nextWork.LastError is not null || nextWork.LeaseOwner is not null || nextWork.LeaseExpiresAt is not null) throw Invalid();
        var payload = new SignerInvitationProtection(keys).Read(next.PayloadJson);
        var wrapper = JsonSerializer.Deserialize<ProtectedWorkPayload>(next.PayloadJson) ?? throw Invalid();
        if (JsonSerializer.Serialize(wrapper) != next.PayloadJson || keys.CreateProtector("QuillSign.SignerInvitationPayload.v1").Unprotect(wrapper.Protected) != JsonSerializer.Serialize(payload) ||
            payload.SignerId != second.Id || payload.DocumentId != f.PdfObjectId || payload.DocumentSha256 != Hex(f.PdfSha256) || payload.DisclosureSha256 != Hex(f.DisclosureSha256) ||
            payload.LastTokenId is not null || payload.ContactRevisionId != Guid.Empty || payload.ContactRevisionNumber != 0) throw Invalid();
    }

    private static JsonDocument Projection(JsonElement original, Dictionary<string, JsonElement> tables, Envelope envelope, Signer[] parties,
        DocumentField[] fields, AuditEvent[] audits, SignaturePreview[] previews, SignerFinishAcceptance? finish, long cut,
        DocumentField[]? originalFields, byte[]? envelopeVersion, byte[]? signerVersion, SignaturePreview? adoption, DateTimeOffset stageAt, bool reduce = true)
    {
        var e = Clone(envelope); e.CurrentFinishId = null; e.CurrentCopyVersion = 0; if (envelopeVersion is not null) e.RowVersion = envelopeVersion;
        var signers = parties.Select(Clone).ToArray(); var first = signers[0]; first.Status = SignerStatus.Viewed; first.SignedAt = null; first.SignedIp = null; first.SignedUa = null;
        if (signerVersion is not null) first.RowVersion = signerVersion;
        if (adoption is not null)
        {
            first.SignatureAdoptionId = adoption.Id; first.SignatureAdoptedAt = adoption.UsedAt; first.SignatureMethod = adoption.Method;
            first.SignatureImageBlob = adoption.SignatureObjectId.ToString("N"); first.InitialsImageBlob = adoption.InitialsObjectId.ToString("N");
            first.SignatureImageSha256 = adoption.SignatureSha256; first.InitialsImageSha256 = adoption.InitialsSha256;
            first.SignatureTypedName = adoption.TypedName; first.SignatureTypedInitials = adoption.TypedInitials;
            first.SignatureNormalizationVersion = adoption.NormalizationVersion; first.SignatureAdoptionVersion = adoption.AdoptionVersion;
        }
        var prior = audits.Where(x => x.Sequence <= cut).ToArray();
        var saved = fields.Where(x => x.SignerId != first.Id).Concat(originalFields ?? fields.Where(x => x.SignerId == first.Id)).ToArray();
        var rawPreviews = previews.Where(x => x.CreatedAt <= stageAt).Select(Clone).ToArray();
        var adoptedIds = prior.Where(x => x.Event == "signature_adopted").Select(x => {
            using var body = JsonDocument.Parse(x.DataJson); return body.RootElement.GetProperty("adoptionId").GetGuid(); }).ToHashSet();
        foreach (var p in rawPreviews) if (!adoptedIds.Contains(p.Id)) p.UsedAt = null;
        var replacements = new Dictionary<string, JsonElement> {
            ["Envelopes"] = JsonSerializer.SerializeToElement(new[] { e }, Rows), ["Signers"] = JsonSerializer.SerializeToElement(signers, Rows),
            ["Fields"] = JsonSerializer.SerializeToElement(saved, Rows), ["SignaturePreviews"] = JsonSerializer.SerializeToElement(rawPreviews, Rows),
            ["SignerReviewCandidates"] = JsonSerializer.SerializeToElement(Array.Empty<SignerReviewCandidate>(), Rows),
            ["SignerFinishAcceptances"] = JsonSerializer.SerializeToElement(Array.Empty<SignerFinishAcceptance>(), Rows),
            ["AuditEvents"] = JsonSerializer.SerializeToElement(prior.Where(x => !reduce || !Added(x.Event)).ToArray(), Rows),
            ["WorkItems"] = JsonSerializer.SerializeToElement(tables["WorkItems"].Deserialize<WorkItem[]>(Rows)!.Where(x => x.Id != finish?.Id && x.Id != finish?.NextInvitationId).ToArray(), Rows),
            ["EmailOutbox"] = JsonSerializer.SerializeToElement(tables["EmailOutbox"].Deserialize<EmailOutbox[]>(Rows)!.Where(x => x.Id != finish?.NextInvitationId).ToArray(), Rows)
        };
        return JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = envelope.Id, CapturedAt = original.GetProperty("CapturedAt").GetDateTimeOffset(),
            Tables = tables.Select(x => new { Table = x.Key, Rows = replacements.GetValueOrDefault(x.Key, x.Value) }) }));
    }

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
    private static InvalidDataException Invalid() => new("The closed first-signer review and checkpoint evidence could not be verified.");
}

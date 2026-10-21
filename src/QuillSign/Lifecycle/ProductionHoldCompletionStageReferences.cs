using System.Data.SqlTypes;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// A CLOSED, settled completion graph. Every original SQL row remains in the
// capture and archive. Only this private factual projection may feed the older
// sequential verifier: saved BeforeEnvelope, saved pre-Claim work and the actual
// unchanged audit prefix. It creates neither a new fingerprint nor authority.
internal static class ProductionHoldCompletionStageReferences
{
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };
    private sealed record Documents(FinalStoredDocument Executed, FinalStoredDocument Certificate);
    internal static HoldReviewCheckpointHistory ReadVerified(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects,
        IDataProtectionProvider keys, IReadOnlyList<VerifiedReviewInput> reviews, IReadOnlyList<VerifiedCompletionInput> inputs,
        HoldWitnessState state, HoldInvitationHistory? invitationHistory = null)
    {
        try { return Verify(sql, objects, keys, reviews, inputs, state, invitationHistory); }
        catch (Exception error) when (error is JsonException or CryptographicException or KeyNotFoundException or InvalidOperationException or
            ArgumentException or FormatException or OverflowException or NullReferenceException or DocumentRejectedException) { throw Invalid(); }
    }

    private static HoldReviewCheckpointHistory Verify(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects,
        IDataProtectionProvider keys, IReadOnlyList<VerifiedReviewInput> reviews, IReadOnlyList<VerifiedCompletionInput> inputs, HoldWitnessState state, HoldInvitationHistory? invitationHistory)
    {
        ProductionHoldAuditChain.Demand(sql);
        var id = sql.GetProperty("RecordId").GetGuid();
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        if (tables.Values.Any(x => x.GetArrayLength() > 4096) || tables.Values.Sum(x => x.GetArrayLength()) > 4096) throw Invalid();
        T[] Table<T>(string name) => tables[name].Deserialize<T[]>(Rows) ?? throw Invalid();
        var current = Table<Envelope>("Envelopes").Single();
        var (operationId, completion) = DemandSettled(id, state);
        var mailHistory=ProductionHoldCompletionMailReferences.ReadVerified(sql,state,keys,objects);
        ProductionHoldCompletionInputReferences.Demand(sql, state, objects, inputs, keys,mailHistory);
        if (inputs.Count != Enum.GetValues<CompletionInputKind>().Length || inputs.Any(x => x.Context.OperationId != operationId) ||
            inputs.Select(x => x.Kind).Distinct().Count() != inputs.Count) throw Invalid();
        VerifiedCompletionInput Input(CompletionInputKind kind) => inputs.Single(x => x.Kind == kind);
        var candidate = Table<CompletionCandidate>("CompletionCandidates").Single();
        var intent = Table<CompletionPublicationIntent>("CompletionPublicationIntents").Single();
        var result = Table<CompletionPublicationResult>("CompletionPublicationResults").Single();
        // The projection below may remove ONLY this one proven owned terminal;
        // an extra/foreign row must not disappear behind a valid selected row.
        if(Table<ProductionRetentionTerminalRecord>("ProductionRetentionTerminals").Single().EnvelopeId!=id)throw Invalid();
        var before = new PublishedCompletionSource(intent.BeforeEnvelopeJson, result.AfterEnvelopeSha256, result.AuditSequence).Project(current);
        if (current.Id != id || current.Status != EnvelopeStatus.Completed || before.Id != id || before.Status != EnvelopeStatus.Sent || before.IsDemo ||
            result.CompletedAt != completion.Slots![CompletionSlot.PublicationResult].Context.RecordedAt || current.CompletedAt != result.CompletedAt ||
            JsonSerializer.Serialize(Input(CompletionInputKind.PublicationResultPlan).Body.Publication!.Before) != intent.BeforeEnvelopeJson) throw Invalid();
        DemandReceipts(id, completion, objects);
        var final = JsonSerializer.Deserialize<Documents>(result.FinalDocumentsJson) ?? throw Invalid();
        var publication = completion.Slots[CompletionSlot.PublicationResult];
        SameFinal(final.Executed, publication.Receipts[CompletionEffect.PublicationExecutedFinal].Final ?? throw Invalid());
        SameFinal(final.Certificate, publication.Receipts[CompletionEffect.PublicationCertificateFinal].Final ?? throw Invalid());
        var until = CompletionRetentionBinding.RequiredUntil(intent, result.CompletedAt);
        foreach (var value in new[] { final.Executed, final.Certificate })
            if (until is null ? value.Protection != FinalProtection.LegalHold || value.ProtectedUntil is not null :
                value.Protection != FinalProtection.LockedTime || value.ProtectedUntil != until) throw Invalid();

        var audits = Table<AuditEvent>("AuditEvents").OrderBy(x => x.Sequence).ToArray();
        var original = audits.Where(x => x.Sequence <= candidate.AuditSequence).ToArray();
        if (original.Length != candidate.AuditSequence || original.Length == 0 || original[^1].Hash is not { Length: 32 } ||
            !original[^1].Hash.AsSpan().SequenceEqual(candidate.AuditAnchor) || original[^1].Event != "signer_completed" ||
            Input(CompletionInputKind.CandidatePlan).Body.AuditCut.Sequence != candidate.AuditSequence ||
            Input(CompletionInputKind.CandidatePlan).Body.AuditCut.Sha256 != Hex(candidate.AuditAnchor)) throw Invalid();
        var suffix = completion.Slots.Values.SelectMany(x => x.Context.SqlRows).Where(x => x.Table == "AuditEvents")
            .Select(x => long.Parse(x.Key, CultureInfo.InvariantCulture)).Concat(mailHistory.AuditSequences).ToArray();
        if (suffix.Distinct().Count() != suffix.Length || !suffix.ToHashSet().SetEquals(audits.Where(x => x.Sequence > candidate.AuditSequence).Select(x => (long)x.Sequence))) throw Invalid();

        var rows = Table<CompletionSealOutput>("CompletionSealOutputs");
        if (rows.Length != 2) throw Invalid();
        var stages = ProductionCompletionInputCodec.DemandIntentFacts(intent);
        if (stages.Id != candidate.Id || !Same(stages.RowVersion, candidate.RowVersion) || !Same(stages.RecipeSha256, candidate.RecipeSha256) ||
            !Same(stages.FrozenStateSha256, candidate.FrozenStateSha256) || stages.AuditSequence != candidate.AuditSequence || !Same(stages.AuditAnchor, candidate.AuditAnchor)) throw Invalid();
        foreach (var stage in stages.outputs)
        {
            var row = rows.Single(x => x.Id == stage.Id);
            var proof = audits.Single(x => x.Sequence == stage.AuditSequence);
            if (row.EnvelopeId != id || row.CandidateId != candidate.Id || row.Kind != stage.Kind || row.PdfObjectId != stage.PdfObjectId ||
                !Same(row.RowVersion, stage.RowVersion) || !Same(row.RecipeSha256, stage.RecipeSha256) || !Same(row.PdfSha256, stage.Sha256) ||
                !Same(proof.Hash, stage.AuditHash) || proof.Event != CompletionSealOutputs.Event(row.Kind) || proof.DataJson != CompletionSealOutputs.Evidence(row)) throw Invalid();
        }
        var policy = Table<ProductionRetentionPolicyRecord>("ProductionRetentionPolicies").Single();
        var enrollment = new VerifiedProductionRetention(ProductionRetentionPolicyContract.Read(policy.PolicyJson, policy.PolicySha256),
            policy.OriginalCreatedAt, policy.EnrolledAt, policy.AuditSequence, Hex(policy.AuditHash));
        if (!ProductionCompletionRetentionBinding.Matches(intent, enrollment)) throw Invalid();
        var output = rows.Single(x => x.Kind == CompletionSealKind.Executed);
        var certificate = rows.Single(x => x.Kind == CompletionSealKind.Certificate);
        DemandSealLinks(candidate,output,certificate,Input(CompletionInputKind.CertificateContext).Body.SealContext!);
        if (intent.CandidateId != candidate.Id || !Same(final.Executed.Sha256, output.PdfSha256) || final.Executed.Length != output.PdfLength ||
            !Same(final.Certificate.Sha256, certificate.PdfSha256) || final.Certificate.Length != certificate.PdfLength) throw Invalid();

        var work = Table<WorkItem>("WorkItems").Single(x => x.Id == completion.Claim.WorkId);
        using var oldWork = JsonDocument.Parse(completion.Claim.WorkBeforeJson);
        var leased = JsonSerializer.Deserialize<WorkItem>(completion.Claim.WorkAfterJson, Rows) ?? throw Invalid();
        if (work.Status != WorkStatus.Completed || work.EnvelopeId != id || work.Kind != WorkKind.Sealing || work.Attempts != completion.Claim.Attempt ||
            work.LeaseOwner is not null || work.LeaseExpiresAt is not null || work.LastError is not null || work.PayloadJson != leased.PayloadJson ||
            work.AvailableAt > completion.Slots[CompletionSlot.WorkFinish].Context.RecordedAt || work.AvailableAt < leased.AvailableAt) throw Invalid();
        var notices = Table<EmailOutbox>("EmailOutbox").Where(x => x.Template == CompletionNotificationJobs.Template).Select(x => x.Id).ToHashSet();
        if (notices.Count != Input(CompletionInputKind.PublicationResultPlan).Body.Publication!.Notifications.Length) throw Invalid();
        using var projection = Project(sql, before, completion.Claim.WorkId, oldWork.RootElement, candidate.AuditSequence, notices,mailHistory.TokenIds);
        // Original complete history is checked on exactly saved facts, never
        // rehashed, relabelled or reconstructed from a newer participant state.
        var history = ProductionHoldReviewCheckpointReferences.ReadVerified(projection.RootElement, objects, keys, reviews, invitationHistory);
        DemandCandidate(projection.RootElement, candidate, objects);
        return history;
    }

    internal static void DemandSealLinks(CompletionCandidate candidate,CompletionSealOutput executed,CompletionSealOutput certificate,CompletionSealInputContext originalCertificate)
    {
        if(executed.EnvelopeId!=candidate.EnvelopeId||certificate.EnvelopeId!=candidate.EnvelopeId||executed.CandidateId!=candidate.Id||certificate.CandidateId!=candidate.Id||
            !Same(executed.CandidateRecipeSha256,candidate.RecipeSha256)||!Same(certificate.CandidateRecipeSha256,candidate.RecipeSha256)||
            !Same(executed.EvidenceSha256,candidate.EvidenceSha256)||!Same(certificate.EvidenceSha256,candidate.EvidenceSha256)||
            executed.SourceObjectId!=candidate.PdfObjectId||executed.SourceLength!=candidate.PdfLength||!Same(executed.SourceSha256,candidate.PdfSha256)||
            !Same(certificate.ExecutedSha256,executed.PdfSha256)||originalCertificate.ExecutedSha256!=Hex(executed.PdfSha256)||
            originalCertificate.ExecutedRecipeSha256!=Hex(executed.RecipeSha256))throw Invalid();
    }

    internal static (Guid OperationId, HoldWitnessCompletionState Completion) DemandSettled(Guid recordId, HoldWitnessState state)
    {
        if (recordId == Guid.Empty || state.Unacknowledged is not null || state.Completions?.Count != 1) throw Invalid();
        var pair = state.Completions.Single(); var id = pair.Key; var value = pair.Value;
        if (state.Operations?.GetValueOrDefault(id) is not { } owner || !ProductionCompletionProtocol.Sealing(owner.Kind) ||
            owner.Reference != value.Claim.WorkId.ToString("N") + "/attempt/" + value.Claim.Attempt.ToString(CultureInfo.InvariantCulture) ||
            !state.SettledOperations.ContainsKey(id) || state.Outcomes?.ContainsKey(id) != true || state.HandlerOutcomes?.ContainsKey(id) != true ||
            state.OutstandingOperation == id || value.ClaimAcknowledged is null || value.Slots?.Count != 7) throw Invalid();
        foreach (var slot in Enum.GetValues<CompletionSlot>())
        {
            if (!value.Slots.TryGetValue(slot, out var saved) || saved.Expected is null || saved.Acknowledged is null ||
                saved.Acknowledged.ContentSha256 != saved.Expected.ContentSha256 || saved.Acknowledged.SqlStateSha256 != saved.Expected.SqlStateSha256 || saved.Rows is null ||
                saved.Context.Slot != slot || saved.Context.OperationId != id || saved.Context.WorkId != value.Claim.WorkId ||
                saved.Started.Count != saved.Receipts.Count || !saved.Started.Keys.ToHashSet().SetEquals(ProductionCompletionProtocol.Effects(slot))) throw Invalid();
        }
        return (id, value);
    }

    private static void DemandReceipts(Guid id, HoldWitnessCompletionState state, IReadOnlyList<HoldObjectEvidence> objects)
    {
        foreach (var slot in state.Slots!.Values)
            foreach (var (effect, started) in slot.Started)
            {
                var receipt = slot.Receipts[effect]; ProductionCompletionProtocol.Receipt(receipt);
                if (ProductionCompletionProtocol.Digest(receipt.Effect) != ProductionCompletionProtocol.Digest(started)) throw Invalid();
                if (receipt.Stored is { } stored)
                {
                    var item = stored.Item; var prefix = item.Blob.Kind switch {
                        DocumentBlobKind.CompletionInput => "completion-inputs/", DocumentBlobKind.CompletionCandidate => "completion-candidates/",
                        DocumentBlobKind.CompletionExecutedSeal => "completion-seals/executed/", DocumentBlobKind.CompletionCertificateSource => "completion-seals/certificate-source/",
                        DocumentBlobKind.CompletionCertificateSeal => "completion-seals/certificate/", _ => throw Invalid() };
                    var name = $"{id:N}/{prefix}{item.Blob.ObjectId:N}";
                    if (item.Blob.EnvelopeId != id || item.Blob.ObjectId != started.TargetId || item.Length != started.Length || item.Sha256 != started.Sha256 ||
                        !objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == name && x.Address.VersionId == stored.VersionId &&
                            x.Address.Snapshot.Length == 0 && x.Address.ETag == stored.ETag && x.Address.Length == item.Length && x.Sha256 == item.Sha256)) throw Invalid();
                }
                else if (receipt.Final is { } final)
                {
                    if (final.Document.EnvelopeId != id || final.Document.ObjectId != started.TargetId || final.Length != started.Length || Hex(final.Sha256) != started.Sha256 ||
                        !objects.Any(x => x.Address.Area == "final" && x.Address.Name == $"{id:N}/{final.Document.Kind.ToString().ToLowerInvariant()}/{final.Document.ObjectId:N}" &&
                            x.Address.VersionId == final.VersionId && x.Address.Snapshot.Length == 0 && x.Address.ETag == final.ETag && x.Address.Length == final.Length && x.Sha256 == Hex(final.Sha256))) throw Invalid();
                }
                else if (!ProductionCompletionProtocol.Tsa(effect)) throw Invalid();
            }
    }

    // Called only after the exact earlier sequential graph succeeds. Reuse the
    // actual collector's pure producer formulas, including original PNG bytes,
    // SQLGuid field/recipient/Finish order and C# Guid adoption ordering.
    internal static void DemandCandidate(JsonElement sql, CompletionCandidate candidate, IReadOnlyList<HoldObjectEvidence> objects)
    {
        var tables = sql.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        T[] Table<T>(string name) => tables[name].Deserialize<T[]>(Rows) ?? throw Invalid();
        var e = Table<Envelope>("Envelopes").Single(); var signers = Table<Signer>("Signers").OrderBy(x => x.Order).ToArray();
        var recipients = Table<Recipient>("Recipients").OrderBy(x => new SqlGuid(x.Id)).ToArray(); var fields = Table<DocumentField>("Fields").OrderBy(x => new SqlGuid(x.Id)).ToArray();
        var finishes = Table<SignerFinishAcceptance>("SignerFinishAcceptances").OrderBy(x => new SqlGuid(x.SignerId)).ToArray();
        var previews = Table<SignaturePreview>("SignaturePreviews"); var adopted = finishes.Select(x => previews.Single(p => p.Id == x.AdoptionId)).OrderBy(x => x.Id).ToArray();
        var audits = Table<AuditEvent>("AuditEvents").OrderBy(x => x.Sequence).ToArray();
        var last = finishes.Single(x => x.Id == e.CurrentFinishId);
        var evidence = CompletionEvidenceValidation.Own(JsonSerializer.Deserialize<CompletionEvidence>(candidate.EvidenceJson) ?? throw Invalid(), default);
        if (e.Id != candidate.EnvelopeId || e.Status != EnvelopeStatus.Sent || candidate.FinishId != last.Id || candidate.SourceObjectId != last.PdfObjectId ||
            candidate.CopyVersion != signers.Length || candidate.CopyVersion != e.CurrentCopyVersion || signers.Any(x => x.Status != SignerStatus.Signed) ||
            !Same(candidate.SourceSha256, last.PdfSha256) || candidate.AuditSequence != audits.Length || !Same(candidate.AuditAnchor, audits[^1].Hash) ||
            !Same(candidate.FrozenStateSha256, CompletionEvidenceCollector.FrozenState(e, signers, recipients, fields, finishes, adopted)) ||
            evidence.PreparedAt != candidate.PreparedAt || !Same(candidate.EvidenceSha256, CompletionEvidenceValidation.Digest(evidence)) ||
            candidate.DocumentPages!=e.PageCount||!SenderPdfRenderer.GeometryMatches(JsonSerializer.Deserialize<PageGeometry[]>(e.PageSizesJson!)??throw Invalid(),
                JsonSerializer.Deserialize<PageGeometry[]>(candidate.GeometryJson)??throw Invalid())) throw Invalid();
        var marks = new Dictionary<Guid, SignerPdfMarks>();
        foreach (var signer in signers)
        {
            var finish = finishes.Single(x => x.SignerId == signer.Id); var mark = adopted.Single(x => x.Id == finish.AdoptionId);
            var saved = evidence.Signers.Single(x => x.Id == signer.Id);
            var signature = Mark(saved.Signature, FieldType.Signature, mark.SignatureObjectId, mark.SignatureSha256);
            var initials = Mark(saved.Initials, FieldType.Initials, mark.InitialsObjectId, mark.InitialsSha256);
            marks.Add(signer.Id, new(mark.Id, mark.SignatureObjectId, mark.InitialsObjectId, signature, initials,
                mark.SignatureSha256, mark.InitialsSha256, mark.NormalizationVersion));
            byte[] Mark(CompletionMark? value, FieldType type, Guid objectId, byte[] hash)
            {
                if (!fields.Any(x => x.SignerId == signer.Id && x.Type == type && x.Value is not null)) { if (value is not null) throw Invalid(); return []; }
                if (value is null || !Same(value.Sha256, hash) || !Same(SHA256.HashData(value.Png), hash) || value.NormalizationVersion != mark.NormalizationVersion ||
                    !objects.Any(x => x.Address.Area == "normalized" && x.Address.Name == $"{e.Id:N}/{objectId:N}" && x.Sha256 == Hex(hash) && x.Address.Length == value.Png.LongLength)) throw Invalid();
                return value.Png;
            }
        }
        var expected = CompletionEvidenceValidation.Own(CompletionEvidenceCollector.ProjectHistorical(e, signers, recipients, fields, finishes, adopted, audits, marks, candidate.PreparedAt), default);
        if (JsonSerializer.Serialize(expected) != candidate.EvidenceJson || !Same(CompletionEvidenceValidation.Digest(expected), candidate.EvidenceSha256)) throw Invalid();
    }

    private static JsonDocument Project(JsonElement original, Envelope before, Guid workId, JsonElement workBefore, long auditCut, HashSet<Guid> notifications,IReadOnlySet<Guid> completionTokens)
    {
        var root = JsonNode.Parse(original.GetRawText())!.AsObject();
        foreach (var entry in root["Tables"]!.AsArray())
        {
            var table = entry!.AsObject(); var name = table["Table"]!.GetValue<string>();
            if (name == "Envelopes") table["Rows"] = new JsonArray(JsonSerializer.SerializeToNode(before, Rows));
            else if (name is "CompletionCandidates" or "CompletionSealOutputs" or "CompletionPublicationIntents" or "CompletionPublicationResults" or "ProductionRetentionTerminals") table["Rows"] = new JsonArray();
            else if(name=="AuthTokens") table["Rows"]=new JsonArray(table["Rows"]!.AsArray().Where(x=>!completionTokens.Contains(x!["Id"]!.GetValue<Guid>())).Select(x=>x!.DeepClone()).ToArray());
            else if (name == "AuditEvents") table["Rows"] = new JsonArray(table["Rows"]!.AsArray().Where(x => x!["Sequence"]!.GetValue<long>() <= auditCut).Select(x => x!.DeepClone()).ToArray());
            else if (name is "WorkItems" or "EmailOutbox") table["Rows"] = new JsonArray(table["Rows"]!.AsArray()
                .Where(x => !notifications.Contains(x!["Id"]!.GetValue<Guid>())).Select(x => name == "WorkItems" && x!["Id"]!.GetValue<Guid>() == workId ? JsonNode.Parse(workBefore.GetRawText()) : x!.DeepClone()).ToArray());
        }
        return JsonDocument.Parse(root.ToJsonString());
    }
    private static void SameFinal(FinalStoredDocument a, FinalStoredDocument b)
    { if (JsonSerializer.Serialize(a) != JsonSerializer.Serialize(b)) throw Invalid(); }
    private static bool Same(byte[]? a, byte[]? b) => a is not null && b is not null && a.AsSpan().SequenceEqual(b);
    private static string Hex(byte[] value) => Convert.ToHexStringLower(value);
    private static InvalidDataException Invalid() => new("The complete preserved completion graph could not be verified.");
}

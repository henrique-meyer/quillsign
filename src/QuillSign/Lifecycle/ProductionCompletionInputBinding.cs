using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// A typed, purpose-authenticated semantic plan, retained BEFORE business SQL.
// It is not a caller-authored table list or a worker/provider capability.
internal sealed class CompletionOwnedRowPlan
{
    private readonly VerifiedCompletionInput input;
    private readonly IDataProtectionProvider keys;
    private CompletionOwnedRowPlan(IDataProtectionProvider keys, VerifiedCompletionInput input)
    {
        if (input.Kind is not (CompletionInputKind.CandidatePlan or CompletionInputKind.ExecutedResult or CompletionInputKind.CertificateResult or
            CompletionInputKind.PublicationIntentPlan or CompletionInputKind.PublicationResultPlan)) throw ProductionCompletionInputCodec.Invalid();
        this.keys = keys; this.input = input;
    }
    internal DateTimeOffset RecordedAt => input.Body.RecordedAt;
    internal VerifiedCompletionInput Input => input;
    internal static CompletionOwnedRowPlan FromInput(IDataProtectionProvider keys, ProductionCompletionInput input) => new(keys, input.Verified);
    internal VerifiedCompletionSlotPlan BindSaved(ProductionRecordOperation scope, JsonElement sql)
    {
        if (scope.RecordId != input.RecordId || scope.OperationId != input.Context.OperationId || sql.GetProperty("RecordId").GetGuid() != input.RecordId) throw ProductionCompletionInputCodec.Invalid();
        return VerifiedCompletionSlotPlan.FromInput(input, keys, sql);
    }
}

internal sealed partial class VerifiedCompletionSlotContext
{
    internal static VerifiedCompletionSlotContext FromInput(VerifiedCompletionInput input)
    {
        if (input.Kind is not (CompletionInputKind.CandidatePlan or CompletionInputKind.ExecutedContext or CompletionInputKind.CertificateContext or
            CompletionInputKind.PublicationIntentPlan)) throw ProductionCompletionInputCodec.Invalid();
        ProductionCompletionInputRows.DemandSelectors(input.Body);
        return new(input.Context) { RecordId = input.RecordId };
    }
    internal static VerifiedCompletionSlotContext FromPublicationIntent(VerifiedCompletionInput input,
        HoldWitnessCompletionContext context, Guid resultId, IReadOnlyList<CompletionNotificationRosterMember> members)
    {
        if (input.Kind != CompletionInputKind.PublicationIntentPlan || context.Slot != CompletionSlot.PublicationResult || resultId == Guid.Empty ||
            context.OperationId != input.Context.OperationId || context.WorkId != input.Context.WorkId || context.Attempt != input.Context.Attempt ||
            context.Until != input.Context.Until || context.PayloadSha256 != input.Context.PayloadSha256 || context.RecordedAt < input.Context.RecordedAt) throw ProductionCompletionInputCodec.Invalid();
        ProductionCompletionProtocol.Context(context); var body = input.Body; var row = body.Intent!;
        var audit = new AuditEvent { EnvelopeId = input.RecordId, Sequence = body.AuditCut.Sequence + 1, At = body.RecordedAt,
            ActorType = PartyType.System, Event = "completion_publication_prepared", DataJson = CompletionPublication.Evidence(row), PrevHash = Convert.FromHexString(body.AuditCut.Sha256) };
        audit.Hash = AuditHash.Compute(audit);
        var cut = new CompletionInputAuditCut(audit.Sequence, ProductionCompletionInputCodec.Hex(audit.Hash));
        var before = JsonSerializer.Deserialize<Envelope>(row.BeforeEnvelopeJson) ?? throw ProductionCompletionInputCodec.Invalid();
        if (!context.SqlRows.SequenceEqual(ProductionCompletionInputRows.ResultSelectors(before, resultId, members, cut)) ||
            context.Targets.Single(x => x.Effect == CompletionEffect.PublicationExecutedFinal).TargetId != row.ExecutedObjectId ||
            context.Targets.Single(x => x.Effect == CompletionEffect.PublicationCertificateFinal).TargetId != row.CertificateObjectId) throw ProductionCompletionInputCodec.Invalid();
        return new(context) { RecordId = input.RecordId };
    }
}

internal sealed partial class VerifiedCompletionSlotPlan
{
    internal static VerifiedCompletionSlotPlan FromInput(VerifiedCompletionInput input, IDataProtectionProvider keys, JsonElement sql)
    {
        var rows = ProductionCompletionInputRows.Bind(input, keys, sql);
        ProductionCompletionInputRows.DemandSelectors(input.Body);
        if (!rows.Select(x => new CompletionSqlSelector(x.Table, x.Key, x.BeforeJson is null ? null : ProductionCompletionProtocol.Digest(x.BeforeJson)))
            .SequenceEqual(input.Context.SqlRows)) throw ProductionCompletionInputCodec.Invalid();
        return new(new(ProductionCompletionInputCodec.ContextSha256(input.Context), input.Descriptor, ProductionCompletionProtocol.Digest(rows)), rows);
    }
}

internal sealed partial class ProductionRecordOperationAdmission
{
    internal async Task<ProductionCompletionSqlPermit> PrepareCompletionSqlLockedAsync(QuillSignDbContext db,
        ProductionRecordOperation scope, CompletionOwnedRowPlan owned, CancellationToken ct = default)
    {
        _ = await DemandCompletionHeadLocked(db, scope, ct);
        var sql = await Capture(db, scope.RecordId, await Requests(db, scope.RecordId, ct), ct);
        using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        var plan = owned.BindSaved(scope, plain.RootElement);
        return await PrepareCompletionSqlLockedAsync(db, scope, plan, ct);
    }
}

internal static partial class ProductionCompletionInputRows
{
    private static readonly JsonSerializerOptions Sql = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, Converters = { new JsonStringEnumConverter() } };
    internal static CompletionSqlSelector[] Selectors(CompletionCandidate row, CompletionInputAuditCut cut)
        => [new("CompletionCandidates", row.Id.ToString("N")), new("AuditEvents", Sequence(cut.Sequence + 1))];
    internal static CompletionSqlSelector[] Selectors(CompletionSealInputContext row, CompletionInputAuditCut cut)
        => [new("CompletionSealOutputs", row.OutputRowId.ToString("N")), new("AuditEvents", Sequence(cut.Sequence + 1))];
    internal static CompletionSqlSelector[] Selectors(CompletionPublicationIntent row, CompletionInputAuditCut cut)
        => [new("CompletionPublicationIntents", row.Id.ToString("N")), new("AuditEvents", Sequence(cut.Sequence + 1))];
    internal static CompletionSqlSelector[] ResultSelectors(Envelope before, Guid resultId,
        IReadOnlyList<CompletionNotificationRosterMember> members, CompletionInputAuditCut cut)
    {
        var result = new List<CompletionSqlSelector> {
            new("Envelopes", before.Id.ToString("N"), ProductionCompletionProtocol.Digest(Canonical(JsonSerializer.SerializeToElement(before, Sql), false))),
            new("CompletionPublicationResults", resultId.ToString("N")), new("ProductionRetentionTerminals", before.Id.ToString("N")),
            new("AuditEvents", Sequence(cut.Sequence + 1)), new("AuditEvents", Sequence(cut.Sequence + 2)) };
        var sequence = cut.Sequence + 3;
        foreach (var member in members)
        {
            var id = CompletionNotificationJobs.Id(resultId, member.Type, member.Id).ToString("N");
            result.Add(new("EmailOutbox", id)); result.Add(new("WorkItems", id)); result.Add(new("AuditEvents", Sequence(sequence++)));
        }
        return result.ToArray();
    }
    internal static void DemandSelectors(CompletionInputV1 body)
    {
        var expected = body.Kind switch {
            CompletionInputKind.CandidatePlan => Selectors(body.Candidate!, body.AuditCut),
            CompletionInputKind.ExecutedContext or CompletionInputKind.ExecutedResult or CompletionInputKind.CertificateContext or CompletionInputKind.CertificateResult
                => Selectors(body.SealContext!, body.AuditCut),
            CompletionInputKind.PublicationIntentPlan => Selectors(body.Intent!, body.AuditCut),
            CompletionInputKind.PublicationResultPlan => ResultSelectors(body.Publication!.Before, body.Publication.Result.Id, body.Publication.Notifications, body.AuditCut),
            _ => throw ProductionCompletionInputCodec.Invalid() };
        if (!expected.SequenceEqual(body.Context.SqlRows)) throw ProductionCompletionInputCodec.Invalid();
    }
    internal static CompletionSqlRow[] Bind(VerifiedCompletionInput input, IDataProtectionProvider keys, JsonElement sql)
    {
        var body = input.Body; DemandSelectors(body); var rows = new List<CompletionSqlRow>();
        if (input.Kind == CompletionInputKind.CandidatePlan)
        {
            var expected = body.Candidate!; var actual = Entity<CompletionCandidate>(sql, "CompletionCandidates", expected.Id.ToString("N"));
            MatchVersioned(expected, actual); var envelope = Entity<Envelope>(sql, "Envelopes", body.RecordId.ToString("N"));
            var evidence = JsonSerializer.Deserialize<CompletionEvidence>(expected.EvidenceJson) ?? throw ProductionCompletionInputCodec.Invalid();
            if (evidence.EnvelopeId.ToString("N") != envelope.PublicId || evidence.Document.Id.ToString("N") != envelope.PdfBlob ||
                expected.FinishId != envelope.CurrentFinishId || expected.CopyVersion != envelope.CurrentCopyVersion) throw ProductionCompletionInputCodec.Invalid();
            Add(rows, sql, "CompletionCandidates", expected.Id.ToString("N"));
            Audit(rows, sql, body, body.AuditCut.Sequence + 1, body.AuditCut.Sha256, "completion_prepared", CompletionCandidates.PreparationJson(expected));
        }
        else if (input.Kind is CompletionInputKind.ExecutedResult or CompletionInputKind.CertificateResult)
        {
            var expected = body.SealResult!; var actual = Entity<CompletionSealOutput>(sql, "CompletionSealOutputs", expected.Id.ToString("N"));
            MatchVersioned(expected, actual); Add(rows, sql, "CompletionSealOutputs", expected.Id.ToString("N"));
            Audit(rows, sql, body, body.AuditCut.Sequence + 1, body.AuditCut.Sha256, CompletionSealOutputs.Event(expected.Kind), CompletionSealOutputs.Evidence(expected));
        }
        else if (input.Kind == CompletionInputKind.PublicationIntentPlan)
        {
            var expected = body.Intent!; var actual = Entity<CompletionPublicationIntent>(sql, "CompletionPublicationIntents", expected.Id.ToString("N"));
            DemandIntentStageRows(body, expected, sql);
            MatchVersioned(expected, actual); Add(rows, sql, "CompletionPublicationIntents", expected.Id.ToString("N"));
            Audit(rows, sql, body, body.AuditCut.Sequence + 1, body.AuditCut.Sha256, "completion_publication_prepared", CompletionPublication.Evidence(expected));
        }
        else if (input.Kind == CompletionInputKind.PublicationResultPlan) BindResult(body, keys, sql, rows);
        else throw ProductionCompletionInputCodec.Invalid();
        return rows.ToArray();
    }
    private static void DemandIntentStageRows(CompletionInputV1 body, CompletionPublicationIntent intent, JsonElement sql)
    {
        var stages = ProductionCompletionInputCodec.DemandIntentFacts(intent);
        var candidate = Entity<CompletionCandidate>(sql, "CompletionCandidates", stages.Id.ToString("N"));
        if (candidate.EnvelopeId != body.RecordId || candidate.AuditSequence != stages.AuditSequence ||
            !candidate.RowVersion.AsSpan().SequenceEqual(stages.RowVersion) || !candidate.RecipeSha256.AsSpan().SequenceEqual(stages.RecipeSha256) ||
            !candidate.FrozenStateSha256.AsSpan().SequenceEqual(stages.FrozenStateSha256) || !candidate.AuditAnchor.AsSpan().SequenceEqual(stages.AuditAnchor)) throw ProductionCompletionInputCodec.Invalid();
        foreach (var output in stages.outputs)
        {
            var saved = Entity<CompletionSealOutput>(sql, "CompletionSealOutputs", output.Id.ToString("N"));
            if (saved.EnvelopeId != body.RecordId || saved.CandidateId != candidate.Id || saved.PdfObjectId != output.PdfObjectId || saved.Kind != output.Kind ||
                !saved.RowVersion.AsSpan().SequenceEqual(output.RowVersion) || !saved.RecipeSha256.AsSpan().SequenceEqual(output.RecipeSha256) ||
                !saved.PdfSha256.AsSpan().SequenceEqual(output.Sha256)) throw ProductionCompletionInputCodec.Invalid();
            var proof = Entity<AuditEvent>(sql, "AuditEvents", Sequence(output.AuditSequence));
            if (proof.EnvelopeId != body.RecordId || proof.Event != CompletionSealOutputs.Event(saved.Kind) || proof.ActorType != PartyType.System ||
                proof.ActorId is not null || proof.ActorEmail is not null || proof.Ip is not null || proof.UserAgent is not null ||
                proof.DataJson != CompletionSealOutputs.Evidence(saved) || !proof.Hash.AsSpan().SequenceEqual(output.AuditHash) ||
                !AuditHash.Compute(proof).AsSpan().SequenceEqual(proof.Hash)) throw ProductionCompletionInputCodec.Invalid();
        }
        if (stages.outputs[1].AuditSequence != body.AuditCut.Sequence || ProductionCompletionInputCodec.Hex(stages.outputs[1].AuditHash) != body.AuditCut.Sha256)
            throw ProductionCompletionInputCodec.Invalid();
    }
    private static T Entity<T>(JsonElement sql, string table, string key) where T : class
        => Raw(sql, table, key).Deserialize<T>(Sql) ?? throw ProductionCompletionInputCodec.Invalid();
    private static JsonElement Raw(JsonElement sql, string table, string key)
        => sql.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == table).GetProperty("Rows")
            .EnumerateArray().Single(x => Key(table, x) == key);
    private static string Key(string table, JsonElement row) => table == "AuditEvents" ? Sequence(row.GetProperty("Sequence").GetInt64()) :
        row.GetProperty(table is "ProductionRetentionTerminals" or "ProductionRetentionPolicies" ? "EnvelopeId" : "Id").GetGuid().ToString("N");
    private static string Sequence(long value) => value.ToString(CultureInfo.InvariantCulture);
    private static string Canonical(JsonElement row, bool audit) => ProductionRecordOperationAdmission.CompletionRow(row, audit);
    private static void Add(List<CompletionSqlRow> rows, JsonElement sql, string table, string key, string? before = null)
        => rows.Add(new(table, key, before, Canonical(Raw(sql, table, key), table == "AuditEvents")));
    private static void MatchVersioned<T>(T expected, T actual) where T : class, IVersionedRecord
    {
        if (actual.RowVersion is not { Length: 8 }) throw ProductionCompletionInputCodec.Invalid();
        var owned = JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(expected, Sql), Sql) ?? throw ProductionCompletionInputCodec.Invalid();
        owned.RowVersion = actual.RowVersion.ToArray();
        if (JsonSerializer.Serialize(owned, Sql) != JsonSerializer.Serialize(actual, Sql)) throw ProductionCompletionInputCodec.Invalid();
    }
    private static AuditEvent Audit(List<CompletionSqlRow> rows, JsonElement sql, CompletionInputV1 body, long sequence,
        string previous, string name, string payload)
    {
        var actual = Entity<AuditEvent>(sql, "AuditEvents", Sequence(sequence));
        var expected = new AuditEvent { Id = actual.Id, EnvelopeId = body.RecordId, Sequence = sequence, At = body.RecordedAt,
            ActorType = PartyType.System, Event = name, DataJson = payload, PrevHash = Convert.FromHexString(previous) };
        expected.Hash = AuditHash.Compute(expected);
        if (actual.Id < 1 || JsonSerializer.Serialize(actual, Sql) != JsonSerializer.Serialize(expected, Sql)) throw ProductionCompletionInputCodec.Invalid();
        Add(rows, sql, "AuditEvents", Sequence(sequence)); return actual;
    }
}

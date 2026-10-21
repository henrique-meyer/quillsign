using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionCompletionIntentInputTests
{
    private static (IDataProtectionProvider Keys, ProductionCompletionInput Input) Create()
    {
        var now = ProductionCompletionInputCodecTests.Now; var hash = Convert.FromHexString(ProductionCompletionInputCodecTests.Hash("synthetic"));
        hash[0] = 251; // Actual binary producer base64 starts with '+'.
        var envelope = new Envelope { Status = EnvelopeStatus.Sent, SenderEmail = "sender@example.invalid", CreatedAt = now.AddHours(-1), RowVersion = [1,2,3,4,5,6,7,8] };
        var row = new CompletionPublicationIntent { EnvelopeId = envelope.Id, CandidateId = Guid.NewGuid(), ExecutedOutputId = Guid.NewGuid(), CertificateOutputId = Guid.NewGuid(),
            BeforeEnvelopeJson = JsonSerializer.Serialize(envelope), PreparedAt = now, RetentionDays = 365 };
        var outputs = new[] { new ProductionCompletionInputCodec.CompletionStageOutput(row.ExecutedOutputId, Guid.NewGuid(), CompletionSealKind.Executed, hash, new byte[8], 2, hash, hash),
            new ProductionCompletionInputCodec.CompletionStageOutput(row.CertificateOutputId, Guid.NewGuid(), CompletionSealKind.Certificate, hash, new byte[8], 3, hash, hash) };
        var stage = new ProductionCompletionInputCodec.CompletionStages(row.CandidateId, envelope.Id, hash, new byte[8], hash, 1, hash, outputs);
        var settings = ProductionRetentionAdmissionContractTests.Settings(); settings.Production.CompletedDays = row.RetentionDays;
        var snapshot = ProductionRetentionPolicyContract.Freeze(envelope.Id, ProductionRetentionLedger.Seconds(envelope.CreatedAt), settings.Production);
        var enrolled = new VerifiedProductionRetention(snapshot, envelope.CreatedAt, envelope.CreatedAt, 1, ProductionCompletionInputCodecTests.Hash("enrollment"));
        row.StageBindingsJson = ProductionCompletionRetentionBinding.Bind(JsonSerializer.Serialize(stage), enrolled); row.RecipeSha256 = CompletionPublication.Recipe(row);
        var cut = new CompletionInputAuditCut(3, Convert.ToHexStringLower(hash));
        var context = ProductionCompletionInputCodecTests.Context(CompletionSlot.PublicationIntent, ProductionCompletionInputRows.Selectors(row, cut));
        var keys = new EphemeralDataProtectionProvider(); return (keys, ProductionCompletionInput.OwnIntent(keys, envelope.Id, context, row, now, cut));
    }
    [Fact]
    public void Actual_retention_wrapper_escaped_base64_preserves_original_recipe_bytes_and_closed_typed_stage_shape()
    {
        var f = Create(); var row = f.Input.Verified.Body.Intent!;
        var original = row.StageBindingsJson; var recipe = row.RecipeSha256.ToArray();
        var stages = ProductionCompletionInputCodec.DemandIntentFacts(row);
        var wrapper = ProductionCompletionRetentionBinding.Read(row)!;
        Assert.Contains("+", JsonSerializer.Serialize(stages), StringComparison.Ordinal);
        Assert.Contains("\\u002B", wrapper.Stages.GetRawText(), StringComparison.Ordinal);
        Assert.Equal(wrapper.Stages.GetRawText(), JsonSerializer.Serialize(JsonSerializer.SerializeToElement(stages)));
        Assert.Equal(original, row.StageBindingsJson); Assert.Equal(recipe, CompletionPublication.Recipe(row));
    }
    [Fact]
    public void Original_frozen_stage_and_policy_can_open_only_same_result_ID_roster_targets_and_recorded_clock_projection()
    {
        var f = Create(); var input = f.Input.Verified; var row = input.Body.Intent!;
        Assert.Equal(row.CandidateId, ProductionCompletionInputCodec.DemandIntentFacts(row).Id);
        var first = VerifiedCompletionSlotContext.FromInput(input); Assert.Equal(input.RecordId, first.RecordId);
        var resultId = Guid.NewGuid(); var members = new[] {new CompletionNotificationRosterMember(PartyType.Sender, null, null, "sender@example.invalid", null)};
        var before = JsonSerializer.Deserialize<Envelope>(row.BeforeEnvelopeJson)!;
        var proof = new AuditEvent { EnvelopeId = input.RecordId, Sequence = input.Body.AuditCut.Sequence + 1, At = input.Body.RecordedAt,
            ActorType = PartyType.System, Event = "completion_publication_prepared", DataJson = CompletionPublication.Evidence(row), PrevHash = Convert.FromHexString(input.Body.AuditCut.Sha256) };
        proof.Hash = AuditHash.Compute(proof); var cut = new CompletionInputAuditCut(proof.Sequence, Convert.ToHexStringLower(proof.Hash));
        var context = ProductionCompletionInputCodecTests.Context(CompletionSlot.PublicationResult) with { OperationId = input.Context.OperationId, WorkId = input.Context.WorkId,
            Until = input.Context.Until, PayloadSha256 = input.Context.PayloadSha256,
            SqlRows = ProductionCompletionInputRows.ResultSelectors(before, resultId, members, cut).ToImmutableArray() };
        context = context with { Targets = context.Targets.Select(x => x with { TargetId = x.Effect switch {
            CompletionEffect.PublicationExecutedFinal => row.ExecutedObjectId, CompletionEffect.PublicationCertificateFinal => row.CertificateObjectId, _ => x.TargetId } }).ToImmutableArray() };
        Assert.Equal(input.RecordId, VerifiedCompletionSlotContext.FromPublicationIntent(input, context, resultId, members).RecordId);
        Assert.Throws<InvalidDataException>(() => VerifiedCompletionSlotContext.FromPublicationIntent(input, context, Guid.NewGuid(), members));
        Assert.Throws<InvalidDataException>(() => VerifiedCompletionSlotContext.FromPublicationIntent(input, context with { WorkId = Guid.NewGuid() }, resultId, members));
    }
    [Theory]
    [InlineData("future-stage")][InlineData("output-order")][InlineData("stage-owner")][InlineData("before-future")]
    [InlineData("before-owner")][InlineData("already-completed")][InlineData("demo")][InlineData("policy-days")][InlineData("null-before")]
    public void Rehashed_intent_cannot_expand_nested_producer_shape_or_replace_frozen_before_policy(string fault)
    {
        var f = Create(); var body = f.Input.Verified.Body; var row = body.Intent!;
        var binding = JsonNode.Parse(row.StageBindingsJson)!; var before = JsonNode.Parse(row.BeforeEnvelopeJson)!;
        switch (fault) {
            case "future-stage": binding["Stages"]!["Future"] = true; break;
            case "output-order": var outputs = binding["Stages"]!["outputs"]!.AsArray(); var a = outputs[0]!.DeepClone(); var b = outputs[1]!.DeepClone(); outputs[0] = b; outputs[1] = a; break;
            case "stage-owner": binding["Stages"]!["EnvelopeId"] = Guid.NewGuid(); break;
            case "before-future": before["Future"] = true; break;
            case "before-owner": before["Id"] = Guid.NewGuid(); break;
            case "already-completed": before["Status"] = (int)EnvelopeStatus.Completed; break;
            case "demo": before["IsDemo"] = true; break;
            case "policy-days": row.RetentionDays++; break; }
        row.BeforeEnvelopeJson = before.ToJsonString(); row.StageBindingsJson = binding.ToJsonString(); row.RecipeSha256 = CompletionPublication.Recipe(row);
        if (fault == "null-before") row.BeforeEnvelopeJson = null!;
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.Encode(body));
    }
}

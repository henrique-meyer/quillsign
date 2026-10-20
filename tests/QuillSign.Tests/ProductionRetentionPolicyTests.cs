using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionRetentionPolicyTests
{
    private static readonly DateTimeOffset Created = new(2028, 2, 28, 12, 0, 0, TimeSpan.Zero);
    private static ProductionRetentionPolicyOptions Options() => new()
    {
        Version = "operator-policy-v1", ArchiveResponsibility = "Operator maintains the authoritative archive.",
        AbandonedDraftDays = 3, ExpiredDays = 5, DeclinedDays = 7, VoidedDays = 11, CompletedDays = 13
    };
    private static ProductionRetentionSnapshot Snapshot(ProductionRetentionPolicyOptions? options = null) =>
        ProductionRetentionPolicyContract.Freeze(Guid.NewGuid(), Created, options ?? Options());
    private static string Hash(string json) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));

    [Theory]
    [InlineData(nameof(ProductionRetentionPolicyOptions.AbandonedDraftDays))]
    [InlineData(nameof(ProductionRetentionPolicyOptions.ExpiredDays))]
    [InlineData(nameof(ProductionRetentionPolicyOptions.DeclinedDays))]
    [InlineData(nameof(ProductionRetentionPolicyOptions.VoidedDays))]
    [InlineData(nameof(ProductionRetentionPolicyOptions.CompletedDays))]
    public void Every_rule_requires_an_explicit_value(string property)
    {
        var options = Options(); typeof(ProductionRetentionPolicyOptions).GetProperty(property)!.SetValue(options, null);
        Assert.Throws<InvalidOperationException>(() => Snapshot(options));
    }

    [Theory]
    [InlineData(0)][InlineData(-1)][InlineData(36501)]
    public void Noncompleted_rules_cannot_be_zero_unbounded_or_outside_the_supported_interval(int days)
    {
        foreach (var property in new[] { "AbandonedDraftDays", "ExpiredDays", "DeclinedDays", "VoidedDays" })
        {
            var options = Options(); typeof(ProductionRetentionPolicyOptions).GetProperty(property)!.SetValue(options, days);
            Assert.Throws<InvalidDataException>(() => Snapshot(options));
        }
    }

    [Theory]
    [InlineData(-1)][InlineData(36501)]
    public void Completed_retention_rejects_invalid_bounds(int days)
    { var options = Options(); options.CompletedDays = days; Assert.Throws<InvalidDataException>(() => Snapshot(options)); }

    [Theory]
    [InlineData(1)][InlineData(36500)]
    public void Supported_finite_extremes_remain_exact(int days)
    {
        var options = Options(); options.CompletedDays = days; var snapshot = Snapshot(options);
        var decision = ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Completed, Created, Created);
        Assert.Equal(Created.AddDays(days), decision.EligibleAt);
    }

    [Theory]
    [InlineData((int)ProductionRecordStage.Draft, (int)ProductionRetentionClock.Creation, 3)]
    [InlineData((int)ProductionRecordStage.Completed, (int)ProductionRetentionClock.Completion, 13)]
    [InlineData((int)ProductionRecordStage.Expired, (int)ProductionRetentionClock.Expiry, 5)]
    [InlineData((int)ProductionRecordStage.Declined, (int)ProductionRetentionClock.Decline, 7)]
    [InlineData((int)ProductionRecordStage.Voided, (int)ProductionRetentionClock.Void, 11)]
    public void Each_lifecycle_uses_its_actual_frozen_rule_and_clock(int state, int expectedClock, int days)
    {
        var stage = (ProductionRecordStage)state; var clock = (ProductionRetentionClock)expectedClock;
        var snapshot = Snapshot(); var terminal = Created.AddDays(2);
        var decision = ProductionRetentionDecision.Evaluate(snapshot, stage, Created.AddDays(50),
            stage == ProductionRecordStage.Draft ? null : terminal);
        Assert.Equal(ProductionRetentionDisposition.Finite, decision.Disposition);
        Assert.Equal(clock, decision.Clock);
        Assert.Equal(stage == ProductionRecordStage.Draft ? Created : terminal, decision.StartedAt);
        Assert.Equal(decision.StartedAt!.Value.AddDays(days), decision.EligibleAt);
    }

    [Theory]
    [InlineData((int)ProductionRecordStage.Signing, (int)ProductionRetentionDisposition.AwaitingTerminalState)]
    [InlineData((int)ProductionRecordStage.Completing, (int)ProductionRetentionDisposition.RequiresDisposition)]
    public void Inflight_or_incomplete_signing_never_becomes_a_purge_candidate_with_age(int state, int expectedDisposition)
    {
        var stage = (ProductionRecordStage)state; var disposition = (ProductionRetentionDisposition)expectedDisposition;
        var decision = ProductionRetentionDecision.Evaluate(Snapshot(), stage, Created.AddYears(20));
        Assert.Equal(disposition, decision.Disposition); Assert.Null(decision.Clock);
        Assert.Null(decision.StartedAt); Assert.Null(decision.EligibleAt);
        Assert.Throws<InvalidDataException>(() => ProductionRetentionDecision.Evaluate(Snapshot(), stage, Created.AddDays(10), Created));
    }

    [Fact]
    public void Explicit_indefinite_completed_retention_has_no_deadline_and_is_not_a_legal_hold()
    {
        var options = Options(); options.CompletedDays = 0; var snapshot = Snapshot(options);
        var decision = ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Completed, Created.AddYears(20), Created);
        Assert.Equal(ProductionRetentionDisposition.Indefinite, decision.Disposition);
        Assert.Equal(ProductionRetentionClock.Completion, decision.Clock); Assert.Equal(Created, decision.StartedAt); Assert.Null(decision.EligibleAt);
        Assert.Equal(Created.AddDays(7), ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Declined, Created, Created).EligibleAt);
        Assert.Equal(ProductionRetentionDisposition.RequiresDisposition,
            ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Completing, Created).Disposition);
    }

    [Fact]
    public void Later_configuration_changes_cannot_rewrite_an_existing_snapshot_or_its_deadline()
    {
        var options = Options(); var snapshot = Snapshot(options); var serialized = ProductionRetentionPolicyContract.Serialize(snapshot);
        var digest = ProductionRetentionPolicyContract.Digest(snapshot);
        options.CompletedDays = 0; options.AbandonedDraftDays = 36500; options.Version = "operator-policy-v2";
        options.ArchiveResponsibility = "Different archive responsibility.";
        Assert.Equal(serialized, ProductionRetentionPolicyContract.Serialize(snapshot)); Assert.Equal(digest, ProductionRetentionPolicyContract.Digest(snapshot));
        Assert.Equal(Created.AddDays(13), ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Completed, Created, Created).EligibleAt);
        Assert.Equal(0, Snapshot(options).Policy.CompletedDays);
    }

    [Fact]
    public void Canonical_snapshot_roundtrips_with_exact_record_binding()
    {
        var snapshot = Snapshot(); var json = ProductionRetentionPolicyContract.Serialize(snapshot);
        Assert.Equal(snapshot, ProductionRetentionPolicyContract.Read(json, ProductionRetentionPolicyContract.Digest(snapshot)));
        var other = snapshot with { RecordId = Guid.NewGuid() };
        Assert.Throws<InvalidDataException>(() => ProductionRetentionPolicyContract.Read(ProductionRetentionPolicyContract.Serialize(other), Hash(json)));
    }

    [Theory]
    [InlineData("FormatVersion")][InlineData("RecordId")][InlineData("CreatedAt")][InlineData("Policy")]
    public void Missing_evidence_fields_are_not_reconstructed_as_trusted_defaults(string property)
    {
        var json = JsonNode.Parse(ProductionRetentionPolicyContract.Serialize(Snapshot()))!.AsObject(); json.Remove(property);
        var changed = json.ToJsonString(); Assert.Throws<InvalidDataException>(() => ProductionRetentionPolicyContract.Read(changed, Hash(changed)));
    }

    [Theory]
    [InlineData("Version")][InlineData("ArchiveResponsibility")][InlineData("AbandonedDraftDays")]
    [InlineData("ExpiredDays")][InlineData("DeclinedDays")][InlineData("VoidedDays")][InlineData("CompletedDays")]
    public void Missing_policy_fields_are_rejected_even_with_a_recomputed_digest(string property)
    {
        var json = JsonNode.Parse(ProductionRetentionPolicyContract.Serialize(Snapshot()))!.AsObject(); json["Policy"]!.AsObject().Remove(property);
        var changed = json.ToJsonString(); Assert.Throws<InvalidDataException>(() => ProductionRetentionPolicyContract.Read(changed, Hash(changed)));
    }

    [Fact]
    public void Duplicate_unknown_trailing_and_noncanonical_json_cannot_replace_saved_evidence()
    {
        var json = ProductionRetentionPolicyContract.Serialize(Snapshot());
        foreach (var changed in new[] { " " + json, json + " ", json + "{}", json.Replace("{\"FormatVersion\":", "{\"Extra\":1,\"FormatVersion\":"),
            json.Replace("{\"FormatVersion\":", "{\"FormatVersion\":\"wrong\",\"FormatVersion\":") })
            Assert.Throws<InvalidDataException>(() => ProductionRetentionPolicyContract.Read(changed, Hash(changed)));
        Assert.Throws<InvalidDataException>(() => ProductionRetentionPolicyContract.Read(new string(' ', 8193), new string('a', 64)));
        Assert.Throws<InvalidDataException>(() => ProductionRetentionPolicyContract.Read(json, new string('A', 64)));
    }

    [Fact]
    public void Unsupported_policy_record_and_time_values_fail_closed()
    {
        var snapshot = Snapshot();
        foreach (var bad in new[] { snapshot with { FormatVersion = "other" }, snapshot with { RecordId = Guid.Empty }, snapshot with { CreatedAt = default },
            snapshot with { CreatedAt = Created.ToOffset(TimeSpan.FromHours(1)) }, snapshot with { CreatedAt = Created.AddTicks(1) },
            snapshot with { Policy = null! }, snapshot with { Policy = snapshot.Policy with { Version = "bad version" } },
            snapshot with { Policy = snapshot.Policy with { ArchiveResponsibility = " " } } })
            Assert.Throws<InvalidDataException>(() => ProductionRetentionPolicyContract.Serialize(bad));
        foreach (var text in new[] { " archive", "archive\n", "owner\uD800", new string('a', 1025) })
        { var options = Options(); options.ArchiveResponsibility = text; Assert.Throws<InvalidDataException>(() => Snapshot(options)); }
    }

    [Fact]
    public void Invalid_terminal_provenance_and_unrepresentable_deadlines_are_refused()
    {
        var snapshot = Snapshot(); var now = Created.AddDays(2);
        foreach (var at in new DateTimeOffset?[] { null, Created.AddSeconds(-1), now.AddSeconds(1), Created.AddTicks(1), Created.ToOffset(TimeSpan.FromHours(1)) })
            Assert.Throws<InvalidDataException>(() => ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Completed, now, at));
        Assert.Throws<InvalidDataException>(() => ProductionRetentionDecision.Evaluate(snapshot, (ProductionRecordStage)999, now));
        Assert.Throws<InvalidDataException>(() => ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Draft, now, Created));
        Assert.Throws<InvalidDataException>(() => ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Draft, Created.AddTicks(-1)));
        Assert.Throws<InvalidDataException>(() => ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Completed,
            DateTimeOffset.MaxValue, new DateTimeOffset(9999, 12, 31, 0, 0, 0, TimeSpan.Zero)));
        Assert.Throws<InvalidDataException>(() => ProductionRetentionPolicyContract.Freeze(Guid.NewGuid(),
            new DateTimeOffset(9999, 12, 31, 0, 0, 0, TimeSpan.Zero), Options()));
    }

    [Fact]
    public void Deadline_does_not_move_when_evaluated_before_at_or_after_eligibility()
    {
        var snapshot = Snapshot(); var deadline = Created.AddDays(13);
        foreach (var now in new[] { deadline.AddTicks(-1), deadline, deadline.AddYears(1) })
            Assert.Equal(deadline, ProductionRetentionDecision.Evaluate(snapshot, ProductionRecordStage.Completed, now, Created).EligibleAt);
    }
}

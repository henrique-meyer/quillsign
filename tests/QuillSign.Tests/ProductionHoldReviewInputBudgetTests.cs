using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldReviewInputBudgetTests
{
    [Fact]
    public void Original_maximum_aggregate_does_not_become_twenty_times_the_roster_size()
    {
        var maximum = ProductionReviewInputCodec.MaximumCipherBytes;
        ProductionHoldCoordinator.DemandReviewInputBudget(Enumerable.Repeat((long)maximum, SignerReviewCandidates.MaximumCandidatesPerSigner));
        Assert.Throws<InvalidDataException>(() => ProductionHoldCoordinator.DemandReviewInputBudget(
            Enumerable.Repeat((long)maximum, SignerReviewCandidates.MaximumCandidatesPerSigner + 1)));
    }
    [Fact]
    public void More_than_twenty_smaller_owned_candidates_remain_possible_with_one_fixed_record_budget()
    {
        ProductionHoldCoordinator.DemandReviewInputBudget(Enumerable.Repeat(1024L, 100 * SignerReviewCandidates.MaximumCandidatesPerSigner));
        var full = Enumerable.Repeat((long)ProductionReviewInputCodec.MaximumCipherBytes, SignerReviewCandidates.MaximumCandidatesPerSigner - 1);
        ProductionHoldCoordinator.DemandReviewInputBudget(full.Concat([(long)ProductionReviewInputCodec.MaximumCipherBytes - 1, 1]));
        Assert.Throws<InvalidDataException>(() => ProductionHoldCoordinator.DemandReviewInputBudget(
            full.Concat([(long)ProductionReviewInputCodec.MaximumCipherBytes - 1, 2])));
    }
    [Theory]
    [InlineData(0)][InlineData(-1)][InlineData(long.MinValue)][InlineData(long.MaxValue)]
    [InlineData(ProductionReviewInputCodec.MaximumCipherBytes + 1L)]
    public void Invalid_length_refuses_before_visiting_any_later_source_metadata(long bad)
    {
        var visited = 0;
        IEnumerable<long> Metadata()
        {
            visited++; yield return bad;
            visited++; throw new InvalidOperationException("Later metadata must not be visited.");
        }
        Assert.Throws<InvalidDataException>(() => ProductionHoldCoordinator.DemandReviewInputBudget(Metadata())); Assert.Equal(1, visited);
    }
    [Fact]
    public void Aggregate_exhaustion_stops_without_enumerating_unbounded_later_values_or_overflowing()
    {
        var visited = 0;
        IEnumerable<long> Metadata()
        {
            for (var index = 0; index <= SignerReviewCandidates.MaximumCandidatesPerSigner; index++)
            { visited++; yield return ProductionReviewInputCodec.MaximumCipherBytes; }
            throw new InvalidOperationException("Budget exhaustion must stop enumeration.");
        }
        Assert.Throws<InvalidDataException>(() => ProductionHoldCoordinator.DemandReviewInputBudget(Metadata()));
        Assert.Equal(SignerReviewCandidates.MaximumCandidatesPerSigner + 1, visited);
    }
}

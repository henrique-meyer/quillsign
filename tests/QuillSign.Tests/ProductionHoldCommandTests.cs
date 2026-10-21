using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionHoldCommandTests
{
    private static ProductionHoldCommand Place() => new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 0,
        ProductionHoldOperation.Place, "Synthetic preservation test", "Synthetic reason", "synthetic-reference");

    [Fact]
    public void Every_scope_revision_operation_and_private_detail_is_bound_to_the_command()
    {
        var command = Place(); var digest = command.Digest();
        Assert.Equal(digest, command.Digest());
        foreach (var other in new[] { command with { CommandId = Guid.NewGuid() }, command with { RecordId = Guid.NewGuid() },
            command with { HoldId = Guid.NewGuid() }, command with { ExpectedRevision = 1 }, command with { Purpose = "Other purpose" },
            command with { Reason = "Other reason" }, command with { Reference = "Other reference" },
            command with { Operation = ProductionHoldOperation.Release, ExpectedRevision = 1 } }) Assert.NotEqual(digest, other.Digest());
        Assert.Equal(ProductionOperatorPermission.PlaceHold, command.Permission);
        Assert.Equal(ProductionOperatorPermission.ReleaseHold, (command with { Operation = ProductionHoldOperation.Release }).Permission);
    }

    [Fact]
    public void Missing_scope_reason_reference_stale_initial_release_and_revision_overflow_are_invalid()
    {
        var command = Place();
        foreach (var invalid in new[] { command with { CommandId = Guid.Empty }, command with { RecordId = Guid.Empty },
            command with { HoldId = Guid.Empty }, command with { ExpectedRevision = -1 }, command with { ExpectedRevision = long.MaxValue },
            command with { Operation = ProductionHoldOperation.Release }, command with { Operation = (ProductionHoldOperation)99 },
            command with { Purpose = "" }, command with { Reason = new string('x', 2049) }, command with { Reference = " " },
            command with { Reason = "reason\0control" }, command with { Reason = new string('\ud800', 1) },
            command with { Reference = " unreviewed whitespace " } })
            Assert.Throws<InvalidDataException>(() => invalid.Digest());
    }
}

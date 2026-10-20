using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionRetentionLedgerContractTests
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Exact_terminal_intervals_preserve_fractional_time_and_explicit_indefinite(bool indefinite)
    {
        var at = new DateTimeOffset(2028, 2, 28, 23, 59, 59, TimeSpan.Zero).AddTicks(9876543);
        var policy = ProductionRetentionLedgerTests.Policy(); if (indefinite) policy.CompletedDays = 0;
        var snapshot = ProductionRetentionPolicyContract.Freeze(Guid.NewGuid(), ProductionRetentionLedger.Seconds(at), policy);
        var saved = new VerifiedProductionRetention(snapshot, at, at, 1, new string('0', 64));
        var terminalAt = at.AddDays(2);
        var terminal = new VerifiedProductionTerminal(EnvelopeStatus.Completed, terminalAt, ProductionRetentionLedger.Seconds(terminalAt), 2, new string('1', 64));
        Assert.Equal(indefinite ? null : terminalAt.AddDays(365), ProductionRetentionLedger.ExactEligibleAt(saved, terminal));
    }

    [Fact]
    public async Task Missing_parent_transaction_fails_before_any_database_connection_or_configuration_read()
    {
        await using var db = Context(); var service = new ProductionRetentionLedger(db, new(db, TimeProvider.System), TimeProvider.System);
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.PrepareNewLockedAsync(new(), new()));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ReadLockedAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.CaptureTerminalLockedAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ReadTerminalLockedAsync(Guid.NewGuid()));
        Assert.Equal(System.Data.ConnectionState.Closed, db.Database.GetDbConnection().State);
    }

    [Theory]
    [InlineData(false, false)][InlineData(false, true)][InlineData(true, false)][InlineData(true, true)]
    public async Task EF_rejects_changes_and_deletes_to_both_record_types_without_connecting(bool terminal, bool delete)
    {
        await using var db = Context();
        object row = terminal ? new ProductionRetentionTerminalRecord { EnvelopeId = Guid.NewGuid() } : new ProductionRetentionPolicyRecord { EnvelopeId = Guid.NewGuid() };
        db.Attach(row); db.Entry(row).State = delete ? EntityState.Deleted : EntityState.Modified;
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
        Assert.Equal(System.Data.ConnectionState.Closed, db.Database.GetDbConnection().State);
    }

    private static QuillSignDbContext Context() => new(new DbContextOptionsBuilder<QuillSignDbContext>()
        .UseSqlServer("Server=127.0.0.1,1;Database=SyntheticNoConnection;Integrated Security=true;Encrypt=true").Options);
}

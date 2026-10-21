using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Lifecycle;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRecordOperationOutcomeJournalTests
{
    [Fact]
    public async Task Original_optional_null_typed_encrypted_history_remains_readable_without_granting_new_settlement_bypass()
    {
        var run = new History(); await run.Write(run.Initialized(), run.Reserved(), run.Settled());
        var state = await run.Journal.ReadAsync(run.Id);
        Assert.Equal(run.NewSql, state.SqlStateSha256); Assert.Equal(run.NewContent, state.BusinessStateSha256);
        Assert.Equal(Hash, state.SettledOperations[run.OperationId]); Assert.Empty(state.Outcomes!);
        // Reading an old receipt does not make it a freshly sealed outcome.
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Journal.SettleOperationAsync(run.Id, state.Operations![run.OperationId],
            Hash, run.NewContent, run.NewSql, Guid.NewGuid()));
    }

    [Theory]
    [InlineData("future-protocol")][InlineData("missing-outcome")][InlineData("wrong-tuple")]
    [InlineData("wrong-head")][InlineData("different-settlement")]
    public async Task Authenticated_future_or_noncanonical_outcome_transitions_fail_closed(string fault)
    {
        var run = new History(); var reserved = run.Reserved() with { OutcomeVersion = "production-record-operation-outcome-v1" };
        var outcome = run.Prepared(); var settled = run.Settled();
        if (fault == "future-protocol") reserved = reserved with { OutcomeVersion = "unknown-future-protocol" };
        if (fault == "wrong-tuple") outcome = outcome with { OperationReference = "different-owned-reference" };
        if (fault == "wrong-head") outcome = outcome with { RequestRevision = 1, RequestFenceHash = Hash };
        if (fault == "different-settlement") settled = settled with { SqlStateSha256 = Hash };
        var entries = fault == "missing-outcome" ? new[] { run.Initialized(), reserved, settled } : [run.Initialized(), reserved, outcome, settled];
        await run.Write(entries);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Journal.ReadAsync(run.Id));
    }

    [Theory]
    [InlineData("future-version")][InlineData("missing-version")][InlineData("sender-kind")]
    [InlineData("after-final")][InlineData("duplicate-handler")][InlineData("settlement-without-final")]
    public async Task Handler_checkpoint_has_closed_protocol_and_cannot_replace_final_settlement(string fault)
    {
        var run = new History(); var reserve = run.Reserved() with { OutcomeVersion = "production-record-operation-outcome-v1" };
        var handler = run.HandlerPrepared();
        if (fault == "future-version") handler = handler with { HandlerOutcomeVersion = "unknown-future-handler-version" };
        if (fault == "missing-version") handler = handler with { HandlerOutcomeVersion = null };
        if (fault == "sender-kind") { reserve = reserve with { OperationKind = "sender/edit" }; handler = handler with { OperationKind = "sender/edit" }; }
        HoldWitnessEvent[] events = fault switch
        {
            "after-final" => [run.Initialized(), reserve, run.Prepared(), handler],
            "duplicate-handler" => [run.Initialized(), reserve, handler, handler with { EventId = Guid.NewGuid() }],
            "settlement-without-final" => [run.Initialized(), reserve, handler, run.Settled()],
            _ => [run.Initialized(), reserve, handler]
        };
        await run.Write(events); await Assert.ThrowsAsync<InvalidDataException>(() => run.Journal.ReadAsync(run.Id));
    }

    private sealed class History
    {
        internal readonly Guid Id = Guid.NewGuid(), OperationId = Guid.NewGuid();
        internal readonly string NewSql = new('d', 64), NewContent = new('e', 64);
        private readonly Clock clock = new(); private readonly Store store = new();
        private readonly IDataProtectionProvider keys = new EphemeralDataProtectionProvider();
        internal ProductionHoldWitnessJournal Journal => new(store, keys, clock, Installation);
        private HoldWitnessEvent Event(HoldWitnessKind kind) => new(ProductionHoldWitnessJournal.Version, Id, 0, Guid.NewGuid(), kind,
            clock.Now, null, null, null, null, null, 0, null, null, null, null, null, null);
        internal HoldWitnessEvent Initialized() => Event(HoldWitnessKind.Initialized) with { BusinessStateSha256 = Hash, SqlStateSha256 = Hash };
        internal HoldWitnessEvent Reserved() => Event(HoldWitnessKind.OperationReserved) with {
            OperationId = OperationId, OperationKind = "work/5", OperationReference = "synthetic-owned-reference",
            BusinessStateSha256 = Hash, SqlStateSha256 = Hash };
        internal HoldWitnessEvent Prepared() => Event(HoldWitnessKind.OperationOutcomePrepared) with {
            OperationId = OperationId, OperationKind = "work/5", OperationReference = "synthetic-owned-reference",
            BusinessStateSha256 = NewContent, SqlStateSha256 = NewSql };
        internal HoldWitnessEvent HandlerPrepared() => Prepared() with { Kind = HoldWitnessKind.HandlerOutcomePrepared,
            HandlerOutcomeVersion = "production-record-handler-outcome-v1" };
        internal HoldWitnessEvent Settled() => Event(HoldWitnessKind.OperationSettled) with {
            OperationId = OperationId, OperationKind = "work/5", OperationReference = "synthetic-owned-reference",
            BusinessStateSha256 = NewContent, SqlStateSha256 = NewSql, ReceiptSha256 = Hash };
        internal async Task Write(params HoldWitnessEvent[] events)
        {
            var protector = keys.CreateProtector(ProductionHoldWitnessJournal.Version, Installation, Id.ToString("N")); string? prior = null;
            for (var index = 0; index < events.Length; index++)
            {
                var entry = events[index] with { Sequence = index + 1, PreviousHash = prior };
                var bytes = protector.Protect(JsonSerializer.SerializeToUtf8Bytes(entry));
                var row = await store.CreateAsync(new(Id, index + 1, bytes)); prior = row.Sha256;
            }
        }
    }
}

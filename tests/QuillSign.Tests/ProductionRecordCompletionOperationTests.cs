using System.Collections.Immutable;
using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionCompletionJournalTests
{
    [Fact]
    public async Task Seven_closed_slots_replay_exact_bytes_and_require_linear_result_ack_before_single_handler_and_finish()
    {
        var r = await Run.Create(); await r.Claim();
        foreach (var slot in Enum.GetValues<CompletionSlot>())
        {
            await r.Open(slot); await r.Effects(slot); await r.Expected(slot);
            if (slot == CompletionSlot.PublicationResult)
                await Assert.ThrowsAsync<InvalidDataException>(() => r.Journal.PrepareHandlerOutcomeAsync(r.Id, r.Operation, Run.Hash("e"), Run.Hash("s"), Guid.NewGuid()));
            if (slot == CompletionSlot.WorkFinish)
            {
                var e = (await r.State()).Slots![slot].Expected!;
                await r.Journal.PrepareOperationOutcomeAsync(r.Id, r.Operation, e.ContentSha256, e.SqlStateSha256, Guid.NewGuid());
            }
            await r.Ack(slot);
            if (slot == CompletionSlot.HandlerReceipt)
            {
                var e = (await r.State()).Slots![slot].Acknowledged!;
                await r.Journal.PrepareHandlerOutcomeAsync(r.Id, r.Operation, e.ContentSha256, e.SqlStateSha256, Guid.NewGuid());
            }
        }
        var final = (await r.State()).Slots![CompletionSlot.WorkFinish].Acknowledged!;
        var saved = await r.Journal.SettleOperationAsync(r.Id, r.Operation, Run.Hash("receipt"), final.ContentSha256, final.SqlStateSha256, Guid.NewGuid());
        Assert.Null(saved.OutstandingOperation); Assert.Equal(7, saved.Completions![r.Op].Slots!.Count);
        Assert.Equal(Run.Hash("receipt"), saved.SettledOperations[r.Op]);
    }

    [Theory]
    [InlineData("predecessor")][InlineData("slot")][InlineData("targets")][InlineData("deadline")][InlineData("payload")][InlineData("work")][InlineData("future-time")][InlineData("old-time")]
    public async Task A_different_context_cannot_rebase_or_open_a_later_slot(string fault)
    {
        var r = await Run.Create(); await r.Claim(); var context = await r.Context(CompletionSlot.Candidate);
        context = fault switch { "predecessor" => context with { PredecessorSqlStateSha256 = Run.Hash("foreign") },
            "slot" => context with { Slot = CompletionSlot.PublicationResult }, "targets" => context with { Targets = [] },
            "deadline" => context with { Until = context.Until.AddSeconds(1) }, "payload" => context with { PayloadSha256 = Run.Hash("foreign") },
            "work" => context with { WorkId = Guid.NewGuid() }, "future-time" => context with { RecordedAt = r.Clock.Now.AddSeconds(1) },
            "old-time" => context with { RecordedAt = r.Clock.Now.AddSeconds(-1) }, _ => context };
        await Assert.ThrowsAsync<InvalidDataException>(() => r.Change(new(CompletionTransitionKind.SlotOpened, context.Slot, Context: context)));
        Assert.Empty((await r.State()).Slots!);
    }

    [Fact]
    public async Task Lost_start_ack_has_no_second_fresh_effect_and_preserves_original_ciphertext()
    {
        var r = await Run.Create(); await r.Claim(); await r.Open(CompletionSlot.Candidate);
        var effect = r.Descriptor((await r.State()).Slots![CompletionSlot.Candidate].Context.Targets[0]); var eventId = Guid.NewGuid();
        r.Store.LostAck = true;
        await Assert.ThrowsAsync<IOException>(() => r.Change(new(CompletionTransitionKind.EffectStarted, CompletionSlot.Candidate, Effect: effect), eventId));
        var bytes = r.Store.Rows.Last().ProtectedPayload.ToArray();
        Assert.False(await r.Change(new(CompletionTransitionKind.EffectStarted, CompletionSlot.Candidate, Effect: effect), eventId));
        Assert.Equal(bytes, r.Store.Rows.Last().ProtectedPayload);
        await Assert.ThrowsAsync<InvalidDataException>(() => r.Change(new(CompletionTransitionKind.EffectStarted, CompletionSlot.Candidate, Effect: effect)));
        await Assert.ThrowsAsync<InvalidDataException>(() => r.Expected(CompletionSlot.Candidate));
    }

    [Theory]
    [InlineData("claim-physical")][InlineData("claim-hash")][InlineData("slot-physical")][InlineData("slot-hash")]
    public async Task An_ack_cannot_use_the_precommit_transaction_or_different_expected_SQL(string fault)
    {
        var r = await Run.Create();
        if (fault.StartsWith("claim", StringComparison.Ordinal))
        {
            await r.Claim(ack: false); var c = await r.State(); var e = c.ClaimExpected!;
            await Assert.ThrowsAsync<InvalidDataException>(() => r.Change(new(CompletionTransitionKind.ClaimAcknowledged,
                ContentSha256: fault == "claim-hash" ? Run.Hash("foreign") : e.ContentSha256, SqlStateSha256: e.SqlStateSha256,
                PhysicalTransaction: fault == "claim-physical" ? c.Claim.PhysicalTransaction : Guid.NewGuid())));
        }
        else
        {
            await r.Claim(); await r.Open(CompletionSlot.Candidate); await r.Effects(CompletionSlot.Candidate); await r.Expected(CompletionSlot.Candidate);
            var s = (await r.State()).Slots![CompletionSlot.Candidate];
            await Assert.ThrowsAsync<InvalidDataException>(() => r.Change(new(CompletionTransitionKind.SlotAcknowledged, CompletionSlot.Candidate,
                ContentSha256: fault == "slot-hash" ? Run.Hash("foreign") : s.Expected!.ContentSha256, SqlStateSha256: s.Expected!.SqlStateSha256,
                PhysicalTransaction: fault == "slot-physical" ? s.PreparingTransaction : Guid.NewGuid())));
        }
    }

    [Fact]
    public async Task Original_expiry_and_pending_hold_do_not_create_a_new_generation_or_early_outcome()
    {
        var r = await Run.Create(); await r.Claim(); await r.Open(CompletionSlot.Candidate);
        var command = ProductionHoldWitnessJournalTests.Place(r.Id);
        await r.Journal.IntentAsync(ProductionHoldWitnessJournalTests.Authority(r.Clock, command.Permission), ProductionHoldWitnessJournalTests.Operators, command, Guid.NewGuid());
        await r.Effects(CompletionSlot.Candidate);
        await Assert.ThrowsAsync<InvalidDataException>(() => r.Journal.PrepareOperationOutcomeAsync(r.Id, r.Operation, Run.Hash("x"), Run.Hash("s"), Guid.NewGuid()));
        r.Clock.Now = r.Clock.Now.AddHours(2);
        await Assert.ThrowsAsync<InvalidDataException>(() => r.Expected(CompletionSlot.Candidate));
        Assert.Equal(r.Op, (await r.Journal.ReadAsync(r.Id)).OutstandingOperation);
    }

    internal sealed class Run
    {
        internal readonly Guid Id = Guid.NewGuid(), Op = Guid.NewGuid(), Work = Guid.NewGuid();
        internal readonly ProductionHoldWitnessJournalTests.Clock Clock = new();
        internal readonly ProductionHoldWitnessJournalTests.Store Store = new();
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider();
        internal ProductionHoldWitnessJournal Journal => new(Store, Keys, Clock, ProductionHoldWitnessJournalTests.Installation);
        internal HoldWitnessOperation Operation = null!;
        internal static string Hash(string value) => ProductionCompletionProtocol.Digest(value);
        internal static async Task<Run> Create()
        {
            var r = new Run(); await r.Journal.InitializeAsync(r.Id, Hash("base"), Hash("sql"), Guid.NewGuid());
            var state = await r.Journal.ReserveOperationAsync(r.Id, r.Op, "work/3", r.Work.ToString("N") + "/attempt/1", new(0, null, []), Hash("base"), Hash("sql"), Guid.NewGuid());
            r.Operation = state.Operations![r.Op]; return r;
        }
        internal async Task<HoldWitnessCompletionState> State() => (await Journal.ReadAsync(Id)).Completions![Op];
        internal Task<bool> Change(HoldWitnessCompletionTransition value, Guid? eventId = null) => Journal.ChangeCompletionAsync(Id, Operation, value, eventId ?? Guid.NewGuid());
        internal async Task Claim(bool ack = true)
        {
            var tx = Guid.NewGuid(); await Change(new(CompletionTransitionKind.ClaimPlanned, Claim: new(Work, 1, Clock.Now.AddHours(1), Hash("payload"), "{}", "{}", Hash("remainder"), tx)));
            await Change(new(CompletionTransitionKind.ClaimExpected, ContentSha256: Hash("claim"), SqlStateSha256: Hash("claim-sql"), PhysicalTransaction: tx));
            if (ack) await Change(new(CompletionTransitionKind.ClaimAcknowledged, ContentSha256: Hash("claim"), SqlStateSha256: Hash("claim-sql"), PhysicalTransaction: Guid.NewGuid()));
        }
        internal async Task<HoldWitnessCompletionContext> Context(CompletionSlot slot)
        {
            var c = await State(); var prior = slot == CompletionSlot.Candidate ? c.ClaimAcknowledged! : c.Slots![slot - 1].Acknowledged!;
            return new(slot, Op, prior.Sequence, prior.SqlStateSha256, prior.ContentSha256, Work, 1, c.Claim.Until, c.Claim.PayloadSha256,
                ProductionCompletionProtocol.Effects(slot).Select(x => new CompletionEffectTarget(x, ProductionCompletionProtocol.Tsa(x) ? Guid.Empty : Guid.NewGuid())).ToImmutableArray(), [], Hash("remainder"), Clock.Now);
        }
        internal async Task Open(CompletionSlot slot) => await Change(new(CompletionTransitionKind.SlotOpened, slot, Context: await Context(slot)));
        internal CompletionEffectDescriptor Descriptor(CompletionEffectTarget target) => new(target.Effect, target.TargetId, 20, Hash(target.Effect.ToString()), 1, [Hash("request-" + target.Effect)]);
        internal async Task Effects(CompletionSlot slot)
        {
            foreach (var target in (await State()).Slots![slot].Context.Targets)
            {
                var d = Descriptor(target); await Change(new(CompletionTransitionKind.EffectStarted, slot, Effect: d));
                var stored = ProductionCompletionProtocol.Tsa(d.Effect) || ProductionCompletionProtocol.FinalEffect(d.Effect) ? null : new ProductionRecordWriteReceipt(new(new(Id, DocumentBlobKind.Normalized, d.TargetId), d.Length, d.Sha256), "synthetic-version", "\"synthetic-etag\"");
                var final = ProductionCompletionProtocol.FinalEffect(d.Effect) ? new FinalStoredDocument(new(Id, d.Effect == CompletionEffect.PublicationExecutedFinal ? FinalDocumentKind.Executed : FinalDocumentKind.Certificate, d.TargetId),
                    d.Length, Convert.FromHexString(d.Sha256), "synthetic-final-v", "\"synthetic-final-e\"", FinalProtection.LockedTime, Clock.Now.AddDays(1), Clock.Now) : null;
                await Change(new(CompletionTransitionKind.EffectRecorded, slot, Receipt: new(d, Hash("receipt-" + target.Effect), stored, final)));
            }
        }
        internal async Task Expected(CompletionSlot slot)
        {
            var s = (await State()).Slots![slot]; var header = new HoldWitnessCompletionRows(ProductionCompletionProtocol.Digest(s.Context), s.Receipts.Values.FirstOrDefault(x => x.Stored is not null)?.Stored?.Item, Hash("rows"));
            await Change(new(CompletionTransitionKind.RowsPlanned, slot, Rows: header, RemainderSha256: Hash("remainder")));
            await Change(new(CompletionTransitionKind.SlotExpected, slot, Rows: header, ContentSha256: Hash("content-" + slot), SqlStateSha256: Hash("sql-" + slot), PhysicalTransaction: Guid.NewGuid()));
        }
        internal async Task Ack(CompletionSlot slot)
        { var e = (await State()).Slots![slot].Expected!; await Change(new(CompletionTransitionKind.SlotAcknowledged, slot, ContentSha256: e.ContentSha256, SqlStateSha256: e.SqlStateSha256, PhysicalTransaction: Guid.NewGuid())); }
    }
}

public sealed class ProductionCompletionClaimTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("success")][InlineData("rollback")][InlineData("foreign")][InlineData("same-transaction")][InlineData("lost-plan-ack")]
    public async Task Actual_native_claim_is_exactly_fenced_beforecommit_and_does_not_rebase(string fault)
    {
        var run = await ProductionRecordOperationAdmissionTests.Run.Create(fixture);
        await using (var edit = fixture.Open()) await edit.WorkItems.Where(x => x.Id == run.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Kind, WorkKind.Sealing));
        var gate = run.Gate(); await gate.InitializeAsync(run.Id); var operation = Guid.NewGuid();
        var scope = await gate.BeginAsync(run.Id, operation, "work/3", run.Work.ToString("N") + "/attempt/1");
        await using var db = fixture.Open(); var tx = await db.Database.BeginTransactionAsync();
        var expected = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == run.Work);
        expected.Attempts = 1; expected.Status = WorkStatus.Leased; expected.LeaseOwner = operation; expected.LeaseExpiresAt = run.Clock.Now.AddMinutes(5);
        if (fault == "lost-plan-ack")
        {
            run.Store.LostAck = true;
            await Assert.ThrowsAsync<IOException>(() => gate.BeginCompletionClaimLockedAsync(db, scope, expected));
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.BeginCompletionClaimLockedAsync(db, scope, expected));
            await tx.RollbackAsync(); await tx.DisposeAsync(); return;
        }
        var permit = await gate.BeginCompletionClaimLockedAsync(db, scope, expected);
        await db.WorkItems.Where(x => x.Id == run.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, expected.Status).SetProperty(w => w.Attempts, expected.Attempts)
            .SetProperty(w => w.LeaseOwner, expected.LeaseOwner).SetProperty(w => w.LeaseExpiresAt, expected.LeaseExpiresAt));
        if (fault == "foreign")
        {
            await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Title, "unrelated"));
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.PrepareCompletionClaimExpectedLockedAsync(db, permit));
            await tx.RollbackAsync(); await tx.DisposeAsync(); return;
        }
        await gate.PrepareCompletionClaimExpectedLockedAsync(db, permit);
        if (fault == "same-transaction")
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.AcknowledgeCompletionClaimLockedAsync(db, scope));
            await tx.RollbackAsync(); await tx.DisposeAsync(); return;
        }
        if (fault == "rollback") await tx.RollbackAsync(); else await tx.CommitAsync(); await tx.DisposeAsync();
        if (fault == "rollback") await Assert.ThrowsAsync<InvalidDataException>(() => gate.AcknowledgeCompletionClaimAsync(scope));
        else
        {
            await gate.AcknowledgeCompletionClaimAsync(scope);
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.DemandAsync(scope));
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.CompleteAsync(scope, ProductionCompletionJournalTests.Run.Hash("no-op")));
            await using var read = fixture.Open(); await using var readTx = await read.Database.BeginTransactionAsync();
            await gate.DemandCompletionProgressLockedAsync(read, scope);
            Assert.NotNull((await gate.ReadCompletionRecoveryLockedAsync(read, scope)).ClaimAcknowledged);
        }
        Assert.Equal(operation, (await run.Journal().ReadAsync(run.Id)).OutstandingOperation);
    }
}

public sealed class ProductionCompletionEffectTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("success")][InlineData("wrong-request")][InlineData("unknown-request")][InlineData("other-context")][InlineData("expired")][InlineData("hold-drain")][InlineData("readonly-reconcile")][InlineData("backwards-observed")]
    public async Task Native_original_context_and_once_only_request_manifest_never_grant_a_repeat(string fault)
    {
        var r = await ProductionRecordOperationAdmissionTests.Run.Create(fixture);
        await using (var edit = fixture.Open()) await edit.WorkItems.Where(x => x.Id == r.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Kind, WorkKind.Sealing));
        var gate = r.Gate(); await gate.InitializeAsync(r.Id); var op = Guid.NewGuid();
        var scope = await gate.BeginAsync(r.Id, op, "work/3", r.Work.ToString("N") + "/attempt/1");
        await using (var claim = fixture.Open())
        {
            await using var tx = await claim.Database.BeginTransactionAsync(); var next = await claim.WorkItems.AsNoTracking().SingleAsync(x => x.Id == r.Work);
            next.Status = WorkStatus.Leased; next.Attempts = 1; next.LeaseOwner = op; next.LeaseExpiresAt = r.Clock.Now.AddMinutes(5);
            var p = await gate.BeginCompletionClaimLockedAsync(claim, scope, next);
            await claim.WorkItems.Where(x => x.Id == r.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, next.Status).SetProperty(w => w.Attempts, next.Attempts)
                .SetProperty(w => w.LeaseOwner, next.LeaseOwner).SetProperty(w => w.LeaseExpiresAt, next.LeaseExpiresAt));
            await gate.PrepareCompletionClaimExpectedLockedAsync(claim, p); await tx.CommitAsync();
        }
        await gate.AcknowledgeCompletionClaimAsync(scope);
        await using var db = fixture.Open(); await using var parent = await db.Database.BeginTransactionAsync();
        var targets = ProductionCompletionProtocol.Effects(CompletionSlot.Candidate).Select(x => new CompletionEffectTarget(x, Guid.NewGuid())).ToArray();
        var context = await gate.CreateCompletionContextLockedAsync(db, scope, CompletionSlot.Candidate, targets, []);
        // A test-only private-constructor invocation isolates kernel/transport
        // consumption; the production CompletionInput codec owns DP verification.
        var verified = (VerifiedCompletionSlotContext)Activator.CreateInstance(typeof(VerifiedCompletionSlotContext), BindingFlags.Instance | BindingFlags.NonPublic, null, [context], null)!;
        typeof(VerifiedCompletionSlotContext).GetProperty("RecordId", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(verified, r.Id);
        await gate.PrepareCompletionSlotLockedAsync(db, scope, verified);
        var request = ProductionCompletionJournalTests.Run.Hash("exact mutation request");
        var effect = new CompletionEffectDescriptor(CompletionEffect.CandidateInput, targets[0].TargetId, 7, ProductionCompletionJournalTests.Run.Hash("bytes"), 1, [request]);
        var permit = await gate.BeginCompletionEffectLockedAsync(db, scope, CompletionSlot.Candidate, effect);
        if (fault == "other-context")
        {
            await using var other = fixture.Open(); await using var tx = await other.Database.BeginTransactionAsync();
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.ConsumeCompletionEffectRequestLockedAsync(other, permit, request)); return;
        }
        if (fault == "wrong-request")
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.ConsumeCompletionEffectRequestLockedAsync(db, permit, ProductionCompletionJournalTests.Run.Hash("wrong")));
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.ConsumeCompletionEffectRequestLockedAsync(db, permit, request)); return;
        }
        if (fault == "backwards-observed")
        {
            r.Clock.Now = r.Clock.Now.AddMinutes(1); await gate.DemandCompletionEffectLockedAsync(db, permit);
            var durable = (await r.Journal().ReadCompletionClockAsync(r.Id)).At;
            r.Clock.Now = r.Clock.Now.AddSeconds(-30); Assert.True(r.Clock.Now > durable);
            var providerCalls = 0;
            async Task Send() { await gate.ConsumeCompletionEffectRequestLockedAsync(db, permit, request); providerCalls++; }
            await Assert.ThrowsAsync<InvalidDataException>(Send); Assert.Equal(0, providerCalls);
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.DemandCompletionProgressLockedAsync(db, scope)); return;
        }
        if (fault == "expired")
        {
            r.Clock.Now = r.Clock.Now.AddMinutes(5);
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.ConsumeCompletionEffectRequestLockedAsync(db, permit, request)); return;
        }
        await gate.ConsumeCompletionEffectRequestLockedAsync(db, permit, request);
        await Assert.ThrowsAsync<InvalidDataException>(() => gate.ConsumeCompletionEffectRequestLockedAsync(db, permit, request));
        if (fault == "unknown-request")
        {
            var facts = await gate.ReadCompletionRecoveryLockedAsync(db, scope); Assert.Single(facts.Slots![CompletionSlot.Candidate].Started);
            Assert.Empty(facts.Slots[CompletionSlot.Candidate].Receipts);
            await Assert.ThrowsAsync<InvalidDataException>(() => gate.BeginCompletionEffectLockedAsync(db, scope, CompletionSlot.Candidate, effect)); return;
        }
        if (fault == "readonly-reconcile")
        {
            var retained = new ProductionRecordWriteReceipt(new(new(r.Id, DocumentBlobKind.Normalized, targets[0].TargetId), effect.Length, effect.Sha256), "synthetic-v", "\"synthetic-e\"");
            var exact = new CompletionEffectReceipt(effect, ProductionCompletionJournalTests.Run.Hash("readonly-receipt"), retained);
            var proof = (VerifiedCompletionEffectReceipt)Activator.CreateInstance(typeof(VerifiedCompletionEffectReceipt), BindingFlags.Instance | BindingFlags.NonPublic, null, [exact, true], null)!;
            var recovery = r.Gate(); await recovery.ReconcileCompletionEffectLockedAsync(db, scope, CompletionSlot.Candidate, proof);
            var count = r.Store.Rows.Count; await recovery.ReconcileCompletionEffectLockedAsync(db, scope, CompletionSlot.Candidate, proof); Assert.Equal(count, r.Store.Rows.Count);
            await Assert.ThrowsAsync<InvalidDataException>(() => recovery.ConsumeCompletionEffectRequestLockedAsync(db, permit, request));
            Assert.Single((await recovery.ReadCompletionRecoveryLockedAsync(db, scope)).Slots![CompletionSlot.Candidate].Receipts); return;
        }
        if (fault == "hold-drain")
        {
            var command = ProductionHoldWitnessJournalTests.Place(r.Id);
            await r.Journal().IntentAsync(ProductionHoldWitnessJournalTests.Authority(r.Clock, command.Permission), ProductionHoldWitnessJournalTests.Operators, command, Guid.NewGuid());
        }
        await gate.AcknowledgeCompletionEffectRequestLockedAsync(db, permit, request);
        var stored = new ProductionRecordWriteReceipt(new(new(r.Id, DocumentBlobKind.Normalized, targets[0].TargetId), effect.Length, effect.Sha256), "synthetic-v", "\"synthetic-e\"");
        var receipt = new CompletionEffectReceipt(effect, ProductionCompletionJournalTests.Run.Hash("receipt"), stored);
        var factual = (VerifiedCompletionEffectReceipt)Activator.CreateInstance(typeof(VerifiedCompletionEffectReceipt), BindingFlags.Instance | BindingFlags.NonPublic, null, [receipt], null)!;
        await gate.RecordCompletionEffectLockedAsync(db, permit, factual);
        await Assert.ThrowsAsync<InvalidDataException>(() => gate.RecordCompletionEffectLockedAsync(db, permit, factual));
        Assert.Single((await gate.ReadCompletionRecoveryLockedAsync(db, scope)).Slots![CompletionSlot.Candidate].Receipts);
    }
}


public sealed class ProductionCompletionProviderTimeTests
{
    [Theory]
    [InlineData(-1, false)][InlineData(0, true)][InlineData(1, false)]
    public void Fractional_original_clock_uses_provider_HTTP_second_precision_without_backdating_facts(int second, bool accepted)
    {
        var original = new DateTimeOffset(2030, 1, 1, 12, 0, 0, TimeSpan.Zero).AddMilliseconds(750);
        var provider = DateTimeOffset.ParseExact("Tue, 01 Jan 2030 12:00:00 GMT", "R", System.Globalization.CultureInfo.InvariantCulture).AddSeconds(second);
        Assert.Equal(accepted, ProductionCompletionProtocol.ProviderCreationMatches(original, provider, original.AddMilliseconds(100)));
        if (!accepted) return;
        var effect = new CompletionEffectDescriptor(CompletionEffect.PublicationExecutedFinal, Guid.NewGuid(), 20, ProductionCompletionJournalTests.Run.Hash("bytes"), 1, [ProductionCompletionJournalTests.Run.Hash("request")]);
        var actual = new FinalStoredDocument(new(Guid.NewGuid(), FinalDocumentKind.Executed, effect.TargetId), effect.Length, Convert.FromHexString(effect.Sha256), "synthetic-version", "\"synthetic-etag\"", FinalProtection.LockedTime, original.AddDays(1), provider);
        var fact = new CompletionEffectReceipt(effect, ProductionCompletionJournalTests.Run.Hash("receipt"), null, actual);
        var verified = (VerifiedCompletionEffectReceipt)Activator.CreateInstance(typeof(VerifiedCompletionEffectReceipt), BindingFlags.Instance | BindingFlags.NonPublic, null, [fact], null)!;
        Assert.Equal(provider, verified.Receipt.Final!.CreatedAt); // actual fact remains whole-second; no synthetic timestamp is substituted.
    }
}

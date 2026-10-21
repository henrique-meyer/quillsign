using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionHoldWitnessJournalTests
{
    internal const string Installation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    internal const string Hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    internal const string Issuer = "https://operator.example.invalid";
    internal static readonly ProductionOperatorPolicy Operators = new(true, [new(Issuer, "synthetic-operator",
        new HashSet<ProductionOperatorPermission> { ProductionOperatorPermission.PlaceHold, ProductionOperatorPermission.ReleaseHold })]);
    internal sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    internal static ProductionOperatorAuthority Authority(Clock clock, ProductionOperatorPermission permission)
        => ProductionOperatorAuthority.FromValidatedTicket(new(new ClaimsPrincipal(new ClaimsIdentity(
            [new("iss", Issuer, ClaimValueTypes.String, Issuer), new("sub", "synthetic-operator", ClaimValueTypes.String, Issuer)], ProductionOperatorAuthority.OidcScheme)),
            new AuthenticationProperties { IssuedUtc = clock.Now, ExpiresUtc = clock.Now.AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme), Operators, permission, clock);
    internal static ProductionHoldCommand Place(Guid id, long revision = 0) => new(Guid.NewGuid(), id, Guid.NewGuid(), revision,
        ProductionHoldOperation.Place, "Synthetic preservation", "Synthetic private reason", "synthetic-reference");
    internal sealed class Store : IProductionHoldWitnessStore
    {
        internal readonly List<ProductionHoldWitnessObject> Rows = [];
        internal bool LostAck;
        public Task<IReadOnlyList<ProductionHoldWitnessObject>> ReadAsync(Guid recordId, CancellationToken ct = default)
        {
            lock (Rows) return Task.FromResult<IReadOnlyList<ProductionHoldWitnessObject>>(Rows.Where(x => x.Path.Contains($"/{recordId:N}/", StringComparison.Ordinal))
                .Select(x => x with { ProtectedPayload = x.ProtectedPayload.ToArray() }).ToArray());
        }
        public Task<ProductionHoldWitnessObject> CreateAsync(ProductionHoldWitnessWrite write, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            lock (Rows)
            {
                var path = $"production-hold-witnesses/{Installation}/{write.RecordId:N}/{write.Sequence:D10}";
                if (Rows.Any(x => x.Path == path)) throw new IOException("Synthetic create-only slot conflict");
                var bytes = write.ProtectedPayload.ToArray();
                var row = new ProductionHoldWitnessObject(write.Sequence, path, $"synthetic-version-{write.Sequence}", $"\"synthetic-{write.Sequence}\"",
                    bytes.Length, ProductionHoldWitnessJournal.Digest(bytes), bytes, true);
                Rows.Add(row);
                if (LostAck) { LostAck = false; throw new IOException("Synthetic lost create acknowledgement"); }
                return Task.FromResult(row with { ProtectedPayload = bytes.ToArray() });
            }
        }
    }

    [Fact]
    public async Task Independent_holds_freeze_until_each_separately_acknowledged_release_and_restart_preserves_receipts()
    {
        var clock = new Clock(); var store = new Store(); var keys = new EphemeralDataProtectionProvider();
        ProductionHoldWitnessJournal Service() => new(store, keys, clock, Installation);
        var id = Guid.NewGuid(); var a = Place(id); var b = Place(id, 1);
        var pending = await Service().IntentAsync(Authority(clock, a.Permission), Operators, a, Guid.NewGuid());
        Assert.True(pending.Frozen);
        ProductionHoldWitnessJournal.DemandSql(pending with { Unacknowledged = null, RequestRevision = 1, RequestFenceHash = Hash },
            new(1, Hash, [new(a.HoldId, a.CommandId, null, ProductionHoldPendingState.PreservationPending)]));
        await Accept(a, 1); await Preserve(a);
        await Service().IntentAsync(Authority(clock, b.Permission), Operators, b, Guid.NewGuid()); await Accept(b, 2); await Preserve(b);
        var releaseA = a with { CommandId = Guid.NewGuid(), ExpectedRevision = 2, Operation = ProductionHoldOperation.Release };
        await Release(releaseA, 3); Assert.True((await Service().ReadAsync(id)).Frozen);
        var releaseB = b with { CommandId = Guid.NewGuid(), ExpectedRevision = 3, Operation = ProductionHoldOperation.Release };
        await Release(releaseB, 4);
        var final = await Service().ReadAsync(id); Assert.False(final.Frozen);
        Assert.All(final.Holds.Values, x => { Assert.True(x.Released); Assert.Equal(Hash, x.PreservationSha256); Assert.Equal(Hash, x.ReleaseSha256); });
        Assert.DoesNotContain(store.Rows, x => System.Text.Encoding.UTF8.GetString(x.ProtectedPayload).Contains(a.Reason, StringComparison.Ordinal));

        async Task Accept(ProductionHoldCommand command, long revision)
        {
            var state = await Service().ReadAsync(id);
            var holds = state.Holds.Values.Select(x => new PendingProductionHold(x.Placement.HoldId, x.Placement.CommandId,
                x.Release?.CommandId, x.Release is null ? ProductionHoldPendingState.PreservationPending : ProductionHoldPendingState.ReleasePending)).ToArray();
            await Service().AcceptSqlAsync(command, new(command.CommandId, revision, new(revision, Hash, holds)), Hash, Guid.NewGuid());
        }
        async Task Preserve(ProductionHoldCommand command)
        {
            var op = Guid.NewGuid(); var plan = Guid.NewGuid(); await Service().ReservePreservationAsync(command, plan, op, Guid.NewGuid());
            await Service().FreezePlanAsync(command, plan, Hash, new(1, Hash), op, Guid.NewGuid());
            await Service().PreserveAsync(command, plan, Hash, Hash, new(1, Hash), op, Guid.NewGuid());
        }
        async Task Release(ProductionHoldCommand command, long revision)
        {
            await Service().IntentAsync(Authority(clock, command.Permission), Operators, command, Guid.NewGuid()); await Accept(command, revision);
            var op = Guid.NewGuid(); await Service().ReserveReleaseAsync(command, op, Guid.NewGuid());
            await Service().ReleaseAsync(command, Hash, new(1, Hash), op, Guid.NewGuid());
        }
    }

    [Fact]
    public async Task Lost_ack_replay_retains_original_ciphertext_and_time_without_a_second_append()
    {
        var clock = new Clock(); var store = new Store { LostAck = true }; var keys = new EphemeralDataProtectionProvider();
        var journal = new ProductionHoldWitnessJournal(store, keys, clock, Installation); var command = Place(Guid.NewGuid()); var eventId = Guid.NewGuid();
        await Assert.ThrowsAsync<IOException>(() => journal.IntentAsync(Authority(clock, command.Permission), Operators, command, eventId));
        var original = Assert.Single(store.Rows).ProtectedPayload.ToArray(); clock.Now = clock.Now.AddMinutes(1);
        var replay = await new ProductionHoldWitnessJournal(store, keys, clock, Installation).IntentAsync(Authority(clock, command.Permission), Operators, command, eventId);
        Assert.True(replay.Frozen); Assert.Single(store.Rows); Assert.Equal(original, store.Rows[0].ProtectedPayload);
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.IntentAsync(Authority(clock, command.Permission), Operators, command with { Reason = "Changed" }, eventId));
    }

    [Fact]
    public async Task Hold_intent_closes_admission_but_prior_operation_requires_explicit_settlement_even_after_expiry()
    {
        var clock = new Clock(); var store = new Store(); var journal = new ProductionHoldWitnessJournal(store, new EphemeralDataProtectionProvider(), clock, Installation);
        var id = Guid.NewGuid(); var operation = Guid.NewGuid(); var command = Place(id);
        await journal.ReserveAsync(id, operation, Guid.NewGuid(), new(0, null, []));
        await journal.IntentAsync(Authority(clock, command.Permission), Operators, command, Guid.NewGuid());
        await journal.AcceptSqlAsync(command, new(command.CommandId, 1, new(1, Hash, [new(command.HoldId, command.CommandId, null, ProductionHoldPendingState.PreservationPending)])), Hash, Guid.NewGuid());
        clock.Now = clock.Now.AddDays(2);
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReservePreservationAsync(command, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()));
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReserveAsync(id, Guid.NewGuid(), Guid.NewGuid(), new(1, Hash, [])));
        await journal.SettleAsync(id, operation, Hash, Hash, Guid.NewGuid());
        Assert.Equal(Hash, (await journal.ReadAsync(id)).SettledOperations[operation]);
        await journal.ReservePreservationAsync(command, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
    }

    [Theory]
    [InlineData("bytes")][InlineData("hash")][InlineData("path")][InlineData("sequence")][InlineData("hold")][InlineData("duplicate")][InlineData("keys")][InlineData("installation")]
    public async Task Changed_or_foreign_external_history_never_reopens_admission(string mode)
    {
        var clock = new Clock(); var keys = new EphemeralDataProtectionProvider(); var store = new Store();
        var command = Place(Guid.NewGuid()); var journal = new ProductionHoldWitnessJournal(store, keys, clock, Installation);
        await journal.IntentAsync(Authority(clock, command.Permission), Operators, command, Guid.NewGuid()); var row = store.Rows[0];
        switch (mode)
        {
            case "bytes": row.ProtectedPayload[0] ^= 1; break;
            case "hash": store.Rows[0] = row with { Sha256 = Hash }; break;
            case "path": store.Rows[0] = row with { Path = row.Path + "/unexpected" }; break;
            case "sequence": store.Rows[0] = row with { Sequence = 2 }; break;
            case "hold": store.Rows[0] = row with { LegalHold = false }; break;
            case "duplicate": store.Rows.Add(row); break;
            case "keys": journal = new(store, new EphemeralDataProtectionProvider(), clock, Installation); break;
            case "installation": journal = new(store, keys, clock, Hash); break;
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadAsync(command.RecordId));
    }

    [Fact]
    public async Task Early_release_is_refused_before_append_and_pending_hold_remains_preservable()
    {
        var clock = new Clock(); var store = new Store(); var journal = new ProductionHoldWitnessJournal(store, new EphemeralDataProtectionProvider(), clock, Installation);
        var command = Place(Guid.NewGuid()); await journal.IntentAsync(Authority(clock, command.Permission), Operators, command, Guid.NewGuid());
        await journal.AcceptSqlAsync(command, new(command.CommandId, 1, new(1, Hash, [new(command.HoldId, command.CommandId, null, ProductionHoldPendingState.PreservationPending)])), Hash, Guid.NewGuid());
        var release = command with { CommandId = Guid.NewGuid(), Operation = ProductionHoldOperation.Release, ExpectedRevision = 1 };
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.IntentAsync(Authority(clock, release.Permission), Operators, release, Guid.NewGuid()));
        Assert.Equal(2, store.Rows.Count); await journal.ReservePreservationAsync(command, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
    }
}

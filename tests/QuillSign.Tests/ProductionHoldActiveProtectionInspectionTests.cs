using System.Data.Common;
using System.Security.Claims;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionHoldActiveProtectionInspectionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private static ProductionOperatorPolicy StatusPolicy() => new(true, [new(Issuer, "synthetic-status",
        new HashSet<ProductionOperatorPermission> { ProductionOperatorPermission.Status })]);
    private static ProductionOperatorAuthority Status(Clock time, ProductionOperatorPolicy policy) => ProductionOperatorAuthority.FromValidatedTicket(
        new(new ClaimsPrincipal(new ClaimsIdentity([new("iss", Issuer, ClaimValueTypes.String, Issuer),
            new("sub", "synthetic-status", ClaimValueTypes.String, Issuer)], ProductionOperatorAuthority.OidcScheme)),
            new AuthenticationProperties { IssuedUtc = time.Now, ExpiresUtc = time.Now.AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme),
        policy, ProductionOperatorPermission.Status, time);

    [Fact]
    public async Task Genuine_review_two_hold_inspection_is_fresh_readonly_exact_and_independent_of_released_business_history()
    {
        await using var run = await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture, store: b => b);
        Assert.NotNull(await run.Prepare()); using var holds = new ProductionSignerMutationAdmissionTests.Holds(fixture, run.Delivered);
        var first = await holds.Place(0); var second = await holds.Place(1); var policy = StatusPolicy();
        using var client = new HttpClient(holds.Provider, false);
        using var reader = new AzureProductionHoldArchiveInspectionStore(new("https://storage.example.invalid"),
            new ProductionHoldArchiveReleaseTests.Credential(), run.Record.Time, new HttpClientTransport(client));
        var coordinator = holds.Coordinator(); var before = await run.Record.Journal.ReadAsync(run.Id); var providerCount = holds.Provider.Calls.Count;
        var controls = await CountControls(run.Id);
        var observed = await coordinator.InspectActiveProtectionAsync(Status(run.Record.Time, policy), policy, run.Id, reader);
        Assert.Equal(2, observed.Holds.Length); Assert.Equal(18, observed.Holds.Sum(x => x.Objects.Length));
        Assert.Equal(before.HeadHash, observed.WitnessHead); Assert.Equal(2, observed.RequestRevision);
        Assert.Equal(before.HeadHash, (await run.Record.Journal.ReadAsync(run.Id)).HeadHash); Assert.Equal(controls, await CountControls(run.Id));
        Assert.All(holds.Provider.Calls.Skip(providerCount), x => Assert.True(x.StartsWith("GET ", StringComparison.Ordinal) || x.StartsWith("HEAD ", StringComparison.Ordinal)));
        Assert.Equal(0, holds.Provider.Clears); Assert.All(holds.Provider.Files.Values, x => Assert.True(x.Held));
        Assert.Equal(2, (await coordinator.InspectActiveProtectionAsync(Status(run.Record.Time, policy), policy, run.Id, reader)).Holds.Length);

        foreach (var fault in new[] { "bad-bytes", "wrong-version", "wrong-etag", "unheld", "hold-race", "public", "versioning-off" })
        {
            holds.Provider.Fault = fault; holds.Provider.Heads = 0;
            await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Record.Time, policy), policy, run.Id, reader));
            Assert.Equal(before.HeadHash, (await run.Record.Journal.ReadAsync(run.Id)).HeadHash); Assert.Equal(0, holds.Provider.Clears);
        }
        holds.Provider.Fault = "normal";
        var originalTime = run.Record.Time.Now;
        holds.Provider.After = phase => { if (phase == "download") run.Record.Time.Now = originalTime.AddMinutes(5); };
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Record.Time, policy), policy, run.Id, reader));
        holds.Provider.After = null; run.Record.Time.Now = originalTime;
        var grant = (HashSet<ProductionOperatorPermission>)policy.Grants.Single().Permissions;
        var authority = Status(run.Record.Time, policy);
        holds.Provider.After = phase => { if (phase == "download") grant.Clear(); };
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => coordinator.InspectActiveProtectionAsync(authority, policy, run.Id, reader));
        holds.Provider.After = null; grant.Add(ProductionOperatorPermission.Status);

        var release = first with { CommandId = Guid.NewGuid(), Operation = ProductionHoldOperation.Release, ExpectedRevision = 2 };
        await coordinator.SubmitAsync(Authority(run.Record.Time, release.Permission), Operators, release);
        providerCount = holds.Provider.Calls.Count;
        await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Record.Time, policy), policy, run.Id, reader));
        Assert.Equal(providerCount, holds.Provider.Calls.Count);
        await coordinator.ReleaseAsync(run.Id, first.HoldId);
        var one = await coordinator.InspectActiveProtectionAsync(Status(run.Record.Time, policy), policy, run.Id, reader);
        Assert.Equal(second.HoldId, Assert.Single(one.Holds).HoldId); Assert.Equal(9, one.Holds[0].Objects.Length);
        Assert.False(await holds.Release(second, 3)); providerCount = holds.Provider.Calls.Count;
        await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Record.Time, policy), policy, run.Id, reader));
        Assert.Equal(providerCount, holds.Provider.Calls.Count);
        // Old released plans retain their original business evidence. They must
        // not incorrectly require that old business state after signing resumes.
        var text = (await run.Marks.Fields())!.Fields.Single(x => x.Type == FieldType.Text);
        Assert.Equal(SignerFieldOutcome.Applied, (await run.Marks.Change(new(text.Id, text.Version, SignerFieldAction.Apply, "Synthetic later business state"))).Outcome);
        var later = await holds.Place(4);
        var current = await coordinator.InspectActiveProtectionAsync(Status(run.Record.Time, policy), policy, run.Id, reader);
        Assert.Equal(later.HoldId, Assert.Single(current.Holds).HoldId); Assert.Equal(9, current.Holds[0].Objects.Length);
        Assert.True((await coordinator.ReadVerifiedAsync(run.Id)).Frozen); Assert.Equal(0, run.Blobs.Deletes);
    }

    [Theory]
    [InlineData("business")][InlineData("missing-receipt")][InlineData("extra-plan")]
    public async Task Restored_SQL_or_a_nonexact_control_set_refuses_before_archive_IO(string fault)
    {
        await using var run = await Draft(); using var provider = new ProductionHoldArchiveReleaseTests.Provider();
        var coordinator = Coordinator(run, provider); var hold = await PlaceAndPreserve(coordinator, run);
        await using (var db = fixture.Open())
        {
            if (fault == "business") await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Message, "Synthetic stale restored state"));
            else if (fault == "missing-receipt") await db.ProductionHoldControls.Where(x => x.EnvelopeId == run.Id && x.Kind == 1).ExecuteDeleteAsync();
            else
            {
                await using var tx = await db.Database.BeginTransactionAsync(); var controls = new ProductionHoldControls(db, run.Keys, run.Time);
                var old = (await controls.ReadLockedAsync(run.Id)).Plans.Values.Single();
                var snapshot = ProductionHoldBundlePlan.OpenVerified(old, run.Keys, run.Time).Snapshot;
                var extra = await ProductionHoldBundlePlan.FreezeLockedAsync(db, run.Keys, run.Time, hold.HoldId, Guid.NewGuid(), snapshot);
                await controls.SavePlanLockedAsync(extra); await tx.CommitAsync();
            }
        }
        var count = provider.Calls.Count; var policy = StatusPolicy();
        using var reader = Reader(provider, run.Time);
        await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Time, policy), policy, run.Id, reader));
        Assert.Equal(count, provider.Calls.Count); Assert.Equal(0, provider.Clears);
        Assert.True((await run.Journal.ReadAsync(run.Id)).Frozen);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task A_new_intent_during_provider_read_or_readonly_completion_invalidates_the_whole_observation(bool onCompletion)
    {
        await using var run = await Draft(); using var provider = new ProductionHoldArchiveReleaseTests.Provider();
        var coordinator = Coordinator(run, provider); _ = await PlaceAndPreserve(coordinator, run);
        var command = Place(run.Id, 1); var count = provider.Calls.Count; var policy = StatusPolicy(); var fired = false;
        async Task Intent()
        {
            if (fired) return; fired = true;
            await run.Journal.IntentAsync(Authority(run.Time, command.Permission), Operators, command, Guid.NewGuid());
        }
        if (onCompletion)
        {
            using var source = fixture.Open(); var connection = source.Database.GetConnectionString();
            coordinator = Coordinator(run, provider, () => new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection)
                .AddInterceptors(new RollbackAction(Intent)).Options));
        }
        else provider.After = phase => { if (phase == "download") Intent().GetAwaiter().GetResult(); };
        using var reader = Reader(provider, run.Time); using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Time, policy), policy, run.Id, reader, timeout.Token));
        Assert.True(fired); Assert.Equal(command, (await run.Journal.ReadAsync(run.Id)).Unacknowledged);
        Assert.True(provider.Calls.Count > count); Assert.Equal(0, provider.Clears);
        await using var db = fixture.Open(); Assert.Equal(1, await db.ProductionHoldRequests.CountAsync(x => x.EnvelopeId == run.Id));
    }

    [Fact]
    public async Task Pending_or_wrong_status_authority_cannot_turn_stored_lifecycle_receipts_into_fresh_protection()
    {
        await using var run = await Draft(); using var provider = new ProductionHoldArchiveReleaseTests.Provider();
        var coordinator = Coordinator(run, provider); var command = Place(run.Id);
        await coordinator.SubmitAsync(Authority(run.Time, command.Permission), Operators, command);
        var policy = StatusPolicy(); using var reader = Reader(provider, run.Time);
        await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Time, policy), policy, run.Id, reader));
        Assert.Empty(provider.Calls);
        await coordinator.PreserveAsync(run.Id, command.HoldId, Guid.NewGuid()); var count = provider.Calls.Count;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => coordinator.InspectActiveProtectionAsync(Authority(run.Time, ProductionOperatorPermission.PlaceHold), Operators, run.Id, reader));
        Assert.Equal(count, provider.Calls.Count);
        Assert.True((await coordinator.ReadVerifiedAsync(run.Id)).Holds[command.HoldId].Effective);
        // Deliberately remove the provider fact with an unchanged receipt: fresh
        // inspection refuses; historical lifecycle remains an explicitly OLD fact.
        provider.Files.Values.First().Held = false;
        await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Time, policy), policy, run.Id, reader));
        Assert.True((await coordinator.ReadVerifiedAsync(run.Id)).Frozen); Assert.Equal(0, provider.Clears);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Provider_scope_cannot_escape_its_authenticated_parent_transaction(bool fail)
    {
        await using var run = await Draft(); using var provider = new ProductionHoldArchiveReleaseTests.Provider();
        var coordinator = Coordinator(run, provider); _ = await PlaceAndPreserve(coordinator, run);
        using var native = Reader(provider, run.Time); var reader = new RetainScope(native, fail); var policy = StatusPolicy();
        if (fail) await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.InspectActiveProtectionAsync(Status(run.Time, policy), policy, run.Id, reader));
        else Assert.Single((await coordinator.InspectActiveProtectionAsync(Status(run.Time, policy), policy, run.Id, reader)).Holds);
        var scope = Assert.IsAssignableFrom<IProductionHoldArchiveReadScope>(reader.Scope); var count = provider.Calls.Count;
        await Assert.ThrowsAsync<InvalidDataException>(() => scope.DemandAsync());
        await Assert.ThrowsAsync<InvalidDataException>(() => native.InspectAsync(scope));
        Assert.Equal(count, provider.Calls.Count); Assert.Equal(0, provider.Clears);
    }
    private sealed class RetainScope(IProductionHoldArchiveInspectionStore native, bool fail) : IProductionHoldArchiveInspectionStore
    {
        internal IProductionHoldArchiveReadScope? Scope { get; private set; }
        public async Task<ProductionHoldArchiveStoredObject> InspectAsync(IProductionHoldArchiveReadScope scope, CancellationToken ct = default)
        {
            Scope = scope; var result = await native.InspectAsync(scope, ct);
            if (fail) throw new InvalidDataException("Synthetic inspection failure.");
            return result;
        }
    }

    private async Task<int> CountControls(Guid id) { await using var db = fixture.Open(); return await db.ProductionHoldControls.CountAsync(x => x.EnvelopeId == id); }
    private async Task<ProductionRuntimeAdmissionTests.Run> Draft()
    {
        var run = await ProductionRuntimeAdmissionTests.Run.Create(fixture);
        await run.DeliverAndFinish(await run.Claim()); await using var db = fixture.Open();
        Assert.NotNull(await run.Sender(db).VerifyAsync(run.Token.Token, "127.0.0.1", "Synthetic active inspection")); return run;
    }
    private static async Task<ProductionHoldCommand> PlaceAndPreserve(ProductionHoldCoordinator coordinator, ProductionRuntimeAdmissionTests.Run run)
    {
        var hold = Place(run.Id); await coordinator.SubmitAsync(Authority(run.Time, hold.Permission), Operators, hold);
        Assert.True((await coordinator.PreserveAsync(run.Id, hold.HoldId, Guid.NewGuid())).Holds[hold.HoldId].Effective); return hold;
    }
    private ProductionHoldCoordinator Coordinator(ProductionRuntimeAdmissionTests.Run run, ProductionHoldArchiveReleaseTests.Provider provider,
        Func<QuillSignDbContext>? open = null)
    {
        var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03) { Transport = new HttpClientTransport(new HttpClient(provider, false)) };
        options.Retry.MaxRetries = 0; var service = new BlobServiceClient(new Uri("https://storage.example.invalid"), new ProductionHoldArchiveReleaseTests.Credential(), options);
        return new(open ?? fixture.Open, run.Keys, run.Time, run.Journal, new EmptySource(), new(service), new(service));
    }
    private static AzureProductionHoldArchiveInspectionStore Reader(ProductionHoldArchiveReleaseTests.Provider provider, TimeProvider time)
        => new(new("https://storage.example.invalid"), new ProductionHoldArchiveReleaseTests.Credential(), time, new HttpClientTransport(new HttpClient(provider, false)));
    private sealed class RollbackAction(Func<Task> action) : DbTransactionInterceptor
    {
        public override Task TransactionRolledBackAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default) => action();
    }
    private sealed class EmptySource : IProductionHoldObjectSource
    {
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct)
        { scope.Demand(ct); return Task.FromResult(new HoldObjectPage([], null)); }
        public Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress address, CancellationToken ct) => throw new InvalidOperationException();
    }
}

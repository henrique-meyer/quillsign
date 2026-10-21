using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionHoldCoordinatorTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false, false, false)][InlineData(true, false, false)][InlineData(false, true, false)][InlineData(false, false, true)]
    public async Task Connected_two_hold_bundle_preservation_restart_and_exact_independent_release(bool lostClearAcknowledgement,
        bool laterPlacementAfterReleaseIntent, bool lostArchiveReadback)
    {
        var run = await CreateNormal(); using var provider = new ProductionHoldArchiveReleaseTests.Provider();
        var service = Client(provider); var store = new Store();
        var source = new HoldObjectAddress("normalized", $"{run.Id:N}/{Guid.NewGuid():N}", "synthetic-source-version", "", "\"synthetic-source-tag\"",
            ProductionHoldArchiveReleaseTests.Raw.Length); provider.Source = source;
        ProductionHoldCoordinator Coordinator() => new(fixture.Open, run.Keys, run.Time,
            new(store, run.Keys, run.Time, Installation), new ProductionHoldArchiveReleaseTests.Sources(source), new(service), new(service));
        var a = Place(run.Id); await Coordinator().SubmitAsync(Authority(run.Time, a.Permission), Operators, a);
        var aPlan = Guid.NewGuid();
        if (lostArchiveReadback)
        {
            provider.After = phase => { if (phase == "download") throw new IOException("Synthetic archive readback interrupted after provider commit"); };
            await Assert.ThrowsAsync<IOException>(() => Coordinator().PreserveAsync(run.Id, a.HoldId, aPlan));
            Assert.Single(provider.Files); provider.After = null;
            var interrupted = await Coordinator().ReadVerifiedAsync(run.Id); Assert.True(interrupted.Frozen);
            Assert.False(interrupted.Holds[a.HoldId].Effective); Assert.NotNull(interrupted.Holds[a.HoldId].PlanSha256);
        }
        var effective = await Coordinator().PreserveAsync(run.Id, a.HoldId, aPlan);
        Assert.True(effective.Frozen); Assert.True(effective.Holds[a.HoldId].Effective); Assert.Equal(3, provider.Files.Count);
        var release = a with { CommandId = Guid.NewGuid(), Operation = ProductionHoldOperation.Release,
            ExpectedRevision = laterPlacementAfterReleaseIntent ? 1 : 2 };
        if (laterPlacementAfterReleaseIntent) await Coordinator().SubmitAsync(Authority(run.Time, release.Permission), Operators, release);
        var b = Place(run.Id, laterPlacementAfterReleaseIntent ? 2 : 1); await Coordinator().SubmitAsync(Authority(run.Time, b.Permission), Operators, b);
        await Coordinator().PreserveAsync(run.Id, b.HoldId, Guid.NewGuid()); Assert.Equal(6, provider.Files.Count);
        var firstFiles = provider.Files.Where(x => x.Key.Contains($"/{a.HoldId:N}/", StringComparison.Ordinal)).Select(x => x.Key).ToArray();
        if (lostClearAcknowledgement) provider.Fault = "lost-ack";
        if (!laterPlacementAfterReleaseIntent) await Coordinator().SubmitAsync(Authority(run.Time, release.Permission), Operators, release);
        var oneReleased = await Coordinator().ReleaseAsync(run.Id, a.HoldId);
        Assert.True(oneReleased.Frozen); Assert.True(oneReleased.Holds[a.HoldId].Released);
        Assert.All(provider.Files, x => Assert.Equal(!firstFiles.Contains(x.Key), x.Value.Held));
        var clearCount = provider.Clears; await Coordinator().ReleaseAsync(run.Id, a.HoldId); Assert.Equal(clearCount, provider.Clears);
        var releaseB = b with { CommandId = Guid.NewGuid(), Operation = ProductionHoldOperation.Release, ExpectedRevision = 3 };
        await Coordinator().SubmitAsync(Authority(run.Time, releaseB.Permission), Operators, releaseB);
        var final = await Coordinator().ReleaseAsync(run.Id, b.HoldId); Assert.False(final.Frozen);
        Assert.False((await Coordinator().ReadVerifiedAsync(run.Id)).Frozen); Assert.All(provider.Files.Values, x => Assert.False(x.Held));
        await using var db = fixture.Open(); Assert.Equal(4, await db.AuditEvents.CountAsync(x => x.EnvelopeId == run.Id));
        Assert.Equal(4, await db.ProductionHoldRequests.CountAsync(x => x.EnvelopeId == run.Id));
        Assert.Equal(8, await db.ProductionHoldControls.CountAsync(x => x.EnvelopeId == run.Id));
        if (laterPlacementAfterReleaseIntent)
        {
            // A previously admitted operation keeps its drain reservation. A new
            // hold closes external admission immediately, but takes no SQL parent
            // lock/acknowledgement until the explicit no-effect reconciliation.
            var journal = new ProductionHoldWitnessJournal(store, run.Keys, run.Time, Installation); var op = Guid.NewGuid();
            ProductionHoldRequestSnapshot requests;
            await using (var tx = await db.Database.BeginTransactionAsync())
            { requests = await new ProductionHoldRequests(db, run.Keys, run.Time).ReadLockedAsync(run.Id); await tx.RollbackAsync(); }
            await journal.ReserveAsync(run.Id, op, Guid.NewGuid(), requests);
            var c = Place(run.Id, 4); var waiting = await Coordinator().SubmitAsync(Authority(run.Time, c.Permission), Operators, c);
            Assert.Equal(c, waiting.Unacknowledged); Assert.Equal(4, await db.ProductionHoldRequests.CountAsync(x => x.EnvelopeId == run.Id));
            await journal.SettleAsync(run.Id, op, Hash, final.BusinessStateSha256!, Guid.NewGuid());
            var drained = await Coordinator().SubmitAsync(Authority(run.Time, c.Permission), Operators, c);
            Assert.Null(drained.Unacknowledged); Assert.Equal(5, drained.RequestRevision); Assert.True(drained.Frozen);
        }
    }

    [Fact]
    public async Task Lost_SQL_commit_acknowledgement_reconciles_the_original_request_before_archiving()
    {
        var run = await CreateNormal(); using var provider = new ProductionHoldArchiveReleaseTests.Provider(); var service = Client(provider); var store = new Store();
        var lost = new LostCommit(); string connection;
        await using (var source = fixture.Open()) connection = source.Database.GetDbConnection().ConnectionString;
        QuillSignDbContext Open() => new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(lost).Options);
        ProductionHoldCoordinator Coordinator(Func<QuillSignDbContext> open) => new(open, run.Keys, run.Time,
            new(store, run.Keys, run.Time, Installation), new EmptySource(), new(service), new(service));
        var command = Place(run.Id);
        await Assert.ThrowsAsync<IOException>(() => Coordinator(Open).SubmitAsync(Authority(run.Time, command.Permission), Operators, command));
        var pending = await new ProductionHoldWitnessJournal(store, run.Keys, run.Time, Installation).ReadAsync(run.Id);
        Assert.True(pending.Frozen); Assert.NotNull(pending.Unacknowledged);
        var beforeObservation=store.Rows.Count;
        var statusPolicy=new ProductionOperatorPolicy(true,[new(Issuer,"synthetic-status",new HashSet<ProductionOperatorPermission>{ProductionOperatorPermission.Status})]);
        var status=ProductionOperatorAuthority.FromValidatedTicket(new(new(new System.Security.Claims.ClaimsIdentity([
            new("iss",Issuer,System.Security.Claims.ClaimValueTypes.String,Issuer),new("sub","synthetic-status",System.Security.Claims.ClaimValueTypes.String,Issuer)],ProductionOperatorAuthority.OidcScheme)),
            new Microsoft.AspNetCore.Authentication.AuthenticationProperties{IssuedUtc=run.Time.Now,ExpiresUtc=run.Time.Now.AddMinutes(5)},ProductionOperatorAuthority.CookieScheme),statusPolicy,ProductionOperatorPermission.Status,run.Time);
        var unresolved=await Coordinator(fixture.Open).ObserveRecoveryAsync(status,statusPolicy,run.Id);
        Assert.Equal(ProductionHoldRecoveryState.Unresolved,unresolved.State);
        Assert.Equal(ProductionHoldRecoveryReason.CommandAcknowledgement,unresolved.Reason);
        Assert.True(unresolved.Frozen);Assert.False(unresolved.SqlHeadVerified);Assert.Equal(command.CommandId,unresolved.CommandId);
        Assert.Equal(beforeObservation,store.Rows.Count);Assert.Empty(provider.Files);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>Coordinator(fixture.Open).ObserveRecoveryAsync(
            Authority(run.Time,ProductionOperatorPermission.PlaceHold),Operators,run.Id));
        await using (var db = fixture.Open()) Assert.Equal(1, await db.ProductionHoldRequests.CountAsync(x => x.EnvelopeId == run.Id));
        var recovered = await Coordinator(fixture.Open).SubmitAsync(Authority(run.Time, command.Permission), Operators, command);
        Assert.Null(recovered.Unacknowledged); Assert.Equal(1, recovered.RequestRevision); Assert.Equal(2, store.Rows.Count);
        Assert.Empty(provider.Files); Assert.True((await Coordinator(fixture.Open).ReadVerifiedAsync(run.Id)).Frozen);
        var incomplete=await Coordinator(fixture.Open).ObserveRecoveryAsync(status,statusPolicy,run.Id);
        Assert.Equal(ProductionHoldRecoveryState.Unresolved,incomplete.State);
        Assert.Equal(ProductionHoldRecoveryReason.Preservation,incomplete.Reason);Assert.True(incomplete.SqlHeadVerified);
        Assert.True(incomplete.Frozen);Assert.Empty(provider.Files);Assert.Equal(2,store.Rows.Count);
    }

    private sealed class LostCommit : DbTransactionInterceptor
    {
        private bool pending = true;
        public override Task TransactionCommittedAsync(System.Data.Common.DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        { if (pending) { pending = false; throw new IOException("Synthetic lost lifecycle SQL commit acknowledgement"); } return Task.CompletedTask; }
    }

    [Fact]
    public async Task Restored_business_state_or_missing_frozen_plan_is_quarantined_without_provider_release()
    {
        var run = await CreateNormal(); using var provider = new ProductionHoldArchiveReleaseTests.Provider(); var service = Client(provider); var store = new Store();
        ProductionHoldCoordinator Coordinator() => new(fixture.Open, run.Keys, run.Time,
            new(store, run.Keys, run.Time, Installation), new EmptySource(), new(service), new(service));
        var a = Place(run.Id); await Coordinator().SubmitAsync(Authority(run.Time, a.Permission), Operators, a);
        await Coordinator().PreserveAsync(run.Id, a.HoldId, Guid.NewGuid());
        await using (var db = fixture.Open())
            await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Title, "Synthetic restored stale business state"));
        var before = provider.Calls.Count;
        await Assert.ThrowsAsync<InvalidDataException>(() => Coordinator().ReadVerifiedAsync(run.Id));
        var release = a with { CommandId = Guid.NewGuid(), Operation = ProductionHoldOperation.Release, ExpectedRevision = 1 };
        await Assert.ThrowsAsync<InvalidDataException>(() => Coordinator().SubmitAsync(Authority(run.Time, release.Permission), Operators, release));
        Assert.Equal(before, provider.Calls.Count); Assert.All(provider.Files.Values, x => Assert.True(x.Held));
        await using (var db = fixture.Open())
            await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Title, (string?)null));
        // Restoring the exact old control prefix is a different rollback: the
        // external frozen-plan receipt still detects its absence.
        await using (var db = fixture.Open())
            await db.ProductionHoldControls.Where(x => x.EnvelopeId == run.Id).ExecuteDeleteAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => Coordinator().ReadVerifiedAsync(run.Id));
        Assert.Equal(before, provider.Calls.Count);
    }

    [Fact]
    public async Task Unknown_audit_schema_stays_pending_and_cannot_manufacture_complete_preservation()
    {
        var run = await CreateNormal();
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            await new AuditWriter(db, run.Time).AppendAsync(run.Id, "future_unknown_history", null, null, null, CancellationToken.None,
                dataJson: "{}", actorType: PartyType.System); await tx.CommitAsync();
        }
        using var provider = new ProductionHoldArchiveReleaseTests.Provider(); var service = Client(provider); var store = new Store();
        var coordinator = new ProductionHoldCoordinator(fixture.Open, run.Keys, run.Time, new(store, run.Keys, run.Time, Installation),
            new EmptySource(), new(service), new(service));
        var a = Place(run.Id); await coordinator.SubmitAsync(Authority(run.Time, a.Permission), Operators, a);
        await Assert.ThrowsAsync<InvalidDataException>(() => coordinator.PreserveAsync(run.Id, a.HoldId, Guid.NewGuid()));
        var journal = await new ProductionHoldWitnessJournal(store, run.Keys, run.Time, Installation).ReadAsync(run.Id);
        Assert.True(journal.Frozen); Assert.False(journal.Holds[a.HoldId].Effective); Assert.Empty(provider.Files);
    }

    private async Task<(Guid Id, IDataProtectionProvider Keys, Clock Time)> CreateNormal()
    {
        var clock = new Clock(); var keys = new EphemeralDataProtectionProvider();
        await using var db = fixture.Open(); var signals = new EmailPilotAdmissionTests.Signals();
        var email = new EmailOptions { Enabled = true, BaseUrl = "https://example.invalid", FromEmail = "noreply@example.invalid" };
        var work = new WorkOptions { Enabled = true }; var payloads = new EmailPayloadProtection(keys);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Database"] = "synthetic-configured", ["Storage:Provider"] = "Azurite" }).Build();
        var sender = new SenderWorkflow(db, new(), new(email, work, config), () => new(db, signals, payloads, work, email, clock),
            new(db, clock), clock, lifecycle: ProductionRetentionAdmissionContractTests.Settings(),
            electronicRecords: ProductionRetentionAdmissionContractTests.Policies());
        var address = "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid";
        Assert.Equal(SenderRequestOutcome.Neutral, await sender.RequestAsync(address, "127.0.0.1", "Synthetic hold lifecycle"));
        var outbox = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.To == address); var token = payloads.Unprotect(outbox.PayloadJson);
        var store = new WorkStore(db, work, clock); var lease = (await store.ClaimAsync(outbox.Id, CancellationToken.None)).Lease!; Assert.NotNull(lease);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(SenderWorkflow).Assembly.FullName,
            ContentRootPath = AppContext.BaseDirectory, EnvironmentName = "Development" });
        builder.Logging.ClearProviders(); builder.Services.AddRazorPages(); builder.Services.AddScoped<RazorEmailViews>();
        await using var app = builder.Build(); using var scope = app.Services.CreateScope(); var captured = new CapturedSender();
        var handler = new EmailWorkHandler(db, email, payloads, new(email, scope.ServiceProvider.GetRequiredService<RazorEmailViews>()), captured, clock);
        var result = await handler.ExecuteAsync(lease, CancellationToken.None); Assert.Equal(WorkOutcome.Completed, result.Outcome);
        await store.FinishAsync(lease, result, CancellationToken.None); Assert.Equal(1, captured.Count);
        var verified = await sender.VerifyAsync(token.Token, "127.0.0.1", "Synthetic hold lifecycle"); Assert.NotNull(verified);
        Assert.Equal(clock.Now, (await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == token.TokenId)).UsedAt);
        return (verified.EnvelopeId, keys, clock);
    }
    private sealed class CapturedSender : IEmailSender
    {
        internal int Count;
        public Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken = default)
        { Assert.EndsWith("@example.invalid", message.To); Count++; return Task.FromResult(new EmailDelivery("SyntheticCapture", "synthetic-receipt")); }
    }
    private static BlobServiceClient Client(ProductionHoldArchiveReleaseTests.Provider handler)
    {
        var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)
            { Transport = new HttpClientTransport(new HttpClient(handler, false)) };
        options.Retry.MaxRetries = 0;
        return new(new Uri("https://storage.example.invalid"), new ProductionHoldArchiveReleaseTests.Credential(), options);
    }
    private sealed class EmptySource : IProductionHoldObjectSource
    {
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct)
            => Task.FromResult(new HoldObjectPage([], null));
        public Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress address, CancellationToken ct)
            => throw new InvalidOperationException("Synthetic empty record has no source object");
    }
}

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
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRuntimeAdmissionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Fresh_sender_baseline_precedes_publication_and_hold_blocks_claim_before_metadata_changes_then_release_resumes()
    {
        await using var run = await Run.Create(fixture); Assert.True(run.PublicationVerified);
        Assert.Equal(1, (await run.Journal.ReadAsync(run.Id)).Sequence);
        var hold = await run.Hold();
        await using (var db = fixture.Open())
        {
            var before = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == run.WorkId);
            var claim = await run.Store(db).ClaimAsync(run.WorkId, CancellationToken.None);
            Assert.Null(claim.Lease); Assert.NotNull(claim.RetryAt); Assert.False(claim.Terminal);
            var after = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == run.WorkId);
            Assert.Equal(before.Attempts, after.Attempts); Assert.Equal(before.Status, after.Status);
            Assert.Null(after.LeaseOwner); Assert.Null(after.LeaseExpiresAt);
            Assert.Empty(await db.AuthTokens.Where(x => x.EnvelopeId == run.Id).ToArrayAsync());
        }
        Assert.True(await run.ProcessOnce()); Assert.Equal(1, run.Deferred); Assert.Equal(0, run.Captured.Calls);
        await run.Release(hold); Assert.True(await run.ProcessOnce());
        Assert.Equal(1, run.Captured.Calls); Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
        Assert.False((await run.Coordinator.ReadVerifiedAsync(run.Id)).Frozen);
    }

    [Fact]
    public async Task Hold_blocks_actual_sender_token_consumption_and_audit_until_exact_release_without_extending_original_expiry()
    {
        await using var run = await Run.Create(fixture); await run.DeliverAndFinish(await run.Claim());
        DateTimeOffset originalExpiry;
        await using (var db = fixture.Open()) originalExpiry = (await db.AuthTokens.SingleAsync(x => x.Id == run.Token.TokenId)).ExpiresAt;
        var hold = await run.Hold();
        await using (var db = fixture.Open())
        {
            Assert.Null(await run.Sender(db).VerifyAsync(run.Token.Token, "127.0.0.1", "Synthetic gated verification"));
            var token = await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == run.Token.TokenId);
            Assert.Null(token.UsedAt); Assert.Equal(originalExpiry, token.ExpiresAt);
            Assert.Equal(3, await db.AuditEvents.CountAsync(x => x.EnvelopeId == run.Id));
        }
        await run.Release(hold);
        await using (var db = fixture.Open())
        {
            Assert.NotNull(await run.Sender(db).VerifyAsync(run.Token.Token, "127.0.0.1", "Synthetic gated verification"));
            var token = await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == run.Token.TokenId);
            Assert.Equal(run.Time.Now, token.UsedAt); Assert.Equal(originalExpiry, token.ExpiresAt);
            Assert.Equal(4, await db.AuditEvents.CountAsync(x => x.EnvelopeId == run.Id));
        }
        Assert.False((await run.Coordinator.ReadVerifiedAsync(run.Id)).Frozen);
    }

    [Fact]
    public async Task Unknown_worker_outcome_and_lease_expiry_do_not_settle_or_advance_pending_hold_SQL()
    {
        await using var run = await Run.Create(fixture); var lease = await run.Claim();
        await using (var db = fixture.Open())
            await run.Store(db).FinishAsync(lease, new(WorkOutcome.Ambiguous, "synthetic-unknown-provider-outcome"), CancellationToken.None);
        var command = Place(run.Id);
        var pending = await run.Coordinator.SubmitAsync(Authority(run.Time, command.Permission), Operators, command);
        Assert.Equal(command, pending.Unacknowledged); Assert.Equal(lease.Owner, pending.OutstandingOperation);
        run.Time.Now = run.Time.Now.AddHours(1);
        await using (var db = fixture.Open())
        {
            Assert.False(await db.ProductionHoldRequests.AnyAsync(x => x.EnvelopeId == run.Id));
            await Assert.ThrowsAsync<ProductionWorkBlockedException>(() => run.Store(db).ReconcileCompletedAsync(lease, run.Id));
        }
        var current = await run.Journal.ReadAsync(run.Id); Assert.True(current.Frozen); Assert.Equal(lease.Owner, current.OutstandingOperation);
        Assert.Equal(0, run.Captured.Calls);
    }

    [Fact]
    public async Task Unimplemented_production_work_kinds_and_mail_templates_are_refused_before_claim_not_after_provider_effects()
    {
        foreach (var changeKind in new[] { true, false })
        {
            await using var run = await Run.Create(fixture);
            var setup = await run.Admission.BeginAsync(run.Id, Guid.NewGuid(), "test/schedule", "synthetic-unimplemented-work");
            await using (var seed = fixture.Open())
            {
                await using var tx = await seed.Database.BeginTransactionAsync();
                if (changeKind) await seed.WorkItems.Where(x => x.Id == run.WorkId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Kind, WorkKind.Rendering));
                else await seed.EmailOutbox.Where(x => x.Id == run.WorkId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Template, "future-unimplemented-template"));
                await run.Admission.PrepareOutcomeLockedAsync(seed, setup); await tx.CommitAsync();
            }
            await run.Admission.CompleteAsync(setup, Hash); var before = await run.Journal.ReadAsync(run.Id);
            await using var db = fixture.Open(); var claim = await run.Store(db).ClaimAsync(run.WorkId, default);
            Assert.Null(claim.Lease); Assert.NotNull(claim.RetryAt);
            var work = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == run.WorkId);
            Assert.Equal(0, work.Attempts); Assert.Null(work.LeaseOwner); Assert.Equal(WorkStatus.Queued, work.Status);
            Assert.Equal(before.HeadHash, (await run.Journal.ReadAsync(run.Id)).HeadHash); Assert.Equal(0, run.Captured.Calls);
        }
    }

    [Fact]
    public async Task Template_changed_after_claim_is_refused_before_dispatch_routing_or_token_issuance()
    {
        await using var run = await Run.Create(fixture); var lease = await run.Claim(); await using var db = fixture.Open();
        await db.EmailOutbox.Where(x => x.Id == lease.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Template, "completion-notification"));
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(() => run.Deliver(lease));
        Assert.Equal(0, run.Captured.Calls); Assert.False(await db.AuthTokens.AnyAsync(x => x.EnvelopeId == run.Id));
        Assert.Equal(lease.Owner, (await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
        Assert.Equal(WorkStatus.Leased, (await db.WorkItems.SingleAsync(x => x.Id == lease.Id)).Status);
    }

    [Fact]
    public async Task Completed_result_without_a_sealed_handler_outcome_cannot_finish_or_relabel_queued_mail()
    {
        await using var run = await Run.Create(fixture); var lease = await run.Claim(); await using var db = fixture.Open();
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(() => run.Store(db).FinishAsync(lease, new(WorkOutcome.Completed), CancellationToken.None));
        var saved = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == lease.Id);
        Assert.Equal(WorkStatus.Leased, saved.Status); Assert.Equal(lease.Owner, saved.LeaseOwner);
        Assert.Equal(lease.Owner, (await run.Journal.ReadAsync(run.Id)).OutstandingOperation); Assert.Equal(0, run.Captured.Calls);
    }

    [Fact]
    public async Task Restoring_post_claim_email_and_token_rows_after_handler_commit_cannot_be_adopted_by_Finish()
    {
        await using var run = await Run.Create(fixture); var lease = await run.Claim();
        await run.Deliver(lease); var checkpoint = (await run.Journal.ReadAsync(run.Id)).HandlerOutcomes![lease.Owner];
        await using (var restore = fixture.Open())
        {
            await using var tx = await restore.Database.BeginTransactionAsync();
            await restore.AuthTokens.Where(x => x.Id == run.Token.TokenId).ExecuteDeleteAsync();
            await restore.EmailOutbox.Where(x => x.Id == run.WorkId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, EmailStatus.Queued)
                .SetProperty(x => x.Provider, (string?)null).SetProperty(x => x.ProviderMessageId, (string?)null)
                .SetProperty(x => x.SubmissionStartedAt, (DateTimeOffset?)null).SetProperty(x => x.Attempts, 0));
            await tx.CommitAsync();
        }
        await using var db = fixture.Open();
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(() => run.Store(db).FinishAsync(lease, new(WorkOutcome.Completed), CancellationToken.None));
        var current = await run.Journal.ReadAsync(run.Id); Assert.Equal(checkpoint, current.HandlerOutcomes![lease.Owner]);
        Assert.False(current.Outcomes!.ContainsKey(lease.Owner)); Assert.Equal(lease.Owner, current.OutstandingOperation);
        Assert.Equal(WorkStatus.Leased, (await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == lease.Id)).Status);
        run.Time.Now = lease.Until.AddSeconds(1); Assert.Null((await run.Store(db).ClaimAsync(run.WorkId, default)).Lease);
        Assert.Equal(1, run.Captured.Calls);
    }

    [Fact]
    public async Task Lost_Finish_commit_acknowledgement_requires_exact_completed_readback_without_provider_replay()
    {
        await using var run = await Run.Create(fixture); var lease = await run.Claim(); await run.Deliver(lease);
        string connection; await using (var source = fixture.Open()) connection = source.Database.GetDbConnection().ConnectionString;
        await using (var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
            await Assert.ThrowsAsync<IOException>(() => run.Store(db).FinishAsync(lease, new(WorkOutcome.Completed), CancellationToken.None));
        Assert.Equal(lease.Owner, (await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
        await using (var db = fixture.Open()) await run.Store(db).ReconcileCompletedAsync(lease, run.Id);
        Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation); Assert.Equal(1, run.Captured.Calls);
        await using (var db = fixture.Open()) await run.Store(db).ReconcileCompletedAsync(lease, run.Id);
        Assert.Equal(1, run.Captured.Calls);
    }

    [Fact]
    public async Task Completed_SQL_readback_cannot_relabel_an_outstanding_reservation_as_another_attempt()
    {
        await using var run = await Run.Create(fixture); var lease = await run.Claim(); await run.Deliver(lease);
        string connection; await using (var source = fixture.Open()) connection = source.Database.GetDbConnection().ConnectionString;
        await using (var lost = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
            await Assert.ThrowsAsync<IOException>(() => run.Store(lost).FinishAsync(lease, new(WorkOutcome.Completed), CancellationToken.None));
        await using var db = fixture.Open();
        await db.WorkItems.Where(x => x.Id == lease.Id).ExecuteUpdateAsync(x => x.SetProperty(w => w.Attempts, lease.Attempt + 1));
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(() => run.Store(db).ReconcileCompletedAsync(lease with { Attempt = lease.Attempt + 1 }, run.Id));
        Assert.Equal(lease.Owner, (await run.Journal.ReadAsync(run.Id)).OutstandingOperation); Assert.Equal(1, run.Captured.Calls);
    }

    [Fact]
    public async Task Opted_in_adapter_preserves_demo_dispatch_and_verification_without_creating_production_witnesses()
    {
        await using var run = await Run.Create(fixture, demo: true); await run.DeliverAndFinish(await run.Claim());
        await using var db = fixture.Open(); Assert.NotNull(await run.Sender(db).VerifyAsync(run.Token.Token, null, null));
        Assert.Empty(run.External.Rows); Assert.Equal(1, run.Captured.Calls);
    }

    [Fact]
    public async Task Unclassified_global_work_cannot_use_a_null_record_to_bypass_admission()
    {
        await using var run = await Run.Create(fixture); await using var db = fixture.Open();
        var work = new WorkItem { Kind = WorkKind.Rendering, PayloadJson = "{}", AvailableAt = run.Time.Now };
        db.Add(work); await db.SaveChangesAsync();
        var claim = await run.Store(db).ClaimAsync(work.Id, CancellationToken.None);
        Assert.Null(claim.Lease); Assert.NotNull(claim.RetryAt);
        var saved = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == work.Id);
        Assert.Equal(0, saved.Attempts); Assert.Equal(WorkStatus.Queued, saved.Status); Assert.Null(saved.LeaseOwner);
        Assert.Equal(1, (await run.Journal.ReadAsync(run.Id)).Sequence);
    }

    [Fact]
    public async Task Expired_worker_lease_cannot_finish_or_settle_even_when_provider_receipt_is_known()
    {
        await using var run = await Run.Create(fixture); var lease = await run.Claim(); await run.Deliver(lease);
        run.Time.Now = lease.Until.AddSeconds(1);
        await using var db = fixture.Open();
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Store(db).FinishAsync(lease, new(WorkOutcome.Completed), CancellationToken.None));
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(() => run.Store(db).ReconcileCompletedAsync(lease, run.Id));
        var saved = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == run.WorkId);
        Assert.Equal(lease.Owner, saved.LeaseOwner); Assert.Equal(WorkStatus.Leased, saved.Status);
        Assert.Equal(lease.Owner, (await run.Journal.ReadAsync(run.Id)).OutstandingOperation); Assert.Equal(1, run.Captured.Calls);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Changing_production_demo_flag_never_bypasses_worker_or_sender_verification_admission(bool dispatched)
    {
        await using var run = await Run.Create(fixture);
        if (dispatched) await run.DeliverAndFinish(await run.Claim());
        await using var db = fixture.Open();
        await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.IsDemo, true));
        if (dispatched)
        {
            Assert.Null(await run.Sender(db).VerifyAsync(run.Token.Token, null, null));
            Assert.Null((await db.AuthTokens.SingleAsync(x => x.Id == run.Token.TokenId)).UsedAt);
        }
        else
        {
            var claim = await run.Store(db).ClaimAsync(run.WorkId, CancellationToken.None);
            Assert.Null(claim.Lease); Assert.NotNull(claim.RetryAt);
            Assert.Equal(0, (await db.WorkItems.SingleAsync(x => x.Id == run.WorkId)).Attempts);
        }
        Assert.Null((await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == run.Id)).SenderVerifiedAt);
    }

    [Fact]
    public async Task Opted_in_sender_cannot_flush_foreign_pending_SQL_changes_with_intake_or_verification()
    {
        await using var run = await Run.Create(fixture); await run.DeliverAndFinish(await run.Claim());
        await using var db = fixture.Open(); var foreign = new Envelope { IsDemo = true, SenderEmail = "unrelated@example.invalid" };
        db.Add(foreign); var state = await run.Journal.ReadAsync(run.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Sender(db).VerifyAsync(run.Token.Token, null, null));
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Sender(db).RequestAsync("another@example.invalid", null, null));
        await using var readback = fixture.Open();
        Assert.False(await readback.Envelopes.AnyAsync(x => x.Id == foreign.Id));
        Assert.Null((await readback.AuthTokens.SingleAsync(x => x.Id == run.Token.TokenId)).UsedAt);
        Assert.Equal(state.HeadHash, (await run.Journal.ReadAsync(run.Id)).HeadHash);
        db.ChangeTracker.Clear(); await using var tx = await db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Sender(db).VerifyAsync(run.Token.Token, null, null));
        await tx.RollbackAsync(); Assert.Equal(state.HeadHash, (await run.Journal.ReadAsync(run.Id)).HeadHash);
    }

    [Fact]
    public async Task Foreign_lease_owner_cannot_finish_or_settle_the_original_operation()
    {
        await using var run = await Run.Create(fixture); var lease = await run.Claim();
        await using (var db = fixture.Open())
            await Assert.ThrowsAsync<ProductionWorkBlockedException>(() => run.Store(db).FinishAsync(lease with { Owner = Guid.NewGuid() }, new(WorkOutcome.Completed), CancellationToken.None));
        await using (var db = fixture.Open())
        {
            var saved = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == run.WorkId);
            Assert.Equal(lease.Owner, saved.LeaseOwner); Assert.Equal(WorkStatus.Leased, saved.Status);
        }
        Assert.Equal(lease.Owner, (await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
        await run.DeliverAndFinish(lease); Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    private sealed class LostCommit : DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(System.Data.Common.DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
            => throw new IOException("Synthetic lost Finish commit acknowledgement");
    }
    internal sealed class CapturedSender : IEmailSender
    {
        internal int Calls;
        public Task<EmailDelivery> SendAsync(OutgoingEmail message, CancellationToken cancellationToken = default)
        { Assert.EndsWith("@example.invalid", message.To); Calls++; return Task.FromResult(new EmailDelivery("SyntheticCapture", "synthetic-receipt")); }
    }
    private sealed class Signals : IWorkSignals
    {
        internal Func<Guid, Task>? BeforePublish;
        internal Guid? WorkId; internal int Deferred;
        public Task PutHintAsync(Guid id, DateTimeOffset due, CancellationToken ct) => Task.CompletedTask;
        public async Task PublishAsync(Guid id, TimeSpan delay, CancellationToken ct) { if (BeforePublish is not null) await BeforePublish(id); }
        public Task RemoveHintAsync(Guid id, CancellationToken ct) => Task.CompletedTask;
        public Task<DateTimeOffset?> ReadDueAsync(Guid id, CancellationToken ct) => Task.FromResult<DateTimeOffset?>(null);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct) => Task.FromResult<WorkDelivery?>(new("synthetic-message", "synthetic-receipt", WorkId));
        public Task DeferAsync(WorkDelivery delivery, TimeSpan delay, CancellationToken ct) { Deferred++; return Task.CompletedTask; }
        public Task AcknowledgeAsync(WorkDelivery delivery, CancellationToken ct) => Task.CompletedTask;
        public Task<int> RecoverAsync(DateTimeOffset now, CancellationToken ct) => Task.FromResult(0);
        public Task VerifyAsync(CancellationToken ct) => Task.CompletedTask;
    }
    private sealed class EmptySource : IProductionHoldObjectSource
    {
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct)
            => Task.FromResult(new HoldObjectPage([], null));
        public Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress address, CancellationToken ct) => throw new InvalidOperationException();
    }
    internal sealed class Run : IAsyncDisposable
    {
        private readonly SqlDatabaseFixture fixture; internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider();
        internal readonly Clock Time = new(); internal readonly Store External = new(); internal readonly CapturedSender Captured = new();
        private readonly Signals signals = new(); private readonly WorkOptions work = new() { Enabled = true };
        private readonly EmailOptions email = new() { Enabled = true, BaseUrl = "https://example.invalid", FromEmail = "noreply@example.invalid" };
        private readonly bool demo; private readonly ProductionHoldArchiveReleaseTests.Provider provider = new();
        internal Guid Id, WorkId; internal VerificationPayload Token = null!; internal bool PublicationVerified;
        internal ProductionHoldWitnessJournal Journal { get; }
        internal ProductionRecordOperationAdmission Admission { get; }
        internal ProductionHoldCoordinator Coordinator { get; }
        private Run(SqlDatabaseFixture fixture, bool demo)
        {
            this.fixture = fixture; this.demo = demo; Journal = new(External, Keys, Time, Installation); Admission = new(fixture.Open, Keys, Time, Journal);
            var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03) { Transport = new HttpClientTransport(new HttpClient(provider, false)) };
            options.Retry.MaxRetries = 0; var client = new BlobServiceClient(new Uri("https://storage.example.invalid"), new ProductionHoldArchiveReleaseTests.Credential(), options);
            Coordinator = new(fixture.Open, Keys, Time, Journal, new EmptySource(), new(client), new(client));
        }
        internal static async Task<Run> Create(SqlDatabaseFixture fixture, bool demo = false)
        {
            var run = new Run(fixture, demo);
            run.signals.BeforePublish = async workId =>
            {
                await using var check = fixture.Open(); var id = await check.WorkItems.Where(x => x.Id == workId).Select(x => x.EnvelopeId).SingleAsync();
                Assert.NotNull(id); var state = await run.Journal.ReadAsync(id.Value);
                Assert.Equal(demo ? 0 : 1, state.Sequence); run.PublicationVerified = true;
            };
            await using var db = fixture.Open(); var address = "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid";
            Assert.Equal(SenderRequestOutcome.Neutral, await run.Sender(db).RequestAsync(address, "127.0.0.1", "Synthetic gated intake"));
            var outbox = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.To == address); run.Id = outbox.EnvelopeId!.Value; run.WorkId = outbox.Id;
            run.Token = new EmailPayloadProtection(run.Keys).Unprotect(outbox.PayloadJson); return run;
        }
        internal SenderWorkflow Sender(QuillSignDbContext db)
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["ConnectionStrings:Database"] = "synthetic-configured", ["Storage:Provider"] = "Azurite" }).Build();
            return new(db, new(), new(email, work, config), () => new(db, signals, new(Keys), work, email, Time), new(db, Time), Time,
                lifecycle: demo ? new() : ProductionRetentionAdmissionContractTests.Settings(), electronicRecords: ProductionRetentionAdmissionContractTests.Policies())
                { HoldAdmission = Admission };
        }
        internal WorkStore Store(QuillSignDbContext db) => new(db, work, Time, new ProductionWorkAdmission(fixture.Open, Admission));
        internal async Task<WorkLease> Claim()
        { await using var db = fixture.Open(); var lease = (await Store(db).ClaimAsync(WorkId, CancellationToken.None)).Lease; Assert.NotNull(lease); return lease; }
        internal async Task Deliver(WorkLease lease)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(SenderWorkflow).Assembly.FullName,
                ContentRootPath = AppContext.BaseDirectory, EnvironmentName = "Development" });
            builder.Logging.ClearProviders(); builder.Services.AddRazorPages(); builder.Services.AddScoped<RazorEmailViews>();
            await using var app = builder.Build(); using var scope = app.Services.CreateScope(); await using var db = fixture.Open();
            var handler = new EmailWorkHandler(db, email, new(Keys), new(email, scope.ServiceProvider.GetRequiredService<RazorEmailViews>()), Captured, Time)
                { HoldAdmission = new ProductionWorkAdmission(fixture.Open, Admission) };
            Assert.Equal(WorkOutcome.Completed, (await handler.ExecuteAsync(lease, CancellationToken.None)).Outcome);
        }
        internal async Task DeliverAndFinish(WorkLease lease)
        { await Deliver(lease); await using var db = fixture.Open(); await Store(db).FinishAsync(lease, new(WorkOutcome.Completed), CancellationToken.None); }
        internal int Deferred => signals.Deferred;
        internal async Task<bool> ProcessOnce()
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(SenderWorkflow).Assembly.FullName,
                ContentRootPath = AppContext.BaseDirectory, EnvironmentName = "Development" });
            builder.Logging.ClearProviders(); builder.Services.AddRazorPages(); builder.Services.AddScoped<RazorEmailViews>();
            await using var app = builder.Build(); using var scope = app.Services.CreateScope(); await using var db = fixture.Open();
            var handler = new EmailWorkHandler(db, email, new(Keys), new(email, scope.ServiceProvider.GetRequiredService<RazorEmailViews>()), Captured, Time)
                { HoldAdmission = new ProductionWorkAdmission(fixture.Open, Admission) };
            signals.WorkId = WorkId;
            return await new WorkProcessor(Store(db), signals, [handler], Time).RunOnceAsync(CancellationToken.None);
        }
        internal async Task<ProductionHoldCommand> Hold()
        {
            var command = Place(Id); await Coordinator.SubmitAsync(Authority(Time, command.Permission), Operators, command);
            await Coordinator.PreserveAsync(Id, command.HoldId, Guid.NewGuid()); return command;
        }
        internal async Task Release(ProductionHoldCommand placement)
        {
            var command = placement with { CommandId = Guid.NewGuid(), ExpectedRevision = 1, Operation = ProductionHoldOperation.Release };
            await Coordinator.SubmitAsync(Authority(Time, command.Permission), Operators, command); await Coordinator.ReleaseAsync(Id, placement.HoldId);
        }
        public ValueTask DisposeAsync() { provider.Dispose(); return ValueTask.CompletedTask; }
    }
}

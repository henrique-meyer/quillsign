using System.Data.Common;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotSecretCleanupTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Preparation_is_exact_nonpersonal_durable_and_restart_does_not_extend_due()
    {
        await using var h = await Create(); var first = await h.Jobs().PrepareAsync(h.Manifest);
        Assert.False(first.Recovered); Assert.True(first.WakeupPublished);
        var row = await h.Db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == first.WorkId);
        Assert.Null(row.EnvelopeId); Assert.Equal(WorkKind.Purge, row.Kind); Assert.Equal(h.Manifest.CreatedAt.AddDays(7), row.AvailableAt);
        Assert.Equal(row.AvailableAt, h.Signals.Hints[first.WorkId]);
        Assert.DoesNotContain("@", row.PayloadJson); Assert.DoesNotContain("capability", row.PayloadJson, StringComparison.OrdinalIgnoreCase);
        h.Clock.Now += TimeSpan.FromHours(2); h.Options.Enabled = false; h.Options.RunId = "";
        await using var restarted = fixture.Open(); var again = await h.Jobs(restarted).PrepareAsync(h.Manifest);
        Assert.True(again.Recovered); Assert.Equal(first.WorkId, again.WorkId);
        Assert.Equal(row.PayloadJson, (await restarted.WorkItems.AsNoTracking().SingleAsync(x => x.Id == first.WorkId)).PayloadJson);
        Assert.Equal(1, await restarted.WorkItems.CountAsync(x => x.Id == first.WorkId));
    }
    [Fact]
    public async Task Missing_wakeup_ack_keeps_committed_work_and_hint_for_explicit_recovery()
    {
        await using var h = await Create(); h.Signals.FailPublish = true;
        var result = await h.Jobs().PrepareAsync(h.Manifest); Assert.False(result.WakeupPublished);
        Assert.True(h.Signals.Hints.ContainsKey(result.WorkId)); Assert.True(await h.Db.WorkItems.AnyAsync(x => x.Id == result.WorkId));
        h.Signals.FailPublish = false; Assert.True((await h.Jobs().PrepareAsync(h.Manifest)).WakeupPublished);
    }
    [Fact]
    public async Task Failed_hint_rolls_back_SQL_and_same_fixed_job_can_be_prepared_again()
    {
        await using var h = await Create(); h.Signals.FailHint = true;
        await Assert.ThrowsAsync<IOException>(() => h.Jobs().PrepareAsync(h.Manifest));
        Assert.False(await h.Db.WorkItems.AnyAsync(x => x.Id == EmailPilotSecretJobs.WorkId(h.Manifest.RunId)));
        h.Signals.FailHint = false; Assert.False((await h.Jobs().PrepareAsync(h.Manifest)).Recovered);
    }
    [Fact]
    public async Task Real_lost_prepare_commit_ack_recovers_identical_work_and_hint_without_publishing_early()
    {
        await using var h = await Create(); await using (var db = h.Fault(new LostAcknowledgement()))
            await Assert.ThrowsAsync<IOException>(() => h.Jobs(db).PrepareAsync(h.Manifest));
        Assert.Equal(0, h.Signals.Publishes);
        var id = EmailPilotSecretJobs.WorkId(h.Manifest.RunId); Assert.True(h.Signals.Hints.ContainsKey(id));
        Assert.True((await h.Jobs().PrepareAsync(h.Manifest)).Recovered); Assert.Equal(1, h.Signals.Publishes);
        Assert.Equal(1, await h.Db.WorkItems.CountAsync(x => x.Id == id));
    }
    [Theory]
    [InlineData("hash")][InlineData("run")][InlineData("due")][InlineData("purpose")][InlineData("whitespace")][InlineData("unattempted-delay")]
    public async Task Changed_manifest_or_existing_work_binding_is_rejected(string fault)
    {
        await using var h = await Create(); var prepared = await h.Jobs().PrepareAsync(h.Manifest); var input = h.Manifest;
        if (fault == "hash") input = input with { CapabilitySha256 = new string('a', 64) };
        if (fault == "run") input = input with { RunId = Guid.NewGuid() };
        if (fault == "due") input = input with { CreatedAt = input.CreatedAt.AddSeconds(1), ExpiresAt = input.ExpiresAt.AddSeconds(1) };
        if (fault == "purpose") await h.Db.WorkItems.Where(x => x.Id == prepared.WorkId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Kind, WorkKind.Rendering));
        if (fault == "whitespace") await h.Db.WorkItems.Where(x => x.Id == prepared.WorkId).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, x => x.PayloadJson + " "));
        if (fault == "unattempted-delay") await h.Db.WorkItems.Where(x => x.Id == prepared.WorkId).ExecuteUpdateAsync(s => s.SetProperty(x => x.AvailableAt, x => x.AvailableAt.AddHours(1)));
        await Assert.ThrowsAsync<InvalidDataException>(() => h.Jobs().PrepareAsync(input));
    }
    [Fact]
    public async Task Exact_due_worker_cleanup_removes_only_secret_and_replay_does_not_restore_it()
    {
        await using var h = await Create(past: true); var prepared = await h.Jobs().PrepareAsync(h.Manifest); await h.Grant();
        var lease = await h.Claim(); Assert.NotNull(lease);
        await h.As("app_worker");
        try { Assert.True(await h.Cleanup().RemoveAsync(lease!)); Assert.False(await h.Cleanup().RemoveAsync(lease!)); }
        finally { await h.Revert(); }
        Assert.False(await h.Db.EmailPilotSecrets.AnyAsync(x => x.RunId == h.Manifest.RunId));
        Assert.True(await h.Db.EmailPilotRuns.AnyAsync(x => x.Id == h.Manifest.RunId));
        Assert.True(await h.Db.EmailPilotReservations.AnyAsync(x => x.RunId == h.Manifest.RunId));
        Assert.True(await h.Db.EmailPilotSecrets.AnyAsync(x => x.RunId == h.Neighbor));
        await new WorkStore(h.Db, new(), h.Clock).FinishAsync(lease!, new(WorkOutcome.Completed), default);
        var recovered = await h.Jobs().PrepareAsync(h.Manifest); Assert.True(recovered.Recovered); Assert.False(recovered.WakeupPublished);
        Assert.True((await new WorkStore(h.Db, new(), h.Clock).ClaimAsync(prepared.WorkId, default)).Terminal);
    }
    [Fact]
    public async Task Database_UTC_prevents_app_clock_from_erasing_a_new_secret_early()
    {
        await using var h = await Create(); await h.Jobs().PrepareAsync(h.Manifest);
        h.Clock.Now = h.Manifest.CreatedAt.AddDays(8); var lease = (await h.Claim())!;
        Assert.Equal(WorkOutcome.Retry, (await h.Cleanup().ExecuteAsync(lease, default)).Outcome);
        Assert.True(await h.Db.EmailPilotSecrets.AnyAsync(x => x.RunId == h.Manifest.RunId));
    }
    [Theory]
    [InlineData("owner")][InlineData("attempt")][InlineData("until")][InlineData("kind")][InlineData("expired")]
    public async Task Unowned_or_expired_lease_never_removes_secrets(string fault)
    {
        await using var h = await Create(past: true); await h.Jobs().PrepareAsync(h.Manifest); var lease = (await h.Claim())!;
        if (fault == "owner") lease = lease with { Owner = Guid.NewGuid() };
        if (fault == "attempt") lease = lease with { Attempt = lease.Attempt + 1 };
        if (fault == "until") lease = lease with { Until = lease.Until.AddSeconds(1) };
        if (fault == "kind") lease = lease with { Kind = WorkKind.Rendering };
        if (fault == "expired") h.Clock.Now = lease.Until;
        Assert.Equal(WorkOutcome.Retry, (await h.Cleanup().ExecuteAsync(lease, default)).Outcome);
        Assert.True(await h.Db.EmailPilotSecrets.AnyAsync(x => x.RunId == h.Manifest.RunId));
    }
    [Fact]
    public async Task Actual_cleanup_commit_lost_ack_is_success_after_restart_without_counter_loss()
    {
        await using var h = await Create(past: true); await h.Jobs().PrepareAsync(h.Manifest); var lease = (await h.Claim())!;
        await using (var db = h.Fault(new LostAcknowledgement()))
            await Assert.ThrowsAsync<IOException>(() => new EmailPilotSecretCleanup(db, h.Clock).RemoveAsync(lease));
        Assert.False(await h.Db.EmailPilotSecrets.AnyAsync(x => x.RunId == h.Manifest.RunId));
        Assert.False(await h.Cleanup().RemoveAsync(lease));
        Assert.True(await h.Db.EmailPilotReservations.AnyAsync(x => x.RunId == h.Manifest.RunId));
    }
    [Fact]
    public async Task Expiry_after_procedure_rolls_back_secret_deletion()
    {
        await using var h = await Create(past: true); await h.Jobs().PrepareAsync(h.Manifest); var lease = (await h.Claim())!;
        await using var db = h.Fault(new ExpireAfterDelete(h.Clock, lease.Until));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new EmailPilotSecretCleanup(db, h.Clock).RemoveAsync(lease));
        Assert.True(await h.Db.EmailPilotSecrets.AnyAsync(x => x.RunId == h.Manifest.RunId));
    }
    [Fact]
    public async Task Runtime_can_prepare_but_cannot_execute_or_directly_delete_even_after_worker_grant()
    {
        await using var h = await Create(past: true); await h.Grant(); await h.As("app_runtime");
        WorkLease lease;
        try {
            await h.Jobs().PrepareAsync(h.Manifest); lease = (await h.Claim())!;
            Assert.Equal(WorkOutcome.Retry, (await h.Cleanup().ExecuteAsync(lease, default)).Outcome);
            var error = await Assert.ThrowsAsync<SqlException>(() => h.Db.EmailPilotSecrets.Where(x => x.RunId == h.Manifest.RunId).ExecuteDeleteAsync());
            Assert.Equal(229, error.Number);
        } finally { await h.Revert(); }
        Assert.True(await h.Db.EmailPilotSecrets.AnyAsync(x => x.RunId == h.Manifest.RunId));
        await h.As("app_worker");
        try { Assert.True(await h.Cleanup().RemoveAsync(lease)); } finally { await h.Revert(); }
    }
    [Fact]
    public async Task Retry_preserves_payload_due_binding_and_lazy_handler_needs_no_document_or_key_authority()
    {
        await using var h = await Create(past: true); var prepared = await h.Jobs().PrepareAsync(h.Manifest); var lease = (await h.Claim())!;
        var unavailable = new DemoPurgeHandler(h.Db, () => throw new Exception("document SQL forbidden"), () => throw new Exception("document recovery forbidden"), h.Clock);
        Assert.Equal(WorkOutcome.Retry, (await unavailable.ExecuteAsync(lease, default)).Outcome);
        await new WorkStore(h.Db, new(), h.Clock).FinishAsync(lease, new(WorkOutcome.Retry), default);
        Assert.True((await h.Jobs().PrepareAsync(h.Manifest)).Recovered);
        h.Clock.Now += TimeSpan.FromMinutes(1); var next = (await h.Claim())!;
        var handler = new DemoPurgeHandler(h.Db, () => throw new Exception("forbidden"), () => throw new Exception("forbidden"), h.Clock, pilotCleanup: h.Cleanup);
        Assert.Equal(WorkOutcome.Completed, (await handler.ExecuteAsync(next, default)).Outcome);
        Assert.Equal(prepared.WorkId, next.Id); Assert.Equal(2, next.Attempt);
    }
    [Fact]
    public async Task Pending_edits_and_caller_transaction_are_not_discarded_or_joined()
    {
        await using var h = await Create(); h.Db.Envelopes.Add(new());
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Jobs().PrepareAsync(h.Manifest)); Assert.True(h.Db.ChangeTracker.HasChanges());
        h.Db.ChangeTracker.Clear(); await using var tx = await h.Db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Jobs().PrepareAsync(h.Manifest));
    }
    [Fact]
    public async Task Concurrent_preparation_and_cleanup_share_one_fixed_item_and_remove_once()
    {
        await using var h = await Create(past: true);
        var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(async _ => {
            await using var db = fixture.Open(); return await h.Jobs(db).PrepareAsync(h.Manifest);
        }));
        Assert.Single(results, x => !x.Recovered); Assert.Single(results.Select(x => x.WorkId).Distinct());
        var lease = (await h.Claim())!;
        var removed = await Task.WhenAll(Enumerable.Range(0, 2).Select(async _ => {
            await using var db = fixture.Open(); return await new EmailPilotSecretCleanup(db, h.Clock).RemoveAsync(lease);
        }));
        Assert.Single(removed, x => x); Assert.Single(removed, x => !x);
        Assert.True(await h.Db.EmailPilotRuns.AnyAsync(x => x.Id == h.Manifest.RunId));
    }
    [Theory]
    [InlineData("digest")][InlineData("secret-deadline")]
    public async Task Cleanup_checks_saved_binding_again_under_lock(string fault)
    {
        await using var h = await Create(past: true); await h.Jobs().PrepareAsync(h.Manifest); var lease = (await h.Claim())!;
        if (fault == "digest") {
            var payload = (await h.Db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == lease.Id)).PayloadJson;
            var binding = EmailPilotSecretJobs.ReadPayload(payload) with { ManifestSha256 = new string('c', 64) };
            await h.Db.WorkItems.Where(x => x.Id == lease.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, EmailPilotSecretJobs.Payload(binding)));
        } else await h.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE EmailPilotSecrets SET DeleteAfter=DATEADD(day,1,DeleteAfter) WHERE RunId={h.Manifest.RunId}");
        Assert.Equal(WorkOutcome.Retry, (await h.Cleanup().ExecuteAsync(lease, default)).Outcome);
        Assert.True(await h.Db.EmailPilotSecrets.AnyAsync(x => x.RunId == h.Manifest.RunId));
    }
    [Fact]
    public void Explicit_registration_is_lazy_and_has_no_key_ring_signals_or_provider_resolution()
    {
        var services = new ServiceCollection(); services.AddSingleton<TimeProvider>(TimeProvider.System);
        services.AddScoped(_ => new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().Options));
        services.AddScoped<Func<IWorkSignals>>(_ => () => throw new Exception("Signals must remain lazy."));
        services.AddEmailPilotSecretCleanup();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        using var scope = provider.CreateScope(); Assert.NotNull(scope.ServiceProvider.GetRequiredService<EmailPilotSecretJobs>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<Func<EmailPilotSecretCleanup>>()());
        Assert.Empty(scope.ServiceProvider.GetServices<IWorkHandler>());
    }
    private async Task<Harness> Create(bool past = false)
    {
        var h = new Harness(fixture.Open());
        if (past) h.Clock.Now -= TimeSpan.FromDays(8);
        h.Manifest = await h.Ledger.CreateAsync(new string('a', 43));
        // A simulator receipt proves accounting remains even when the private row is gone.
        Assert.Equal(EmailPilotReservationOutcome.Reserved, await h.Ledger.ReserveAsync(new(Guid.NewGuid(), null, Guid.NewGuid(), EmailPilotAttemptKind.Simulator,
            EmailPilotRole.Simulator, 100, new string('b', 64)), null));
        h.Options.RunId = h.Neighbor.ToString("N"); await h.Ledger.CreateAsync(new string('a', 43)); h.Options.RunId = h.Manifest.RunId.ToString("N");
        h.Clock.Now = DateTimeOffset.UtcNow; return h;
    }
    private sealed class Harness(QuillSignDbContext db) : IAsyncDisposable
    {
        public readonly QuillSignDbContext Db = db; public readonly Clock Clock = new(); public readonly Signals Signals = new();
        public readonly Guid Neighbor = Guid.NewGuid(); public EmailPilotManifest Manifest = null!;
        public readonly EmailPilotOptions Options = new() { Enabled = true, RunId = Guid.NewGuid().ToString("N"), Mailboxes = EmailPilotProtectionTests.Mailboxes() };
        private readonly EmailPilotProtection protection = new(new EphemeralDataProtectionProvider());
        public EmailPilotLedger Ledger => new(Options, new(), () => Db, () => protection, Clock);
        public EmailPilotSecretJobs Jobs(QuillSignDbContext? context = null) => new(context ?? Db, () => Signals, Clock);
        public EmailPilotSecretCleanup Cleanup() => new(Db, Clock);
        public async Task<WorkLease?> Claim() => (await new WorkStore(Db, new(), Clock).ClaimAsync(EmailPilotSecretJobs.WorkId(Manifest.RunId), default)).Lease;
        public QuillSignDbContext Fault(IInterceptor interceptor) => new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(Db.Database.GetConnectionString()).AddInterceptors(interceptor).Options);
        public async Task As(string user) { await Db.Database.ExecuteSqlRawAsync(user == "app_worker" ? "EXECUTE AS USER='app_worker'" : "EXECUTE AS USER='app_runtime'"); }
        public Task Revert() => Db.Database.ExecuteSqlRawAsync("REVERT");
        public async Task Grant() {
            await Db.Database.ExecuteSqlRawAsync("IF DATABASE_PRINCIPAL_ID('app_worker') IS NULL CREATE USER app_worker WITHOUT LOGIN; IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER app_runtime WITHOUT LOGIN;");
            var c = (SqlConnection)Db.Database.GetDbConnection(); await DatabasePermissions.GrantRuntimeAsync(c);
            await Db.Database.ExecuteSqlRawAsync("ALTER ROLE app_runtime_role ADD MEMBER app_worker");
            await DatabasePermissions.GrantEmailPilotRetentionAsync(c);
        }
        public ValueTask DisposeAsync() => Db.DisposeAsync();
    }
    private sealed class Clock : TimeProvider { public DateTimeOffset Now = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class LostAcknowledgement : DbTransactionInterceptor {
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData e, CancellationToken ct = default) => throw new IOException("Synthetic lost cleanup acknowledgement.");
    }
    private sealed class ExpireAfterDelete(Clock clock, DateTimeOffset deadline) : DbCommandInterceptor {
        public override ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData e, int result, CancellationToken ct = default) {
            if (command.CommandText.Contains("EXEC dbo.RemoveExpiredEmailPilotSecrets", StringComparison.Ordinal)) clock.Now = deadline;
            return ValueTask.FromResult(result);
        }
    }
    private sealed class Signals : IWorkSignals
    {
        public Dictionary<Guid, DateTimeOffset> Hints = []; public bool FailHint, FailPublish; public int Publishes;
        public Task PutHintAsync(Guid id, DateTimeOffset due, CancellationToken ct) { if (FailHint) throw new IOException("Synthetic hint failure."); Hints[id] = due; return Task.CompletedTask; }
        public Task PublishAsync(Guid id, TimeSpan delay, CancellationToken ct) { if (FailPublish) throw new IOException("Synthetic wake failure."); Publishes++; return Task.CompletedTask; }
        public Task<DateTimeOffset?> ReadDueAsync(Guid id, CancellationToken ct) => Task.FromResult(Hints.TryGetValue(id, out var due) ? (DateTimeOffset?)due : null);
        public Task RemoveHintAsync(Guid id, CancellationToken ct) { Hints.Remove(id); return Task.CompletedTask; }
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct) => Task.FromResult<WorkDelivery?>(null);
        public Task DeferAsync(WorkDelivery d, TimeSpan delay, CancellationToken ct) => Task.CompletedTask;
        public Task AcknowledgeAsync(WorkDelivery d, CancellationToken ct) => Task.CompletedTask;
        public Task<int> RecoverAsync(DateTimeOffset now, CancellationToken ct) => Task.FromResult(0);
        public Task VerifyAsync(CancellationToken ct) => Task.CompletedTask;
    }
}

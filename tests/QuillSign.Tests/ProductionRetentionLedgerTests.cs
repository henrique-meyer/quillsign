using System.Data.Common;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using Shared = QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class ProductionRetentionLedgerTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    internal static ProductionRetentionPolicyOptions Policy() => new()
    {
        Version = "synthetic-policy-v1", ArchiveResponsibility = "Synthetic operators preserve their own retained copies.",
        AbandonedDraftDays = 14, ExpiredDays = 30, DeclinedDays = 31, VoidedDays = 32, CompletedDays = 365
    };

    [Fact]
    public async Task Creation_freezes_one_policy_with_exact_origin_and_restart_never_consults_changed_settings()
    {
        var clock = new Clock(); var e = New(clock); var options = Policy();
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync(); db.Add(e);
            var saved = await Service(db, clock).PrepareNewLockedAsync(e, options);
            Assert.Equal(e.CreatedAt, saved.OriginalCreatedAt); Assert.Equal(ProductionRetentionLedger.Seconds(e.CreatedAt), saved.Snapshot.CreatedAt);
            Assert.Equal(1, saved.AuditSequence); await tx.CommitAsync();
        }
        options.CompletedDays = 1; options.Version = "replacement"; options.ArchiveResponsibility = "Changed after creation";
        clock.Now = clock.Now.AddDays(1);
        var recovered = await Read(e.Id, clock);
        Assert.Equal(ProductionEnrollmentKind.Enrolled, recovered.Kind); Assert.Equal(365, recovered.Enrollment!.Snapshot.Policy.CompletedDays);
        Assert.Equal("synthetic-policy-v1", recovered.Enrollment.Snapshot.Policy.Version);
        await using var check = fixture.Open(); Assert.Single(await check.ProductionRetentionPolicies.Where(x => x.EnvelopeId == e.Id).ToArrayAsync());
        Assert.Single(await check.AuditEvents.Where(x => x.EnvelopeId == e.Id).ToArrayAsync());
    }

    [Fact]
    public async Task Missing_demo_and_legacy_records_are_distinct_and_reads_never_backfill()
    {
        var clock = new Clock(); var ordinary = New(clock); var demo = New(clock); demo.IsDemo = true;
        await using (var db = fixture.Open()) { db.AddRange(ordinary, demo); await db.SaveChangesAsync(); }
        Assert.Equal(ProductionEnrollmentKind.MissingRecord, (await Read(Guid.NewGuid(), clock)).Kind);
        Assert.Equal(ProductionEnrollmentKind.Unenrolled, (await Read(ordinary.Id, clock)).Kind);
        Assert.Equal(ProductionEnrollmentKind.Demo, (await Read(demo.Id, clock)).Kind);
        await using var check = fixture.Open(); await using var tx = await check.Database.BeginTransactionAsync();
        var old = await check.Envelopes.SingleAsync(x => x.Id == ordinary.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Service(check, clock).PrepareNewLockedAsync(old, Policy()));
        Assert.False(await check.ProductionRetentionPolicies.AnyAsync(x => x.EnvelopeId == ordinary.Id || x.EnvelopeId == demo.Id));
    }

    [Theory]
    [InlineData("demo")][InlineData("sent")][InlineData("verified")][InlineData("source")][InlineData("future")][InlineData("unrelated")]
    public async Task Enrollment_requires_only_a_new_untouched_production_creation(string change)
    {
        var clock = new Clock(); var e = New(clock);
        if (change == "demo") e.IsDemo = true; if (change == "sent") e.Status = EnvelopeStatus.Sent;
        if (change == "verified") e.SenderVerifiedAt = clock.Now; if (change == "source") e.PdfBlob = Guid.NewGuid().ToString("N");
        if (change == "future") e.CreatedAt = clock.Now.AddTicks(1);
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync(); db.Add(e);
        if (change == "unrelated") db.Add(New(clock));
        var error = await Record.ExceptionAsync(() => Service(db, clock).PrepareNewLockedAsync(e, Policy()));
        Assert.True(error is InvalidOperationException or InvalidDataException);
        await tx.RollbackAsync();
        await using var check = fixture.Open(); Assert.False(await check.Envelopes.AnyAsync(x => x.Id == e.Id));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Audit_rollback_and_lost_commit_recover_only_original_saved_creation(bool lost)
    {
        var clock = new Clock(); var e = New(clock); var faults = new Faults(ProductionRetentionLedger.EnrollmentEvent, lost);
        await using var baseline = fixture.Open();
        var builder = new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(faults);
        await using (var db = new QuillSignDbContext(builder.Options))
        {
            await using var tx = await db.Database.BeginTransactionAsync(); db.Add(e);
            async Task Capture() { await Service(db, clock).PrepareNewLockedAsync(e, Policy()); await tx.CommitAsync(); }
            if (lost) await Assert.ThrowsAsync<IOException>(Capture); else await Assert.ThrowsAsync<DbUpdateException>(Capture);
        }
        var recovered = await Read(e.Id, clock);
        Assert.Equal(lost ? ProductionEnrollmentKind.Enrolled : ProductionEnrollmentKind.MissingRecord, recovered.Kind);
        if (lost) Assert.Equal(365, recovered.Enrollment!.Snapshot.Policy.CompletedDays);
    }

    [Fact]
    public async Task Concurrent_creation_and_explicit_recovery_never_backfill_or_duplicate_enrollment()
    {
        var clock = new Clock(); var original = New(clock);
        async Task<bool> Create()
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var e = new Envelope { Id = original.Id, PublicId = original.PublicId, CreatedAt = original.CreatedAt, SenderEmail = original.SenderEmail };
            db.Add(e);
            try { await Service(db, clock).PrepareNewLockedAsync(e, Policy()); await tx.CommitAsync(); return true; }
            catch (InvalidDataException) { return false; }
        }
        var results = await Task.WhenAll(Create(), Create()); Assert.Single(results, x => x);
        Assert.Equal(ProductionEnrollmentKind.Enrolled, (await Read(original.Id, clock)).Kind);
        await using var check = fixture.Open(); Assert.Single(await check.AuditEvents.Where(x => x.EnvelopeId == original.Id).ToArrayAsync());
    }

    [Theory]
    [InlineData("policy")][InlineData("mode")][InlineData("created")][InlineData("sender")][InlineData("audit")][InlineData("missing")]
    public async Task Corrupted_saved_policy_origin_or_audit_never_becomes_legacy_or_current_config(string change)
    {
        var clock = new Clock(); var e = await Create(clock);
        await using (var db = fixture.Open())
        {
            if (change == "mode") await db.Envelopes.Where(x => x.Id == e.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.IsDemo, true));
            if (change == "created") await db.Envelopes.Where(x => x.Id == e.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.CreatedAt, clock.Now.AddSeconds(-1)));
            if (change == "sender") await db.Envelopes.Where(x => x.Id == e.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SenderEmail, "changed@example.invalid"));
            if (change == "policy")
            {
                var row = await db.ProductionRetentionPolicies.AsNoTracking().SingleAsync(x => x.EnvelopeId == e.Id);
                var policy = ProductionRetentionPolicyContract.Read(row.PolicyJson, row.PolicySha256);
                var altered = policy with { Policy = policy.Policy with { CompletedDays = 1 } };
                await db.ProductionRetentionPolicies.Where(x => x.EnvelopeId == e.Id).ExecuteUpdateAsync(s => s
                    .SetProperty(x => x.PolicyJson, ProductionRetentionPolicyContract.Serialize(altered)).SetProperty(x => x.PolicySha256, ProductionRetentionPolicyContract.Digest(altered)));
            }
            if (change == "audit") await db.AuditEvents.Where(x => x.EnvelopeId == e.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.DataJson, "{}"));
            if (change == "missing") await db.ProductionRetentionPolicies.Where(x => x.EnvelopeId == e.Id).ExecuteDeleteAsync();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => Read(e.Id, clock));
    }

    [Theory]
    [InlineData("Void")][InlineData("Decline")][InlineData("Expiry")]
    public async Task Actual_terminal_operations_bind_once_to_their_verified_source_and_exact_elapsed_interval(string operation)
    {
        await using var h = await Shared.Create(fixture, browser: true, productionRetention: Policy()); Assert.NotNull(await h.Send());
        h.Clock.Advance(TimeSpan.FromTicks(7654321)); var original = await Close(h, operation);
        var first = await Capture(h.Envelope.Id, h.Clock); var second = await Capture(h.Envelope.Id, h.Clock);
        Assert.Equal(first, second); Assert.Equal(original, first.OriginalAt); Assert.Equal(ProductionRetentionLedger.Seconds(original), first.ClockAt);
        var enrolled = (await Read(h.Envelope.Id, h.Clock)).Enrollment!;
        var days = operation == "Void" ? 32 : operation == "Decline" ? 31 : 30;
        Assert.Equal(original.AddDays(days), ProductionRetentionLedger.ExactEligibleAt(enrolled, first));
        await using var db = fixture.Open(); Assert.Single(await db.ProductionRetentionTerminals.Where(x => x.EnvelopeId == h.Envelope.Id).ToArrayAsync());
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == h.Envelope.Id && x.Event == ProductionRetentionLedger.TerminalEvent).ToArrayAsync());
        // A pre-transition Sent DTO cannot hide the saved terminal deadline.
        var deadline=await QuillSign.Documents.DocumentRetentionAccess.ReadAsync(db,h.Envelope,h.Clock,default);
        Assert.Equal(original.AddDays(days),deadline);
        h.Clock.Advance(deadline!.Value-h.Clock.GetUtcNow()-TimeSpan.FromTicks(1));
        QuillSign.Documents.DocumentRetentionAccess.Check(deadline,h.Clock);
        h.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.Throws<QuillSign.Documents.DocumentRetentionExpiredException>(()=>QuillSign.Documents.DocumentRetentionAccess.Check(deadline,h.Clock));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Terminal_rollback_or_unknown_commit_then_concurrent_recovery_preserves_one_anchor(bool lost)
    {
        await using var h = await Shared.Create(fixture, browser: true, productionRetention: Policy()); Assert.NotNull(await h.Send());
        await using var baseline = fixture.Open();
        var before=await baseline.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);
        var until=h.Clock.GetUtcNow().AddHours(1);
        var options = new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString())
            .AddInterceptors(new Faults(ProductionRetentionLedger.TerminalEvent, lost));
        await using (var db = new QuillSignDbContext(options.Options))
        {
            var operation=new SenderVoid(db,new(db,h.Clock),new(db,h.Clock),h.Clock);
            Task<SenderVoidResult> CloseAndCommit()=>operation.VoidAsync(h.Principal,before.PublicId,until,before.RowVersion,
                true,SenderVoidStatement.Version,"Synthetic faulted void",null,null);
            if(lost)await Assert.ThrowsAsync<IOException>(CloseAndCommit);else await Assert.ThrowsAsync<DbUpdateException>(CloseAndCommit);
        }
        Assert.Equal(lost ? EnvelopeStatus.Voided : EnvelopeStatus.Sent,
            (await baseline.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==before.Id)).Status);
        Assert.Equal(lost ? 1 : 0,await baseline.ProductionRetentionTerminals.CountAsync(x=>x.EnvelopeId==before.Id));
        var retry=await new SenderVoid(baseline,new(baseline,h.Clock),new(baseline,h.Clock),h.Clock).VoidAsync(h.Principal,
            before.PublicId,until,before.RowVersion,true,SenderVoidStatement.Version,"Synthetic faulted void",null,null);
        Assert.Equal(lost ? SenderVoidOutcome.AlreadyVoided : SenderVoidOutcome.Voided,retry.Outcome);
        var results = await Task.WhenAll(Capture(h.Envelope.Id, h.Clock), Capture(h.Envelope.Id, h.Clock)); Assert.Equal(results[0], results[1]);
        Assert.Single(await baseline.ProductionRetentionTerminals.Where(x => x.EnvelopeId == h.Envelope.Id).ToArrayAsync());
    }

    [Theory]
    [InlineData("anchor")][InlineData("source")][InlineData("status")][InlineData("missing")]
    public async Task Saved_terminal_must_still_match_authoritative_state_source_and_policy(string change)
    {
        await using var h = await Shared.Create(fixture, browser: true, productionRetention: Policy()); Assert.NotNull(await h.Send());
        _ = await Close(h, "Void"); _ = await Capture(h.Envelope.Id, h.Clock);
        await using (var db = fixture.Open())
        {
            if (change == "anchor") await db.ProductionRetentionTerminals.Where(x => x.EnvelopeId == h.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SourceAuditHash, new byte[32]));
            if (change == "source") await db.AuditEvents.Where(x => x.EnvelopeId == h.Envelope.Id && x.Event == "voided").ExecuteUpdateAsync(s => s.SetProperty(x => x.DataJson, "{}"));
            if (change == "status") await db.Envelopes.Where(x => x.Id == h.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, EnvelopeStatus.Completed));
            if (change == "missing") await db.ProductionRetentionTerminals.Where(x => x.EnvelopeId == h.Envelope.Id).ExecuteDeleteAsync();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => Capture(h.Envelope.Id, h.Clock));
    }

    [Fact]
    public async Task Runtime_has_only_insert_read_and_EF_rejects_mutating_both_provenance_records()
    {
        var clock = new Clock(); var e = New(clock);
        await using var db = fixture.Open(); await db.Database.OpenConnectionAsync(); var connection = (SqlConnection)db.Database.GetDbConnection();
        await using var command = connection.CreateCommand(); command.CommandText = "IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN"; await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection); command.CommandText = "EXECUTE AS USER = 'app_runtime'"; await command.ExecuteNonQueryAsync();
        try
        {
            await using (var tx = await db.Database.BeginTransactionAsync()) { db.Add(e); await Service(db, clock).PrepareNewLockedAsync(e, Policy()); await tx.CommitAsync(); }
            await Assert.ThrowsAsync<SqlException>(() => db.ProductionRetentionPolicies.Where(x => x.EnvelopeId == e.Id).ExecuteDeleteAsync());
            await Assert.ThrowsAsync<SqlException>(() => db.ProductionRetentionPolicies.Where(x => x.EnvelopeId == e.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PolicySha256, new string('0', 64))));
            // Empty-table writes must still be denied: no destructive terminal grant is present.
            await Assert.ThrowsAsync<SqlException>(() => db.ProductionRetentionTerminals.Where(x => x.EnvelopeId == e.Id).ExecuteDeleteAsync());
        }
        finally { command.CommandText = "REVERT"; await command.ExecuteNonQueryAsync(); }
        db.ChangeTracker.Clear(); var row = await db.ProductionRetentionPolicies.SingleAsync(x => x.EnvelopeId == e.Id); row.EnrolledAt = row.EnrolledAt.AddSeconds(1);
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    private async Task<Envelope> Create(Clock clock)
    {
        var e = New(clock); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        db.Add(e); await Service(db, clock).PrepareNewLockedAsync(e, Policy()); await tx.CommitAsync(); return e;
    }
    private async Task<ProductionEnrollmentRead> Read(Guid id, TimeProvider clock)
    {
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        return await Service(db, clock).ReadLockedAsync(id);
    }
    private async Task<VerifiedProductionTerminal> Capture(Guid id, TimeProvider clock)
    {
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var result = await Service(db, clock).CaptureTerminalLockedAsync(id); await tx.CommitAsync(); return result;
    }
    private async Task<DateTimeOffset> Close(Shared h, string operation)
    {
        if (operation == "Decline")
        {
            Assert.True(await h.Once()); var raw = Regex.Match(h.Sender.Last!.Text, "token=([A-Za-z0-9_-]{43})").Groups[1].Value;
            using var scope = h.App.Services.CreateScope(); var access = scope.ServiceProvider.GetRequiredService<SignerAccess>();
            var identity = (await access.RedeemAsync(raw, null, null))!; Assert.NotNull(identity);
            var principal = SignerAccessConfiguration.Principal(identity);
            Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SignerConsent>().DeclineAsync(principal, h.Envelope.PublicId, "Synthetic refusal", null, null));
            return h.Clock.GetUtcNow();
        }
        if (operation == "Expiry")
        {
            var deadline = h.Envelope.ExpiresAt!.Value; h.Clock.Advance(deadline - h.Clock.GetUtcNow() + TimeSpan.FromDays(3));
            await using var db = fixture.Open(); var result = await new SigningExpiry(db, new(db, h.Clock), new(db, h.Clock), h.Clock).ExpireAsync(h.Envelope.Id);
            Assert.Equal(SigningExpiryOutcome.Expired, result.Outcome); return deadline;
        }
        await using (var db = fixture.Open())
        {
            var e = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == h.Envelope.Id);
            using var scope = h.App.Services.CreateScope(); var result = await scope.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(h.Principal, e.PublicId,
                h.Clock.GetUtcNow().AddHours(1), e.RowVersion, true, SenderVoidStatement.Version, "Synthetic void", null, null);
            Assert.Equal(SenderVoidOutcome.Voided, result.Outcome); return result.Action!.VoidedAt;
        }
    }
    private static ProductionRetentionLedger Service(QuillSignDbContext db, TimeProvider clock) => new(db, new(db, clock), clock);
    private static Envelope New(Clock clock) => new() { SenderEmail = "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid", CreatedAt = clock.Now };
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new DateTimeOffset(2028, 2, 28, 23, 59, 59, TimeSpan.Zero).AddTicks(1234567);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class Faults(string eventName, bool lost) : DbTransactionInterceptor, ISaveChangesInterceptor
    {
        private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e, InterceptionResult<int> result, CancellationToken ct = default)
        {
            if (e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x => x.State == EntityState.Added && x.Entity.Event == eventName))
            { if (!lost) throw new DbUpdateException("Synthetic retention rollback"); armed = true; }
            return ValueTask.FromResult(result);
        }
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData e, CancellationToken ct = default)
        { if (armed) throw new IOException("Synthetic lost retention commit acknowledgement"); return Task.CompletedTask; }
    }
}

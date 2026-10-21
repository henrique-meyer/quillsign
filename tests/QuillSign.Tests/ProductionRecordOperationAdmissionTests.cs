using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionRecordOperationAdmissionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private const string Receipt = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    [Fact]
    public async Task Acknowledgement_R0_preserves_full_enrolled_SQL_but_cannot_mint_any_hold_object_or_archive_scope()
    {
        var run = await Run.Create(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var inventory = new ProductionHoldSqlInventory(db, run.Keys, run.Clock);
        var sql = await inventory.CaptureAcknowledgementLockedAsync(run.Id, 0, null);
        Assert.True(sql.AcknowledgementOnly); Assert.Equal(0, sql.Revision); Assert.Null(sql.FenceHash);
        using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, run.Keys);
        Assert.Equal(0, plain.RootElement.GetProperty("Revision").GetInt64()); Assert.NotEmpty(ProductionRecordOperationAdmission.ContentDigest(sql, run.Keys));
        Assert.Throws<InvalidDataException>(() => ProductionHoldSqlInventory.OpenVerified(sql, run.Keys));
        Assert.Throws<InvalidDataException>(() => ProductionHoldObjectScope.FromVerified(sql, run.Keys, run.Clock));
        Assert.Throws<InvalidDataException>(() => ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql with { AcknowledgementOnly = false }, run.Keys));
        await Assert.ThrowsAsync<InvalidDataException>(() => inventory.CaptureLockedAsync(run.Id, 0, null!));
        await Assert.ThrowsAsync<InvalidDataException>(() => inventory.CaptureAcknowledgementLockedAsync(run.Id, 0, Receipt));
        await Assert.ThrowsAsync<InvalidDataException>(() => inventory.CaptureAcknowledgementLockedAsync(run.Id, 0, null, new(MaximumRows: 1)));
    }

    [Fact]
    public async Task Positive_acknowledgement_is_not_positive_archive_authority_and_full_request_rows_remain_bound()
    {
        var run = await Run.Create(fixture); var command = ProductionHoldWitnessJournalTests.Place(run.Id);
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var requests = await new ProductionHoldRequests(db, run.Keys, run.Clock).PrepareLockedAsync(
            ProductionHoldWitnessJournalTests.Authority(run.Clock, command.Permission), ProductionHoldWitnessJournalTests.Operators, command);
        var inventory = new ProductionHoldSqlInventory(db, run.Keys, run.Clock);
        var ack = await inventory.CaptureAcknowledgementLockedAsync(run.Id, requests.Current.Revision, requests.Current.FenceHash);
        var positive = await inventory.CaptureLockedAsync(run.Id, requests.Current.Revision, requests.Current.FenceHash!);
        Assert.Equal(positive.StateSha256, ack.StateSha256); Assert.NotEqual(positive.PayloadSha256, ack.PayloadSha256);
        Assert.Equal(ProductionRecordOperationAdmission.ContentDigest(positive, run.Keys), ProductionRecordOperationAdmission.ContentDigest(ack, run.Keys));
        using var full = ProductionHoldSqlInventory.OpenAcknowledgementVerified(ack, run.Keys);
        Assert.Single(full.RootElement.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == "ProductionHoldRequests").GetProperty("Rows").EnumerateArray());
        Assert.Throws<InvalidDataException>(() => ProductionHoldObjectScope.FromVerified(ack, run.Keys, run.Clock));
        await Assert.ThrowsAsync<InvalidDataException>(() => ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(db, run.Keys, run.Clock, command.HoldId, ack));
        Assert.NotNull(await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(db, run.Keys, run.Clock, command.HoldId, positive));
    }

    [Fact]
    public async Task Fresh_baseline_is_exact_idempotent_restart_safe_and_does_not_authorize_legacy_unknown_history()
    {
        var run = await Run.Create(fixture); var initialized = await run.Gate().InitializeAsync(run.Id);
        Assert.True(initialized.Initialized); Assert.Equal(1, initialized.Sequence); Assert.False(initialized.Frozen);
        Assert.Equal(initialized.HeadHash, (await run.Gate().InitializeAsync(run.Id)).HeadHash);
        Assert.Single(run.Store.Rows);
        await using var db = fixture.Open(); await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Message, "Unknown old SQL state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().InitializeAsync(run.Id));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "sender/edit", "synthetic-reference"));
        Assert.Single(run.Store.Rows);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Authorized_request_acknowledgement_never_mislabels_old_R0_full_fingerprint_as_current(bool fullHash)
    {
        var run = await Run.Create(fixture); var initialized = await run.Gate().InitializeAsync(run.Id);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Journal().ReserveAsync(run.Id, Guid.NewGuid(), Guid.NewGuid(), new(0, null, [])));
        var command = ProductionHoldWitnessJournalTests.Place(run.Id); var authority = ProductionHoldWitnessJournalTests.Authority(run.Clock, command.Permission);
        await run.Journal().IntentAsync(authority, ProductionHoldWitnessJournalTests.Operators, command, Guid.NewGuid());
        ProductionHoldRequestReceipt receipt; ProductionHoldSqlSnapshot snapshot;
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            receipt = await new ProductionHoldRequests(db, run.Keys, run.Clock).PrepareLockedAsync(authority, ProductionHoldWitnessJournalTests.Operators, command);
            snapshot = await new ProductionHoldSqlInventory(db, run.Keys, run.Clock).CaptureAcknowledgementLockedAsync(run.Id, receipt.Current.Revision, receipt.Current.FenceHash);
            await tx.CommitAsync();
        }
        var acknowledged = await run.Journal().AcceptSqlAsync(command, receipt, ProductionRecordOperationAdmission.ContentDigest(snapshot, run.Keys), Guid.NewGuid(),
            sqlStateSha256: fullHash ? snapshot.StateSha256 : null);
        Assert.NotEqual(initialized.SqlStateSha256, snapshot.StateSha256);
        Assert.Equal(fullHash ? snapshot.StateSha256 : null, acknowledged.SqlStateSha256);
        Assert.Equal(initialized.BusinessStateSha256, acknowledged.BusinessStateSha256);
        Assert.Equal(1, acknowledged.RequestRevision); Assert.True(acknowledged.Frozen);
    }

    [Theory]
    [InlineData("leased")][InlineData("attempted")][InlineData("submitted")][InlineData("verified")][InlineData("old-audit")][InlineData("unknown-witness")]
    public async Task Initial_baseline_refuses_old_or_inflight_work_instead_of_forgetting_possible_provider_writes(string fault)
    {
        var run = await Run.Create(fixture);
        await using (var db = fixture.Open())
        {
            if (fault == "leased") await db.WorkItems.Where(x => x.Id == run.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, WorkStatus.Leased)
                .SetProperty(w => w.LeaseOwner, Guid.NewGuid()).SetProperty(w => w.LeaseExpiresAt, run.Clock.Now.AddMinutes(5)));
            if (fault == "attempted") await db.WorkItems.Where(x => x.Id == run.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Attempts, 1));
            if (fault == "submitted") await db.EmailOutbox.Where(x => x.Id == run.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.SubmissionStartedAt, run.Clock.Now));
            if (fault == "verified") await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.SenderVerifiedAt, run.Clock.Now));
            if (fault == "old-audit")
            { await using var tx = await db.Database.BeginTransactionAsync(); await new AuditWriter(db, run.Clock).AppendAsync(run.Id, "old-unwitnessed-mutation", null, null, null, default, "{}", PartyType.System); await tx.CommitAsync(); }
        }
        if (fault == "unknown-witness")
        {
            var command = ProductionHoldWitnessJournalTests.Place(run.Id);
            await run.Journal().IntentAsync(ProductionHoldWitnessJournalTests.Authority(run.Clock, command.Permission), ProductionHoldWitnessJournalTests.Operators, command, Guid.NewGuid());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().InitializeAsync(run.Id));
        Assert.Equal(fault == "unknown-witness" ? 1 : 0, run.Store.Rows.Count);
    }

    [Theory]
    [InlineData("initialize")][InlineData("reserve")][InlineData("settle")]
    public async Task Lost_external_acknowledgement_recovers_exact_original_event_without_duplicate_authority(string phase)
    {
        var run = await Run.Create(fixture); var op = Guid.NewGuid(); ProductionRecordOperation? scope = null;
        if (phase == "initialize")
        {
            run.Store.LostAck = true; await Assert.ThrowsAsync<IOException>(() => run.Gate().InitializeAsync(run.Id));
            var bytes = run.Store.Rows[0].ProtectedPayload.ToArray(); run.Clock.Now = run.Clock.Now.AddMinutes(1);
            await run.Gate().InitializeAsync(run.Id); Assert.Equal(bytes, run.Store.Rows[0].ProtectedPayload); Assert.Single(run.Store.Rows); return;
        }
        await run.Gate().InitializeAsync(run.Id);
        if (phase == "reserve")
        {
            run.Store.LostAck = true; await Assert.ThrowsAsync<IOException>(() => run.Gate().BeginAsync(run.Id, op, "work/0", run.Work.ToString("N")));
            scope = await run.Gate().ResumeAsync(run.Id, op, "work/0", run.Work.ToString("N"));
            Assert.Equal(scope, await run.Gate().BeginAsync(run.Id, op, "work/0", run.Work.ToString("N"))); Assert.Equal(2, run.Store.Rows.Count);
        }
        else
        {
            scope = await run.Gate().BeginAsync(run.Id, op, "work/0", run.Work.ToString("N"));
            await run.Edit("Verified committed operation outcome"); run.Store.LostAck = true;
            await Assert.ThrowsAsync<IOException>(() => run.Gate().CompleteAsync(scope, Receipt));
            var bytes = run.Store.Rows[^1].ProtectedPayload.ToArray(); run.Clock.Now = run.Clock.Now.AddMinutes(1);
            var resumed = await run.Gate().ResumeAsync(run.Id, op, "work/0", run.Work.ToString("N"));
            Assert.Equal(scope, resumed); Assert.Equal(Receipt, (await run.Gate().CompleteAsync(resumed, Receipt)).SettledOperations[op]);
            Assert.Equal(bytes, run.Store.Rows[^1].ProtectedPayload); Assert.Equal(3, run.Store.Rows.Count);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().DemandAsync(resumed));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().CompleteAsync(resumed, new string('a', 64)));
        }
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Concurrent_exact_or_distinct_admissions_have_one_durable_outstanding_operation(bool same)
    {
        var run = await Run.Create(fixture); await run.Gate().InitializeAsync(run.Id); var a = Guid.NewGuid(); var b = same ? a : Guid.NewGuid();
        async Task<Exception?> Attempt(Guid id) => await Record.ExceptionAsync(() => run.Gate().BeginAsync(run.Id, id, "work/0", run.Work.ToString("N")));
        var errors = await Task.WhenAll(Attempt(a), Attempt(b));
        Assert.Equal(same ? 0 : 1, errors.Count(x => x is not null));
        var state = await run.Journal().ReadAsync(run.Id); Assert.Equal(2, state.Sequence); Assert.NotNull(state.OutstandingOperation);
        Assert.Single(state.Operations!); Assert.Equal(2, run.Store.Rows.Count);
    }

    [Fact]
    public async Task Only_original_typed_scope_drains_pending_hold_and_no_clock_or_lease_expiry_settles_it()
    {
        var run = await Run.Create(fixture); await run.Gate().InitializeAsync(run.Id);
        var scope = await run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "work/0", run.Work.ToString("N"));
        var command = ProductionHoldWitnessJournalTests.Place(run.Id);
        await run.Journal().IntentAsync(ProductionHoldWitnessJournalTests.Authority(run.Clock, command.Permission), ProductionHoldWitnessJournalTests.Operators, command, Guid.NewGuid());
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "work/0", run.Work.ToString("N")));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().ResumeAsync(run.Id, scope.OperationId, "work/1", run.Work.ToString("N")));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().DemandAsync(scope with { Reference = "foreign-reference" }));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Journal().AcceptSqlAsync(command, new(command.CommandId, 1,
            new(1, Receipt, [new(command.HoldId, command.CommandId, null, ProductionHoldPendingState.PreservationPending)])), Receipt, Guid.NewGuid()));
        await run.Edit("Own admitted SQL edit may differ during its operation"); run.Clock.Now = run.Clock.Now.AddDays(2);
        await run.Gate().DemandAsync(scope); Assert.Equal(scope.OperationId, (await run.Journal().ReadAsync(run.Id)).OutstandingOperation);
        var done = await run.Gate().CompleteAsync(scope, Receipt);
        Assert.Null(done.OutstandingOperation); Assert.Equal(command, done.Unacknowledged); Assert.True(done.Frozen);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().DemandAsync(scope));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "work/0", run.Work.ToString("N")));
    }

    [Fact]
    public async Task Demand_does_not_recapture_work_under_its_callers_row_lock_and_complete_requires_committed_SQL()
    {
        var run = await Run.Create(fixture); await run.Gate().InitializeAsync(run.Id);
        var scope = await run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "work/0", run.Work.ToString("N"));
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            _ = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={run.Work}").SingleAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5)); await run.Gate().DemandAsync(scope, timeout.Token);
            await db.WorkItems.Where(x => x.Id == run.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, WorkStatus.Completed));
            await tx.CommitAsync();
        }
        var done = await run.Gate().CompleteAsync(scope, Receipt); Assert.Equal(Receipt, done.SettledOperations[scope.OperationId]);
        var next = await run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "sender/edit", "synthetic-next"); await run.Gate().DemandAsync(next);
    }

    [Fact]
    public async Task SQL_rollback_or_restored_older_rows_do_not_reopen_unknown_operation_or_erase_current_acknowledgement()
    {
        var run = await Run.Create(fixture); await run.Gate().InitializeAsync(run.Id);
        var scope = await run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "sender/edit", "synthetic-reference");
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Message, "Rolled back transaction"));
            await tx.RollbackAsync();
        }
        Assert.Equal(scope.OperationId, (await run.Journal().ReadAsync(run.Id)).OutstandingOperation); await run.Gate().DemandAsync(scope);
        await run.Edit("Committed verified outcome"); await run.Gate().CompleteAsync(scope, Receipt);
        await run.Edit(null); // Simulated older restored business value; even a new SQL rowversion cannot pass the saved content binding.
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "sender/edit", "next-reference"));
        Assert.Null((await run.Journal().ReadAsync(run.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task Released_external_control_prefix_rejects_older_control_SQL_even_when_business_and_request_head_match()
    {
        var run = await Run.Create(fixture, work: false); await run.Gate().InitializeAsync(run.Id);
        var placement = ProductionHoldWitnessJournalTests.Place(run.Id); var authority = ProductionHoldWitnessJournalTests.Authority(run.Clock, placement.Permission);
        await run.Journal().IntentAsync(authority, ProductionHoldWitnessJournalTests.Operators, placement, Guid.NewGuid());
        ProductionHoldProtectedPlan plan; ProductionHoldControlPrefix prefix;
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            var receipt = await new ProductionHoldRequests(db, run.Keys, run.Clock).PrepareLockedAsync(authority, ProductionHoldWitnessJournalTests.Operators, placement);
            var inventory = await new ProductionHoldObjectInventory(db, run.Keys, run.Clock, new EmptySources()).CaptureLockedAsync(run.Id, 1, receipt.Current.FenceHash!);
            plan = await ProductionHoldBundlePlan.FreezeLockedAsync(db, run.Keys, run.Clock, placement.HoldId, Guid.NewGuid(), inventory);
            var controls = new ProductionHoldControls(db, run.Keys, run.Clock); await controls.SavePlanLockedAsync(plan); prefix = (await controls.ReadLockedAsync(run.Id)).Prefix;
            await tx.CommitAsync();
            await run.Journal().AcceptSqlAsync(placement, receipt, ProductionRecordOperationAdmission.ContentDigest(inventory.Sql, run.Keys), Guid.NewGuid(), sqlStateSha256: inventory.Sql.StateSha256);
        }
        // Synthetic journal transitions test SQL-prefix admission only; this is
        // deliberately not provider preservation/release acceptance evidence.
        var preserve = Guid.NewGuid(); await run.Journal().ReservePreservationAsync(placement, plan.PlanId, preserve, Guid.NewGuid());
        await run.Journal().FreezePlanAsync(placement, plan.PlanId, plan.Sha256, prefix, preserve, Guid.NewGuid());
        await run.Journal().PreserveAsync(placement, plan.PlanId, plan.Sha256, Receipt, prefix, preserve, Guid.NewGuid());
        var release = placement with { CommandId = Guid.NewGuid(), ExpectedRevision = 1, Operation = ProductionHoldOperation.Release };
        var releaseAuthority = ProductionHoldWitnessJournalTests.Authority(run.Clock, release.Permission);
        await run.Journal().IntentAsync(releaseAuthority, ProductionHoldWitnessJournalTests.Operators, release, Guid.NewGuid());
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            var receipt = await new ProductionHoldRequests(db, run.Keys, run.Clock).PrepareLockedAsync(releaseAuthority, ProductionHoldWitnessJournalTests.Operators, release);
            var ack = await new ProductionHoldSqlInventory(db, run.Keys, run.Clock).CaptureAcknowledgementLockedAsync(run.Id, 2, receipt.Current.FenceHash);
            await tx.CommitAsync(); await run.Journal().AcceptSqlAsync(release, receipt, ProductionRecordOperationAdmission.ContentDigest(ack, run.Keys), Guid.NewGuid(), sqlStateSha256: ack.StateSha256);
        }
        var releasing = Guid.NewGuid(); await run.Journal().ReserveReleaseAsync(release, releasing, Guid.NewGuid());
        await run.Journal().ReleaseAsync(release, Receipt, prefix, releasing, Guid.NewGuid());
        await using (var db = fixture.Open()) await db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM [ProductionHoldControls] WHERE [EnvelopeId]={run.Id}");
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "sender/edit", "synthetic-reference"));
    }

    [Theory]
    [InlineData("")][InlineData("invalid kind")][InlineData("work/0\n")]
    public async Task Unbounded_or_noncanonical_operation_tuple_never_appends(string kind)
    {
        var run = await Run.Create(fixture); await run.Gate().InitializeAsync(run.Id);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginAsync(run.Id, Guid.NewGuid(), kind, run.Work.ToString("N")));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginAsync(run.Id, Guid.NewGuid(), "work/0", new string('x', 513)));
        Assert.Single(run.Store.Rows);
    }

    private sealed class Run(SqlDatabaseFixture fixture)
    {
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider();
        internal readonly ProductionHoldWitnessJournalTests.Clock Clock = new();
        internal readonly ProductionHoldWitnessJournalTests.Store Store = new();
        internal Guid Id, Work;
        internal ProductionHoldWitnessJournal Journal() => new(Store, Keys, Clock, ProductionHoldWitnessJournalTests.Installation);
        internal ProductionRecordOperationAdmission Gate() => new(fixture.Open, Keys, Clock, Journal());
        internal static async Task<Run> Create(SqlDatabaseFixture fixture, bool work = true)
        {
            var run = new Run(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var e = new Envelope { SenderEmail = "synthetic-operation@example.invalid", CreatedAt = run.Clock.Now };
            db.Add(e); await new ProductionRetentionLedger(db, new(db, run.Clock), run.Clock).PrepareNewLockedAsync(e, ProductionRetentionLedgerTests.Policy());
            run.Id = e.Id; run.Work = Guid.NewGuid();
            if (work) db.AddRange(new WorkItem { Id = run.Work, EnvelopeId = e.Id, Kind = WorkKind.Email, Status = WorkStatus.Queued, AvailableAt = run.Clock.Now },
                new EmailOutbox { Id = run.Work, EnvelopeId = e.Id, To = e.SenderEmail, Template = "sender-verification", AvailableAt = run.Clock.Now });
            await db.SaveChangesAsync(); await tx.CommitAsync(); return run;
        }
        internal async Task Edit(string? value)
        { await using var db = fixture.Open(); await db.Envelopes.Where(x => x.Id == Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Message, value)); }
    }
    private sealed class EmptySources : IProductionHoldObjectSource
    {
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct) => Task.FromResult(new HoldObjectPage([], null));
        public Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress address, CancellationToken ct) => throw new InvalidOperationException();
    }
}

using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;
using QuillSign.Lifecycle;
using Run = QuillSign.Tests.ProductionRecordOperationAdmissionTests.Run;

namespace QuillSign.Tests;

public sealed class ProductionRecordDispatchAdmissionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private const string Receipt = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    [Fact]
    public async Task Fresh_dispatch_requires_committed_exact_SQL_once_and_receipt_transaction_before_final_seal()
    {
        var run = await Ready(fixture); await using var db = fixture.Open(); ProductionRecordDispatchPermit permit;
        var prefix = run.Seed.Store.Rows.Select(x => x.ProtectedPayload.ToArray()).ToArray();
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await Stage(db, run); permit = await run.Gate.PrepareDispatchLockedAsync(db, run.Scope);
            Assert.Equal(run.Seed.Id, permit.RecordId);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(db, permit));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandDispatchReceiptLockedAsync(db, permit));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope));
            await tx.CommitAsync();
        }
        for (var i = 0; i < prefix.Length; i++) Assert.Equal(prefix[i], run.Seed.Store.Rows[i].ProtectedPayload);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandAsync(run.Scope));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ResumeAsync(run.Seed.Id, run.Scope.OperationId, run.Scope.Kind, run.Scope.Reference));
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await run.Gate.ConsumeDispatchLockedAsync(db, permit);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(db, permit));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandDispatchReceiptLockedAsync(db, permit));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope));
            await tx.RollbackAsync();
        }
        // A fixture-owned synthetic provider result is accepted only through the
        // receipt boundary. The kernel itself neither sends mail nor invents it.
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await run.Gate.DemandDispatchReceiptLockedAsync(db, permit);
            Assert.Equal(run.Scope, await run.Gate.ResumeLockedAsync(db, run.Seed.Id, run.Scope.OperationId, run.Scope.Kind, run.Scope.Reference));
            await db.EmailOutbox.Where(x => x.Id == run.Seed.Work).ExecuteUpdateAsync(x => x.SetProperty(e => e.Provider, "synthetic-local")
                .SetProperty(e => e.ProviderMessageId, "captured-synthetic-receipt").SetProperty(e => e.Status, EmailStatus.Sent));
            await run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope); await tx.CommitAsync();
        }
        var sealedState = await run.Seed.Journal().ReadAsync(run.Seed.Id);
        Assert.Single(sealedState.DispatchStarts!); Assert.Single(sealedState.HandlerOutcomes!); Assert.Empty(sealedState.Outcomes!);
        await using (var finish = fixture.Open())
        {
            await using var tx = await finish.Database.BeginTransactionAsync();
            await run.Seed.Gate().DemandHandlerOutcomeLockedAsync(finish, run.Scope);
            // Use one kernel for the ordinary finalization read/prepare pair.
            var finalizer = run.Seed.Gate(); await finalizer.DemandHandlerOutcomeLockedAsync(finish, run.Scope);
            await finish.WorkItems.Where(x => x.Id == run.Seed.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, WorkStatus.Completed)
                .SetProperty(w => w.LeaseOwner, (Guid?)null).SetProperty(w => w.LeaseExpiresAt, (DateTimeOffset?)null));
            await finalizer.PrepareOutcomeLockedAsync(finish, run.Scope); await tx.CommitAsync();
        }
        Assert.Equal(Receipt, (await run.Seed.Gate().CompleteAsync(run.Scope, Receipt)).SettledOperations[run.Scope.OperationId]);
        Assert.Equal(Receipt, (await run.Seed.Gate().CompleteAsync(run.Scope, Receipt)).SettledOperations[run.Scope.OperationId]);
        Assert.Equal(6, run.Seed.Store.Rows.Count); // baseline, reserve, start, handler, final outcome, settlement
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Rolled_back_or_unknown_dispatch_checkpoint_never_reissues_a_permit(bool lostAcknowledgement)
    {
        var run = await Ready(fixture); await using var db = fixture.Open();
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await Stage(db, run); run.Seed.Store.LostAck = lostAcknowledgement;
            if (lostAcknowledgement) await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareDispatchLockedAsync(db, run.Scope));
            else _ = await run.Gate.PrepareDispatchLockedAsync(db, run.Scope);
            await tx.RollbackAsync();
        }
        var state = await run.Seed.Journal().ReadAsync(run.Seed.Id); var marker = Assert.Single(state.DispatchStarts!);
        var bytes = run.Seed.Store.Rows[^1].ProtectedPayload.ToArray(); run.Seed.Clock.Now = run.Seed.Clock.Now.AddSeconds(1);
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await Stage(db, run);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareDispatchLockedAsync(db, run.Scope));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Seed.Gate().PrepareDispatchLockedAsync(db, run.Scope));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope));
            await tx.RollbackAsync();
        }
        Assert.Equal(bytes, run.Seed.Store.Rows[^1].ProtectedPayload); Assert.Equal(marker.Value, (await run.Seed.Journal().ReadAsync(run.Seed.Id)).DispatchStarts![run.Scope.OperationId]);
        Assert.Equal(3, run.Seed.Store.Rows.Count); Assert.Empty(state.HandlerOutcomes!); Assert.Empty(state.Outcomes!); Assert.Empty(state.SettledOperations);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(run.Scope, Receipt));
    }

    [Fact]
    public async Task Permit_cannot_move_to_another_context_kernel_or_forged_identity_and_consumption_is_once_only()
    {
        var run = await Ready(fixture); await using var db = fixture.Open(); var permit = await PrepareCommitted(db, run);
        await using (var foreign = fixture.Open())
        {
            await using var tx = await foreign.Database.BeginTransactionAsync();
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(foreign, permit));
            await tx.RollbackAsync();
        }
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Seed.Gate().ConsumeDispatchLockedAsync(db, permit));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(db, new(run.Seed.Id)));
            await run.Gate.ConsumeDispatchLockedAsync(db, permit);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(db, permit)); await tx.RollbackAsync();
        }
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await run.Gate.DemandDispatchReceiptLockedAsync(db, permit);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandDispatchReceiptLockedAsync(db, permit)); await tx.RollbackAsync();
        }
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope)); await tx.RollbackAsync();
        }
        Assert.Empty((await run.Seed.Journal().ReadAsync(run.Seed.Id)).HandlerOutcomes!);
    }

    [Theory]
    [InlineData("payload")]
    [InlineData("token")]
    [InlineData("lease")]
    [InlineData("other-business")]
    [InlineData("expired")]
    public async Task Exact_intended_SQL_and_original_lease_are_rechecked_before_once_only_consumption(string change)
    {
        var run = await Ready(fixture); await using var db = fixture.Open(); var permit = await PrepareCommitted(db, run);
        if (change == "expired") run.Seed.Clock.Now = run.Seed.Clock.Now.AddMinutes(6);
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            if (change == "payload") await db.EmailOutbox.Where(x => x.Id == run.Seed.Work).ExecuteUpdateAsync(x => x.SetProperty(e => e.PayloadJson, "{\"changed\":true}"));
            if (change == "token") await db.AuthTokens.Where(x => x.Id == run.Token).ExecuteUpdateAsync(x => x.SetProperty(t => t.TokenSha256, new byte[32]));
            if (change == "lease") await db.WorkItems.Where(x => x.Id == run.Seed.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.LeaseExpiresAt, run.Seed.Clock.Now.AddMinutes(7)));
            if (change == "other-business") await db.Envelopes.Where(x => x.Id == run.Seed.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Message, "changed-owned-history"));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(db, permit)); await tx.RollbackAsync();
        }
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(db, permit)); await tx.RollbackAsync();
        }
        Assert.Empty((await run.Seed.Journal().ReadAsync(run.Seed.Id)).HandlerOutcomes!);
    }

    [Fact]
    public async Task Receipt_readback_rejects_restored_or_changed_pre_submission_SQL_before_any_receipt_edit()
    {
        var run = await Ready(fixture); await using var db = fixture.Open(); var permit = await PrepareCommitted(db, run);
        await using (var tx = await db.Database.BeginTransactionAsync()) { await run.Gate.ConsumeDispatchLockedAsync(db, permit); await tx.RollbackAsync(); }
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await db.EmailOutbox.Where(x => x.Id == run.Seed.Work).ExecuteUpdateAsync(x => x.SetProperty(e => e.SubmissionStartedAt, (DateTimeOffset?)null));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandDispatchReceiptLockedAsync(db, permit));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope)); await tx.RollbackAsync();
        }
        await using var check = fixture.Open(); Assert.Null((await check.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == run.Seed.Work)).ProviderMessageId);
        Assert.Empty((await run.Seed.Journal().ReadAsync(run.Seed.Id)).HandlerOutcomes!);
    }

    [Fact]
    public async Task Whole_database_restore_to_the_same_live_lease_cannot_reissue_unknown_provider_dispatch()
    {
        var isolated = new SqlDatabaseFixture(); await isolated.InitializeAsync(); string? backup = null;
        try
        {
            var run = await Ready(isolated); string connection;
            await using (var db = isolated.Open()) connection = db.Database.GetConnectionString()!;
            var builder = new SqlConnectionStringBuilder(connection); var name = builder.InitialCatalog;
            Assert.Matches("^QuillSignTests_[a-f0-9]{32}$", name); builder.InitialCatalog = "master"; builder.Pooling = false;
            await using var master = new SqlConnection(builder.ConnectionString); await master.OpenAsync();
            await using var command = master.CreateCommand(); command.CommandTimeout = 120;
            command.CommandText = "SELECT CONVERT(nvarchar(4000),SERVERPROPERTY('InstanceDefaultBackupPath'))";
            var directory = Assert.IsType<string>(await command.ExecuteScalarAsync()); Assert.False(string.IsNullOrWhiteSpace(directory));
            backup = directory.TrimEnd('\\', '/') + (directory.Contains('\\') ? "\\" : "/") + name + "-dispatch.bak";
            command.CommandText = $"BACKUP DATABASE [{name}] TO DISK=@backup WITH COPY_ONLY, INIT";
            command.Parameters.AddWithValue("@backup", backup); await command.ExecuteNonQueryAsync();
            await using (var db = isolated.Open())
            {
                var permit = await PrepareCommitted(db, run);
                await using var tx = await db.Database.BeginTransactionAsync(); await run.Gate.ConsumeDispatchLockedAsync(db, permit); await tx.RollbackAsync();
            }
            var checkpoint = (await run.Seed.Journal().ReadAsync(run.Seed.Id)).DispatchStarts![run.Scope.OperationId];
            command.CommandText = $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; RESTORE DATABASE [{name}] FROM DISK=@backup WITH REPLACE; ALTER DATABASE [{name}] SET MULTI_USER";
            await command.ExecuteNonQueryAsync(); using (var pooled = new SqlConnection(connection)) SqlConnection.ClearPool(pooled);
            await using (var db = isolated.Open())
            {
                var saved = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == run.Seed.Work);
                Assert.Equal(run.Scope.OperationId, saved.LeaseOwner); Assert.Equal(1, saved.Attempts); Assert.Equal(WorkStatus.Leased, saved.Status);
                Assert.Equal(run.Deadline, saved.LeaseExpiresAt); Assert.True(saved.LeaseExpiresAt > run.Seed.Clock.Now);
                Assert.Null((await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == run.Seed.Work)).SubmissionStartedAt);
                await using var tx = await db.Database.BeginTransactionAsync();
                await Assert.ThrowsAsync<InvalidDataException>(() => run.Seed.Gate().ResumeLockedAsync(db, run.Seed.Id, run.Scope.OperationId, run.Scope.Kind, run.Scope.Reference));
                await Stage(db, run);
                await Assert.ThrowsAsync<InvalidDataException>(() => run.Seed.Gate().PrepareDispatchLockedAsync(db, run.Scope)); await tx.RollbackAsync();
            }
            Assert.Equal(checkpoint, (await run.Seed.Journal().ReadAsync(run.Seed.Id)).DispatchStarts![run.Scope.OperationId]);
            Assert.Equal(3, run.Seed.Store.Rows.Count); Assert.Empty((await run.Seed.Journal().ReadAsync(run.Seed.Id)).HandlerOutcomes!);
        }
        finally { await isolated.DisposeAsync(); if (backup is not null && File.Exists(backup)) File.Delete(backup); }
    }

    [Fact]
    public async Task Relabeling_the_same_uncommitted_physical_transaction_cannot_consume_provider_permission()
    {
        var run = await Ready(fixture); await using var db = fixture.Open();
        await using var original = await db.Database.BeginTransactionAsync(); await Stage(db, run);
        var permit = await run.Gate.PrepareDispatchLockedAsync(db, run.Scope); var native = original.GetDbTransaction();
        await db.Database.UseTransactionAsync(null);
        await using var alias = await db.Database.UseTransactionAsync(native, Guid.NewGuid());
        Assert.NotEqual(original.TransactionId, db.Database.CurrentTransaction!.TransactionId);
        Assert.Same(native, db.Database.CurrentTransaction.GetDbTransaction());
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(db, permit));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope));
        Assert.Empty((await run.Seed.Journal().ReadAsync(run.Seed.Id)).HandlerOutcomes!);
    }
    [Fact]
    public async Task Original_lease_expiring_during_the_final_async_checkpoint_read_never_returns_provider_permission()
    {
        CrossAfterRead? crossing = null;
        var run = await Ready(fixture, seed => {
            crossing = new(seed.Store, seed.Clock);
            return new(fixture.Open, seed.Keys, seed.Clock,
                new ProductionHoldWitnessJournal(crossing, seed.Keys, seed.Clock, ProductionHoldWitnessJournalTests.Installation));
        });
        await using var db = fixture.Open(); var permit = await PrepareCommitted(db, run); crossing!.Enabled = true;
        await using var tx = await db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ConsumeDispatchLockedAsync(db, permit));
        Assert.True(crossing.Crossed); Assert.True(run.Seed.Clock.Now >= run.Deadline);
        Assert.Empty((await run.Seed.Journal().ReadAsync(run.Seed.Id)).HandlerOutcomes!);
    }

    private sealed class CrossAfterRead(IProductionHoldWitnessStore inner, ProductionHoldWitnessJournalTests.Clock clock) : IProductionHoldWitnessStore
    {
        internal bool Enabled, Crossed; private int reads;
        public async Task<IReadOnlyList<ProductionHoldWitnessObject>> ReadAsync(Guid id, CancellationToken ct = default)
        {
            var result = await inner.ReadAsync(id, ct);
            if (Enabled && Interlocked.Increment(ref reads) == 2) { clock.Now = clock.Now.AddMinutes(6); Crossed = true; }
            return result;
        }
        public Task<ProductionHoldWitnessObject> CreateAsync(ProductionHoldWitnessWrite write, CancellationToken ct = default) => inner.CreateAsync(write, ct);
    }
    [Fact]
    public async Task Reusing_a_rolled_back_receipt_transaction_GUID_on_a_new_physical_transaction_cannot_seal_handler_outcome()
    {
        var run = await Ready(fixture); await using var db = fixture.Open(); var permit = await PrepareCommitted(db, run);
        await using (var tx = await db.Database.BeginTransactionAsync()) { await run.Gate.ConsumeDispatchLockedAsync(db, permit); await tx.RollbackAsync(); }
        Guid receiptId; System.Data.Common.DbTransaction receiptSql;
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await run.Gate.DemandDispatchReceiptLockedAsync(db, permit);
            receiptId = tx.TransactionId; receiptSql = tx.GetDbTransaction(); await tx.RollbackAsync();
        }
        await db.Database.OpenConnectionAsync();
        await using var replacement = await db.Database.GetDbConnection().BeginTransactionAsync();
        await using var alias = await db.Database.UseTransactionAsync(replacement, receiptId);
        Assert.Equal(receiptId, db.Database.CurrentTransaction!.TransactionId);
        Assert.NotSame(receiptSql, db.Database.CurrentTransaction.GetDbTransaction());
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ResumeLockedAsync(db, run.Seed.Id, run.Scope.OperationId, run.Scope.Kind, run.Scope.Reference));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope));
        Assert.Empty((await run.Seed.Journal().ReadAsync(run.Seed.Id)).HandlerOutcomes!);
        Assert.Empty((await run.Seed.Journal().ReadAsync(run.Seed.Id)).Outcomes!);
    }
    private sealed record DispatchRun(Run Seed, ProductionRecordOperationAdmission Gate, ProductionRecordOperation Scope, Guid Token, DateTimeOffset Deadline);
    private static async Task<DispatchRun> Ready(SqlDatabaseFixture fixture, Func<Run, ProductionRecordOperationAdmission>? create = null)
    {
        var seed = await Run.Create(fixture); var gate = create?.Invoke(seed) ?? seed.Gate(); await gate.InitializeAsync(seed.Id); var owner = Guid.NewGuid();
        var scope = await gate.BeginAsync(seed.Id, owner, "work/" + ((int)WorkKind.Email).ToString(CultureInfo.InvariantCulture), seed.Work.ToString("N") + "/attempt/1");
        var deadline = seed.Clock.Now.AddMinutes(5);
        await using var db = fixture.Open();
        await db.WorkItems.Where(x => x.Id == seed.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, WorkStatus.Leased)
            .SetProperty(w => w.Attempts, 1).SetProperty(w => w.LeaseOwner, owner).SetProperty(w => w.LeaseExpiresAt, deadline));
        return new(seed, gate, scope, Guid.NewGuid(), deadline);
    }
    private static async Task Stage(QuillSignDbContext db, DispatchRun run)
    {
        db.ChangeTracker.Clear(); // A prior synthetic transaction may have rolled back its tracked token.
        await db.EmailOutbox.Where(x => x.Id == run.Seed.Work).ExecuteUpdateAsync(x => x.SetProperty(e => e.SubmissionStartedAt, run.Seed.Clock.Now).SetProperty(e => e.Attempts, 1));
        if (!await db.AuthTokens.AnyAsync(x => x.Id == run.Token))
        {
            db.AuthTokens.Add(new AuthToken { Id = run.Token, EnvelopeId = run.Seed.Id, Purpose = TokenPurpose.SenderVerify,
                PartyType = PartyType.Sender, Email = "synthetic-operation@example.invalid", TokenSha256 = SHA256.HashData(run.Token.ToByteArray()), ExpiresAt = run.Seed.Clock.Now.AddMinutes(15) });
            await db.SaveChangesAsync();
        }
    }
    private static async Task<ProductionRecordDispatchPermit> PrepareCommitted(QuillSignDbContext db, DispatchRun run)
    {
        await using var tx = await db.Database.BeginTransactionAsync(); await Stage(db, run);
        var permit = await run.Gate.PrepareDispatchLockedAsync(db, run.Scope); await tx.CommitAsync(); return permit;
    }
}
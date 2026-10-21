using System.Data.Common;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Lifecycle;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRecordHandlerOutcomeTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Handler_checkpoint_then_exact_same_transaction_finalizer_drains_pending_hold_without_provider_replay()
    {
        var run = await Run.Create(fixture); await run.Handle();
        var command = Place(run.Record.Id);
        await run.Record.Journal().IntentAsync(Authority(run.Record.Clock, command.Permission), Operators, command, Guid.NewGuid());
        await run.Finish(); var state = await run.Gate.CompleteAsync(run.Scope, Hash);
        Assert.Equal(Hash, state.SettledOperations[run.Scope.OperationId]); Assert.Null(state.OutstandingOperation); Assert.Equal(command, state.Unacknowledged);
        Assert.True(state.Outcomes![run.Scope.OperationId].Sequence > state.HandlerOutcomes![run.Scope.OperationId].Sequence);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandAsync(run.Scope));
    }

    [Fact]
    public async Task Handler_seal_allows_receipt_only_resume_and_disables_all_provider_or_starting_admission()
    {
        var run = await Run.Create(fixture); await run.Handle();
        Assert.Equal(run.Scope, await run.Gate.ResumeAsync(run.Record.Id, run.Scope.OperationId, run.Scope.Kind, run.Scope.Reference));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandAsync(run.Scope));
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandLockedAsync(db, run.Scope));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandStartingLockedAsync(db, run.Scope));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ResumeLockedAsync(db, run.Record.Id, run.Scope.OperationId, run.Scope.Kind, run.Scope.Reference));
        await tx.RollbackAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(run.Scope, Hash));
        Assert.Empty((await run.Record.Journal().ReadAsync(run.Record.Id)).Outcomes!);
    }

    [Fact]
    public async Task Missing_handler_checkpoint_refuses_same_context_resume_without_new_connection_or_self_deadlock()
    {
        var run = await Run.Create(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={run.Record.Id}").SingleAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ResumeHandlerLockedAsync(db, run.Record.Id,
            run.Scope.OperationId, run.Scope.Kind, run.Scope.Reference, timeout.Token));
        Assert.Equal(run.Scope.OperationId, (await run.Record.Journal().ReadAsync(run.Record.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task Lost_handler_checkpoint_acknowledgement_only_replays_identical_bytes_before_commit()
    {
        var run = await Run.Create(fixture); await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync(); await run.HandlerWrites(db);
            run.Record.Store.LostAck = true;
            await Assert.ThrowsAsync<IOException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope));
            var bytes = run.Record.Store.Rows[^1].ProtectedPayload.ToArray();
            await run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope); Assert.Equal(bytes, run.Record.Store.Rows[^1].ProtectedPayload);
            await db.Envelopes.Where(x => x.Id == run.Record.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Message, "Different handler fork"));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope));
            await tx.RollbackAsync();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(run.Scope, Hash));
        Assert.Single((await run.Record.Journal().ReadAsync(run.Record.Id)).HandlerOutcomes!);
    }

    [Fact]
    public async Task Lost_handler_SQL_commit_acknowledgement_requires_exact_checkpoint_readback_then_final_finish()
    {
        var run = await Run.Create(fixture); string connection;
        await using (var source = fixture.Open()) connection = source.Database.GetConnectionString()!;
        await using (var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
        {
            await using var tx = await db.Database.BeginTransactionAsync(); await run.HandlerWrites(db);
            await run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope); await Assert.ThrowsAsync<IOException>(() => tx.CommitAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandAsync(run.Scope));
        await run.Finish(); Assert.Equal(Hash, (await run.Gate.CompleteAsync(run.Scope, Hash)).SettledOperations[run.Scope.OperationId]);
    }

    [Theory]
    [InlineData("new-context")][InlineData("new-transaction")][InlineData("fork-scope")][InlineData("different-kernel")]
    public async Task Handler_finalization_permit_is_bound_to_exact_context_transaction_scope_and_kernel(string fault)
    {
        var run = await Run.Create(fixture); await run.Handle();
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        await run.Gate.DemandHandlerOutcomeLockedAsync(db, run.Scope);
        if (fault == "new-context")
        {
            await tx.RollbackAsync(); await using var other = fixture.Open(); await using var otherTx = await other.Database.BeginTransactionAsync();
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(other, run.Scope));
        }
        if (fault == "new-transaction")
        {
            await tx.RollbackAsync(); await tx.DisposeAsync(); await using var otherTx = await db.Database.BeginTransactionAsync();
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, run.Scope));
        }
        if (fault == "fork-scope") await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, run.Scope with { OperationId = Guid.NewGuid() }));
        if (fault == "different-kernel") await Assert.ThrowsAsync<InvalidDataException>(() => run.Record.Gate().PrepareOutcomeLockedAsync(db, run.Scope));
        Assert.Empty((await run.Record.Journal().ReadAsync(run.Record.Id)).Outcomes!);
    }

    [Fact]
    public async Task Final_outcome_cannot_be_sealed_without_first_authenticating_current_handler_state()
    {
        var run = await Run.Create(fixture); await run.Handle(); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        await run.FinishWrites(db);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, run.Scope));
        await tx.RollbackAsync(); await run.Finish(); await run.Gate.CompleteAsync(run.Scope, Hash);
    }

    [Fact]
    public async Task Handler_noop_checkpoint_still_requires_final_bookkeeping_seal_and_never_uses_original_noop_fallback()
    {
        var run = await Run.Create(fixture); await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync(); await run.Gate.PrepareHandlerOutcomeLockedAsync(db, run.Scope); await tx.CommitAsync();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(run.Scope, Hash));
        await run.Finish(); Assert.Equal(Hash, (await run.Gate.CompleteAsync(run.Scope, Hash)).SettledOperations[run.Scope.OperationId]);
    }

    [Fact]
    public async Task Actual_database_restore_after_claim_and_handler_commit_preserves_exact_lease_but_cannot_erase_handler_effects_and_finish()
    {
        var isolated = new SqlDatabaseFixture(); await isolated.InitializeAsync(); string? backup = null;
        try
        {
            var run = await Run.Create(isolated); string connection;
            await using (var db = isolated.Open()) connection = db.Database.GetConnectionString()!;
            var builder = new SqlConnectionStringBuilder(connection); var name = builder.InitialCatalog;
            Assert.Matches("^QuillSignTests_[a-f0-9]{32}$", name); builder.InitialCatalog = "master"; builder.Pooling = false;
            await using var master = new SqlConnection(builder.ConnectionString); await master.OpenAsync();
            await using var command = master.CreateCommand(); command.CommandTimeout = 120;
            command.CommandText = "SELECT CONVERT(nvarchar(4000),SERVERPROPERTY('InstanceDefaultBackupPath'))";
            var directory = Assert.IsType<string>(await command.ExecuteScalarAsync()); Assert.False(string.IsNullOrWhiteSpace(directory));
            backup = directory.TrimEnd('\\', '/') + (directory.Contains('\\') ? "\\" : "/") + name + "-handler.bak";
            command.CommandText = $"BACKUP DATABASE [{name}] TO DISK=@backup WITH COPY_ONLY, INIT";
            command.Parameters.AddWithValue("@backup", backup); await command.ExecuteNonQueryAsync();
            await run.Handle(); var expected = (await run.Record.Journal().ReadAsync(run.Record.Id)).HandlerOutcomes![run.Scope.OperationId];
            command.CommandText = $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; RESTORE DATABASE [{name}] FROM DISK=@backup WITH REPLACE; ALTER DATABASE [{name}] SET MULTI_USER";
            await command.ExecuteNonQueryAsync(); using (var pooled = new SqlConnection(connection)) SqlConnection.ClearPool(pooled);
            await using (var db = isolated.Open())
            {
                var work = await db.WorkItems.SingleAsync(x => x.Id == run.Record.Work); Assert.Equal(WorkStatus.Leased, work.Status);
                Assert.Equal(run.Scope.OperationId, work.LeaseOwner); Assert.Equal(1, work.Attempts);
                Assert.Equal(EmailStatus.Queued, (await db.EmailOutbox.SingleAsync(x => x.Id == run.Record.Work)).Status);
                Assert.False(await db.AuthTokens.AnyAsync(x => x.EnvelopeId == run.Record.Id));
                await using var tx = await db.Database.BeginTransactionAsync();
                await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ResumeHandlerLockedAsync(db, run.Record.Id, run.Scope.OperationId, run.Scope.Kind, run.Scope.Reference));
                await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, run.Scope));
            }
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(run.Scope, Hash));
            var state = await run.Record.Journal().ReadAsync(run.Record.Id); Assert.Equal(expected, state.HandlerOutcomes![run.Scope.OperationId]);
            Assert.Empty(state.Outcomes!); Assert.Empty(state.SettledOperations); Assert.Equal(run.Scope.OperationId, state.OutstandingOperation);
        }
        finally { await isolated.DisposeAsync(); if (backup is not null && File.Exists(backup)) File.Delete(backup); }
    }

    private sealed class LostCommit : DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData data, CancellationToken ct = default)
            => throw new IOException("Synthetic handler SQL acknowledgement lost");
    }

    private sealed class Run(SqlDatabaseFixture fixture, ProductionRecordOperationAdmissionTests.Run record)
    {
        internal readonly ProductionRecordOperationAdmissionTests.Run Record = record;
        internal readonly ProductionRecordOperationAdmission Gate = record.Gate();
        internal ProductionRecordOperation Scope = null!;
        internal static async Task<Run> Create(SqlDatabaseFixture fixture)
        {
            var run = new Run(fixture, await ProductionRecordOperationAdmissionTests.Run.Create(fixture)); await run.Gate.InitializeAsync(run.Record.Id);
            run.Scope = await run.Gate.BeginAsync(run.Record.Id, Guid.NewGuid(), "work/4", run.Record.Work.ToString("N") + "/attempt/1");
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            await run.Gate.DemandStartingLockedAsync(db, run.Scope);
            await db.WorkItems.Where(x => x.Id == run.Record.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, WorkStatus.Leased)
                .SetProperty(w => w.Attempts, 1).SetProperty(w => w.LeaseOwner, run.Scope.OperationId).SetProperty(w => w.LeaseExpiresAt, run.Record.Clock.Now.AddMinutes(5)));
            await tx.CommitAsync(); return run;
        }
        internal async Task HandlerWrites(QuillSignDbContext db)
        {
            await db.EmailOutbox.Where(x => x.Id == Record.Work).ExecuteUpdateAsync(x => x.SetProperty(e => e.Status, EmailStatus.Sent)
                .SetProperty(e => e.Provider, "synthetic-captured").SetProperty(e => e.ProviderMessageId, "synthetic-handler-receipt"));
            db.AuthTokens.Add(new() { EnvelopeId = Record.Id, PartyType = PartyType.Sender, Purpose = TokenPurpose.SenderVerify,
                Email = "synthetic-operation@example.invalid", TokenSha256 = SHA256.HashData(Guid.NewGuid().ToByteArray()), ExpiresAt = Record.Clock.Now.AddHours(1) });
            await db.SaveChangesAsync();
        }
        internal async Task Handle()
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            await HandlerWrites(db); await Gate.PrepareHandlerOutcomeLockedAsync(db, Scope); await tx.CommitAsync();
        }
        internal Task FinishWrites(QuillSignDbContext db) => db.WorkItems.Where(x => x.Id == Record.Work).ExecuteUpdateAsync(x => x
            .SetProperty(w => w.Status, WorkStatus.Completed).SetProperty(w => w.LeaseOwner, (Guid?)null).SetProperty(w => w.LeaseExpiresAt, (DateTimeOffset?)null));
        internal async Task Finish()
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            Assert.Equal(Scope, await Gate.ResumeHandlerLockedAsync(db, Record.Id, Scope.OperationId, Scope.Kind, Scope.Reference));
            await FinishWrites(db); await Gate.PrepareOutcomeLockedAsync(db, Scope); await tx.CommitAsync();
        }
    }
}

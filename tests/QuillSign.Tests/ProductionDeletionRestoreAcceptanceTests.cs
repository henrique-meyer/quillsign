using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionDeletionRestoreAcceptanceTests
{
    [Fact]
    public async Task Actual_pre_reservation_whole_database_restore_cannot_resurrect_access_hold_or_cleanup_after_the_original_lease_expires()
    {
        // Restoring a class/shared fixture would disturb unrelated tests. This
        // database, native backup and connection pool belong to this case only.
        var fixture = new SqlDatabaseFixture();
        await fixture.InitializeAsync();
        string? backup = null, connection = null, name = null;
        var singleUser = false;
        try
        {
            var ready = await new ProductionDeletionConnectedTests(fixture).CreateReady();
            await using var run = ready.Run;
            var workId = await ready.Coordinator.PrepareAsync(run.Id);
            Envelope original;
            WorkItem queued;
            DateTimeOffset originalTokenExpiry;
            int originalAudits;
            await using (var db = fixture.Open())
            {
                connection = db.Database.GetConnectionString()!;
                original = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == run.Id);
                queued = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == workId);
                originalTokenExpiry = (await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == run.Token.TokenId)).ExpiresAt;
                originalAudits = await db.AuditEvents.CountAsync(x => x.EnvelopeId == run.Id);
            }
            Assert.Equal(WorkStatus.Queued, queued.Status);
            Assert.Equal(0, queued.Attempts);
            Assert.Null((await run.Journal.ReadAsync(run.Id)).Deletion?.Header);

            var builder = new SqlConnectionStringBuilder(connection);
            name = builder.InitialCatalog;
            Assert.Matches("^QuillSignTests_[a-f0-9]{32}$", name);
            builder.InitialCatalog = "master";
            builder.Pooling = false;
            await using var master = new SqlConnection(builder.ConnectionString);
            await master.OpenAsync();
            await using var command = master.CreateCommand();
            command.CommandTimeout = 120;
            command.CommandText = "SELECT CONVERT(nvarchar(4000),SERVERPROPERTY('InstanceDefaultBackupPath'))";
            var directory = Assert.IsType<string>(await command.ExecuteScalarAsync());
            backup = directory.TrimEnd('\\', '/') + (directory.Contains('\\') ? "\\" : "/") + name + "-production-deletion.bak";
            command.CommandText = $"BACKUP DATABASE [{name}] TO DISK=@backup WITH COPY_ONLY, INIT";
            command.Parameters.AddWithValue("@backup", backup);
            await command.ExecuteNonQueryAsync();

            ready.Signals.Next = workId;
            await using (var worker = fixture.Open())
            {
                var store = new WorkStore(worker, new() { Enabled = true, LeaseSeconds = 600 }, run.Time)
                { DeletionAdmission = ready.Coordinator };
                var processor = new WorkProcessor(store, ready.Signals, [new ProductionDeletionWork(() => ready.Coordinator)], run.Time);
                Assert.True(await processor.RunOnceAsync(default));
            }
            var terminal = await run.Journal.ReadAsync(run.Id);
            Assert.True(terminal.Deletion!.Terminal);
            Assert.True(terminal.Deletion.WorkFinished);
            Assert.True(terminal.Frozen);
            Assert.Equal(4, ready.Files.RootDeletes);
            Assert.Equal(8, ready.Files.VersionDeletes);
            Assert.Equal(1, run.Captured.Calls);
            await using (var removed = fixture.Open())
                Assert.False(await removed.Envelopes.AnyAsync(x => x.Id == run.Id));
            var recorded = await ready.Coordinator.ReadRecordedStatusAsync(run.Id);
            Assert.True(recorded.SqlRemoved);
            Assert.True(recorded.ActiveDataCleaned);
            Assert.Contains("Recorded", recorded.State);

            // Expiry is deliberately after the irreversible cut, not authority
            // to replay the restored queued lease or reopen participant access.
            run.Time.Now = terminal.Deletion.Lease!.Until.AddMinutes(1);
            using (var ownPool = new SqlConnection(connection)) SqlConnection.ClearPool(ownPool);
            command.CommandText = $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE";
            await command.ExecuteNonQueryAsync();
            singleUser = true;
            command.CommandText = $"RESTORE DATABASE [{name}] FROM DISK=@backup WITH REPLACE";
            await command.ExecuteNonQueryAsync();
            command.CommandText = $"ALTER DATABASE [{name}] SET MULTI_USER";
            await command.ExecuteNonQueryAsync();
            singleUser = false;
            using (var ownPool = new SqlConnection(connection)) SqlConnection.ClearPool(ownPool);

            await using (var restored = fixture.Open())
            {
                var row = await restored.Envelopes.AsNoTracking().SingleAsync(x => x.Id == run.Id);
                Assert.Equal(original.RowVersion, row.RowVersion);
                Assert.Equal(original.CreatedAt, row.CreatedAt);
                Assert.Equal(original.SenderVerifiedAt, row.SenderVerifiedAt);
                Assert.Equal(originalAudits, await restored.AuditEvents.CountAsync(x => x.EnvelopeId == run.Id));
                Assert.Equal(originalTokenExpiry, (await restored.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == run.Token.TokenId)).ExpiresAt);
            }

            var events = run.External.Rows.Count;
            var deletes = ready.Files.RootDeletes + ready.Files.VersionDeletes;
            var freshJournal = new ProductionHoldWitnessJournal(run.External, run.Keys, run.Time, Installation);
            var freshAdmission = new ProductionRecordOperationAdmission(fixture.Open, run.Keys, run.Time, freshJournal);
            var closedJournal = new ProductionHoldWitnessJournal(new ReadOnlyProductionWitnessStore(run.External), run.Keys, run.Time, Installation);
            var closedAdmission = new ProductionRecordOperationAdmission(fixture.Open, run.Keys, run.Time, closedJournal)
            { AuthenticatedDemoOrigin = true, ProductionAdmissionEnabled = false };
            await Assert.ThrowsAsync<InvalidDataException>(() => freshAdmission.BeginAsync(run.Id, Guid.NewGuid(), "test/restored-production", "new-operation"));
            await Assert.ThrowsAsync<InvalidDataException>(() => closedAdmission.BeginAsync(run.Id, Guid.NewGuid(), "test/restored-disabled-production", "new-operation"));
            var hold = Place(run.Id);
            await Assert.ThrowsAsync<InvalidDataException>(() => freshJournal.IntentAsync(Authority(run.Time, hold.Permission), Operators, hold, Guid.NewGuid()));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Coordinator.SubmitAsync(Authority(run.Time, hold.Permission), Operators, hold));

            var freshDeletion = new ProductionDeletionCoordinator(fixture.Open, run.Keys, run.Time, freshJournal,
                run.Coordinator, freshAdmission, ready.Files, new UnusedRecoveryIndex(),
                new() { Enabled = true, CompletedCommitmentStatement = "Synthetic explicit per-record copy/archive commitment." },
                new() { Enabled = true, LeaseSeconds = 600 }, () => ready.Signals);
            await using (var worker = fixture.Open())
            {
                var store = new WorkStore(worker, new() { Enabled = true, LeaseSeconds = 600 }, run.Time)
                { DeletionAdmission = freshDeletion };
                var claim = await store.ClaimAsync(workId, default);
                Assert.Null(claim.Lease);
                Assert.True(claim.Terminal);
            }
            var current = await freshDeletion.ReadStatusAsync(run.Id);
            Assert.Equal("Restored SQL quarantined", current.State);
            Assert.False(current.SqlRemoved);
            Assert.False(current.ActiveDataCleaned);
            var historical = await freshDeletion.ReadRecordedStatusAsync(run.Id);
            Assert.True(historical.SqlRemoved);
            Assert.True(historical.ActiveDataCleaned);
            Assert.Contains("Recorded", historical.State);

            await using (var check = fixture.Open())
            {
                var row = await check.WorkItems.AsNoTracking().SingleAsync(x => x.Id == workId);
                Assert.Equal(queued.RowVersion, row.RowVersion);
                Assert.Equal(queued.Status, row.Status);
                Assert.Equal(queued.Attempts, row.Attempts);
                Assert.Equal(queued.PayloadJson, row.PayloadJson);
                Assert.Null(row.LeaseOwner);
                Assert.Null(row.LeaseExpiresAt);
                Assert.Empty(await check.ProductionHoldRequests.Where(x => x.EnvelopeId == run.Id).ToArrayAsync());
            }
            Assert.Equal(events, run.External.Rows.Count);
            Assert.Equal(terminal.HeadHash, (await freshJournal.ReadAsync(run.Id)).HeadHash);
            Assert.Equal(deletes, ready.Files.RootDeletes + ready.Files.VersionDeletes);
            Assert.Equal(1, run.Captured.Calls);
        }
        finally
        {
            if (singleUser && connection is not null && name is not null)
            {
                var builder = new SqlConnectionStringBuilder(connection) { InitialCatalog = "master", Pooling = false };
                await using var master = new SqlConnection(builder.ConnectionString);
                await master.OpenAsync();
                await using var command = master.CreateCommand();
                command.CommandText = $"ALTER DATABASE [{name}] SET MULTI_USER";
                command.CommandTimeout = 120;
                await command.ExecuteNonQueryAsync();
            }
            await fixture.DisposeAsync();
            if (backup is not null && File.Exists(backup)) File.Delete(backup);
        }
    }

    private sealed class UnusedRecoveryIndex : IProductionDeletionRecoveryIndex
    {
        public Task RememberAsync(ProductionDeletionObjectScope scope, ProductionDeletionRecoveryHint hint, CancellationToken ct = default)
            => throw new InvalidOperationException("A terminal journal cannot create new recovery authority.");
        public Task<ProductionDeletionRecoveryHint> ReadAsync(Guid recordId, Guid deletionId, CancellationToken ct = default)
            => throw new InvalidOperationException("An index hint is not required to verify the immutable terminal barrier.");
        public Task<ProductionDeletionRecoveryPage> ListAsync(string? continuation, int maximum, CancellationToken ct = default)
            => throw new InvalidOperationException("A restored queued row cannot restart recovery discovery.");
    }
}

using System.Data.Common;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Work;
using Run = QuillSign.Tests.ProductionRuntimeAdmissionTests.Run;

namespace QuillSign.Tests;

public sealed class ProductionWorkMissingHintTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Uncommitted_wakeup_waits_for_insert_commit_instead_of_discarding_snapshot_absence(bool production)
    {
        var fixture = new SqlDatabaseFixture(); await fixture.InitializeAsync();
        try
        {
            await EnableOwnSnapshotReads(fixture);
            await using var run = await Run.Create(fixture);
            await using var writer = fixture.Open(); await writer.Database.OpenConnectionAsync();
            var writerId = ((SqlConnection)writer.Database.GetDbConnection()).ServerProcessId;
            await using var transaction = await writer.Database.BeginTransactionAsync();
            var item = new WorkItem { EnvelopeId = run.Id, Kind = WorkKind.Rendering, AvailableAt = run.Time.Now };
            writer.Add(item); await writer.SaveChangesAsync(); // The wakeup can now escape, before this commit.
            await using (var snapshot = fixture.Open())
                Assert.Null(await snapshot.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == item.Id));
            var journalBefore = await run.Journal.ReadAsync(run.Id);
            var commands = new Probe();
            await using var db = OpenIntercepted(fixture, commands);
            var store = production ? run.Store(db) : new WorkStore(db, new WorkOptions { Enabled = true }, run.Time);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var claim = store.ClaimAsync(item.Id, timeout.Token);
            try
            {
                // On the buggy production preflight, claim wins this race by returning Terminal.
                // The locking query must instead reach SQL while the insertion remains uncommitted.
                var first = await Task.WhenAny(commands.Locking.Task, claim).WaitAsync(timeout.Token);
                Assert.Same(commands.Locking.Task, first);
                var claimantId = await commands.Locking.Task;
                if (production) Assert.False(await commands.SnapshotHadRows.Task.WaitAsync(timeout.Token));
                await WaitForWriterBlock(fixture, claimantId, writerId, timeout.Token);
                Assert.False(claim.IsCompleted);
                await transaction.CommitAsync(timeout.Token);
                var result = await claim.WaitAsync(timeout.Token);
                Assert.False(result.Terminal);
                await using var readback = fixture.Open();
                var saved = await readback.WorkItems.AsNoTracking().SingleAsync(x => x.Id == item.Id, timeout.Token);
                if (production)
                {
                    Assert.Null(result.Lease); Assert.Equal(run.Time.Now.AddMinutes(15), result.RetryAt);
                    Assert.Equal(WorkStatus.Queued, saved.Status); Assert.Equal(0, saved.Attempts);
                    Assert.Null(saved.LeaseOwner); Assert.Null(saved.LeaseExpiresAt); Assert.Null(saved.LastError);
                    Assert.Equal(journalBefore.HeadHash, (await run.Journal.ReadAsync(run.Id)).HeadHash);
                    Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
                    Assert.Equal(0, run.Captured.Calls);
                }
                else
                {
                    Assert.NotNull(result.Lease); Assert.Null(result.RetryAt);
                    Assert.Equal(WorkStatus.Leased, saved.Status); Assert.Equal(1, saved.Attempts);
                    Assert.Equal(result.Lease.Owner, saved.LeaseOwner);
                }
            }
            finally
            {
                timeout.Cancel();
                if (writer.Database.CurrentTransaction is not null) await transaction.RollbackAsync();
                try { await claim; } catch (OperationCanceledException) { }
            }
        }
        finally { await fixture.DisposeAsync(); }
    }

    [Fact]
    public async Task Confirmed_absent_production_wakeup_is_terminal_after_key_probe_without_reservation()
    {
        var fixture = new SqlDatabaseFixture(); await fixture.InitializeAsync();
        try
        {
            await EnableOwnSnapshotReads(fixture); await using var run = await Run.Create(fixture);
            var before = await run.Journal.ReadAsync(run.Id); var commands = new Probe();
            await using var db = OpenIntercepted(fixture, commands);
            var result = await run.Store(db).ClaimAsync(Guid.NewGuid(), CancellationToken.None);
            Assert.True(result.Terminal); Assert.Null(result.Lease); Assert.Null(result.RetryAt);
            Assert.True(commands.Locking.Task.IsCompletedSuccessfully);
            Assert.False(await commands.SnapshotHadRows.Task);
            Assert.Null(db.Database.CurrentTransaction);
            Assert.Equal(before.HeadHash, (await run.Journal.ReadAsync(run.Id)).HeadHash);
            Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
        }
        finally { await fixture.DisposeAsync(); }
    }

    private static QuillSignDbContext OpenIntercepted(SqlDatabaseFixture fixture, Probe probe)
    {
        using var source = fixture.Open();
        return new(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(probe).Options);
    }

    private static async Task EnableOwnSnapshotReads(SqlDatabaseFixture fixture)
    {
        await using var source = fixture.Open(); var builder = new SqlConnectionStringBuilder(source.Database.GetConnectionString());
        var name = builder.InitialCatalog;
        if (!Regex.IsMatch(name, "^QuillSignTests_[a-f0-9]{32}$", RegexOptions.CultureInvariant))
            throw new InvalidOperationException("Refusing isolation changes outside this disposable fixture");
        builder.InitialCatalog = "master";
        await using var connection = new SqlConnection(builder.ConnectionString); await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"ALTER DATABASE [{name}] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE";
        await command.ExecuteNonQueryAsync();
        command.CommandText = "SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name=@name";
        command.Parameters.AddWithValue("@name", name);
        Assert.True(Convert.ToBoolean(await command.ExecuteScalarAsync()));
    }

    private static async Task WaitForWriterBlock(SqlDatabaseFixture fixture, int claimant, int writer, CancellationToken ct)
    {
        await using var observer = fixture.Open(); await observer.Database.OpenConnectionAsync(ct);
        await using var command = observer.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sys.dm_exec_requests WHERE session_id=@claimant AND blocking_session_id=@writer AND wait_type LIKE 'LCK_M_%'";
        command.Parameters.Add(new SqlParameter("@claimant", claimant)); command.Parameters.Add(new SqlParameter("@writer", writer));
        while (Convert.ToInt32(await command.ExecuteScalarAsync(ct)) != 1) await Task.Delay(20, ct);
    }

    private sealed class Probe : DbCommandInterceptor
    {
        internal readonly TaskCompletionSource<int> Locking = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource<bool> SnapshotHadRows = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData data,
            InterceptionResult<DbDataReader> result, CancellationToken ct = default)
        {
            if (command.CommandText.Contains("[WorkItems]", StringComparison.Ordinal) && command.CommandText.Contains("UPDLOCK", StringComparison.OrdinalIgnoreCase))
                Locking.TrySetResult(((SqlConnection)command.Connection!).ServerProcessId);
            return ValueTask.FromResult(result);
        }
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData data,
            DbDataReader result, CancellationToken ct = default)
        {
            if (command.CommandText.Contains("[WorkItems]", StringComparison.Ordinal) && !command.CommandText.Contains("UPDLOCK", StringComparison.OrdinalIgnoreCase))
                SnapshotHadRows.TrySetResult(result.HasRows);
            return ValueTask.FromResult(result);
        }
    }
}
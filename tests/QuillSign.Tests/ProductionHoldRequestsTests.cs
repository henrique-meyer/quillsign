using System.Data.Common;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionHoldRequestsTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private const string Issuer = "https://operator.synthetic.invalid";
    private readonly IDataProtectionProvider keys = new EphemeralDataProtectionProvider();
    private readonly Clock clock = new();
    private static ProductionOperatorPolicy Operators(string subject = "synthetic-operator") => new(true,
        [new(Issuer, subject, new HashSet<ProductionOperatorPermission> { ProductionOperatorPermission.PlaceHold, ProductionOperatorPermission.ReleaseHold })]);
    private ProductionOperatorAuthority Authority(ProductionOperatorPermission permission, string subject = "synthetic-operator")
        => ProductionOperatorAuthority.FromValidatedTicket(new(new ClaimsPrincipal(new ClaimsIdentity(
            [new("iss", Issuer, ClaimValueTypes.String, Issuer), new("sub", subject, ClaimValueTypes.String, Issuer)], ProductionOperatorAuthority.OidcScheme)),
            new AuthenticationProperties { IssuedUtc = clock.Now, ExpiresUtc = clock.Now.AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme),
            Operators(subject), permission, clock);
    private static ProductionHoldCommand Place(Guid id, long revision = 0) => new(Guid.NewGuid(), id, Guid.NewGuid(), revision,
        ProductionHoldOperation.Place, "Synthetic case preservation", "Private synthetic reason", "synthetic-reference");
    private ProductionHoldRequests Service(QuillSignDbContext db) => new(db, keys, clock);

    [Fact]
    public async Task Pending_place_and_release_survive_restart_and_every_hold_continues_to_block_deletion()
    {
        var id = await Create(); var first = Place(id); var second = Place(id, 1);
        var placed = await Prepare(first); Assert.True(placed.Current.BlocksDeletion);
        Assert.Equal(ProductionHoldPendingState.PreservationPending, Assert.Single(placed.Current.Holds).State);
        await Prepare(second);
        var released = await Prepare(first with { CommandId = Guid.NewGuid(), ExpectedRevision = 2, Operation = ProductionHoldOperation.Release });
        Assert.Equal(3, released.Current.Revision); Assert.True(released.Current.BlocksDeletion); Assert.Equal(2, released.Current.Holds.Count);
        Assert.Equal(ProductionHoldPendingState.ReleasePending, released.Current.Holds.Single(x => x.HoldId == first.HoldId).State);
        var restarted = await Read(id); Assert.Equal(released.Current.FenceHash, restarted.FenceHash);
        await using var db = fixture.Open(); var rows = await db.ProductionHoldRequests.Where(x => x.EnvelopeId == id).ToArrayAsync();
        Assert.All(rows, x => { Assert.DoesNotContain(first.Reason, x.ProtectedEvidence); Assert.DoesNotContain("synthetic-operator", x.ProtectedEvidence); });
        // Private operations do not disclose their reason/reference/actor in participant audit evidence.
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == id).ToArrayAsync());
    }

    [Fact]
    public async Task Exact_replay_recovers_the_original_receipt_but_changed_command_actor_or_record_conflicts()
    {
        var id = await Create(); var command = Place(id); var first = await Prepare(command);
        var replay = await Prepare(command); Assert.Equal(first.CommandRevision, replay.CommandRevision); Assert.Equal(first.Current.FenceHash, replay.Current.FenceHash);
        await Assert.ThrowsAsync<DocumentConflictException>(() => Prepare(command with { Reason = "Different private reason" }));
        await Assert.ThrowsAsync<DocumentConflictException>(() => Prepare(command, "another-synthetic-operator"));
        var other = await Create(); await Assert.ThrowsAsync<DocumentConflictException>(() => Prepare(command with { RecordId = other }));
        Assert.Equal(1, (await Read(id)).Revision); Assert.Equal(0, (await Read(other)).Revision);
    }

    [Fact]
    public async Task Two_concurrent_placements_with_the_same_expected_revision_cannot_both_commit()
    {
        var id = await Create();
        async Task<bool> Attempt(ProductionHoldCommand command)
        {
            try { await Prepare(command); return true; }
            catch (DocumentConflictException) { return false; }
        }
        var results = await Task.WhenAll(Attempt(Place(id)), Attempt(Place(id)));
        Assert.Single(results, x => x); Assert.Equal(1, (await Read(id)).Revision);
    }

    [Fact]
    public async Task A_command_id_cannot_commit_under_two_different_parent_records_during_a_race()
    {
        var first = await Create(); var second = await Create(); var command = Place(first);
        async Task<bool> Attempt(ProductionHoldCommand value)
        {
            try { await Prepare(value); return true; }
            catch (DocumentConflictException) { return false; }
        }
        var results = await Task.WhenAll(Attempt(command), Attempt(command with { RecordId = second }));
        Assert.Single(results, x => x);
        await using var db = fixture.Open(); Assert.Single(await db.ProductionHoldRequests.Where(x => x.CommandId == command.CommandId).ToArrayAsync());
    }

    [Fact]
    public async Task Rollback_does_not_leave_a_pending_request_or_advance_the_fence()
    {
        var id = await Create(); var command = Place(id);
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            await Service(db).PrepareLockedAsync(Authority(command.Permission), Operators(), command);
            await tx.RollbackAsync();
        }
        var unchanged = await Read(id); Assert.False(unchanged.BlocksDeletion); Assert.Equal(0, unchanged.Revision);
        Assert.Null(unchanged.FenceHash); Assert.Equal(1, (await Prepare(command)).CommandRevision);
    }

    [Fact]
    public async Task A_lost_commit_acknowledgement_is_reconciled_without_a_second_command_or_clock_reset()
    {
        var id = await Create(); var command = Place(id);
        await using var source = fixture.Open(); var interceptor = new LostCommit();
        await using (var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(interceptor).Options))
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            await Service(db).PrepareLockedAsync(Authority(command.Permission), Operators(), command);
            await Assert.ThrowsAsync<IOException>(() => tx.CommitAsync());
        }
        clock.Now = clock.Now.AddSeconds(1);
        var recovered = await Prepare(command); Assert.Equal(1, recovered.CommandRevision); Assert.Equal(1, recovered.Current.Revision);
        Assert.Single(await source.ProductionHoldRequests.Where(x => x.EnvelopeId == id).ToArrayAsync());
    }

    [Theory]
    [InlineData("ciphertext")][InlineData("scope")][InlineData("clock")][InlineData("missing-prefix")]
    public async Task Even_recomputed_unkeyed_hashes_cannot_authenticate_corrupted_or_missing_private_evidence(string change)
    {
        var id = await Create(); await Prepare(Place(id)); await Prepare(Place(id, 1));
        await using var db = fixture.Open();
        if (change == "missing-prefix") await db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM [ProductionHoldRequests] WHERE [EnvelopeId]={id} AND [Revision]=1");
        else
        {
            var row = await db.ProductionHoldRequests.AsNoTracking().SingleAsync(x => x.EnvelopeId == id && x.Revision == 2);
            if (change == "ciphertext") row.ProtectedEvidence = row.ProtectedEvidence[..^1] + (row.ProtectedEvidence[^1] == 'A' ? "B" : "A");
            if (change == "scope") row.HoldId = Guid.NewGuid();
            if (change == "clock") row.At = row.At.AddTicks(-1);
            var hash = (byte[])typeof(ProductionHoldRequests).GetMethod("Hash", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [row])!;
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE [ProductionHoldRequests] SET [ProtectedEvidence]={row.ProtectedEvidence},[HoldId]={row.HoldId},[At]={row.At},[Hash]={hash} WHERE [CommandId]={row.CommandId}");
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => Read(id));
    }

    [Theory]
    [InlineData("missing")][InlineData("legacy")][InlineData("demo")]
    public async Task Commands_cannot_enroll_or_target_missing_demo_or_legacy_records(string kind)
    {
        var envelope = New();
        if (kind != "missing") { envelope.IsDemo = kind == "demo"; await using var db = fixture.Open(); db.Add(envelope); await db.SaveChangesAsync(); }
        await Assert.ThrowsAsync<InvalidDataException>(() => Prepare(Place(envelope.Id)));
        await using var check = fixture.Open(); Assert.False(await check.ProductionHoldRequests.AnyAsync(x => x.EnvelopeId == envelope.Id));
        Assert.False(await check.ProductionRetentionPolicies.AnyAsync(x => x.EnvelopeId == envelope.Id));
    }

    [Fact]
    public async Task Ordinary_runtime_and_worker_principals_have_no_private_hold_table_permissions()
    {
        await using var db = fixture.Open(); await db.Database.OpenConnectionAsync(); var connection = (SqlConnection)db.Database.GetDbConnection();
        await using var sql = connection.CreateCommand();
        sql.CommandText = "CREATE USER [app_runtime] WITHOUT LOGIN; CREATE USER [app_worker] WITHOUT LOGIN"; await sql.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection);
        foreach (var user in new[] { "app_runtime", "app_worker" })
        {
            sql.CommandText = $"EXECUTE AS USER='{user}'"; await sql.ExecuteNonQueryAsync();
            try
            {
                foreach (var permission in new[] { "SELECT", "INSERT", "UPDATE", "DELETE", "ALTER" })
                {
                    sql.CommandText = $"SELECT HAS_PERMS_BY_NAME('dbo.ProductionHoldRequests','OBJECT','{permission}')";
                    Assert.Equal(0, Convert.ToInt32(await sql.ExecuteScalarAsync()));
                }
                sql.CommandText = "SELECT * FROM [ProductionHoldRequests]";
                Assert.Equal(229, (await Assert.ThrowsAsync<SqlException>(async () => await sql.ExecuteReaderAsync())).Number);
            }
            finally { sql.CommandText = "REVERT"; await sql.ExecuteNonQueryAsync(); }
        }
    }

    [Fact]
    public async Task Expired_or_revoked_authority_cannot_append_even_a_replayed_command()
    {
        var id = await Create(); var command = Place(id); var authority = Authority(command.Permission); await Prepare(command);
        clock.Now = clock.Now.AddMinutes(5);
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Service(db).PrepareLockedAsync(authority, Operators(), command));
        authority = Authority(command.Permission);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Service(db).PrepareLockedAsync(authority, Operators() with { Enabled = false }, command));
        Assert.Equal(1, await db.ProductionHoldRequests.CountAsync(x => x.EnvelopeId == id));
    }

    private async Task<Guid> Create()
    {
        var envelope = New(); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync(); db.Add(envelope);
        await new ProductionRetentionLedger(db, new(db, clock), clock).PrepareNewLockedAsync(envelope, ProductionRetentionLedgerTests.Policy());
        await tx.CommitAsync(); return envelope.Id;
    }
    private Envelope New() => new() { SenderEmail = "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid", CreatedAt = clock.Now };
    private async Task<ProductionHoldRequestReceipt> Prepare(ProductionHoldCommand command, string subject = "synthetic-operator")
    {
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var receipt = await Service(db).PrepareLockedAsync(Authority(command.Permission, subject), Operators(subject), command);
        await tx.CommitAsync(); return receipt;
    }
    private async Task<ProductionHoldRequestSnapshot> Read(Guid id)
    {
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var result = await Service(db).ReadLockedAsync(id); await tx.RollbackAsync(); return result;
    }
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class LostCommit : DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
            => throw new IOException("Synthetic lost private hold commit acknowledgement");
    }
}

public sealed class ProductionHoldRequestGuardTests
{
    [Fact]
    public async Task Missing_transaction_and_EF_mutations_fail_without_opening_a_connection()
    {
        await using var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer("Server=127.0.0.1,1;Database=SyntheticNoConnection;Integrated Security=true;Encrypt=true").Options);
        var service = new ProductionHoldRequests(db, new EphemeralDataProtectionProvider(), TimeProvider.System);
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ReadLockedAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<InvalidOperationException>(() => new ProductionHoldSqlInventory(db, new EphemeralDataProtectionProvider(), TimeProvider.System)
            .CaptureLockedAsync(Guid.NewGuid(), 1, new string('0', 64)));
        var command = new ProductionHoldCommand(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 0, ProductionHoldOperation.Place,
            "Synthetic purpose", "Synthetic reason", "synthetic-reference");
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.PrepareLockedAsync(null!, new(false, []), command));
        var row = new ProductionHoldRequestRecord { CommandId = Guid.NewGuid() }; db.Attach(row);
        foreach (var state in new[] { EntityState.Modified, EntityState.Deleted })
        {
            db.Entry(row).State = state;
            await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
        }
        Assert.Equal(System.Data.ConnectionState.Closed, db.Database.GetDbConnection().State);
    }
}

using System.Data;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed partial class DocumentLookupDeliveryTests
{
    [Fact]
    public async Task Late_feedback_still_suppresses_the_address_after_lookup_contact_cleanup()
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); Assert.True(await h.Once()); var lease = await CleanupLease(h, id);
        string messageId;
        await using (var db = fixture.Open()) { var email = await db.EmailOutbox.SingleAsync(x => x.Id == id); messageId = email.ProviderMessageId!; }
        Assert.True(await Remove(h, lease));
        await using (var db = fixture.Open()) await new SesFeedbackProcessor(db, h.Clock).ApplyAsync(new(messageId, [h.Address], EmailStatus.Complained, SuppressionReason.Complaint), default);
        var next = Guid.NewGuid(); await h.Request(next);
        await using var check = fixture.Open(); Assert.Equal(SuppressionReason.Complaint, (await check.Suppressions.SingleAsync(x => x.Email == h.Address)).Reason);
        Assert.False(await check.EmailOutbox.AnyAsync(x => x.Id == next || x.Id == id)); Assert.Equal(1, h.Transport.Calls);
    }

    [Fact]
    public async Task A_concurrent_email_claim_either_keeps_a_live_lease_or_observes_the_terminal_cleanup_tombstone()
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); var purge = await CleanupLease(h, id);
        var cleanup = Record.ExceptionAsync(() => Remove(h, purge));
        async Task<WorkClaim> Claim() { using var scope = h.App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(id, default); }
        var claim = Claim(); await Task.WhenAll(cleanup, claim);
        var cleanupError = await cleanup; var claimed = await claim;
        await using var db = fixture.Open();
        if (cleanupError is { } error) { Assert.Equal(50002, Assert.IsType<SqlException>(error).Number); Assert.NotNull(claimed.Lease); Assert.True(await db.EmailOutbox.AnyAsync(x => x.Id == id)); }
        else { Assert.True(claimed.Terminal); Assert.Null(claimed.Lease); Assert.False(await db.EmailOutbox.AnyAsync(x => x.Id == id)); }
        Assert.Equal(0, h.Transport.Calls);
    }

    [Fact]
    public async Task Cleanup_module_execution_is_worker_only_and_never_grants_direct_policy_deletion()
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); var lease = await CleanupLease(h, id);
        await using (var db = fixture.Open()) {
            await db.Database.OpenConnectionAsync(); var connection = (SqlConnection)db.Database.GetDbConnection();
            Assert.Equal(50001, (await Assert.ThrowsAsync<SqlException>(() => DatabasePermissions.GrantLookupRetentionAsync(connection))).Number);
            await db.Database.ExecuteSqlRawAsync("CREATE USER app_runtime WITHOUT LOGIN; CREATE USER app_worker WITHOUT LOGIN; CREATE USER app_lookup_retention_role WITHOUT LOGIN");
            await DatabasePermissions.GrantRuntimeAsync(connection);
            Assert.Equal(50001, (await Assert.ThrowsAsync<SqlException>(() => DatabasePermissions.GrantLookupRetentionAsync(connection))).Number);
            await db.Database.ExecuteSqlRawAsync("DROP USER app_lookup_retention_role; CREATE ROLE app_lookup_retention_role AUTHORIZATION app_runtime");
            Assert.Equal(50001, (await Assert.ThrowsAsync<SqlException>(() => DatabasePermissions.GrantLookupRetentionAsync(connection))).Number);
            await db.Database.ExecuteSqlRawAsync("DROP ROLE app_lookup_retention_role; CREATE ROLE app_lookup_retention_role AUTHORIZATION dbo; ALTER ROLE app_lookup_retention_role ADD MEMBER app_runtime");
            Assert.Equal(50001, (await Assert.ThrowsAsync<SqlException>(() => DatabasePermissions.GrantLookupRetentionAsync(connection))).Number);
            await db.Database.ExecuteSqlRawAsync("ALTER ROLE app_lookup_retention_role DROP MEMBER app_runtime; ALTER ROLE app_runtime_role ADD MEMBER app_worker");
            await DatabasePermissions.GrantLookupRetentionAsync(connection); await DatabasePermissions.GrantLookupRetentionAsync(connection);
        }
        foreach (var worker in new[] { false, true }) await AsLookupUser(worker, async db => {
            Assert.Equal(229, (await Assert.ThrowsAsync<SqlException>(() => db.Database.ExecuteSqlRawAsync("DELETE FROM dbo.LookupContactRetentionSnapshots WHERE 1=0"))).Number);
            Assert.Equal(229, (await Assert.ThrowsAsync<SqlException>(() => db.Database.ExecuteSqlRawAsync("UPDATE dbo.LookupContactRetentionSnapshots SET Days=1 WHERE 1=0"))).Number);
            if (!worker) Assert.Equal(229, (await Assert.ThrowsAsync<SqlException>(() => new LookupContactCleanup(db, () => h.Signals, h.Clock).RemoveAsync(lease))).Number);
            else Assert.True(await new LookupContactCleanup(db, () => h.Signals, h.Clock).RemoveAsync(lease));
        });
        await using var check = fixture.Open(); Assert.False(await check.EmailOutbox.AnyAsync(x => x.Id == id));
    }

    [Theory]
    [InlineData("owner")][InlineData("attempt")][InlineData("request")][InlineData("digest")][InlineData("deadline")][InlineData("transaction")]
    public async Task Direct_SQL_cleanup_module_independently_rejects_mixed_scope_before_removing_contacts(string fault)
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); var lease = await CleanupLease(h, id);
        await using var db = fixture.Open(); await db.Database.OpenConnectionAsync();
        using var payload = JsonDocument.Parse((await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == lease.Id)).PayloadJson);
        var digest = payload.RootElement.GetProperty("retentionSha256").GetString()!; var deadline = payload.RootElement.GetProperty("deleteAfter").GetDateTimeOffset();
        await using var tx = fault == "transaction" ? null : await db.Database.BeginTransactionAsync();
        await using var command = db.Database.GetDbConnection().CreateCommand(); command.Transaction = tx?.GetDbTransaction();
        command.CommandText = "dbo.RemoveExpiredLookupContacts"; command.CommandType = CommandType.StoredProcedure;
        command.Parameters.Add(new SqlParameter("@RequestId", SqlDbType.UniqueIdentifier) { Value = fault == "request" ? Guid.NewGuid() : id });
        command.Parameters.Add(new SqlParameter("@WorkId", SqlDbType.UniqueIdentifier) { Value = lease.Id });
        command.Parameters.Add(new SqlParameter("@Owner", SqlDbType.UniqueIdentifier) { Value = fault == "owner" ? Guid.NewGuid() : lease.Owner });
        command.Parameters.Add(new SqlParameter("@Attempt", SqlDbType.Int) { Value = lease.Attempt + (fault == "attempt" ? 1 : 0) });
        command.Parameters.Add(new SqlParameter("@Until", SqlDbType.DateTimeOffset) { Value = lease.Until });
        command.Parameters.Add(new SqlParameter("@PolicySha256", SqlDbType.NVarChar, 64) { Value = fault == "digest" ? new string('0', 64) : digest });
        command.Parameters.Add(new SqlParameter("@DeleteAfter", SqlDbType.DateTimeOffset) { Value = fault == "deadline" ? deadline.AddSeconds(-1) : deadline });
        Assert.Equal(50001, (await Assert.ThrowsAsync<SqlException>(() => command.ExecuteScalarAsync())).Number);
        if (tx is not null) await tx.RollbackAsync();
        await using var check = fixture.Open(); Assert.True(await check.EmailOutbox.AnyAsync(x => x.Id == id)); Assert.True(await check.LookupContactRetentionSnapshots.AnyAsync(x => x.RequestId == id));
    }

    private async Task AsLookupUser(bool worker, Func<QuillSignDbContext, Task> action)
    {
        await using var db = fixture.Open(); await db.Database.OpenConnectionAsync();
        if (worker) await db.Database.ExecuteSqlRawAsync("EXECUTE AS USER='app_worker'"); else await db.Database.ExecuteSqlRawAsync("EXECUTE AS USER='app_runtime'");
        try { await action(db); } finally { await db.Database.ExecuteSqlRawAsync("REVERT"); }
    }
}

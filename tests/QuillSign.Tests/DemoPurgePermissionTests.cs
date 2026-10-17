using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Tests;

public sealed class DemoPurgePermissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Explicit_grant_rejects_role_collisions_untrusted_ownership_and_non_worker_members()
    {
        await using var db=fixture.Open();await db.Database.OpenConnectionAsync();var connection=(SqlConnection)db.Database.GetDbConnection();
        var absent=await Assert.ThrowsAsync<SqlException>(()=>DatabasePermissions.GrantDemoPurgeAsync(connection));Assert.Equal(50001,absent.Number);
        await db.Database.ExecuteSqlRawAsync("CREATE USER app_runtime WITHOUT LOGIN; CREATE USER app_worker WITHOUT LOGIN; CREATE USER app_demo_purge_role WITHOUT LOGIN");
        await DatabasePermissions.GrantRuntimeAsync(connection);
        var collision=await Assert.ThrowsAsync<SqlException>(()=>DatabasePermissions.GrantDemoPurgeAsync(connection));Assert.Equal(50001,collision.Number);
        await db.Database.ExecuteSqlRawAsync("DROP USER app_demo_purge_role; CREATE ROLE app_demo_purge_role AUTHORIZATION app_runtime");
        var ownership=await Assert.ThrowsAsync<SqlException>(()=>DatabasePermissions.GrantDemoPurgeAsync(connection));Assert.Equal(50001,ownership.Number);
        await db.Database.ExecuteSqlRawAsync("DROP ROLE app_demo_purge_role; CREATE ROLE app_demo_purge_role AUTHORIZATION dbo; ALTER ROLE app_demo_purge_role ADD MEMBER app_runtime");
        var member=await Assert.ThrowsAsync<SqlException>(()=>DatabasePermissions.GrantDemoPurgeAsync(connection));Assert.Equal(50001,member.Number);
        await db.Database.ExecuteSqlRawAsync("ALTER ROLE app_demo_purge_role DROP MEMBER app_runtime; ALTER ROLE app_runtime_role ADD MEMBER app_worker");
        await DatabasePermissions.GrantDemoPurgeAsync(connection);await DatabasePermissions.GrantDemoPurgeAsync(connection);
        await using var command=connection.CreateCommand();
        foreach(var user in new[]{"app_runtime","app_worker"}) {
            command.CommandText=user=="app_runtime" ? "EXECUTE AS USER='app_runtime'" : "EXECUTE AS USER='app_worker'";await command.ExecuteNonQueryAsync();
            try {
                command.CommandText="SELECT HAS_PERMS_BY_NAME('dbo.RemoveExpiredDemoPrivateRecords','OBJECT','EXECUTE')";
                Assert.Equal(user=="app_worker" ? 1:0,Convert.ToInt32(await command.ExecuteScalarAsync()));
                command.CommandText="SELECT HAS_PERMS_BY_NAME('dbo.AuditEvents','OBJECT','DELETE')";Assert.Equal(0,Convert.ToInt32(await command.ExecuteScalarAsync()));
            }finally{command.CommandText="REVERT";await command.ExecuteNonQueryAsync();}
        }
    }
}

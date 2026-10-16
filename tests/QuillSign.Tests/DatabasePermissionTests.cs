using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Tests;

public sealed class DatabasePermissionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Runtime_can_use_application_tables_but_cannot_change_schema_audit_or_migrations()
    {
        await using var db = fixture.Open();
        await db.Database.OpenConnectionAsync();
        var connection = (SqlConnection)db.Database.GetDbConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN";
        await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection);
        await DatabasePermissions.GrantRuntimeAsync(connection);
        var before = await db.Envelopes.CountAsync();
        command.CommandText = "EXECUTE AS USER = 'app_runtime'";
        await command.ExecuteNonQueryAsync();
        try
        {
            await DatabaseCommands.VerifyRuntimeAsync(db);
            foreach (var table in db.Model.GetEntityTypes().Select(x => x.GetTableName()).Distinct())
            {
                foreach (var permission in new[] { "SELECT", "INSERT", "UPDATE", "DELETE", "ALTER" })
                {
                    command.CommandText = "SELECT HAS_PERMS_BY_NAME(@object, 'OBJECT', @permission)";
                    command.Parameters.Clear();
                    command.Parameters.AddWithValue("@object", "dbo." + table);
                    command.Parameters.AddWithValue("@permission", permission);
                    var expected = permission == "ALTER" || (table is "AuditEvents" or "CompletionCandidates" or "CompletionSealOutputs" && permission is "UPDATE" or "DELETE") || (table is "SignaturePreviews" or "SignerReviewCandidates" or "SignerFinishAcceptances" && permission == "UPDATE") ? 0 : 1;
                    Assert.Equal(expected, Convert.ToInt32(await command.ExecuteScalarAsync()));
                }
            }
            command.Parameters.Clear();
            command.CommandText = "SELECT HAS_PERMS_BY_NAME('dbo.SignaturePreviews', 'OBJECT', 'UPDATE', 'UsedAt', 'COLUMN')";
            Assert.Equal(1,Convert.ToInt32(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT HAS_PERMS_BY_NAME('dbo.SignaturePreviews', 'OBJECT', 'UPDATE', 'SignatureSha256', 'COLUMN')";
            Assert.Equal(0,Convert.ToInt32(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT HAS_PERMS_BY_NAME('dbo.SignerReviewCandidates', 'OBJECT', 'UPDATE', 'UsedAt', 'COLUMN')";
            Assert.Equal(1,Convert.ToInt32(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT HAS_PERMS_BY_NAME('dbo.SignerReviewCandidates', 'OBJECT', 'UPDATE', 'SupersededAt', 'COLUMN')";
            Assert.Equal(1,Convert.ToInt32(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT HAS_PERMS_BY_NAME('dbo.SignerReviewCandidates', 'OBJECT', 'UPDATE', 'PdfSha256', 'COLUMN')";
            Assert.Equal(0,Convert.ToInt32(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT HAS_PERMS_BY_NAME('dbo.SignerFinishAcceptances', 'OBJECT', 'UPDATE', 'ProcessedAt', 'COLUMN')";
            Assert.Equal(1,Convert.ToInt32(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT HAS_PERMS_BY_NAME('dbo.SignerFinishAcceptances', 'OBJECT', 'UPDATE', 'NextInvitationId', 'COLUMN')";
            Assert.Equal(1,Convert.ToInt32(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT HAS_PERMS_BY_NAME('dbo.SignerFinishAcceptances', 'OBJECT', 'UPDATE', 'FieldsJson', 'COLUMN')";
            Assert.Equal(0,Convert.ToInt32(await command.ExecuteScalarAsync()));
        }
        finally
        {
            command.Parameters.Clear();
            command.CommandText = "REVERT";
            await command.ExecuteNonQueryAsync();
        }
        Assert.Equal(before, await db.Envelopes.CountAsync());
        Assert.Equal(0, await db.AuditEvents.CountAsync());
    }

    [Fact]
    public async Task Verification_rejects_excessive_privilege_and_rolls_back_even_unexpected_DDL()
    {
        await using var db = fixture.Open();
        await db.Database.OpenConnectionAsync();
        var connection = (SqlConnection)db.Database.GetDbConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN";
        await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection);
        command.CommandText = "GRANT CREATE TABLE TO [app_runtime]; GRANT ALTER ON SCHEMA::[dbo] TO [app_runtime]; EXECUTE AS USER = 'app_runtime'";
        await command.ExecuteNonQueryAsync();
        try { await Assert.ThrowsAsync<InvalidOperationException>(() => DatabaseCommands.VerifyRuntimeAsync(db)); }
        finally
        {
            command.CommandText = "REVERT; REVOKE CREATE TABLE FROM [app_runtime]; REVOKE ALTER ON SCHEMA::[dbo] FROM [app_runtime]";
            await command.ExecuteNonQueryAsync();
        }
        command.CommandText = "SELECT OBJECT_ID('dbo.__QuillSignPermissionProbe')";
        Assert.IsType<DBNull>(await command.ExecuteScalarAsync());
        Assert.Equal(0, await db.Envelopes.CountAsync());
        Assert.Equal(0, await db.AuditEvents.CountAsync());
    }
}

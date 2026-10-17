using Microsoft.Data.SqlClient;

namespace QuillSign.Data;

public static class DatabasePermissions
{
    public const string RuntimeUser = "app_runtime";
    public const string MigrationUser = "app_migrations";
    public const string WorkerUser = "app_worker";

    // A separate administrator provisions these contained users. Client IDs are used
    // for service principals/managed identities; no Graph directory grants are needed.
    public static async Task ProvisionIdentitiesAsync(SqlConnection connection, Guid runtimeClientId, Guid migrationClientId)
    {
        if (runtimeClientId == Guid.Empty || migrationClientId == Guid.Empty || runtimeClientId == migrationClientId)
            throw new ArgumentException("Supply distinct runtime and migration managed identities.");
        foreach (var (name, id) in new[] { (RuntimeUser, runtimeClientId), (MigrationUser, migrationClientId) })
        {
            var sid = "0x" + Convert.ToHexString(id.ToByteArray());
            // Names are fixed application aliases; SID text can only contain hex digits.
            await using var command = connection.CreateCommand();
            command.CommandText = $"""
                IF DATABASE_PRINCIPAL_ID(N'{name}') IS NULL
                    CREATE USER [{name}] WITH SID = {sid}, TYPE = E;
                ELSE IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'{name}' AND sid = {sid} AND type = 'E')
                    THROW 50001, 'Existing database principal does not match the configured identity.', 1;
                """;
            await command.ExecuteNonQueryAsync();
        }
        await using var migration = connection.CreateCommand();
        migration.CommandText = """
            ALTER ROLE [db_ddladmin] ADD MEMBER [app_migrations];
            ALTER ROLE [db_datareader] ADD MEMBER [app_migrations];
            ALTER ROLE [db_datawriter] ADD MEMBER [app_migrations];
            """;
        await migration.ExecuteNonQueryAsync();
    }

    // Explicit object grants keep future tables private until deliberately included.
    public static async Task GrantRuntimeAsync(SqlConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            IF DATABASE_PRINCIPAL_ID(N'app_runtime_role') IS NULL CREATE ROLE [app_runtime_role];
            ALTER ROLE [app_runtime_role] ADD MEMBER [app_runtime];
            """;
        await command.ExecuteNonQueryAsync();
        foreach (var table in new[] { "Envelopes", "Signers", "Recipients", "Fields", "AuthTokens", "EmailOutbox", "WorkItems", "Suppressions" })
        {
            command.CommandText = $"GRANT SELECT, INSERT, UPDATE, DELETE ON OBJECT::[dbo].[{table}] TO [app_runtime_role];";
            await command.ExecuteNonQueryAsync();
        }
        command.CommandText = """
            GRANT SELECT, INSERT, DELETE ON OBJECT::[dbo].[SignaturePreviews] TO [app_runtime_role];
            GRANT UPDATE ON OBJECT::[dbo].[SignaturePreviews] ([UsedAt]) TO [app_runtime_role];
            GRANT SELECT, INSERT, DELETE ON OBJECT::[dbo].[SignerReviewCandidates] TO [app_runtime_role];
            GRANT UPDATE ON OBJECT::[dbo].[SignerReviewCandidates] ([UsedAt], [SupersededAt]) TO [app_runtime_role];
            GRANT SELECT, INSERT, DELETE ON OBJECT::[dbo].[SignerFinishAcceptances] TO [app_runtime_role];
            GRANT UPDATE ON OBJECT::[dbo].[SignerFinishAcceptances] ([ProcessedAt], [NextInvitationId]) TO [app_runtime_role];
            GRANT SELECT, INSERT ON OBJECT::[dbo].[AuditEvents] TO [app_runtime_role];
            DENY UPDATE, DELETE ON OBJECT::[dbo].[AuditEvents] TO [app_runtime_role];
            GRANT SELECT, INSERT ON OBJECT::[dbo].[DocumentRetentionSnapshots] TO [app_runtime_role];
            DENY UPDATE, DELETE ON OBJECT::[dbo].[DocumentRetentionSnapshots] TO [app_runtime_role];
            GRANT SELECT, INSERT ON OBJECT::[dbo].[CompletionCandidates] TO [app_runtime_role];
            DENY UPDATE, DELETE ON OBJECT::[dbo].[CompletionCandidates] TO [app_runtime_role];
            GRANT SELECT, INSERT ON OBJECT::[dbo].[CompletionSealOutputs] TO [app_runtime_role];
            DENY UPDATE, DELETE ON OBJECT::[dbo].[CompletionSealOutputs] TO [app_runtime_role];
            GRANT SELECT, INSERT ON OBJECT::[dbo].[CompletionPublicationIntents] TO [app_runtime_role];
            DENY UPDATE, DELETE ON OBJECT::[dbo].[CompletionPublicationIntents] TO [app_runtime_role];
            GRANT SELECT, INSERT ON OBJECT::[dbo].[CompletionPublicationResults] TO [app_runtime_role];
            DENY UPDATE, DELETE ON OBJECT::[dbo].[CompletionPublicationResults] TO [app_runtime_role];
            GRANT SELECT ON OBJECT::[dbo].[__EFMigrationsHistory] TO [app_runtime_role];
            DENY INSERT, UPDATE, DELETE ON OBJECT::[dbo].[__EFMigrationsHistory] TO [app_runtime_role];
            """;
        await command.ExecuteNonQueryAsync();
    }

    public static async Task ProvisionWorkerAsync(SqlConnection connection, Guid clientId)
    {
        if (clientId == Guid.Empty) throw new ArgumentException("Supply the worker client ID.");
        var sid = "0x" + Convert.ToHexString(clientId.ToByteArray());
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            IF DATABASE_PRINCIPAL_ID(N'app_worker') IS NULL CREATE USER [app_worker] WITH SID = {sid}, TYPE = E;
            ELSE IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'app_worker' AND sid = {sid} AND type = 'E')
                THROW 50001, 'Existing database principal does not match the worker identity.', 1;
            ALTER ROLE [app_runtime_role] ADD MEMBER [app_worker];
            """;
        await command.ExecuteNonQueryAsync();
    }
}

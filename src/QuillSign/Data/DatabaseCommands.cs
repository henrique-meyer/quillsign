using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

public static class DatabaseCommands
{
    public static async Task<int> RunAsync(string[] args)
    {
        IConfiguration? configuration = null;
        if (args.Length != 1 || args[0] is not ("provision-identities" or "provision-worker" or "migrate" or "grant-runtime" or "verify-runtime"))
        {
            Console.Error.WriteLine("Usage: database provision-identities|provision-worker|migrate|grant-runtime|verify-runtime");
            return 2;
        }
        try
        {
            var builder = WebApplication.CreateBuilder();
            configuration = builder.Configuration;
            builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.None);
            builder.Services.AddQuillSignDatabase(builder.Configuration);
            using var provider = builder.Services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
            if (args[0] == "migrate") await SqlResume.RunAsync(() => db.Database.MigrateAsync());
            else if (args[0] == "verify-runtime") await VerifyRuntimeAsync(db);
            else
            {
                await db.Database.OpenConnectionAsync();
                var connection = (SqlConnection)db.Database.GetDbConnection();
                if (args[0] == "provision-identities")
                    await DatabasePermissions.ProvisionIdentitiesAsync(connection,
                        Guid.Parse(builder.Configuration["Database:RuntimeClientId"] ?? ""),
                        Guid.Parse(builder.Configuration["Database:MigrationClientId"] ?? ""));
                else if (args[0] == "provision-worker")
                    await DatabasePermissions.ProvisionWorkerAsync(connection, Guid.Parse(builder.Configuration["Database:WorkerClientId"] ?? ""));
                else await DatabasePermissions.GrantRuntimeAsync(connection);
            }
            Console.WriteLine($"{{\"operation\":\"{args[0]}\",\"status\":\"ok\"}}");
            return 0;
        }
        catch (Exception exception)
        {
            // Connection exceptions can include private endpoints; do not print their text.
            var code = exception is SqlException sql ? $", SQL error {sql.Number}" : "";
            var diagnosticFile = configuration?["Database:DiagnosticFile"];
            if (!string.IsNullOrWhiteSpace(diagnosticFile))
            {
                try { await File.WriteAllTextAsync(diagnosticFile, exception.ToString()); }
                catch (Exception diagnosticError) when (diagnosticError is IOException or UnauthorizedAccessException)
                { Console.Error.WriteLine("Could not write the private diagnostic file."); }
            }
            Console.Error.WriteLine($"Database command failed ({exception.GetType().Name}{code}).");
            return 1;
        }
    }

    // Explicit, operator-invoked verification only; never a health probe or periodic job.
    // Everything is rolled back, including an unexpected successful schema mutation.
    public static async Task VerifyRuntimeAsync(QuillSignDbContext db)
    {
        await using var transaction = await db.Database.BeginTransactionAsync();
        try
        {
            if ((await db.Database.GetPendingMigrationsAsync()).Any())
                throw new InvalidOperationException("Apply pending migrations through the migration identity first.");
            var envelope = new Envelope { SenderEmail = "probe@example.invalid", Title = "Synthetic permission probe" };
            db.Envelopes.Add(envelope);
            await db.SaveChangesAsync();
            envelope.Title = "Updated synthetic permission probe";
            await db.SaveChangesAsync();
            if (!await db.Envelopes.AnyAsync(x => x.Id == envelope.Id && x.Title == envelope.Title))
                throw new InvalidOperationException("Runtime read/write verification failed.");
            db.Envelopes.Remove(envelope);
            await db.SaveChangesAsync();

            db.ChangeTracker.Clear();
            envelope = new Envelope { SenderEmail = "probe@example.invalid" };
            db.Envelopes.Add(envelope);
            var audit = new AuditEvent { EnvelopeId = envelope.Id, Sequence = 1, At = DateTimeOffset.UtcNow,
                ActorType = PartyType.System, Event = "permission_probe" };
            audit.Hash = AuditHash.Compute(audit);
            db.AuditEvents.Add(audit);
            await db.SaveChangesAsync();
            if (!await db.AuditEvents.AnyAsync(x => x.EnvelopeId == envelope.Id))
                throw new InvalidOperationException("Runtime audit read/insert verification failed.");

            await DemandDenied(() => db.Database.ExecuteSqlInterpolatedAsync($"UPDATE [dbo].[AuditEvents] SET [Event] = 'forbidden' WHERE [Id] = {audit.Id}"));
            await DemandDenied(() => db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM [dbo].[AuditEvents] WHERE [Id] = {audit.Id}"));
            await DemandDenied(() => db.Database.ExecuteSqlRawAsync("UPDATE [dbo].[__EFMigrationsHistory] SET [ProductVersion] = 'forbidden'"));
            await DemandDenied(() => db.Database.ExecuteSqlRawAsync("CREATE TABLE [dbo].[__QuillSignPermissionProbe] ([Id] int NOT NULL)"));
        }
        finally
        {
            await transaction.RollbackAsync();
            db.ChangeTracker.Clear();
        }
    }

    private static async Task DemandDenied(Func<Task<int>> operation)
    {
        try { await operation(); }
        catch (SqlException exception) when (exception.Number is 229 or 262) { return; }
        throw new InvalidOperationException("Runtime has a database permission that should be denied.");
    }
}

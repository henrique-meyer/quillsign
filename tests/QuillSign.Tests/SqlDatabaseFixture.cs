using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Tests;

public sealed class SqlDatabaseFixture : IAsyncLifetime
{
    private string? connection;
    public QuillSignDbContext Open() => new(new DbContextOptionsBuilder<QuillSignDbContext>()
        .UseSqlServer(connection ?? throw new InvalidOperationException("Test fixture was not initialized.")).Options);

    public async Task InitializeAsync()
    {
        var source = Environment.GetEnvironmentVariable("QUILLSIGN_TEST_DATABASE");
        if (string.IsNullOrWhiteSpace(source))
            throw new InvalidOperationException("Run scripts/dev/Use-LocalDatabase.ps1 -Action Test with the local SQL service running.");
        var builder = new SqlConnectionStringBuilder(source)
        {
            InitialCatalog = "QuillSignTests_" + Guid.NewGuid().ToString("N")
        };
        connection = builder.ConnectionString;
        await using var db = Open();
        await db.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        if (connection is null) return;
        var name = new SqlConnectionStringBuilder(connection).InitialCatalog;
        if (!name.StartsWith("QuillSignTests_", StringComparison.Ordinal))
            throw new InvalidOperationException("Refusing to delete a database outside this fixture.");
        await using var db = Open();
        await db.Database.EnsureDeletedAsync();
    }
}

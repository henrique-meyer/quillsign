using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace QuillSign.Data;

public static class DatabaseConfiguration
{
    public static void AddQuillSignDatabase(this IServiceCollection services, IConfiguration config)
    {
        services.AddDbContext<QuillSignDbContext>(options =>
        {
            var connection = config.GetConnectionString("Database");
            if (string.IsNullOrWhiteSpace(connection))
                throw new InvalidOperationException("Set ConnectionStrings__Database before using database features.");
            options.UseSqlServer(connection);
        });
    }
}

public sealed class QuillSignDbContextFactory : IDesignTimeDbContextFactory<QuillSignDbContext>
{
    public QuillSignDbContext CreateDbContext(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var connection = builder.Configuration.GetConnectionString("Database");
        // A provider-only context allows migration generation without credentials or a connection.
        var options = new DbContextOptionsBuilder<QuillSignDbContext>();
        if (string.IsNullOrWhiteSpace(connection)) options.UseSqlServer();
        else options.UseSqlServer(connection);
        return new QuillSignDbContext(options.Options);
    }
}

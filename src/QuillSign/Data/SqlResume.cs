using Microsoft.Data.SqlClient;

namespace QuillSign.Data;

public static class SqlResume
{
    public static bool IsUnavailable(Exception error) => error.GetBaseException() is SqlException { Number: 40613 };

    // Only an explicit migration or received work item invokes this. It never runs
    // during startup, health checks, or an empty-queue recovery pass.
    public static async Task RunAsync(Func<Task> operation, CancellationToken cancellationToken = default)
    {
        for (var attempt = 0; ; attempt++)
        {
            try { await operation(); return; }
            catch (Exception e) when (attempt < 3 && IsUnavailable(e))
            { await Task.Delay(TimeSpan.FromSeconds(10 * (attempt + 1)), cancellationToken); }
        }
    }
}

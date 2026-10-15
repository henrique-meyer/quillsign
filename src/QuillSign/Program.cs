using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Work;
using QuillSign.Storage;
using QuillSign.Sender;

if (args.Length > 0 && args[0] == "database")
{
    Environment.ExitCode = await DatabaseCommands.RunAsync(args[1..]);
    return;
}
if (args.Length > 0 && args[0] == "work")
{
    Environment.ExitCode = await WorkCommands.RunAsync(args[1..]);
    return;
}

var builder = WebApplication.CreateBuilder(args);
// Linked brand assets are copied to the build output; include them during dotnet run.
var outputWebRoot = Path.Combine(AppContext.BaseDirectory, "wwwroot");
if (builder.Environment.IsDevelopment() && Directory.Exists(outputWebRoot))
    builder.Environment.WebRootFileProvider = new Microsoft.Extensions.FileProviders.CompositeFileProvider(
        builder.Environment.WebRootFileProvider, new Microsoft.Extensions.FileProviders.PhysicalFileProvider(outputWebRoot));
builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning); // Magic links must not enter request-URL logs.
builder.Services.AddRazorPages();
builder.Services.AddQuillSignDatabase(builder.Configuration);
builder.Services.AddQuillSignStorage(builder.Configuration, builder.Environment);
builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
builder.Services.AddQuillSignWork(builder.Configuration, builder.Environment);
builder.Services.AddQuillSignSender(builder.Configuration, builder.Environment);
var app = builder.Build();
app.UseForwardedHeaders();

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    await next();
});
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
app.MapSesFeedback();
// Liveness must never wake the serverless database or call an external service.
app.MapGet("/health", () => Results.Json(new { status = "ok" }));
app.Run();

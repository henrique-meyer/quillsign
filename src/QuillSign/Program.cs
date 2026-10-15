using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Storage;

if (args.Length > 0 && args[0] == "database")
{
    Environment.ExitCode = await DatabaseCommands.RunAsync(args[1..]);
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddQuillSignDatabase(builder.Configuration);
builder.Services.AddQuillSignStorage(builder.Configuration, builder.Environment);
builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    await next();
});
app.UseStaticFiles();
app.MapRazorPages();
app.MapSesFeedback();
// Liveness must never wake the serverless database or call an external service.
app.MapGet("/health", () => Results.Json(new { status = "ok" }));
app.Run();

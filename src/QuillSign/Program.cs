using QuillSign.Data;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddQuillSignDatabase(builder.Configuration);
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
// Liveness must never wake the serverless database or call an external service.
app.MapGet("/health", () => Results.Json(new { status = "ok" }));
app.Run();

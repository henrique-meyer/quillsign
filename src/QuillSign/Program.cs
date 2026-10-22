using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;
using QuillSign.Storage;
using QuillSign.Sender;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Sealing;
using QuillSign.Completion;
using QuillSign.Verification;

// Use the same effective web/command configuration before ANY early dispatch.
var (builder,privateWeb)=EmailPilotCloseoutWebStartup.Prepare(args);

if (args.Length > 0 && args[0] == "staging")
{
    Environment.ExitCode = await QuillSign.Operations.StagingCommands.RunAsync(args[1..]);
    return;
}

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

EmailPilotCloseoutWebStartup.Demand(builder.Configuration,privateWeb);
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
builder.Services.AddQuillSignSignerAccess(builder.Configuration,builder.Environment);
builder.Services.AddQuillSignSignerConsent();
builder.Services.AddScoped<SignaturePreviewProtection>();
builder.Services.AddScoped<SignatureAdoption>();
builder.Services.AddScoped<SignerFields>();
builder.Services.AddScoped<SignerFieldView>();
builder.Services.AddScoped<SignerReviewProtection>();
builder.Services.AddScoped<SignerReviewCandidates>();
builder.Services.AddScoped<SignerFinish>();
builder.Services.AddScoped<SignerCheckpointReads>();
builder.Services.AddSignerReviewBrowser();
builder.Services.AddQuillSignSignerSetup(builder.Configuration);
builder.Services.AddQuillSignFieldEditor(builder.Configuration);
builder.Services.AddQuillSignDocuments(builder.Configuration);
builder.Services.AddPlatformPdfSeals(builder.Configuration);
builder.Services.AddScoped<SendDraftWorkflow>();
builder.Services.AddScoped<Func<SendDraftWorkflow>>(sp=>()=>sp.GetRequiredService<SendDraftWorkflow>());
builder.Services.AddScoped<SenderSentStatus>();
builder.Services.AddScoped<Func<SenderSentStatus>>(sp=>()=>sp.GetRequiredService<SenderSentStatus>());
builder.Services.AddScoped<SenderSendReadiness>();
builder.Services.AddCompletionDownloads();
builder.Services.AddDocumentLookup(builder.Configuration);
builder.Services.AddCompletionReaderBrowser(builder.Environment);
builder.Services.AddDocumentLookupBrowser(builder.Environment);
builder.Services.AddPdfVerificationBrowser(builder.Configuration);
builder.Services.AddRestrictedEmailPilotRuntime(builder.Configuration,privateWeb:privateWeb);
if(privateWeb)builder.Services.AddScoped<EmailPilotCloseoutWebAccess>();
var app = builder.Build();
app.UseForwardedHeaders();
if(privateWeb)app.UseCloseoutWebRoutes();

app.Use(async (context, next) =>
{
    SenderConfiguration.PrivateStatusHeaders(context);
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.OnStarting(() =>
    {
        context.Response.Headers["Content-Security-Policy"] = QuillSign.Analytics.PublicAnalytics.ContentSecurityPolicy(context, app.Configuration);
        return Task.CompletedTask;
    });
    if (HttpMethods.IsPost(context.Request.Method) && context.Request.Path.StartsWithSegments("/draft"))
    {
        var body = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
        if (body is { IsReadOnly: false }) body.MaxRequestBodySize = app.Services.GetRequiredService<DocumentOptions>().MaximumBytes + 65536;
    }
    await next();
});
app.UseStaticFiles();
app.UseRouting();
app.UseDocumentLookupBrowser();
app.UseRateLimiter();
app.UseMiddleware<VerificationUploadBoundary>();
app.UseAuthentication();
if(privateWeb)app.UseCloseoutWebAccess();
app.UseAuthorization();
app.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
app.MapSesFeedback();
app.MapFieldEditor();
// Liveness must never wake the serverless database or call an external service.
app.MapGet("/health", () => Results.Json(new { status = "ok" }));
app.Run();

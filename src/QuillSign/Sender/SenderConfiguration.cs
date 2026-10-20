using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Sender;

public static class SenderConfiguration
{
    public const string PublicIdClaim = "quillsign:public-id";
    public const string RatePolicy = "sender";

    public static IServiceCollection AddQuillSignSender(this IServiceCollection services, IConfiguration config, IHostEnvironment environment)
    {
        var options = config.GetSection("Sender").Get<SenderOptions>() ?? new();
        if (options.SessionHours is < 1 or > 24 || options.DailyRequests is < 1 or > 100 ||
            options.RequestsPerWindow is < 1 or > 1000 || options.WindowMinutes is < 1 or > 60)
            throw new InvalidOperationException("Invalid sender session or request limits.");
        services.AddSingleton(options);
        services.AddSingleton(config.GetSection("Files").Get<Documents.PdfFilePresentationOptions>() ?? new());
        services.Configure<Microsoft.AspNetCore.Mvc.MvcOptions>(mvc=>mvc.Filters.Add<Documents.PdfFilePresentationFilter>());
        services.AddSingleton<SenderAvailability>();
        services.AddScoped<SenderWorkflow>();
        // Scanner-safe/custom hosts can register sender HTTP plumbing without SQL.
        // Resolve the mutation backend only when a trusted caller invokes it.
        services.AddScoped<SenderVoid>(sp=> {
            var db=sp.GetRequiredService<QuillSignDbContext>();var clock=sp.GetRequiredService<TimeProvider>();
            return new(db,new(db,clock),sp.GetRequiredService<AuditWriter>(),clock,sp.GetService<Func<Work.VoidNotificationJobs>>(),sp.GetService<Email.Pilot.EmailPilotReadBounds>());
        });
        services.AddScoped<SenderVoidState>(sp=> {
            var db=sp.GetRequiredService<QuillSignDbContext>();var clock=sp.GetRequiredService<TimeProvider>();
            return new(db,new(db,clock),clock,sp.GetService<Email.Pilot.EmailPilotReadBounds>());
        });
        services.AddScoped<Func<SenderVoidState>>(sp=>()=>sp.GetRequiredService<SenderVoidState>());
        services.AddScoped<Func<Work.EmailOutboxWriter>>(sp => () => sp.GetRequiredService<Work.EmailOutboxWriter>());
        services.AddScoped<Func<SenderWorkflow>>(sp => () => sp.GetRequiredService<SenderWorkflow>());
        services.AddScoped<AuditWriter>();
        services.AddScoped<BrowserNotices>();
        services.AddScoped<InvitationResendReviewProtection>();
        services.AddScoped<Func<InvitationResends>>(sp=>()=>sp.GetRequiredService<InvitationResends>());
        services.AddQuillSignSignerContactCorrections(config);
        services.AddScoped<SignerContactCorrectionBrowser>();
        services.AddAuthentication(EnvelopeStorageAuthorization.SenderScheme).AddCookie(EnvelopeStorageAuthorization.SenderScheme, cookie =>
        {
            cookie.Cookie.Name = environment.IsDevelopment() ? "QuillSign.Sender" : "__Host-QuillSign.Sender";
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.SameSite = SameSiteMode.Lax;
            cookie.Cookie.SecurePolicy = environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            cookie.ExpireTimeSpan = TimeSpan.FromHours(options.SessionHours);
            cookie.SlidingExpiration = false;
            cookie.LoginPath = "/";
            cookie.Events.OnRedirectToLogin = context =>
            {
                if (WantsJson(context.HttpContext)) context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                else
                {
                    context.HttpContext.RequestServices.GetRequiredService<BrowserNotices>().Set(context.HttpContext, NoticeCode.SessionRequired);
                    context.Response.Redirect("/");
                }
                return Task.CompletedTask;
            };
            cookie.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };
        });
        services.AddOptions<CookieAuthenticationOptions>(EnvelopeStorageAuthorization.SenderScheme)
            .Configure<TimeProvider>((cookie, time) => cookie.TimeProvider = time);
        services.AddAuthorization();
        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.OnRejected = async (rejected,ct) =>
            {
                var context=rejected.HttpContext;
                if(context.Request.Path.StartsWithSegments("/operator")) {
                    PrivateStatusHeaders(context);
                    const string message="Too many operator requests. Wait and check saved status before repeating an action.";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new{message},ct);
                    else await context.Response.WriteAsync(message,ct);
                    return;
                }
                if(IsContactCorrection(context.Request.Path)) {
                    PrivateStatusHeaders(context);
                    const string message="Too many contact correction actions. Wait and check saved request status before retrying; this response does not confirm a correction.";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new {message},ct);
                    else {context.Response.ContentType="text/html; charset=utf-8";await context.Response.WriteAsync("<!doctype html><html lang=\"en\"><head><title>Wait before retrying</title></head><body><main><h1>Wait before retrying</h1><p>"+message+"</p><p><a href=\""+System.Net.WebUtility.HtmlEncode(context.Request.Path.Value!.TrimEnd('/')[..^15]+"sent")+"\">Check saved request status</a></p></main></body></html>",ct);}return;
                }
                if(IsResend(context.Request.Path)) {
                    PrivateStatusHeaders(context);
                    const string message="Too many resend actions. Wait before retrying and check saved request status first; no new replacement is confirmed by this response.";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new {message},ct);
                    else {context.Response.ContentType="text/html; charset=utf-8";await context.Response.WriteAsync("<!doctype html><html lang=\"en\"><head><title>Wait before retrying</title></head><body><main><h1>Wait before retrying</h1><p>"+message+"</p><p><a href=\""+System.Net.WebUtility.HtmlEncode(context.Request.Path.Value![..^6]+"sent")+"\">Check saved request status</a></p></main></body></html>",ct);}return;
                }
                if(QuillSign.Verification.VerificationBrowser.IsPath(context)) {
                    await QuillSign.Verification.VerificationBrowser.Error(context,429,"Verification is busy or its request limit was reached. Wait before selecting and submitting your PDF again; no integrity result is confirmed.",ct);return;
                }
                if(context.Request.Path.StartsWithSegments("/draft") && context.Request.Path.Value is { } voidPath && voidPath.EndsWith("/void",StringComparison.Ordinal)) {
                    const string message="Too many void actions. Wait before retrying and check saved request status first; no new void is confirmed by this response.";
                    context.Response.Headers.CacheControl="no-store";context.Response.Headers["Referrer-Policy"]="no-referrer";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new {message},ct);
                    else {context.Response.ContentType="text/html; charset=utf-8";await context.Response.WriteAsync("<!doctype html><html lang=\"en\"><head><title>Wait before retrying</title></head><body><main><h1>Wait before retrying</h1><p>"+message+"</p><p><a href=\""+System.Net.WebUtility.HtmlEncode(voidPath[..^4]+"sent")+"\">Check saved request status</a></p></main></body></html>",ct);}return;
                }
                if(context.Request.Path.StartsWithSegments("/complete")) {
                    context.Response.Headers.CacheControl="no-store"; context.Response.Headers["Referrer-Policy"]="no-referrer";
                    const string message="Too many completed-record requests. Wait before retrying. If access was already opened, return to your saved records; do not assume the link is unused.";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new {message},ct);
                    else await context.Response.WriteAsync(message,ct); return;
                }
                if(context.Request.Path.StartsWithSegments("/find")) {
                    const string message="Too many document lookup requests. Wait before trying again. If you already opened your documents, return to that view.";
                    context.Response.Headers.CacheControl="no-store";context.Response.Headers["Referrer-Policy"]="no-referrer";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new {message},ct);
                    else {var target=context.Request.Path.StartsWithSegments("/find/request") ? "/find/request" : "/find/access";context.Response.ContentType="text/html; charset=utf-8";await context.Response.WriteAsync("<!doctype html><html lang=\"en\"><head><title>Wait before retrying</title></head><body><main><h1>Wait before retrying</h1><p>"+message+"</p><p><a href=\""+target+"\">Return to lookup access</a></p></main></body></html>",ct);}return;
                }
                if(IsFinalFile(context.Request.Path) || context.Request.Query["handler"]=="Download" &&
                    (context.Request.Path.StartsWithSegments("/draft") || context.Request.Path.StartsWithSegments("/sign"))) {
                    context.Response.Headers.CacheControl="no-store"; context.Response.Headers["Referrer-Policy"]="no-referrer";
                    const string downloadMessage="Too many download requests. Wait before preparing a new download from your private confirmation page.";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new {message=downloadMessage},ct);
                    else await context.Response.WriteAsync(downloadMessage,ct); return;
                }
                if(context.Request.Path.StartsWithSegments("/draft") && context.Request.Path.Value is { } draftPath &&
                    (draftPath.EndsWith("/review",StringComparison.Ordinal) || draftPath.EndsWith("/sent",StringComparison.Ordinal))) {
                    const string message="Too many request actions. Wait before retrying and check private status before repeating Send.";
                    context.Response.Headers.CacheControl="no-store"; context.Response.Headers["Referrer-Policy"]="no-referrer";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new { message },ct);
                    else { context.Response.ContentType="text/html; charset=utf-8"; await context.Response.WriteAsync("<!doctype html><html lang=\"en\"><head><title>Wait before retrying</title></head><body><main><h1>Wait before retrying</h1><p>"+message+"</p><p><a href=\""+System.Net.WebUtility.HtmlEncode(draftPath)+"\">Check saved request state</a></p></main></body></html>",ct); }
                    return;
                }
                if(context.Request.Path.StartsWithSegments("/sign") && context.Request.Path.Value is { } path &&
                    (path.EndsWith("/signature",StringComparison.Ordinal) || path.EndsWith("/fields",StringComparison.Ordinal) || path.EndsWith("/review",StringComparison.Ordinal) || path.EndsWith("/confirmed",StringComparison.Ordinal)))
                {
                    var isSignature=path.EndsWith("/signature",StringComparison.Ordinal);
                    var isReview=path.EndsWith("/review",StringComparison.Ordinal) || path.EndsWith("/confirmed",StringComparison.Ordinal);
                    var message=isSignature ? "Too many signature requests. Wait before trying again; adoption has not been confirmed." :
                        isReview ? "Too many review requests. Wait before retrying. Check your signing confirmation before repeating Finish." :
                        "Too many field requests. Wait before retrying and refresh saved state; saving has not been confirmed.";
                    context.Response.Headers.CacheControl="no-store";
                    context.Response.Headers["Referrer-Policy"]="no-referrer";
                    if(WantsJson(context))await context.Response.WriteAsJsonAsync(new { message },ct);
                    else { context.Response.ContentType="text/html; charset=utf-8"; await context.Response.WriteAsync("<!doctype html><html lang=\"en\"><head><title>Wait before retrying</title></head><body><main><h1>Wait before retrying</h1><p>"+message+"</p><p><a href=\""+System.Net.WebUtility.HtmlEncode(path)+"\">"+(isSignature ? "Return to your signature page" : "Return to saved fields")+"</a></p></main></body></html>",ct); }
                }
            };
            limiter.AddPolicy(RatePolicy, context =>
            {
                var limited = (context.Request.Path == "/" && HttpMethods.IsPost(context.Request.Method)) || context.Request.Path == "/sender/verify" || context.Request.Path == "/sign/invitation" ||
                    (context.Request.Path.StartsWithSegments("/draft") && context.Request.Path.Value?.EndsWith("/review",StringComparison.Ordinal)==true && HttpMethods.IsPost(context.Request.Method)) ||
                    (context.Request.Path.StartsWithSegments("/sign") && context.Request.Path.Value?.EndsWith("/signature",StringComparison.Ordinal) == true && HttpMethods.IsPost(context.Request.Method));
                var address = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                if(context.Request.Path.StartsWithSegments("/operator"))
                    return RateLimitPartition.GetFixedWindowLimiter((HttpMethods.IsPost(context.Request.Method)?"pilot-operator-action:":"pilot-operator-read:")+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=HttpMethods.IsPost(context.Request.Method)?Math.Min(20,options.RequestsPerWindow):120,
                        Window=TimeSpan.FromMinutes(HttpMethods.IsPost(context.Request.Method)?options.WindowMinutes:1),QueueLimit=0,AutoReplenishment=true });
                if(IsContactCorrection(context.Request.Path))
                    return RateLimitPartition.GetFixedWindowLimiter((HttpMethods.IsPost(context.Request.Method) ? "sender-contact-correction-action:" : "sender-contact-correction-read:")+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=options.RequestsPerWindow,Window=TimeSpan.FromMinutes(options.WindowMinutes),QueueLimit=0,AutoReplenishment=true });
                if(IsResend(context.Request.Path))
                    return RateLimitPartition.GetFixedWindowLimiter((HttpMethods.IsPost(context.Request.Method) ? "sender-resend-action:" : "sender-resend-read:")+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=options.RequestsPerWindow,Window=TimeSpan.FromMinutes(options.WindowMinutes),QueueLimit=0,AutoReplenishment=true });
                if(context.Request.Path.StartsWithSegments("/find/request") && HttpMethods.IsPost(context.Request.Method))
                    return RateLimitPartition.GetFixedWindowLimiter("lookup-request:"+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=options.RequestsPerWindow,Window=TimeSpan.FromMinutes(options.WindowMinutes),QueueLimit=0,AutoReplenishment=true });
                if(context.Request.Path.StartsWithSegments("/find/access") && HttpMethods.IsPost(context.Request.Method))
                    return RateLimitPartition.GetFixedWindowLimiter("lookup-entry:"+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=options.RequestsPerWindow,Window=TimeSpan.FromMinutes(options.WindowMinutes),QueueLimit=0,AutoReplenishment=true });
                if(context.Request.Path.StartsWithSegments("/find"))
                    return RateLimitPartition.GetFixedWindowLimiter((HttpMethods.IsPost(context.Request.Method) ? "lookup-action:" : "lookup-read:")+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=HttpMethods.IsPost(context.Request.Method) ? 30 : 120,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true });
                if(QuillSign.Verification.VerificationBrowser.IsPath(context))
                    return RateLimitPartition.GetFixedWindowLimiter((HttpMethods.IsPost(context.Request.Method) ? "pdf-verification-action:" : "pdf-verification-read:")+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=HttpMethods.IsPost(context.Request.Method) ? context.RequestServices.GetService<QuillSign.Verification.VerificationBrowserOptions>()?.RequestsPerMinute??10 : 120,
                        Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true });
                if(context.Request.Path.StartsWithSegments("/draft") && context.Request.Path.Value?.EndsWith("/void",StringComparison.Ordinal)==true)
                    return RateLimitPartition.GetFixedWindowLimiter((HttpMethods.IsPost(context.Request.Method) ? "sender-void-action:" : "sender-void-read:")+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=HttpMethods.IsPost(context.Request.Method) ? Math.Min(10,options.RequestsPerWindow) : 120,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true });
                if(context.Request.Path=="/complete/access" && HttpMethods.IsPost(context.Request.Method))
                    return RateLimitPartition.GetFixedWindowLimiter("completion-entry:"+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=options.RequestsPerWindow,Window=TimeSpan.FromMinutes(options.WindowMinutes),QueueLimit=0,AutoReplenishment=true });
                if(context.Request.Path.StartsWithSegments("/complete") && context.Request.Path!="/complete/access")
                    return RateLimitPartition.GetFixedWindowLimiter("completion-records:"+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=120,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true });
                if(IsFinalFile(context.Request.Path))return RateLimitPartition.GetFixedWindowLimiter("final-download:"+address,_=>new FixedWindowRateLimiterOptions {
                    PermitLimit=120,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true });
                if(context.Request.Path.StartsWithSegments("/draft") && context.Request.Path.Value?.EndsWith("/sent",StringComparison.Ordinal)==true)
                    return RateLimitPartition.GetFixedWindowLimiter("sender-status:"+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=120,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true });
                if(context.Request.Path.StartsWithSegments("/sign") && context.Request.Path.Value is { } fieldPath &&
                    (fieldPath.EndsWith("/fields",StringComparison.Ordinal) || fieldPath.EndsWith("/review",StringComparison.Ordinal) || fieldPath.EndsWith("/confirmed",StringComparison.Ordinal)))
                    return RateLimitPartition.GetFixedWindowLimiter("signer-fields:"+address,_=>new FixedWindowRateLimiterOptions {
                        PermitLimit=120,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true });
                return limited ? RateLimitPartition.GetFixedWindowLimiter(address, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = options.RequestsPerWindow, Window = TimeSpan.FromMinutes(options.WindowMinutes),
                    QueueLimit = 0, AutoReplenishment = true
                }) : RateLimitPartition.GetNoLimiter("unlimited");
            });
        });
        if (!string.IsNullOrWhiteSpace(config["CONTAINER_APP_NAME"]))
            services.Configure<ForwardedHeadersOptions>(forwarded =>
            {
                // Only the platform-hosted app accepts its ingress's last forwarded hop.
                // Standalone/self-hosted deployments keep the framework's trusted defaults.
                forwarded.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                forwarded.ForwardLimit = 1;
                forwarded.KnownIPNetworks.Clear();
                forwarded.KnownProxies.Clear();
            });
        return services;
    }

    public static bool WantsJson(HttpContext context) => context.Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase);
    private static bool IsContactCorrection(PathString path) => path.StartsWithSegments("/draft") && path.Value?.TrimEnd('/').EndsWith("/correct-contact",StringComparison.OrdinalIgnoreCase)==true;
    private static bool IsResend(PathString path) => path.StartsWithSegments("/draft") && path.Value?.EndsWith("/resend",StringComparison.Ordinal)==true;
    // Called before authorization/CSRF/rate rejection as well as page handlers.
    public static void PrivateStatusHeaders(HttpContext context)
    {
        if(context.Request.Path.StartsWithSegments("/operator")) {Email.Pilot.EmailPilotOperatorBrowser.PrivateHeaders(context);return;}
        if(!IsContactCorrection(context.Request.Path) && !IsResend(context.Request.Path) && !(context.Request.Path.StartsWithSegments("/draft") && context.Request.Path.Value?.EndsWith("/sent",StringComparison.Ordinal)==true))return;
        context.Response.Headers.CacheControl="no-store";context.Response.Headers["Referrer-Policy"]="no-referrer";
        context.Response.Headers["X-Robots-Tag"]="noindex, nofollow, noarchive";
    }
    private static bool IsFinalFile(PathString path) {
        var parts=path.Value?.Split('/'); return parts is {Length:5} && parts[1] is "draft" or "sign" && parts[3]=="final";
    }

    public static ClaimsPrincipal Principal(VerifiedSender sender) => new(new ClaimsIdentity([
        new Claim(EnvelopeStorageAuthorization.EnvelopeClaim, sender.EnvelopeId.ToString()),
        new Claim(PublicIdClaim, sender.PublicId), new Claim(ClaimTypes.Email, sender.Email)
    ], EnvelopeStorageAuthorization.SenderScheme));
}

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
        services.AddSingleton<SenderAvailability>();
        services.AddScoped<SenderWorkflow>();
        services.AddScoped<Func<Work.EmailOutboxWriter>>(sp => () => sp.GetRequiredService<Work.EmailOutboxWriter>());
        services.AddScoped<Func<SenderWorkflow>>(sp => () => sp.GetRequiredService<SenderWorkflow>());
        services.AddScoped<AuditWriter>();
        services.AddScoped<BrowserNotices>();
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
            limiter.AddPolicy(RatePolicy, context =>
            {
                var limited = (context.Request.Path == "/" && HttpMethods.IsPost(context.Request.Method)) || context.Request.Path == "/sender/verify";
                var address = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
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

    public static ClaimsPrincipal Principal(VerifiedSender sender) => new(new ClaimsIdentity([
        new Claim(EnvelopeStorageAuthorization.EnvelopeClaim, sender.EnvelopeId.ToString()),
        new Claim(PublicIdClaim, sender.PublicId), new Claim(ClaimTypes.Email, sender.Email)
    ], EnvelopeStorageAuthorization.SenderScheme));
}

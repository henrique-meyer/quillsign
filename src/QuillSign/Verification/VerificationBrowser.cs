using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Completion;

namespace QuillSign.Verification;

public sealed class VerificationBrowserOptions
{
    public int RequestsPerMinute {get;set;}=10;
    public int BodyTimeoutSeconds {get;set;}=30;
    public void Validate() {
        if(RequestsPerMinute is <1 or >20 || BodyTimeoutSeconds is <1 or >30)throw new InvalidOperationException("Invalid verification request limits.");
    }
}
public static class VerificationBrowser
{
    public static bool IsPath(HttpContext http)=>string.Equals(http.Request.Path.Value?.TrimEnd('/'),"/verify",StringComparison.OrdinalIgnoreCase);
    public static void Private(HttpContext http) {
        http.Response.Headers.CacheControl="no-store";http.Response.Headers["Referrer-Policy"]="no-referrer";http.Response.Headers["X-Content-Type-Options"]="nosniff";
    }
    public static async Task Error(HttpContext http,int status,string message,CancellationToken ct=default)
    {
        Private(http);http.Response.StatusCode=status;
        if(QuillSign.Sender.SenderConfiguration.WantsJson(http))await http.Response.WriteAsJsonAsync(new {status=status is 400 or 413 ? "RejectedInput" : "Unavailable",message},ct);
        else {
            http.Response.ContentType="text/html; charset=utf-8";
            await http.Response.WriteAsync("<!doctype html><html lang=\"en\"><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>PDF verification</title></head><body><main><h1>PDF verification</h1><p role=\"alert\">"+
                System.Net.WebUtility.HtmlEncode(message)+"</p><p><a href=\"/verify\">Choose a PDF again</a></p></main></body></html>",ct);
        }
    }
    public static IServiceCollection AddPdfVerificationBrowser(this IServiceCollection services,IConfiguration config)
    {
        services.AddUploadedPdfVerification(config);
        var options=config.GetSection("PdfVerification").Get<VerificationBrowserOptions>()??new();options.Validate();services.TryAddSingleton(options);
        services.TryAddScoped<Func<UploadedPdfVerification>>(sp=>()=>sp.GetRequiredService<UploadedPdfVerification>());
        services.Configure<RateLimiterOptions>(limits=> {
            var memory=PartitionedRateLimiter.Create<HttpContext,string>(http=>IsPath(http) && HttpMethods.IsPost(http.Request.Method) ?
                RateLimitPartition.GetConcurrencyLimiter("pdf-verification-memory",_=>new ConcurrencyLimiterOptions {PermitLimit=1,QueueLimit=0}) : RateLimitPartition.GetNoLimiter("other"));
            limits.GlobalLimiter=limits.GlobalLimiter is { } existing ? PartitionedRateLimiter.CreateChained(existing,memory) : memory;
        });
        return services;
    }
}

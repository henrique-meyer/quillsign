using System.Text.RegularExpressions;

namespace QuillSign.Analytics;

/// <summary>One public landing page; no transaction routes or request-derived metadata.</summary>
public static partial class PublicAnalytics
{
    public const string DefaultPolicy = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self' data: blob:; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

    public static string? MeasurementId(HttpContext context, IConfiguration configuration)
    {
        var request = context.Request;
        var id = configuration["Analytics:MeasurementId"];
        return bool.TryParse(configuration["Analytics:Enabled"], out var enabled) && enabled &&
            HttpMethods.IsGet(request.Method) && request.Path == "/" &&
            !request.QueryString.HasValue && context.Response.StatusCode == StatusCodes.Status200OK &&
            id is not null && IdPattern().IsMatch(id) ? id : null;
    }

    public static string ContentSecurityPolicy(HttpContext context, IConfiguration configuration) =>
        MeasurementId(context, configuration) is null ? DefaultPolicy : DefaultPolicy
            .Replace("script-src 'self' 'wasm-unsafe-eval'", "script-src 'self' 'wasm-unsafe-eval' https://www.googletagmanager.com", StringComparison.Ordinal)
            .Replace("img-src 'self' data: blob:", "img-src 'self' data: blob: https://www.google-analytics.com https://region1.google-analytics.com", StringComparison.Ordinal)
            + "; connect-src 'self' https://www.googletagmanager.com https://www.google-analytics.com https://region1.google-analytics.com";

    [GeneratedRegex(@"\AG-[A-Z0-9]{4,20}\z", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();
}

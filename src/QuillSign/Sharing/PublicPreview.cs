namespace QuillSign.Sharing;

public sealed record PublicPreview(string Title, string Description, string CanonicalUrl, string ImageUrl)
{
    // Only stable public entry pages can publish cards. Never use request Host,
    // query strings, ViewData or transaction content to construct a preview.
    public static PublicPreview? For(HttpContext context, IConfiguration configuration)
    {
        if ((!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method)) ||
            context.Response.StatusCode != StatusCodes.Status200OK || context.Request.QueryString.HasValue)
            return null;

        var page = context.Request.Path.Value switch
        {
            "/" => ("QuillSign · Open-source e-signatures", "Explore QuillSign, an open-source e-signature app with no accounts or subscriptions. Open the PDF verification and completed-document lookup tools."),
            "/verify" => ("Verify a PDF · QuillSign", "Check whether a PDF matches a completed file retained by this QuillSign instance, and whether its seal and timestamp evidence verify. The upload is processed in memory and is not saved."),
            "/find/request" => ("Find your completed documents · QuillSign", "Find completed documents still retained for an email address you used as a sender, signer or completion recipient. Request a lookup link when email delivery is available, or use an existing link."),
            _ => ((string Title, string Description)?)null
        };
        if (page is null ||
            !Uri.TryCreate(configuration["PublicSite:Origin"], UriKind.Absolute, out var origin) ||
            origin.Scheme != Uri.UriSchemeHttps || origin.Host.Length == 0 || origin.UserInfo.Length != 0 ||
            origin.AbsolutePath != "/" || origin.Query.Length != 0 || origin.Fragment.Length != 0)
            return null;

        return new(page.Value.Title, page.Value.Description,
            new Uri(origin, context.Request.Path.Value!).AbsoluteUri,
            new Uri(origin, "/logo.png").AbsoluteUri);
    }
}

using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.WebUtilities;

namespace QuillSign.Email;

public sealed record SenderMagicLinkModel(Uri Link);

public sealed class VerificationEmailTemplate(EmailOptions options,RazorEmailViews views)
{
    public async Task<OutgoingEmail> RenderAsync(string recipient, string token, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var address = EmailAddress.Normalize(recipient);
        if (!Regex.IsMatch(token, "^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant))
            throw new ArgumentException("A 256-bit URL-safe token is required.");
        var baseUri = new Uri(options.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var url = QueryHelpers.AddQueryString(new Uri(baseUri, "sender/verify").AbsoluteUri, "token", token);
        var model = new SenderMagicLinkModel(new Uri(url));
        var text = await views.RenderAsync("/Views/Email/SenderMagicLink.text.cshtml", model);
        var html = await views.RenderAsync("/Views/Email/SenderMagicLink.html.cshtml", model);
        return new OutgoingEmail(address, "Verify your email to start your document", text, html);
    }

}

public sealed class RazorEmailViews(IRazorViewEngine views,ITempDataProvider tempData,IServiceProvider services)
{
    public async Task<string> RenderAsync<T>(string path,T model)
    {
        var result = views.GetView(null, path, true);
        if (!result.Success) throw new InvalidOperationException("The email template was not found.");
        var http = new DefaultHttpContext { RequestServices = services };
        var action = new ActionContext(http, new RouteData(), new ActionDescriptor());
        var data = new ViewDataDictionary<T>(new EmptyModelMetadataProvider(), new ModelStateDictionary()) { Model = model };
        using var writer = new StringWriter();
        await result.View.RenderAsync(new ViewContext(action, result.View, data, new TempDataDictionary(http, tempData), writer, new HtmlHelperOptions()));
        return writer.ToString();
    }
}

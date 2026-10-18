using QuillSign.Completion;

namespace QuillSign.Email;

public sealed record LookupEmailModel(Uri Link, Uri Entry, string Code, DateTimeOffset ExpiresAt);

public sealed class LookupEmailTemplate(EmailOptions options, RazorEmailViews views, DocumentLookupProtection protection, IHostEnvironment environment)
{
    internal async Task<OutgoingEmail> RenderAsync(string recipient, DocumentLookupLink link, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var address = EmailAddress.Normalize(recipient); var issued = protection.Link(link.Transport);
        if (issued is null || issued.TokenId != link.TokenId || issued.Email != address || issued.ExpiresAt != link.ExpiresAt)
            throw new InvalidDataException("Lookup mail link is unavailable.");
        if (!Uri.TryCreate(options.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute, out var root) || root.UserInfo.Length != 0 ||
            root.Query.Length != 0 || root.Fragment.Length != 0 ||
            root.Scheme != "https" && !(environment.IsDevelopment() && root.Scheme == "http" && root.IsLoopback))
            throw new InvalidDataException("Lookup mail origin is unavailable.");
        var entry = new Uri(root, "find/access");
        var model = new LookupEmailModel(new Uri(entry.AbsoluteUri + "#token=" + link.Transport), entry, link.Transport, link.ExpiresAt);
        return new(address, "Your private document lookup link", await views.RenderAsync("/Views/Email/Lookup.text.cshtml", model),
            await views.RenderAsync("/Views/Email/Lookup.html.cshtml", model));
    }
}

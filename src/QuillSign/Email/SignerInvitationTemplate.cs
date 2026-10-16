using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Signing;
namespace QuillSign.Email;
public sealed record SignerInviteModel(string Title,string Sender,string SignerName,string? Role,string? Message,Uri Link,DateTimeOffset ExpiresAt);
public sealed class SignerInvitationTemplate(EmailOptions options,RazorEmailViews views)
{
    public async Task<OutgoingEmail> RenderAsync(SignerReadContext context,string? message,string rawToken,DateTimeOffset expiresAt,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (SignerInvitationFactory.TokenHash(rawToken) is null) throw new ArgumentException("Invalid invitation token.");
        var root = new Uri(options.BaseUrl.TrimEnd('/') + "/",UriKind.Absolute);
        var link = new Uri(QueryHelpers.AddQueryString(new Uri(root,"sign/invitation").AbsoluteUri,"token",rawToken));
        var model = new SignerInviteModel(context.Title,context.Disclosure.SenderContact,context.SignerName,context.Role,message,link,expiresAt);
        return new(context.Identity.Email,"Review your signing request",await views.RenderAsync("/Views/Email/SignerInvite.text.cshtml",model),
            await views.RenderAsync("/Views/Email/SignerInvite.html.cshtml",model),context.Identity.EnvelopeId);
    }
}

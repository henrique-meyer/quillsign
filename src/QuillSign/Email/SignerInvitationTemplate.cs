using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Signing;
using QuillSign.Work;
namespace QuillSign.Email;
public sealed record SignerInviteModel(string Title,string Sender,string SignerName,string? Role,string? Message,Uri Link,DateTimeOffset ExpiresAt,string? Heading=null,string? Notice=null);
public sealed class SignerInvitationTemplate(EmailOptions options,RazorEmailViews views)
{
    public async Task<OutgoingEmail> RenderAsync(SignerReadContext context,string? message,string rawToken,DateTimeOffset expiresAt,CancellationToken ct,InvitationSuccessorReason? reason=null)
    {
        ct.ThrowIfCancellationRequested();
        if (SignerInvitationFactory.TokenHash(rawToken) is null) throw new ArgumentException("Invalid invitation token.");
        var root = new Uri(options.BaseUrl.TrimEnd('/') + "/",UriKind.Absolute);
        var link = new Uri(QueryHelpers.AddQueryString(new Uri(root,"sign/invitation").AbsoluteUri,"token",rawToken));
        var heading=reason switch {null=>null,InvitationSuccessorReason.Reminder=>"Reminder: review your signing request",
            InvitationSuccessorReason.ContactCorrection=>"Review your corrected signing invitation",InvitationSuccessorReason.ManualResend=>"Review your replacement signing invitation",
            _=>throw new ArgumentException("Unsupported invitation reason.")};
        var notice=reason switch {null=>null,InvitationSuccessorReason.ContactCorrection=>"The sender corrected the contact address for this signer. Previous access and unfinished entries were retired. Review the disclosure and document again before deciding whether to sign.",
            _=>"This invitation replaces earlier unused links for this request. Your saved progress in an already opened session remains available."};
        var model = new SignerInviteModel(context.Title,context.Disclosure.SenderContact,context.SignerName,context.Role,message,link,expiresAt,heading,notice);
        return new(context.Identity.Email,heading??"Review your signing request",await views.RenderAsync("/Views/Email/SignerInvite.text.cshtml",model),
            await views.RenderAsync("/Views/Email/SignerInvite.html.cshtml",model),context.Identity.EnvelopeId);
    }
}

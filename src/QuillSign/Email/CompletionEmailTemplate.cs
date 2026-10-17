using QuillSign.Completion;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Email;

public sealed record CompletionEmailModel(string Title,DateTimeOffset CompletedAt,DateTimeOffset? RetainedUntil,Uri Link,DateTimeOffset LinkExpiresAt,bool LinkOnly,bool IsDemo);
internal sealed record PreparedCompletionEmail(OutgoingEmail Message,bool LinkOnly);

public sealed class CompletionEmailTemplate(EmailOptions options,RazorEmailViews views)
{
    public const string Version="completion-email-v1";
    internal async Task<PreparedCompletionEmail> RenderAsync(CompletionAccessPreparation prepared,CompletionNotificationPayload scope,string to,CompletionAccessLink link,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();options.Attachments.Validate();
        if(SignerInvitationFactory.TokenHash(link.RawToken) is null)throw new ArgumentException("Invalid completion link.");
        var root=new Uri(options.BaseUrl.TrimEnd('/')+"/",UriKind.Absolute);
        var url=new Uri(root,"complete/access#token="+link.RawToken);
        var pair=prepared.Verified;
        var linkOnly=pair.ExecutedBytes.LongLength+pair.CertificateBytes.LongLength>options.Attachments.MaximumDecodedBytes ||
            pair.ExecutedBytes.LongLength>EmailAttachmentOptions.HardDecodedBytes || pair.CertificateBytes.LongLength>EmailAttachmentOptions.HardDecodedBytes;
        if(!linkOnly) {
            var attached=await Message(false,[new("QuillSign-executed.pdf",pair.ExecutedBytes),new("QuillSign-certificate.pdf",pair.CertificateBytes)]);
            try {return new(PdfEmailAttachments.Snapshot(attached,options.Attachments,ct),false);}
            catch(EmailAttachmentLimitException) { /* explicit size-only fallback, including a sender warning */ }
        }
        return new(PdfEmailAttachments.Snapshot(await Message(true,[]),options.Attachments,ct),true);

        async Task<OutgoingEmail> Message(bool only,IReadOnlyList<PdfEmailAttachment> files) {
            var model=new CompletionEmailModel(prepared.Saved.Title,prepared.Saved.CompletedAt,prepared.Saved.PurgeAfter,url,link.ExpiresAt,only,scope.IsDemo);
            return new(to,"Your completed QuillSign records",await views.RenderAsync("/Views/Email/Completion.text.cshtml",model),
                await views.RenderAsync("/Views/Email/Completion.html.cshtml",model),prepared.Saved.EnvelopeId,files);
        }
    }
}

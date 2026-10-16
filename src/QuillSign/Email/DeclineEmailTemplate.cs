using QuillSign.Work;
namespace QuillSign.Email;
public sealed class DeclineEmailTemplate(RazorEmailViews views)
{
    public async Task<OutgoingEmail> RenderAsync(string to,Guid? envelope,DeclinePayload model,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (model.Title is not { Length: > 0 and <= 512 } || model.SignerName is not { Length: > 0 and <= 512 } || model.Reason is { Length: > 512 })
            throw new ArgumentException("Invalid decline notification.");
        _ = EmailAddress.Normalize(model.SignerEmail);
        var text = await views.RenderAsync("/Views/Email/EnvelopeDeclined.text.cshtml",model);
        var html = await views.RenderAsync("/Views/Email/EnvelopeDeclined.html.cshtml",model);
        return new(EmailAddress.Normalize(to),"Your signing request was declined",text,html,envelope);
    }
}

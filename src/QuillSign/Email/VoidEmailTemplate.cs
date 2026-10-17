using QuillSign.Sender;

namespace QuillSign.Email;

public sealed record VoidEmailModel(string Title,DateTimeOffset VoidedAt,string? Reason,bool IsDemo);

public sealed class VoidEmailTemplate(RazorEmailViews views)
{
    public const string Version="void-email-v1";
    internal async Task<OutgoingEmail> RenderAsync(SenderVoidScope saved,string to,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var model=new VoidEmailModel(saved.Envelope.Title!,saved.Evidence.VoidedAt,saved.Evidence.Reason,saved.Envelope.IsDemo);
        return new(to,"A QuillSign signing request was voided",await views.RenderAsync("/Views/Email/Void.text.cshtml",model),
            await views.RenderAsync("/Views/Email/Void.html.cshtml",model),saved.Envelope.Id);
    }
}

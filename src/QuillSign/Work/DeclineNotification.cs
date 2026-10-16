using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Signing;

namespace QuillSign.Work;

public sealed record DeclinePayload(string Title,string SignerName,string SignerEmail,string? Reason);
public sealed class DeclinePayloadProtection(IDataProtectionProvider provider)
{
    private readonly IDataProtector protector = provider.CreateProtector("QuillSign.DeclineNotification.v1");
    public string Protect(DeclinePayload value) => JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(JsonSerializer.Serialize(value))));
    public DeclinePayload Read(string value) => JsonSerializer.Deserialize<DeclinePayload>(protector.Unprotect(
        JsonSerializer.Deserialize<ProtectedWorkPayload>(value)?.Protected ?? throw new JsonException())) ?? throw new JsonException();
    public static OutgoingEmail Render(string to,Guid? envelope,DeclinePayload value)
    {
        if (value.Title is not { Length: > 0 and <= 512 } || value.SignerName is not { Length: > 0 and <= 512 } || value.Reason is { Length: > 512 })
            throw new ArgumentException("Invalid decline notification.");
        var text = $"The signing request for {value.Title} was declined by {value.SignerName} ({value.SignerEmail}).\n\nReason: {value.Reason ?? "No reason provided."}\n\nThis envelope is closed. Contact the signer to discuss another arrangement.";
        return new(EmailAddress.Normalize(to),"Your signing request was declined",text,"<p>" + HtmlEncoder.Default.Encode(text).Replace("\n","<br />") + "</p>",envelope);
    }
}
public sealed class DeclineNotificationWriter(QuillSignDbContext db,Func<IWorkSignals> signals,WorkOptions options,
    DeclinePayloadProtection protection,TimeProvider time)
{
    public async Task<Guid> PrepareAsync(SignerReadContext context,string? reason,CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Preparing notification requires a transaction.");
        var email = new EmailOutbox { EnvelopeId = context.Identity.EnvelopeId,To = context.Disclosure.SenderContact,Template = "signer-declined",
            PayloadJson = protection.Protect(new(context.Title,context.SignerName,context.Identity.Email,reason)),AvailableAt = time.GetUtcNow() };
        db.EmailOutbox.Add(email); db.WorkItems.Add(new WorkItem { Id = email.Id,EnvelopeId = email.EnvelopeId,Kind = WorkKind.Email,AvailableAt = email.AvailableAt });
        await db.SaveChangesAsync(ct);
        // Disabled delivery never prevents declining. Persisted work remains for an explicit recovery run.
        if (options.Enabled) await signals().PutHintAsync(email.Id,email.AvailableAt,ct);
        return email.Id;
    }
    public async Task PublishAsync(Guid id,CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is not null) throw new InvalidOperationException("Commit before publishing.");
        if (!options.Enabled) return;
        try { await signals().PublishAsync(id,TimeSpan.Zero,ct); }
        catch (Exception e) when (e is Azure.RequestFailedException or IOException or OperationCanceledException or HttpRequestException) { /* durable hint survives */ }
    }
    public async Task<bool> RepublishAsync(Guid id,CancellationToken ct)
    {
        if (!options.Enabled || id == Guid.Empty) throw new InvalidOperationException("Enable approved durable work configuration first.");
        // Explicit operator recovery for one known item. This never runs on a timer.
        var pending = await db.EmailOutbox.AsNoTracking().AnyAsync(x => x.Id == id && x.Template == "signer-declined" &&
            x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null,ct);
        if (!pending || !await db.WorkItems.AsNoTracking().AnyAsync(x => x.Id == id && x.Status == WorkStatus.Queued,ct)) return false;
        await signals().PutHintAsync(id,time.GetUtcNow(),ct);
        await PublishAsync(id,ct); return true;
    }
}

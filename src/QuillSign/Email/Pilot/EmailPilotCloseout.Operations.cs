using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotCloseout
{
    internal async Task<Guid?> ReadStepLockedAsync(QuillSignDbContext db, EmailPilotCloseoutSnapshot snapshot, EmailPilotCloseoutStep step, CancellationToken ct = default)
    {
        var current = await Current(db, snapshot, ct);
        var known = current.Manifest.Queue.SingleOrDefault(x => x.Step == step); if (known is not null) return known.WorkId;
        return (await Operations(db, current, ct)).SingleOrDefault(x => x.Kind == 0 && x.Step == step)?.WorkId;
    }

    internal async Task BindNewWorkLockedAsync(QuillSignDbContext db, EmailPilotCloseoutSnapshot snapshot, EmailPilotCloseoutStep step, Guid workId, CancellationToken ct = default)
    {
        var current = await Current(db, snapshot, ct);
        if (step < EmailPilotCloseoutStep.DeclineVerification || !Enum.IsDefined(step) || workId == Guid.Empty ||
            (await Operations(db, current, ct)).Any(x => x.Step == step)) throw Invalid();
        var record = step == EmailPilotCloseoutStep.Lookup ? current.CompletionRecord : current.DeclineRecord;
        var mail = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == workId, ct);
        var item = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == workId, ct);
        var template = step switch { EmailPilotCloseoutStep.DeclineVerification => "sender-verification", EmailPilotCloseoutStep.DeclineInvitation => "signer-invitation",
            EmailPilotCloseoutStep.DeclineNotice => "signer-declined", EmailPilotCloseoutStep.Lookup => LookupDeliveryProtection.Template, _ => throw Invalid() };
        if (step == EmailPilotCloseoutStep.Lookup)
        {
            if (mail.EnvelopeId is not null || item.EnvelopeId is not null || mail.Template != template || mail.Id != item.Id ||
                mail.Status != EmailStatus.Queued || item.Kind != WorkKind.Email || item.Status != WorkStatus.Queued || mail.Attempts != 0 || item.Attempts != 0 ||
                mail.SubmissionStartedAt is not null || mail.Provider is not null || mail.ProviderMessageId is not null || item.LeaseOwner is not null || item.LeaseExpiresAt is not null) throw Invalid();
        }
        else Queued(mail, item, record, template);
        var expectedRole = step == EmailPilotCloseoutStep.DeclineInvitation ? EmailPilotRole.FirstSigner : EmailPilotRole.Sender;
        if (Role(current.Mailboxes, mail.To) != expectedRole || mail.AvailableAt > Now || item.AvailableAt > Now ||
            await db.Suppressions.AnyAsync(x => x.Email == mail.To, ct)) throw Invalid();
        var lookup = step == EmailPilotCloseoutStep.Lookup ? await (Lookup?.Invoke() ?? throw Invalid()).CaptureBindingLockedAsync(db,current,workId,ct) : null;
        if (lookup is not null && (lookup.RequestId!=workId || lookup.Deadline>current.Until || lookup.RequestedAt<current.Manifest.CreatedAt || lookup.RequestedAt>Now)) throw Invalid();
        var receipt = new EmailPilotCloseoutReceipt(EmailPilotCloseoutLimits.Version, current.AuthorizationId, 0, step, record, workId, Now, 0, Hash(new { Mail=Raw(mail), Work=Raw(item) }),lookup);
        db.EmailPilotCloseoutOperations.Add(Row(receipt)); await db.SaveChangesAsync(ct);
        if (!Available) throw Invalid();
    }

    internal async Task<EmailPilotCloseoutLookupBinding?> ReadLookupBindingLockedAsync(QuillSignDbContext db,EmailPilotCloseoutSnapshot snapshot,CancellationToken ct=default)
    {
        var current=await Current(db,snapshot,ct);
        return (await Operations(db,current,ct)).SingleOrDefault(x=>x.Kind==0&&x.Step==EmailPilotCloseoutStep.Lookup)?.LookupBinding;
    }

    // Recognition is independent of enable/expiry/secret availability. It never
    // authorizes an ordinary fallback or returns a token/recipient capability.
    internal Task<bool> IsKnownWorkAsync(Guid workId, CancellationToken ct = default) => database().EmailPilotCloseoutOperations.AsNoTracking().AnyAsync(x => x.WorkId == workId, ct);

    internal async Task<EmailPilotCloseoutSnapshot> Current(QuillSignDbContext db, EmailPilotCloseoutSnapshot prior, CancellationToken ct)
    {
        var current = await ReadLockedAsync(db, ct) ?? throw Invalid();
        if (current.AuthorizationId != prior.AuthorizationId || Hash(current.Manifest) != Hash(prior.Manifest)) throw Invalid(); return current;
    }

    private async Task<EmailPilotCloseoutReceipt[]> Operations(QuillSignDbContext db, EmailPilotCloseoutSnapshot current, CancellationToken ct)
    {
        var rows = await db.EmailPilotCloseoutOperations.AsNoTracking().Where(x => x.CloseoutId == current.AuthorizationId).Take(15).ToArrayAsync(ct);
        if (rows.Length > 14) throw Invalid(); var result = new List<EmailPilotCloseoutReceipt>();
        foreach (var row in rows)
        {
            var value = protection().Read<EmailPilotCloseoutReceipt>(row.CloseoutId, ReceiptPurpose, row.ProtectedReceipt, 8192);
            if (value != new EmailPilotCloseoutReceipt(EmailPilotCloseoutLimits.Version, row.CloseoutId, row.Kind, (EmailPilotCloseoutStep)row.Step,
                    row.SubjectEnvelopeId, row.WorkId, row.At, row.EncodedBytes, Convert.ToHexStringLower(row.RequestSha256),value.LookupBinding) ||
                value.At.Offset != TimeSpan.Zero || value.At < current.Manifest.CreatedAt || value.At >= current.Until || value.At > Now ||
                !Enum.IsDefined(value.Step) || value.Kind is not (0 or 1) || value.WorkId == Guid.Empty || value.RequestSha256.Length != 64 ||
                value.SubjectEnvelopeId != (value.Step is EmailPilotCloseoutStep.Lookup or <= EmailPilotCloseoutStep.CompletionRecipient ? current.CompletionRecord :
                    value.Step is EmailPilotCloseoutStep.VoidSender or EmailPilotCloseoutStep.VoidSigner ? current.VoidRecord : current.DeclineRecord)) throw Invalid();
            if (value.Kind == 0 ? value.Step < EmailPilotCloseoutStep.DeclineVerification || value.EncodedBytes != 0 : value.EncodedBytes is < 1 or > EmailPilotLimits.MessageBytes) throw Invalid();
            if ((value.Kind==0 && value.Step==EmailPilotCloseoutStep.Lookup) != (value.LookupBinding is not null) ||
                value.LookupBinding is {} lookup && (lookup.RequestId!=value.WorkId || lookup.Deadline>current.Until || lookup.RequestedAt<current.Manifest.CreatedAt || lookup.RequestedAt>value.At)) throw Invalid();
            result.Add(value);
        }
        if (result.GroupBy(x => (x.Kind, x.Step)).Any(x => x.Count() != 1) || result.Count(x => x.Kind == 0) > 4 || result.Count(x => x.Kind == 1) > 10 ||
            result.Where(x => x.Kind == 1).Sum(x => (long)x.EncodedBytes) > EmailPilotCloseoutLimits.EncodedBytes) throw Invalid();
        return result.ToArray();
    }

    private EmailPilotCloseoutOperationRecord Row(EmailPilotCloseoutReceipt value) => new() { Id=Identity(value.AuthorizationId,value.Kind,value.Step),
        CloseoutId=value.AuthorizationId,Kind=value.Kind,Step=(int)value.Step,SubjectEnvelopeId=value.SubjectEnvelopeId,WorkId=value.WorkId,At=value.At,
        EncodedBytes=value.EncodedBytes,RequestSha256=Convert.FromHexString(value.RequestSha256),ProtectedReceipt=protection().Protect(value.AuthorizationId,ReceiptPurpose,value) };
    internal static Guid Identity(Guid authorization, int kind, EmailPilotCloseoutStep step) => new(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes($"pilot-closeout-v1:{authorization:N}:{kind}:{(int)step}")).AsSpan(0,16));
}

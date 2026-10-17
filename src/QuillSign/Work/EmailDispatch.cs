using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Documents;

namespace QuillSign.Work;

public sealed record VerificationPayload(string Token, Guid TokenId);
public sealed record ProtectedWorkPayload(string Protected);

public sealed class EmailPayloadProtection(IDataProtectionProvider provider)
{
    private readonly IDataProtector protector = provider.CreateProtector("QuillSign.EmailPayload.v1");
    public string Protect(VerificationPayload payload) => JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(JsonSerializer.Serialize(payload))));
    public VerificationPayload Unprotect(string json) => JsonSerializer.Deserialize<VerificationPayload>(
        protector.Unprotect(JsonSerializer.Deserialize<ProtectedWorkPayload>(json)?.Protected ?? throw new InvalidOperationException("Invalid email payload.")))
        ?? throw new InvalidOperationException("Invalid email payload.");
}

public sealed record QueuedEmail(Guid Id, bool WakeupPublished);

public sealed class EmailOutboxWriter(QuillSignDbContext db, IWorkSignals signals, EmailPayloadProtection protection,
    WorkOptions workOptions, EmailOptions emailOptions, TimeProvider time)
{
    public async Task<QueuedEmail> EnqueueVerificationAsync(Guid envelopeId, string recipient, CancellationToken cancellationToken = default)
    {
        if (!workOptions.Enabled || !emailOptions.Enabled) throw new EmailDisabledException();
        Guid id;
        await using (var transaction = await db.Database.BeginTransactionAsync(cancellationToken))
        {
            id = await PrepareVerificationAsync(envelopeId, recipient, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        return await PublishCommittedAsync(id, cancellationToken);
    }

    public async Task<Guid> PrepareVerificationAsync(Guid envelopeId, string recipient, CancellationToken cancellationToken = default)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Preparing an outbox item requires a transaction.");
        if (!workOptions.Enabled || !emailOptions.Enabled) throw new EmailDisabledException();
        recipient = EmailAddress.Normalize(recipient);
        if (!await db.Envelopes.AnyAsync(x => x.Id == envelopeId && x.SenderEmail == recipient && x.Status == EnvelopeStatus.Draft, cancellationToken))
            throw new InvalidOperationException("Verification requires a matching draft sender.");
        if (await db.Suppressions.AnyAsync(x => x.Email == recipient, cancellationToken)) throw new RecipientSuppressedException();
        var payload = new VerificationPayload(WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32)), Guid.NewGuid());
        var email = new EmailOutbox { EnvelopeId = envelopeId, To = recipient, Template = "sender-verification", PayloadJson = protection.Protect(payload), AvailableAt = time.GetUtcNow() };
        var item = new WorkItem { Id = email.Id, EnvelopeId = envelopeId, Kind = WorkKind.Email, AvailableAt = email.AvailableAt,
            PayloadJson = JsonSerializer.Serialize(new { emailId = email.Id }) };
        db.EmailOutbox.Add(email); db.WorkItems.Add(item);
        await db.SaveChangesAsync(cancellationToken);
        await signals.PutHintAsync(item.Id, item.AvailableAt, cancellationToken);
        return item.Id;
    }

    public async Task<QueuedEmail> PublishCommittedAsync(Guid id, CancellationToken cancellationToken = default)
    {
        if (db.Database.CurrentTransaction is not null) throw new InvalidOperationException("Commit before publishing work.");
        // Commit and queue publication cannot be atomic. The persisted hint makes a
        // lost publication recoverable, including cancellation immediately after commit.
        try { await signals.PublishAsync(id, TimeSpan.Zero, cancellationToken); return new(id, true); }
        catch (Exception e) when (e is RequestFailedException or IOException or OperationCanceledException or HttpRequestException)
        { return new(id, false); }
    }
}

public sealed class EmailWorkHandler(QuillSignDbContext db, EmailOptions options, EmailPayloadProtection protection,
    VerificationEmailTemplate template, IEmailSender sender, TimeProvider time,DeclinePayloadProtection? declines = null,
    DeclineEmailTemplate? declineTemplate = null,SignerInvitationDelivery? invitations = null,Func<CompletionNotificationDelivery>? completions=null,
    Func<VoidNotificationDelivery>? voids=null) : IWorkHandler
{
    public WorkKind Kind => WorkKind.Email;

    public async Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken cancellationToken)
    {
        if (!options.Enabled) return new(WorkOutcome.Retry, "delivery-disabled");
        var email = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == lease.Id, cancellationToken);
        if(email.Template==VoidNotificationJobs.Template)return await (voids?.Invoke()??throw new InvalidOperationException("Missing void notification delivery.")).ExecuteAsync(lease,cancellationToken);
        if(email.Template==CompletionNotificationJobs.Template)return await (completions?.Invoke()??throw new InvalidOperationException("Missing completion notification delivery.")).ExecuteAsync(lease,cancellationToken);
        if (email.Template == "signer-invitation") return await (invitations ?? throw new InvalidOperationException("Missing signer invitation delivery.")).ExecuteAsync(lease,cancellationToken);
        if (email.Template is not ("sender-verification" or "signer-declined")) return new(WorkOutcome.Failed, "unsupported-template");
        var isDecline = email.Template == "signer-declined";
        VerificationPayload payload;
        OutgoingEmail outgoing;
        try
        {
            if (isDecline)
            {
                payload = new("",Guid.Empty);
                outgoing = await (declineTemplate ?? throw new InvalidOperationException("Missing decline template.")).RenderAsync(email.To,email.EnvelopeId,
                    (declines ?? throw new InvalidOperationException("Missing decline protection.")).Read(email.PayloadJson),cancellationToken);
            }
            else
            {
                payload = protection.Unprotect(email.PayloadJson);
                outgoing = (await template.RenderAsync(email.To, payload.Token, cancellationToken)) with { EnvelopeId = email.EnvelopeId };
            }
        }
        catch (CryptographicException)
        { return new(WorkOutcome.Retry, "payload-unavailable"); }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        { return new(WorkOutcome.Failed, "invalid-payload"); }
        if (email.EnvelopeId is null || (!isDecline && payload.TokenId == Guid.Empty)) return new(WorkOutcome.Failed, "invalid-token-scope");
        if (await db.Suppressions.AnyAsync(x => x.Email == email.To, cancellationToken)) return new(WorkOutcome.Failed, "recipient-suppressed");
        var at = time.GetUtcNow();
        DateTimeOffset? retentionDeadline=null;
        await using (var transaction = await db.Database.BeginTransactionAsync(cancellationToken))
        {
            // Common parent-before-work order also fences expiry cleanup. No new
            // submission intent may outlive an enrolled document's access deadline.
            var parent=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={email.EnvelopeId.Value}")
                .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
            if(parent is null)return new(WorkOutcome.Failed,"email-parent-unavailable");
            var owned = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {lease.Id}")
                .AsNoTracking().SingleAsync(cancellationToken);
            at=time.GetUtcNow();
            if (owned.Kind!=WorkKind.Email || owned.EnvelopeId!=parent.Id || owned.Attempts!=lease.Attempt ||
                owned.Status != WorkStatus.Leased || owned.LeaseOwner != lease.Owner || owned.LeaseExpiresAt!=lease.Until || owned.LeaseExpiresAt <= at)
                throw new InvalidOperationException("Work lease is no longer owned.");
            try{retentionDeadline=await DocumentRetentionAccess.ReadAsync(db,parent,cancellationToken);}
            catch(InvalidDataException){return new(WorkOutcome.Retry,"email-retention-unavailable");}
            if(retentionDeadline<=time.GetUtcNow())return new(WorkOutcome.Failed,"email-retention-expired");
            var changed = await db.EmailOutbox.Where(x => x.Id == lease.Id && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.SubmissionStartedAt, at).SetProperty(x => x.Attempts, lease.Attempt), cancellationToken);
            if (changed != 1) throw new InvalidOperationException("Email submission is no longer available.");
            if (!isDecline)
            {
                var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload.Token));
                var token = await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x => x.Id == payload.TokenId, cancellationToken);
                if (token is null)
                {
                    db.AuthTokens.Add(new() { Id = payload.TokenId, TokenSha256 = hash, Purpose = TokenPurpose.SenderVerify,
                        EnvelopeId = email.EnvelopeId, Email = email.To, PartyType = PartyType.Sender, ExpiresAt = at.AddMinutes(15) });
                    await db.SaveChangesAsync(cancellationToken);
                }
                else
                {
                    if (token.UsedAt is not null || token.EnvelopeId != email.EnvelopeId || token.Email != email.To || token.Purpose != TokenPurpose.SenderVerify ||
                        !CryptographicOperations.FixedTimeEquals(token.TokenSha256, hash)) throw new InvalidOperationException("Token scope is no longer available.");
                    await db.AuthTokens.Where(x => x.Id == token.Id).ExecuteUpdateAsync(set => set.SetProperty(x => x.ExpiresAt, at.AddMinutes(15)), cancellationToken);
                }
            }
            if(retentionDeadline<=time.GetUtcNow())return new(WorkOutcome.Failed,"email-retention-expired");
            if(lease.Until<=time.GetUtcNow())throw new InvalidOperationException("Work lease is no longer owned.");
            await transaction.CommitAsync(cancellationToken);
        }
        if(retentionDeadline<=time.GetUtcNow()) {
            await ClearSubmissionAsync(email.Id,payload.TokenId,cancellationToken);
            return new(WorkOutcome.Failed,"email-retention-expired");
        }
        try
        {
            var delivery = await sender.SendAsync(outgoing, cancellationToken);
            // Late feedback can advance status; preserve it while recording the receipt.
            await db.EmailOutbox.Where(x => x.Id == lease.Id).ExecuteUpdateAsync(set => set
                .SetProperty(x => x.Provider, delivery.Provider).SetProperty(x => x.ProviderMessageId, delivery.MessageId)
                .SetProperty(x => x.Status, x => x.Status == EmailStatus.Queued ? EmailStatus.Sent : x.Status), cancellationToken);
            return new(WorkOutcome.Completed);
        }
        catch (EmailNotSubmittedException e)
        {
            await ClearSubmissionAsync(email.Id, payload.TokenId, cancellationToken);
            return new(e.Retryable ? WorkOutcome.Retry : WorkOutcome.Failed, "provider-rejected");
        }
        catch (Exception e) when (e is RecipientSuppressedException or EmailDisabledException)
        {
            await ClearSubmissionAsync(email.Id, payload.TokenId, cancellationToken);
            return new(WorkOutcome.Failed, e is RecipientSuppressedException ? "recipient-suppressed" : "delivery-disabled");
        }
        // Any other exception might follow provider acceptance. Leave submission intent
        // intact; expiry recovery marks it ambiguous without another provider call.
    }

    private async Task ClearSubmissionAsync(Guid id, Guid tokenId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(set => set.SetProperty(x => x.SubmissionStartedAt, (DateTimeOffset?)null), cancellationToken);
        if(tokenId!=Guid.Empty)await db.AuthTokens.Where(x => x.Id == tokenId && x.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(x => x.ExpiresAt, time.GetUtcNow()), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }
}

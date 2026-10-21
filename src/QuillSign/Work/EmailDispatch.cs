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
using QuillSign.Lifecycle;

namespace QuillSign.Work;

public sealed record VerificationPayload(string Token, Guid TokenId,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    DemoCreationOrigin? DemoOrigin = null);
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
        return await PrepareVerificationCoreAsync(envelopeId,recipient,cancellationToken);
    }

    internal async Task<Guid> PrepareInitialDemoVerificationAsync(Envelope envelope, DemoCreationOrigin origin, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null || !workOptions.Enabled || !emailOptions.Enabled ||
            !ProductionDemoOrigin.Matches(origin, envelope) ||
            await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == envelope.Id, ct)) throw new InvalidDataException("Original demo admission is unavailable.");
        return await PrepareVerificationCoreAsync(envelope.Id, envelope.SenderEmail, ct, origin);
    }

    internal async Task<Guid> PreparePilotVerificationAsync(Guid envelopeId, string recipient,
        Email.Pilot.EmailPilotAdmissionScope scope, CancellationToken cancellationToken)
    {
        if (!workOptions.Enabled || emailOptions.Enabled) throw new EmailDisabledException();
        scope.Demand(db,envelopeId,recipient);
        return await PrepareVerificationCoreAsync(envelopeId,recipient,cancellationToken);
    }

    private async Task<Guid> PrepareVerificationCoreAsync(Guid envelopeId, string recipient, CancellationToken cancellationToken,
        DemoCreationOrigin? origin = null)
    {
        recipient = EmailAddress.Normalize(recipient);
        if (!await db.Envelopes.AnyAsync(x => x.Id == envelopeId && x.SenderEmail == recipient && x.Status == EnvelopeStatus.Draft, cancellationToken))
            throw new InvalidOperationException("Verification requires a matching draft sender.");
        if (await db.Suppressions.AnyAsync(x => x.Email == recipient, cancellationToken)) throw new RecipientSuppressedException();
        var payload = new VerificationPayload(WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32)), Guid.NewGuid(), origin);
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
    Func<VoidNotificationDelivery>? voids=null,Func<LookupLinkDelivery>? lookups=null,Func<InvitationResendDelivery>? resends=null,
    Func<InvitationSuccessorDelivery>? successors=null,Email.Pilot.EmailPilotDispatch? pilot=null,
    Func<Email.Pilot.EmailPilotSimulatorDelivery>? simulators=null,Email.Pilot.EmailPilotLookupAccess? pilotLookups=null) : IWorkHandler
{
    internal IProductionWorkAdmission? HoldAdmission { get; init; }
    public WorkKind Kind => WorkKind.Email;

    public async Task<WorkResult> ExecuteAsync(WorkLease lease, CancellationToken cancellationToken)
    {
        var admitted = HoldAdmission is null ? null : await HoldAdmission.ReadDispatchAsync(db, lease, cancellationToken);
        // Simulator work has no document parent. Recognize its reserved template
        // before the envelope-only pilot decision, and never ordinary-fallback.
        if(admitted is null && (simulators is not null || pilot is not null || options.Enabled)) {
            var simulator=await db.EmailOutbox.AsNoTracking().AnyAsync(x=>x.Id==lease.Id && x.Template==Email.Pilot.EmailPilotSimulator.Template,cancellationToken);
            if(simulator)return simulators is null ? new(WorkOutcome.Failed,"pilot-simulator-unavailable") : await simulators().ExecuteAsync(lease,cancellationToken);
        }
        // Only the optional exact lookup mapping/marker may select this typed
        // null-envelope path. The lookup handler independently verifies it.
        if (admitted is null && pilotLookups is not null && await pilotLookups.IsKnownWorkAsync(lease.Id,cancellationToken))
            return await (lookups?.Invoke()??throw new InvalidOperationException("Missing lookup delivery.")).ExecuteAsync(lease,cancellationToken);
        var pilotDecision=pilot is null ? null : await pilot.DecideAsync(lease,cancellationToken);
        if(pilotDecision?.Refusal is {} refusal)return refusal;
        if(pilotDecision is null && !options.Enabled)return new(WorkOutcome.Retry,"delivery-disabled");
        var email = admitted ?? await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == lease.Id, cancellationToken);
        if(email.Template==InvitationSuccessorProtection.Template)
        {
            var delivery=successors?.Invoke()??throw new InvalidOperationException("Missing invitation successor delivery.");
            return admitted is null?await delivery.ExecuteAsync(lease,cancellationToken):await delivery.ExecuteAdmittedAsync(lease,HoldAdmission!,cancellationToken);
        }
        if(email.Template==InvitationResendProtection.Template)
        {
            var delivery=resends?.Invoke()??throw new InvalidOperationException("Missing invitation resend delivery.");
            return admitted is null?await delivery.ExecuteAsync(lease,cancellationToken):await delivery.ExecuteAdmittedAsync(lease,HoldAdmission!,cancellationToken);
        }
        if(email.Template==LookupDeliveryProtection.Template)return await (lookups?.Invoke()??throw new InvalidOperationException("Missing lookup delivery.")).ExecuteAsync(lease,cancellationToken);
        if(email.Template==VoidNotificationJobs.Template)
        {
            var delivery=voids?.Invoke()??throw new InvalidOperationException("Missing void notification delivery.");
            return admitted is null?await delivery.ExecuteAsync(lease,cancellationToken):await delivery.ExecuteAdmittedAsync(lease,HoldAdmission!,cancellationToken);
        }
        if(email.Template==CompletionNotificationJobs.Template) {
            var completion=completions?.Invoke()??throw new InvalidOperationException("Missing completion notification delivery.");
            return admitted is null ? await completion.ExecuteAsync(lease,cancellationToken) :
                await completion.ExecuteAdmittedAsync(lease,admitted,HoldAdmission!,cancellationToken);
        }
        if (email.Template == "signer-invitation")
        {
            var invitation = invitations ?? throw new InvalidOperationException("Missing signer invitation delivery.");
            return admitted is null ? await invitation.ExecuteAsync(lease,cancellationToken) :
                await invitation.ExecuteAdmittedAsync(lease,admitted,HoldAdmission!,cancellationToken);
        }
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
        ProductionRecordDispatchPermit? dispatchPermit=null;
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
            if (HoldAdmission is not null)
                await HoldAdmission.DemandLockedAsync(db, lease.Id, email.EnvelopeId, lease.Kind, lease.Owner, lease.Attempt, false, cancellationToken);
            if (admitted is not null)
            {
                var saved = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == lease.Id, cancellationToken);
                if (saved.EnvelopeId != email.EnvelopeId || saved.Template != email.Template || saved.To != email.To ||
                    saved.PayloadJson != email.PayloadJson || saved.AttachmentsJson != email.AttachmentsJson || saved.Attempts != email.Attempts ||
                    saved.SubmissionStartedAt != email.SubmissionStartedAt || saved.Provider != email.Provider || saved.ProviderMessageId != email.ProviderMessageId)
                    throw new ProductionWorkBlockedException();
            }
            try{retentionDeadline=await DocumentRetentionAccess.ReadAsync(db,parent,time,cancellationToken);}
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
                        EnvelopeId = email.EnvelopeId, Email = email.To, PartyType = PartyType.Sender, ExpiresAt = Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,at.AddMinutes(15)) });
                    await db.SaveChangesAsync(cancellationToken);
                }
                else
                {
                    if (token.UsedAt is not null || token.EnvelopeId != email.EnvelopeId || token.Email != email.To || token.Purpose != TokenPurpose.SenderVerify ||
                        !CryptographicOperations.FixedTimeEquals(token.TokenSha256, hash)) throw new InvalidOperationException("Token scope is no longer available.");
                    await db.AuthTokens.Where(x => x.Id == token.Id).ExecuteUpdateAsync(set => set.SetProperty(x => x.ExpiresAt, Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,at.AddMinutes(15))), cancellationToken);
                }
            }
            if(retentionDeadline<=time.GetUtcNow())return new(WorkOutcome.Failed,"email-retention-expired");
            if(HoldAdmission is not null)
            {
                dispatchPermit=await HoldAdmission.PrepareDispatchLockedAsync(db,lease,email.EnvelopeId,cancellationToken);
                if(admitted is not null && dispatchPermit is null)throw new ProductionWorkBlockedException();
                DemandDispatchClocks(lease,email,Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,at.AddMinutes(15)),retentionDeadline);
            }
            if(pilotDecision?.Scope?.RunExpiresAt<=time.GetUtcNow())throw new EmailDisabledException();
            if(lease.Until<=time.GetUtcNow())throw new InvalidOperationException("Work lease is no longer owned.");
            await transaction.CommitAsync(cancellationToken);
        }
        if(retentionDeadline<=time.GetUtcNow()) {
            if(dispatchPermit is null)await ClearSubmissionAsync(email.Id,payload.TokenId,cancellationToken);
            // An externally prepared dispatch which never reached the provider
            // remains parked; expiry is not a cancellation/absence proof.
            return new(WorkOutcome.Failed,"email-retention-expired");
        }
        try
        {
            if(dispatchPermit is not null)
            {
                await using var proof=await db.Database.BeginTransactionAsync(cancellationToken);
                await DemandWitnessedIntentLockedAsync(lease,email,payload,at,Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,at.AddMinutes(15)),cancellationToken);
                DocumentRetentionAccess.Check(retentionDeadline,time);
                await HoldAdmission!.ConsumeDispatchLockedAsync(db,dispatchPermit,cancellationToken);
                DemandDispatchClocks(lease,email,Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,at.AddMinutes(15)),retentionDeadline);await proof.RollbackAsync(cancellationToken);
            }
            if(dispatchPermit is not null)DemandDispatchClocks(lease,email,Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,at.AddMinutes(15)),retentionDeadline);
            var delivery = pilot is null ? await sender.SendAsync(outgoing, cancellationToken) : await pilot.SendAsync(lease,outgoing, cancellationToken);
            // Late feedback can advance status; preserve it while recording the receipt.
            if (HoldAdmission is null)
                await SaveReceiptAsync(lease.Id, delivery, cancellationToken);
            else await SaveWitnessedReceiptAsync(lease, email, payload, at, Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision, at.AddMinutes(15)), delivery,dispatchPermit,retentionDeadline,cancellationToken);
            return new(WorkOutcome.Completed);
        }
        catch (EmailNotSubmittedException e)
        {
            await ClearOwnedSubmissionAsync();
            return new(e.Retryable ? WorkOutcome.Retry : WorkOutcome.Failed, e.FailureCode);
        }
        catch (Exception e) when (e is RecipientSuppressedException or EmailDisabledException)
        {
            await ClearOwnedSubmissionAsync();
            return new(WorkOutcome.Failed, e is RecipientSuppressedException ? "recipient-suppressed" : "delivery-disabled");
        }
        // Any other exception might follow provider acceptance. Leave submission intent
        // intact; expiry recovery marks it ambiguous without another provider call.

        async Task ClearOwnedSubmissionAsync()
        {
            if(dispatchPermit is null){await ClearSubmissionAsync(email.Id,payload.TokenId,cancellationToken);return;}
            await using var tx=await db.Database.BeginTransactionAsync(cancellationToken);
            await DemandWitnessedIntentLockedAsync(lease,email,payload,at,Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,at.AddMinutes(15)),cancellationToken);
            await HoldAdmission!.DemandDispatchReceiptLockedAsync(db,dispatchPermit,cancellationToken);
            DemandDispatchClocks(lease,email,Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,at.AddMinutes(15)),retentionDeadline);
            await db.EmailOutbox.Where(x=>x.Id==email.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,(DateTimeOffset?)null),cancellationToken);
            if(payload.TokenId!=Guid.Empty)await db.AuthTokens.Where(x=>x.Id==payload.TokenId && x.UsedAt==null)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,time.GetUtcNow()),cancellationToken);
            await tx.CommitAsync(cancellationToken); // Retain the external reservation for explicit noncompleted reconciliation.
        }
    }

    private Task<int> SaveReceiptAsync(Guid id, EmailDelivery delivery, CancellationToken ct)
        => db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(set => set
            .SetProperty(x => x.Provider, delivery.Provider).SetProperty(x => x.ProviderMessageId, delivery.MessageId)
            .SetProperty(x => x.Status, x => x.Status == EmailStatus.Queued ? EmailStatus.Sent : x.Status), ct);

    private async Task SaveWitnessedReceiptAsync(WorkLease lease, EmailOutbox original, VerificationPayload payload,
        DateTimeOffset intentAt, DateTimeOffset tokenExpiry, EmailDelivery delivery,ProductionRecordDispatchPermit? dispatchPermit,DateTimeOffset? deadline,CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DemandWitnessedIntentLockedAsync(lease,original,payload,intentAt,tokenExpiry,ct);
        if(dispatchPermit is not null)await HoldAdmission!.DemandDispatchReceiptLockedAsync(db,dispatchPermit,ct);
        else await HoldAdmission!.DemandLockedAsync(db,lease.Id,original.EnvelopeId,lease.Kind,lease.Owner,lease.Attempt,false,ct);
        DemandDispatchClocks(lease,original,tokenExpiry,deadline);
        if(string.IsNullOrWhiteSpace(delivery.Provider) || delivery.Provider.Length>128 || string.IsNullOrWhiteSpace(delivery.MessageId) || delivery.MessageId.Length>1024)
            throw new ProductionWorkBlockedException();
        if (await SaveReceiptAsync(lease.Id, delivery, ct) != 1) throw new ProductionWorkBlockedException();
        await HoldAdmission.PrepareHandlerOutcomeLockedAsync(db, lease, original.EnvelopeId, ct);
        DemandDispatchClocks(lease,original,tokenExpiry,deadline);
        await tx.CommitAsync(ct);
    }

    private async Task DemandWitnessedIntentLockedAsync(WorkLease lease,EmailOutbox original,VerificationPayload payload,
        DateTimeOffset intentAt,DateTimeOffset tokenExpiry,CancellationToken ct)
    {
        _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={original.EnvelopeId}")
            .AsNoTracking().SingleAsync(ct);
        var work = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == lease.Id, ct);
        var current = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == lease.Id, ct);
        if (work.EnvelopeId != original.EnvelopeId || work.Kind != lease.Kind || work.Status != WorkStatus.Leased ||
            work.LeaseOwner != lease.Owner || work.LeaseExpiresAt != lease.Until || work.Attempts != lease.Attempt || lease.Until<=time.GetUtcNow() ||
            current.EnvelopeId != original.EnvelopeId || current.Template != original.Template || current.To != original.To ||
            current.PayloadJson != original.PayloadJson || current.AttachmentsJson != original.AttachmentsJson ||
            current.SubmissionStartedAt != intentAt || current.Attempts != lease.Attempt || current.Provider is not null || current.ProviderMessageId is not null ||
            current.Status is not (EmailStatus.Queued or EmailStatus.Bounced or EmailStatus.Complained)) throw new ProductionWorkBlockedException();
        if (original.Template == "sender-verification")
        {
            if(tokenExpiry<=time.GetUtcNow())throw new ProductionWorkBlockedException();
            var token = await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x => x.Id == payload.TokenId, ct);
            if (token is null || token.EnvelopeId != original.EnvelopeId || token.Purpose != TokenPurpose.SenderVerify ||
                token.PartyType != PartyType.Sender || token.PartyId is not null || token.Email != original.To || token.UsedAt is not null ||
                token.DocumentId is not null || token.DocumentSha256 is not null || token.DisclosureSha256 is not null ||
                token.SignerContactRevisionId is not null || token.EmailPilotLookupRequestId is not null || token.CompletionPublicationId is not null ||
                token.CompletionRecipeSha256 is not null || token.CompletionPartySha256 is not null ||
                token.ExpiresAt != tokenExpiry || !token.TokenSha256.AsSpan().SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes(payload.Token))))
                throw new ProductionWorkBlockedException();
        }
    }

    private void DemandDispatchClocks(WorkLease lease,EmailOutbox original,DateTimeOffset tokenExpiry,DateTimeOffset? deadline)
    {
        if(lease.Until<=time.GetUtcNow() || original.Template=="sender-verification" && tokenExpiry<=time.GetUtcNow())throw new ProductionWorkBlockedException();
        DocumentRetentionAccess.Check(deadline,time);
    }

    private async Task ClearSubmissionAsync(Guid id, Guid tokenId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(set => set.SetProperty(x => x.SubmissionStartedAt, (DateTimeOffset?)null), cancellationToken);
        if(tokenId!=Guid.Empty)await db.AuthTokens.Where(x => x.Id == tokenId && x.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(x => x.ExpiresAt, time.GetUtcNow()), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }
}

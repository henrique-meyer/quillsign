using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Legal;
using QuillSign.Signing;
namespace QuillSign.Work;

public sealed record SignerInvitationPayload(Guid SignerId,Guid? LastTokenId = null,Guid DocumentId=default,string? DocumentSha256=null,string? DisclosureSha256=null,
    [property: JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingDefault)] Guid ContactRevisionId=default,
    [property: JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingDefault)] int ContactRevisionNumber=0)
{
    internal SignerContactEpoch Contact=>new(ContactRevisionId,ContactRevisionNumber);
}
public sealed class SignerInvitationProtection(IDataProtectionProvider provider)
{
    private readonly IDataProtector protector = provider.CreateProtector("QuillSign.SignerInvitationPayload.v1");
    public string Protect(SignerInvitationPayload value) => JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(JsonSerializer.Serialize(value))));
    public SignerInvitationPayload Read(string value) => JsonSerializer.Deserialize<SignerInvitationPayload>(protector.Unprotect(
        JsonSerializer.Deserialize<ProtectedWorkPayload>(value)?.Protected ?? throw new JsonException())) ?? throw new JsonException();
}
public sealed class SignerInvitationOutbox(QuillSignDbContext db,Func<IWorkSignals> signals,WorkOptions work,EmailOptions email,
    SignerInvitationProtection protection,TimeProvider time,EmailPilotEnvelopeAccess? pilot=null)
{
    public async Task<Guid> PrepareAsync(Guid envelopeId,Guid signerId,string recipient,CancellationToken ct,Guid? invitationId=null)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Preparing invitations requires a transaction.");
        if (!work.Enabled || !email.Enabled && pilot is null) throw new EmailDisabledException();
        var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelopeId,ct);
        var cohort=pilot is null ? null : await pilot.RequireSendRosterLockedAsync(envelope,ct);
        if(!email.Enabled && cohort?.Allowed!=true)throw new EmailDisabledException();
        var source=await new SignerCheckpointState(db,time).CurrentAsync(envelope,ct) ?? throw new InvalidDataException("Current invitation document is unavailable.");
        if(envelope.ErsdSha256 is not { Length:32 })throw new InvalidDataException("Current invitation disclosure is unavailable.");
        if(cohort?.IsEnrolled==true)await DemandPilotSource(envelope,cohort,signerId,recipient,source,ct);
        var contact=SignerContactEpoch.Legacy;
        if(await InvitationLineage.RequiresVerifiedHistoryAsync(db,envelopeId,ct)) {
            var contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(envelope,ct);
            var party=contacts.Current.SingleOrDefault(x=>x.Id==signerId)??throw InvitationSuccessorProtection.Invalid();
            if(party.Email!=recipient)throw InvitationSuccessorProtection.Invalid();contact=party.Epoch;
        }
        var row = new EmailOutbox { EnvelopeId = envelopeId,To = EmailAddress.Normalize(recipient),Template = "signer-invitation",
            PayloadJson = protection.Protect(new(signerId,DocumentId:source.ObjectId,DocumentSha256:Convert.ToHexStringLower(source.Sha256),DisclosureSha256:Convert.ToHexStringLower(envelope.ErsdSha256),
                ContactRevisionId:contact.RevisionId,ContactRevisionNumber:contact.Number)),AvailableAt = time.GetUtcNow() };
        if(invitationId is Guid id) { if(id==Guid.Empty)throw new ArgumentException("Invalid invitation ID."); row.Id=id; }
        db.EmailOutbox.Add(row); db.WorkItems.Add(new WorkItem { Id = row.Id,EnvelopeId = envelopeId,Kind = WorkKind.Email,AvailableAt = row.AvailableAt });
        await db.SaveChangesAsync(ct); await signals().PutHintAsync(row.Id,row.AvailableAt,ct);
        if(cohort is not null) {
            var current=await pilot!.RequireSendRosterLockedAsync(envelope,ct);
            if(current.IsEnrolled!=cohort.IsEnrolled || current.RunId!=cohort.RunId || current.RunExpiresAt!=cohort.RunExpiresAt ||
                current.Scenario!=cohort.Scenario || current.IsEnrolled && !current.Allowed)throw new EmailDisabledException();
            if(current.IsEnrolled)await DemandPilotSource(envelope,current,signerId,recipient,source,ct);
        }
        return row.Id;
    }
    private async Task DemandPilotSource(Envelope envelope,EmailPilotEnvelopeCohort cohort,Guid signerId,string recipient,SignerCurrentSource source,CancellationToken ct)
    {
        if(!cohort.Allowed || !cohort.EnvelopeExists || cohort.RunExpiresAt is not {} until || until<=time.GetUtcNow())throw new EmailDisabledException();
        var parent=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelope.Id,ct);
        var current=await new SignerCheckpointState(db,time).CurrentAsync(parent,ct);
        var next=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==parent.Id && x.Status!=SignerStatus.Signed).OrderBy(x=>x.Order).FirstOrDefaultAsync(ct);
        if(parent.Status!=EnvelopeStatus.Sent || parent.SentAt is null || parent.SentAt>time.GetUtcNow() || parent.ExpiresAt<=time.GetUtcNow() ||
            parent.ErsdVersion is null || parent.Title is null || parent.ErsdText is null || parent.ErsdSha256 is not {Length:32} ||
            !ElectronicRecordDisclosure.Verify(new(parent.ErsdVersion,parent.PublicId,parent.Title,parent.SenderEmail,parent.ErsdText,parent.ErsdSha256)) ||
            envelope.ErsdSha256 is not {Length:32} || !parent.ErsdSha256.AsSpan().SequenceEqual(envelope.ErsdSha256) ||
            current is null || current.ObjectId!=source.ObjectId || current.Version!=source.Version || current.FinishId!=source.FinishId ||
            !current.Sha256.AsSpan().SequenceEqual(source.Sha256) || next is null || next.Id!=signerId || next.Email!=recipient ||
            next.Status!=SignerStatus.Pending || next.Order!=source.Version+1 ||
            await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==parent.Id && x.SignerId==signerId,ct) || cohort.RunExpiresAt<=time.GetUtcNow())
            throw new EmailDisabledException();
    }
    public async Task PublishAsync(Guid id,CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is not null) throw new InvalidOperationException("Commit before publishing.");
        try { await signals().PublishAsync(id,TimeSpan.Zero,ct); }
        catch (Exception e) when (e is Azure.RequestFailedException or IOException or OperationCanceledException or HttpRequestException) { /* committed hint recovers */ }
    }
}
public sealed class SignerInvitationDelivery(QuillSignDbContext db,SignerAccess access,SignerInvitationFactory tokens,
    SignerInvitationProtection protection,SignerInvitationTemplate template,IEmailSender sender,EmailOptions options,AuditWriter audit,TimeProvider time,InvitationLineage? lineage=null,Email.Pilot.EmailPilotDispatch? pilot=null)
{
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        var pilotDecision=pilot is null ? null : await pilot.DecideAsync(lease,ct);
        if(pilotDecision?.Refusal is {} refusal)return refusal;
        if(pilotDecision is null && !options.Enabled)return new(WorkOutcome.Retry,"delivery-disabled");
        var email = await db.EmailOutbox.AsNoTracking().SingleAsync(x => x.Id == lease.Id,ct);
        SignerInvitationPayload payload;
        try { payload = protection.Read(email.PayloadJson); }
        catch (CryptographicException) { return new(WorkOutcome.Retry,"payload-unavailable"); }
        catch (Exception e) when (e is JsonException or ArgumentException) { return new(WorkOutcome.Failed,"invalid-payload"); }
        if (email.Template != "signer-invitation" || email.EnvelopeId is not Guid envelopeId || payload.SignerId == Guid.Empty) return new(WorkOutcome.Failed,"invalid-invitation-scope");
        OutgoingEmail outgoing; SignerInvitation invitation; SignerReadContext context;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            // All sender/signer mutations use envelope first. Never lock work before this scope.
            var eligible = await access.GetEligibleLockedAsync(envelopeId,payload.SignerId,ct);
            if (eligible is null || eligible.Identity.Email != email.To) return new(WorkOutcome.Failed,"invitation-unavailable"); context = eligible;
            await InvitationResendRules.VerifyIndexAsync(db,envelopeId,ct,time);
            if(await InvitationResendRules.LatestAuditAsync(db,envelopeId,payload.SignerId,ct) is not null)return new(WorkOutcome.Failed,"invitation-replaced");
            if(payload.Contact!=SignerContactEpoch.Legacy || await InvitationLineage.RequiresVerifiedHistoryAsync(db,envelopeId,ct)) {
                var parent=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelopeId,ct);
                var contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(parent,ct);
                var history=await (lineage??throw InvitationSuccessorProtection.Invalid()).ReadLockedAsync(parent,payload.SignerId,contacts,ct);
                var current=contacts.Current.SingleOrDefault(x=>x.Id==payload.SignerId);
                if(history is null || history.Latest.Id!=email.Id || current is null || current.Epoch!=payload.Contact || current.Email!=email.To)
                    return new(WorkOutcome.Failed,"invitation-replaced");
            }
            if(payload.DocumentId!=context.Identity.DocumentId || payload.DocumentSha256!=context.Identity.DocumentHash || payload.DisclosureSha256!=context.Identity.DisclosureHash)
                return new(WorkOutcome.Failed,"invitation-source-changed");
            if (await db.Suppressions.AnyAsync(x => x.Email == email.To,ct)) return new(WorkOutcome.Failed,"recipient-suppressed");
            var owned = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {lease.Id}").AsNoTracking().SingleAsync(ct);
            var now = time.GetUtcNow();
            if (owned.Status != WorkStatus.Leased || owned.LeaseOwner != lease.Owner || owned.LeaseExpiresAt <= now) throw new InvalidOperationException("Work lease is no longer owned.");
            var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == envelopeId,ct);
            invitation = tokens.Create(envelopeId,payload.SignerId,email.To,Email.Pilot.EmailPilotDispatch.Clamp(pilotDecision,envelope.ExpiresAt??DateTimeOffset.MaxValue),context.Identity.DocumentId,context.DocumentSha256,context.Disclosure.Sha256,
                payload.ContactRevisionNumber==0 ? null : payload.ContactRevisionId);
            outgoing = await template.RenderAsync(context,envelope.Message,invitation.RawToken,invitation.Record.ExpiresAt,ct);
            if (invitation.Record.ExpiresAt <= time.GetUtcNow()) return new(WorkOutcome.Failed,"invitation-expired");
            var protectedScope = protection.Protect(payload with { LastTokenId = invitation.Record.Id });
            var changed = await db.EmailOutbox.Where(x => x.Id == lease.Id && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt,now).SetProperty(x => x.Attempts,lease.Attempt).SetProperty(x => x.PayloadJson,protectedScope),ct);
            if (changed != 1) throw new InvalidOperationException("Invitation submission is no longer available.");
            db.AuthTokens.Add(invitation.Record); await db.SaveChangesAsync(ct);
            if(pilotDecision?.Scope?.RunExpiresAt<=time.GetUtcNow())throw new EmailDisabledException();
            await transaction.CommitAsync(ct);
        }
        try
        {
            var delivery = pilot is null ? await sender.SendAsync(outgoing,ct) : await pilot.SendAsync(lease,outgoing,ct);
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {envelopeId}").AsNoTracking().SingleAsync(ct);
            await db.EmailOutbox.Where(x => x.Id == lease.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Provider,delivery.Provider)
                .SetProperty(x => x.ProviderMessageId,delivery.MessageId).SetProperty(x => x.Status,x => x.Status == EmailStatus.Queued ? EmailStatus.Sent : x.Status),ct);
            await db.Signers.Where(x => x.Id == payload.SignerId && x.EnvelopeId == envelopeId && x.Status == SignerStatus.Pending)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.Status,SignerStatus.Notified),ct);
            await audit.AppendAsync(envelopeId,"invitation_submitted",null,null,null,ct,JsonSerializer.Serialize(new {
                emailId = email.Id,tokenId = invitation.Record.Id,documentSha256 = context.Identity.DocumentHash,disclosureSha256 = context.Identity.DisclosureHash,
                signerId = payload.SignerId,recipient = email.To,provider = delivery.Provider,providerMessageId = delivery.MessageId,
                meaning = "provider_accepted_not_proof_of_delivery" }),PartyType.System);
            await transaction.CommitAsync(ct); return new(WorkOutcome.Completed);
        }
        catch (EmailNotSubmittedException e) { await RejectedAsync(email.Id,invitation.Record.Id,ct); return new(e.Retryable ? WorkOutcome.Retry : WorkOutcome.Failed,e.FailureCode); }
        catch (Exception e) when (e is RecipientSuppressedException or EmailDisabledException)
        { await RejectedAsync(email.Id,invitation.Record.Id,ct); return new(WorkOutcome.Failed,e is RecipientSuppressedException ? "recipient-suppressed" : "delivery-disabled"); }
        // Unknown outcomes retain submission intent; work recovery forbids another provider call.
    }
    private async Task RejectedAsync(Guid emailId,Guid tokenId,CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await db.EmailOutbox.Where(x => x.Id == emailId).ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt,(DateTimeOffset?)null),ct);
        await db.AuthTokens.Where(x => x.Id == tokenId && x.UsedAt == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt,time.GetUtcNow()),ct);
        await transaction.CommitAsync(ct);
    }
}

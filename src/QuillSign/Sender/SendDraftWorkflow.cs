using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Legal;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using QuillSign.Lifecycle;

namespace QuillSign.Sender;

public sealed record SentDraft(Guid EnvelopeId,string PublicId,Guid InvitationWorkId,string DocumentHash,string DisclosureHash)
{
    public SignerReminderPolicy? Reminders {get;init;}
    public string? ReminderSchedulingVersion {get;init;}
}

// The public handler adds CSRF and deliberate sender confirmation; this service owns atomic freeze and replay.
public sealed class SendDraftWorkflow(QuillSignDbContext db,IBlobStore storage,DocumentOptions documents,
    SignerSetupOptions signerOptions,FieldEditorOptions fieldOptions,PreparationOptions preparation,SenderPdfRenderer renderer,
    ElectronicRecordDisclosure disclosures,SignerInvitationOutbox outbox,WorkOptions workOptions,EmailOptions emailOptions,
    AuditWriter audit,TimeProvider time,ILogger<SendDraftWorkflow> logger,SigningExpiryJobs expiry,SignerReminderOptions? reminderOptions=null,SignerReminderJobs? reminderJobs=null,
    EmailPilotEnvelopeAccess? pilot=null)
{
    internal ProductionRecordSendAdmission? HoldAdmission { get; init; }
    public async Task<SentDraft?> SendAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,bool exclusionsAcknowledged,
        bool sendAcknowledged,string? statementVersion,string? ip,string? userAgent,CancellationToken ct = default,string? reviewedRetentionSha256=null,
        string? reviewedReminderSha256=null,string? reviewedReminderSchedulingVersion=null,string? reviewedDisclosureSha256=null)
    {
        var identity = Identity(sender,publicId); if (identity is null) return null;
        if (!exclusionsAcknowledged) throw new DocumentRejectedException("Confirm that this transaction is suitable for electronic signing.");
        if(!sendAcknowledged || statementVersion!=SenderSendStatement.Version)throw new DocumentRejectedException("Confirm the reviewed Send statement.");
        if (expectedVersion is not { Length: 8 }) throw new DocumentConflictException();
        if(HoldAdmission is not null)ProductionRecordSendAdmission.DemandStandalone(db);
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        DocumentBlob? created = null; var commitStarted = false; SentDraft? result = null;Guid? expiryId=null;DateTimeOffset? expiryDue=null;IReadOnlyList<ScheduledSignerReminder> reminderSchedule=[];
        ProductionRecordOperation? operation=null;
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            var envelope = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {identity.Value.Id}")
                .AsNoTracking().SingleOrDefaultAsync(ct);
            if (envelope is null || envelope.PublicId != publicId || envelope.SenderEmail != identity.Value.Email || envelope.SenderVerifiedAt is null) return null;
            var production=await ProductionRecordRetentionAccess.EnrollmentAsync(db,envelope,time,ct);
            if(production is not null) {
                _=await SenderPreparationRetention.ReadAsync(db,envelope,time,ct);
                if(envelope.Status!=EnvelopeStatus.Draft && reviewedDisclosureSha256!=Convert.ToHexStringLower(envelope.ErsdSha256??[]))throw new DocumentConflictException();
            }
            var cohort=pilot is null ? null : await pilot.RequireSendRosterLockedAsync(envelope,ct);
            if(envelope.Status!=EnvelopeStatus.Draft) {
                var existing=await SenderSentStatus.ReadSentAsync(db,envelope,expectedVersion,ct);
                var queued=workOptions.Enabled && envelope.Status==EnvelopeStatus.Sent && (envelope.ExpiresAt is null || envelope.ExpiresAt>time.GetUtcNow()) &&
                    await db.WorkItems.AnyAsync(x=>x.Id==existing.InvitationWorkId && x.Status==WorkStatus.Queued,ct);
                if(workOptions.Enabled && envelope.Status==EnvelopeStatus.Sent && envelope.ExpiresAt is not null)
                {
                    var workId=SigningExpiryJobs.WorkId(envelope.Id);
                    var job=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId,ct);
                    if(job is not null) {
                        if(!SigningExpiryJobs.Matches(envelope,job))throw SigningExpiryJobs.Invalid();
                        if(job.Status==WorkStatus.Queued) {expiryId=job.Id;expiryDue=job.AvailableAt;}
                    }
                }
                if(cohort is not null)SameCohort(cohort,await pilot!.RequireSendRosterLockedAsync(envelope,ct));
                if(HoldAdmission is null)await transaction.CommitAsync(ct);else await transaction.RollbackAsync(ct);
                await transaction.DisposeAsync();
                if(HoldAdmission is not null)await HoldAdmission.ReconcileAsync(envelope.Id,publicId,expectedVersion,existing,ct);
                if(cohort?.IsEnrolled==true)SameCohort(cohort,await pilot!.ReadAsync(envelope.Id,ct));
                if(queued)await outbox.PublishAsync(existing.InvitationWorkId,ct);
                if(expiryId is Guid pending)await expiry.PublishAsync(pending,expiryDue!.Value,ct);return existing;
            }
            if(!envelope.RowVersion.AsSpan().SequenceEqual(expectedVersion))throw new DocumentConflictException();
            var reminders=(reminderOptions??new()).Freeze(envelope.IsDemo);
            SignerReminderSendEvidence.DemandReview(reminders,reviewedReminderSha256,reviewedReminderSchedulingVersion);
            if(!reminders.Days.IsEmpty && reminderJobs is null)throw new InvalidOperationException("Configure durable reminder processing before enabling reminders.");
            var retention=await RetentionSigningDeadline.ReadAsync(db,envelope,ct);
            if(production is null)RetentionSigningDeadline.DemandReview(retention,reviewedRetentionSha256);
            else {
                if(retention.Policy is not null || reviewedRetentionSha256!=ProductionRetentionPolicyContract.Digest(production.Snapshot))throw new DocumentConflictException();
                CheckProductionDraft(production);
            }
            RetentionSigningDeadline.CheckDeadline(retention,time.GetUtcNow());
            envelope.ExpiresAt=retention.Effective;
            if(!workOptions.Enabled || !emailOptions.Enabled && cohort?.Allowed!=true)throw new EmailDisabledException();
            if(retention.Policy is not null && !await DemoPurgeJobs.IsPreparedLockedAsync(db,retention.Policy,ct))
                throw new DocumentRejectedException("This demo document's retention service needs attention before sending.");
            if (envelope.ExpiresAt <= time.GetUtcNow()) throw new DocumentRejectedException("This draft has expired.");
            var signers = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Order).ToListAsync(ct);
            var fields = await db.Fields.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Id).ToListAsync(ct);
            var recipients = await db.Recipients.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Id).ToListAsync(ct);
            var review = DraftReview.CheckPreparation(envelope,signers.Select(x => new SignerListItem(x.Id,x.Order,x.FullName,x.Email,x.Role)).ToArray(),
                fields,recipients.Select(x => new RecipientItem(x.Id,x.Name,x.Email)).ToArray());
            if (!review.ChecksPassed) throw new DocumentRejectedException("Complete document preparation before sending.");
            if (signers.Count > signerOptions.MaximumSigners || fields.Count > fieldOptions.MaximumFields || recipients.Count > preparation.MaximumRecipients ||
                signers.Where((x,i) => x.Order != i + 1 || x.Status != SignerStatus.Pending || x.ConsentAt is not null ||
                    !Name(x.FullName) || !Address(x.Email) || x.Role is { Length: > 512 }).Any() ||
                recipients.Any(x => !Name(x.Name) || !Address(x.Email)) || envelope.Message is { Length: > 4000 } ||
                envelope.Message?.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t')) == true)
                throw new DocumentRejectedException("The draft's party or field details are invalid.");
            var emails = signers.Select(x => x.Email).Concat(recipients.Select(x => x.Email)).Append(envelope.SenderEmail).Distinct().ToArray();
            if (await db.Suppressions.AnyAsync(x => emails.Contains(x.Email),ct)) throw new RecipientSuppressedException();
            var disclosure = production is null ? disclosures.Build(envelope.PublicId,envelope.Title!,envelope.SenderEmail,
                DemoDisclosureContext.From(envelope.IsDemo,envelope.PublicId,retention.Policy)) : disclosures.BuildProduction(envelope,envelope.Title!,production);
            if(production is not null && reviewedDisclosureSha256!=Convert.ToHexStringLower(disclosure.Sha256))throw new DocumentConflictException();
            envelope.Title = disclosure.Title; // Keep the persisted context identical to the canonical snapshot header.
            if (!Guid.TryParseExact(envelope.PdfBlob,"N",out var originalId) || originalId == Guid.Empty) throw new DocumentRejectedException("The confirmed PDF is unavailable.");
            using var source = new MemoryStream(); using var bounded = new BoundedDocumentStream(source,Math.Min(documents.MaximumBytes,64 * 1024 * 1024));
            var length = await storage.CopyToAsync(sender,new(envelope.Id,DocumentBlobKind.Normalized,originalId),bounded,ct);
            if (length != source.Length) throw new DocumentRejectedException("The saved PDF size changed.");
            var pages = JsonSerializer.Deserialize<List<PageGeometry>>(envelope.PageSizesJson!) ?? throw new DocumentRejectedException("The PDF page information is unavailable.");
            var rendered = renderer.Render(source.ToArray(),envelope.PdfSha256!,pages,fields.Where(x => x.SignerId is null).Select(x =>
                new SenderPrefillField(x.Id,null,x.Type.ToString(),x.Page,x.X,x.Y,x.Width,x.Height,x.Value)).ToArray());
            if(HoldAdmission is not null)
            {
                // Copying and rendering are read-only, but can outlive the
                // originally reviewed request. Reject before reserving effects.
                if(production is not null)CheckProductionDraft(production);
                RetentionSigningDeadline.CheckDeadline(retention,time.GetUtcNow());
                if(envelope.ExpiresAt<=time.GetUtcNow())throw new DocumentRejectedException("This draft has expired.");
                try { operation=await HoldAdmission.BeginLockedAsync(db,envelope.Id,publicId,expectedVersion,ct); }
                catch(Exception error) when(error is InvalidDataException or UnauthorizedAccessException or DocumentConflictException){return null;}
            }
            created = new(envelope.Id,DocumentBlobKind.Normalized,Guid.NewGuid());
            using(var frozen=new MemoryStream(rendered.Bytes))
            {
                if(operation is null)await storage.WriteAsync(sender,created.Value,frozen,frozen.Length,ct);
                else
                {
                    var target=new ProductionRecordWriteDescriptor(created.Value,frozen.Length,Convert.ToHexStringLower(rendered.Sha256));
                    var original=new ProductionRecordWriteDescriptor(new(envelope.Id,DocumentBlobKind.Normalized,originalId),length,Convert.ToHexStringLower(envelope.PdfSha256!));
                    await HoldAdmission!.PrepareAsync(db,operation,original,target,ct);
                    await HoldAdmission.WriteAsync(db,operation,sender,target,frozen,ct);
                }
            }
            // Slow storage must not let a now-expired draft become Sent.
            if (envelope.ExpiresAt <= time.GetUtcNow()) throw new DocumentRejectedException("This draft has expired.");
            var now = time.GetUtcNow(); envelope.Status = EnvelopeStatus.Sent; envelope.SentAt = now; envelope.ExclusionsAckAt = now;
            envelope.SentPdfBlob = created.Value.ObjectId.ToString("N"); envelope.SentPdfSha256 = rendered.Sha256;
            envelope.ErsdVersion = disclosure.Version; envelope.ErsdText = disclosure.Text; envelope.ErsdSha256 = disclosure.Sha256;
            var changed = await db.Envelopes.Where(x => x.Id == envelope.Id && x.Status == EnvelopeStatus.Draft && x.RowVersion == expectedVersion)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.Status,EnvelopeStatus.Sent).SetProperty(x => x.SentAt,now).SetProperty(x => x.ExclusionsAckAt,now)
                    .SetProperty(x => x.SentPdfBlob,envelope.SentPdfBlob).SetProperty(x => x.SentPdfSha256,rendered.Sha256)
                    .SetProperty(x => x.ExpiresAt,envelope.ExpiresAt).SetProperty(x => x.Title,disclosure.Title).SetProperty(x => x.ErsdVersion,disclosure.Version).SetProperty(x => x.ErsdText,disclosure.Text).SetProperty(x => x.ErsdSha256,disclosure.Sha256),ct);
            if (changed != 1) throw new DocumentConflictException();
            Func<Guid,DateTimeOffset,CancellationToken,Task>? demandHint=operation is null?null:
                (id,due,token)=>HoldAdmission!.DemandHintAsync(db,operation,id,due,token);
            var invitation = await outbox.PrepareAsync(envelope.Id,signers[0].Id,signers[0].Email,ct,demandHint:demandHint);
            RetentionSigningDeadline.CheckDeadline(retention,time.GetUtcNow());
            var fieldSnapshot = JsonSerializer.SerializeToUtf8Bytes(fields.Select(x => new { x.Id,x.SignerId,x.Type,x.Page,x.X,x.Y,x.Width,x.Height,x.Required,x.Label,x.Value }));
            var documentHash = Convert.ToHexStringLower(rendered.Sha256); var disclosureHash = Convert.ToHexStringLower(disclosure.Sha256);
            await audit.AppendAsync(envelope.Id,"fields_finalized",envelope.SenderEmail,ip,userAgent,ct,JsonSerializer.Serialize(new {
                fieldSnapshotSha256 = Convert.ToHexStringLower(SHA256.HashData(fieldSnapshot)),fieldCount = fields.Count,documentSha256 = documentHash }));
            RetentionSigningDeadline.CheckDeadline(retention,time.GetUtcNow());
            var sentData=JsonSerializer.Serialize(new {
                documentSha256 = documentHash,sourceSha256 = Convert.ToHexStringLower(rendered.SourceSha256),disclosureVersion = disclosure.Version,
                disclosureSha256 = disclosureHash,invitationWorkId = invitation,dispatch = "queued",exclusionsAcknowledged,
                expiryWorkId=envelope.ExpiresAt is null ? (Guid?)null : SigningExpiryJobs.WorkId(envelope.Id),signingDeadline=envelope.ExpiresAt?.ToUniversalTime(),
                reviewedVersion=Convert.ToBase64String(expectedVersion),senderConfirmed=sendAcknowledged,
                senderStatementVersion=SenderSendStatement.Version,senderStatement=SenderSendStatement.Text,senderStatementSha256=SenderSendStatement.Sha256,
                reminderPolicy=reminders.CanonicalJson,reminderPolicySha256=reminders.Sha256,reminderSchedulingVersion=SignerReminderEvidence.Version });
            if(retention.Policy is not null)
            {
                var data=JsonSerializer.Deserialize<Dictionary<string,JsonElement>>(sentData)!;
                data["retentionSigning"]=JsonSerializer.SerializeToElement(RetentionSigningDeadline.Evidence(retention));sentData=JsonSerializer.Serialize(data);
            }
            await audit.AppendAsync(envelope.Id,"sent",envelope.SenderEmail,ip,userAgent,ct,sentData);
            if(production is not null)CheckProductionDraft(production);
            RetentionSigningDeadline.CheckDeadline(retention,time.GetUtcNow());
            expiryId=await expiry.PrepareAsync(envelope.Id,ct,demandHint);expiryDue=envelope.ExpiresAt;
            if(reminderJobs is not null)reminderSchedule=await reminderJobs.PrepareCurrentLockedAsync(envelope.Id,ct,demandHint);
            result = new(envelope.Id,envelope.PublicId,invitation,documentHash,disclosureHash){Reminders=reminders,ReminderSchedulingVersion=SignerReminderEvidence.Version};
            RetentionSigningDeadline.CheckDeadline(retention,time.GetUtcNow());
            if((reminderOptions??new()).Freeze(envelope.IsDemo).Sha256!=reminders.Sha256)throw new DocumentConflictException();
            if(cohort is not null)SameCohort(cohort,await pilot!.RequireSendRosterLockedAsync(envelope,ct));
            if(cohort?.IsEnrolled==true) {
                var savedParent=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelope.Id,ct);
                if(await SenderSentStatus.ReadSentAsync(db,savedParent,expectedVersion,ct)!=result)throw new DocumentConflictException();
            }
            if(production is not null)CheckProductionDraft(production);
            if(operation is not null)
            {
                await HoldAdmission!.PrepareOutcomeLockedAsync(db,operation,ct);
                if(production is not null)CheckProductionDraft(production);
            }
            commitStarted = true; await transaction.CommitAsync(ct);
        }
        catch
        {
            // A failed commit can have an unknown outcome. Preserve potentially referenced bytes.
            if (!commitStarted && operation is null && created is DocumentBlob orphan)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try { await storage.DeleteAsync(sender,orphan,timeout.Token); }
                catch (Exception e) when (e is Azure.RequestFailedException or IOException or OperationCanceledException)
                { logger.LogWarning("Frozen PDF cleanup deferred ({FailureType}).",e.GetType().Name); }
            }
            throw;
        }
        if(operation is not null)await HoldAdmission!.CompleteAsync(operation,result!,ct);
        if(pilot is not null) {
            var cohort=await pilot.ReadAsync(result!.EnvelopeId,ct);
            if(cohort.IsEnrolled && !cohort.Allowed || !cohort.EnvelopeExists)throw new EmailDisabledException();
        }
        await outbox.PublishAsync(result!.InvitationWorkId,ct);
        if(reminderJobs is not null)await reminderJobs.PublishAsync(reminderSchedule,ct);
        if(expiryId is Guid scheduled)await expiry.PublishAsync(scheduled,expiryDue!.Value,ct);return result;
    }
    private void CheckProductionDraft(VerifiedProductionRetention policy)
    {
        if(ProductionRetentionPolicyContract.AddDays(policy.OriginalCreatedAt,policy.Snapshot.Policy.AbandonedDraftDays)<=time.GetUtcNow())
            throw new DocumentRejectedException("This draft has reached its fixed retention deadline.");
    }
    private static bool Name(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static void SameCohort(EmailPilotEnvelopeCohort before,EmailPilotEnvelopeCohort after)
    {
        if(!after.EnvelopeExists || before.IsEnrolled!=after.IsEnrolled || before.RunId!=after.RunId ||
            before.Scenario!=after.Scenario || before.RunExpiresAt!=after.RunExpiresAt || after.IsEnrolled && !after.Allowed)
            throw new EmailDisabledException();
    }
    private static bool Address(string value) { try { return EmailAddress.Normalize(value) == value; } catch (ArgumentException) { return false; } }
    internal static (Guid Id,string Email)? Identity(ClaimsPrincipal principal,string publicId)
    {
        var identities = principal.Identities.Where(x => x.IsAuthenticated).ToArray();
        if (identities.Length != 1 || identities[0].AuthenticationType != EnvelopeStorageAuthorization.SenderScheme) return null;
        string? One(string type) { var values = identities[0].FindAll(type).ToArray(); return values.Length == 1 ? values[0].Value : null; }
        return Guid.TryParse(One(EnvelopeStorageAuthorization.EnvelopeClaim),out var id) && id != Guid.Empty &&
            One(SenderConfiguration.PublicIdClaim) == publicId && One(ClaimTypes.Email) is string email && Address(email) ? (id,email) : null;
    }
}

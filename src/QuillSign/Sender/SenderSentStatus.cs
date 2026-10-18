using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Legal;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Sender;

public sealed record SenderSignerProgress(int Order,string Name,string Email,string? Role,string State,DateTimeOffset? SignedAt)
{
    public SenderInvitationProgress? Invitation {get;init;}
}
public sealed record SenderSentSnapshot(string PublicId,string Title,string? Message,EnvelopeStatus Status,DateTimeOffset SentAt,
    DateTimeOffset? ExpiresAt,IReadOnlyList<SenderSignerProgress> Signers,IReadOnlyList<RecipientItem> Recipients,SentDraft Sent)
{
    internal DateTimeOffset? RetentionDeadline {get;init;}
    public string State=>Status switch { EnvelopeStatus.Completed=>"Completed",EnvelopeStatus.Declined=>"Declined",EnvelopeStatus.Voided=>"Voided",
        EnvelopeStatus.Expired=>"Expired",_=>Signers.All(x=>x.SignedAt is not null) ? "Final completion pending" : "Sent for sequential signing" };
}

// Metadata-only private status; this grants no document reads, edits or signing authority.
public sealed class SenderSentStatus(QuillSignDbContext db,TimeProvider time,SignerCheckpointState checkpoints,InvitationResendProtection? resends=null,InvitationLineage? lineage=null)
{
    public async Task<SenderSentSnapshot?> GetAsync(ClaimsPrincipal sender,string publicId,byte[]? reviewedVersion=null,CancellationToken ct=default)
    {
        var identity=SendDraftWorkflow.Identity(sender,publicId); if(identity is null)return null;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct); await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {identity.Value.Id}")
            .AsNoTracking().SingleOrDefaultAsync(ct);
        if(envelope is null || envelope.PublicId!=publicId || envelope.SenderEmail!=identity.Value.Email || envelope.SenderVerifiedAt is null || envelope.Status==EnvelopeStatus.Draft)return null;
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope,time,ct);
        var sent=await ReadSentAsync(db,envelope,reviewedVersion,ct);
        await InvitationResendRules.VerifyIndexAsync(db,envelope.Id,ct,time);
        if(await checkpoints.CurrentAsync(envelope,ct) is null)throw new InvalidDataException("The saved signing state could not be verified.");
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        if(signers.Length is <1 or >100 || signers.Where((s,i)=>s.Order!=i+1 || !Enum.IsDefined(s.Status)).Any())throw new InvalidDataException("Invalid saved signing order.");
        var finishes=await db.SignerFinishAcceptances.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).Take(101).ToDictionaryAsync(x=>x.SignerId,ct);
        var invitations=await db.EmailOutbox.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Template=="signer-invitation")
            .Select(x=>new { x.To,x.Status,x.SubmissionStartedAt,Ambiguous=x.LastError=="submission-ambiguous" }).Take(101).ToArrayAsync(ct);
        if(invitations.Length>100 || invitations.Any(x=>!Enum.IsDefined(x.Status)))throw new InvalidDataException("Invalid invitation state.");
        var opened=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Event=="link_opened" && x.ActorType==PartyType.Signer).ToArrayAsync(ct);
        var corrected=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Event==SignerContactHistory.Event)
            .Select(x=>x.DataJson).Take(101).ToArrayAsync(ct);
        if(corrected.Length>100)throw InvitationSuccessorProtection.Invalid();
        var correctedSlots=new HashSet<Guid>();
        foreach(var raw in corrected) {using var change=JsonDocument.Parse(raw);correctedSlots.Add(change.RootElement.GetProperty("signerId").GetGuid());}
        var progress=new List<SenderSignerProgress>();
        foreach(var signer in signers) {
            // An earlier mailbox returning to the same address cannot make an
            // old opening look like activity in a corrected contact epoch.
            var linkOpened=!correctedSlots.Contains(signer.Id) && opened.Where(x=>x.ActorId==signer.Id && x.ActorEmail==signer.Email).Any(x=>
                x.At>=envelope.SentAt && x.At<=time.GetUtcNow() && CryptographicOperations.FixedTimeEquals(AuditHash.Compute(x),x.Hash));
            var invitation=invitations.SingleOrDefault(x=>x.To==signer.Email);
            var delivery=invitation is null ? "Waiting for their turn" : invitation.Status switch {
                EmailStatus.Sent=>linkOpened ? "Opened; consent pending" : "Invitation submitted",
                EmailStatus.Bounced=>"Invitation bounced; delivery needs attention",EmailStatus.Complained=>"Invitation complaint reported",
                EmailStatus.Failed=>invitation.Ambiguous ? "Invitation submission not confirmed" : "Invitation not sent; delivery needs attention",
                _=>invitation.SubmissionStartedAt is not null ? "Invitation submission not confirmed" : "Invitation queued" };
            var latest=await SenderInvitationStatus.LatestAsync(db,envelope,signer,resends,time,ct,lineage);
            if(latest is not null)delivery=latest.State;
            var mail=latest??(invitation is null ? null : new SenderInvitationProgress("Original",invitation.Status switch {
                EmailStatus.Sent=>"Invitation submitted",EmailStatus.Bounced=>"Invitation bounced; delivery needs attention",
                EmailStatus.Complained=>"Invitation complaint reported",EmailStatus.Failed=>invitation.Ambiguous ? "Invitation submission not confirmed" : "Invitation not sent; delivery needs attention",
                _=>invitation.SubmissionStartedAt is not null ? "Invitation submission not confirmed" : "Invitation queued" },null));
            var state=signer.Status switch { SignerStatus.Viewed=>envelope.Status==EnvelopeStatus.Voided ? "Consent recorded before void" : "Consent recorded; signing incomplete",
                SignerStatus.Signed=>"Signed",SignerStatus.Declined=>"Declined",_=>linkOpened ? "Opened; consent pending" : delivery };
            if(envelope.Status==EnvelopeStatus.Voided && (signer.Status is SignerStatus.Pending or SignerStatus.Notified))state="Not signed; request voided";
            if(finishes.TryGetValue(signer.Id,out var finish) && finish.ProcessedAt is null) {
                if(await checkpoints.AcceptanceAsync(finish,signer,ct) is null)throw new InvalidDataException("The saved Finish could not be verified.");
                state=envelope.Status==EnvelopeStatus.Voided ? "Finish accepted before void" :
                    envelope.Status==EnvelopeStatus.Sent && (envelope.ExpiresAt is null || envelope.ExpiresAt>time.GetUtcNow()) ? "Finish accepted; signing copy processing" : "Finish accepted; request closed";
            }
            progress.Add(new(signer.Order,signer.FullName,signer.Email,signer.Role,state,signer.Status==SignerStatus.Signed ? signer.SignedAt : null){Invitation=mail});
        }
        var recipients=await db.Recipients.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).OrderBy(x=>x.Name).Take(101).Select(x=>new RecipientItem(x.Id,x.Name,x.Email)).ToArrayAsync(ct);
        if(recipients.Length>100 || envelope.SentAt>time.GetUtcNow())throw new InvalidDataException("Invalid saved request state.");
        if(envelope.Status==EnvelopeStatus.Completed && (progress.Any(x=>x.SignedAt is null) || envelope.CompletedAt is null ||
            envelope.CompletedAt<envelope.SentAt || envelope.CompletedAt>time.GetUtcNow() || envelope.FinalSha256 is not { Length:32 } ||
            envelope.CertificateSha256 is not { Length:32 } || !Guid.TryParseExact(envelope.FinalBlob,"N",out var final) || final==Guid.Empty ||
            !Guid.TryParseExact(envelope.CertificateBlob,"N",out var certificate) || certificate==Guid.Empty ||
            string.IsNullOrWhiteSpace(envelope.SealProvider) || string.IsNullOrWhiteSpace(envelope.SealCertThumbprint)))
            throw new InvalidDataException("Completion metadata could not be verified.");
        var effective=envelope.Status==EnvelopeStatus.Sent && envelope.ExpiresAt<=time.GetUtcNow() ? EnvelopeStatus.Expired : envelope.Status;
        DocumentRetentionAccess.Check(deadline,time);
        await transaction.CommitAsync(ct);DocumentRetentionAccess.Check(deadline,time);
        return new(envelope.PublicId,envelope.Title!,envelope.Message,effective,envelope.SentAt!.Value,envelope.ExpiresAt,progress,recipients,sent){RetentionDeadline=deadline};
    }

    internal static async Task<SentDraft> ReadSentAsync(QuillSignDbContext db,Envelope envelope,byte[]? version,CancellationToken ct)
    {
        if(!Enum.IsDefined(envelope.Status) || envelope.Status==EnvelopeStatus.Draft || envelope.SentAt is null || envelope.ExclusionsAckAt!=envelope.SentAt ||
            envelope.SentPdfSha256 is not { Length:32 } || envelope.PdfSha256 is not { Length:32 } || envelope.ErsdSha256 is not { Length:32 } ||
            !Guid.TryParseExact(envelope.SentPdfBlob,"N",out var blob) || blob==Guid.Empty ||
            !ElectronicRecordDisclosure.Verify(new(envelope.ErsdVersion!,envelope.PublicId,envelope.Title!,envelope.SenderEmail,envelope.ErsdText!,envelope.ErsdSha256)))
            throw new InvalidDataException("The sent request could not be verified.");
        var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Event=="sent").Take(2).ToArrayAsync(ct);
        if(events.Length!=1 || events[0].ActorType!=PartyType.Sender || events[0].ActorEmail!=envelope.SenderEmail || events[0].DataJson.Length>16384 ||
            !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(events[0]),events[0].Hash))throw new InvalidDataException("The Send evidence could not be verified.");
        try {
            using var data=JsonDocument.Parse(events[0].DataJson,new JsonDocumentOptions { MaxDepth=8 }); var p=data.RootElement;
            if(p.GetProperty("documentSha256").GetString()!=Convert.ToHexStringLower(envelope.SentPdfSha256) ||
                p.GetProperty("sourceSha256").GetString()!=Convert.ToHexStringLower(envelope.PdfSha256) ||
                p.GetProperty("disclosureSha256").GetString()!=Convert.ToHexStringLower(envelope.ErsdSha256) ||
                p.GetProperty("disclosureVersion").GetString()!=envelope.ErsdVersion || !p.GetProperty("exclusionsAcknowledged").GetBoolean() ||
                p.GetProperty("dispatch").GetString()!="queued")throw new InvalidDataException("The Send bindings could not be verified.");
            if(version is not null && (version.Length!=8 || !p.TryGetProperty("reviewedVersion",out var reviewed) || reviewed.GetString()!=Convert.ToBase64String(version) ||
                !p.TryGetProperty("senderConfirmed",out var confirmed) || !confirmed.GetBoolean() ||
                !p.TryGetProperty("senderStatementVersion",out var statementVersion) || statementVersion.GetString()!=SenderSendStatement.Version ||
                !p.TryGetProperty("senderStatement",out var statement) || statement.GetString()!=SenderSendStatement.Text ||
                !p.TryGetProperty("senderStatementSha256",out var statementHash) || statementHash.GetString()!=SenderSendStatement.Sha256))
                throw new DocumentConflictException();
            var invitation=p.GetProperty("invitationWorkId").GetGuid();
            if(invitation==Guid.Empty || !await db.EmailOutbox.AnyAsync(x=>x.Id==invitation && x.EnvelopeId==envelope.Id && x.Template=="signer-invitation",ct))
                throw new InvalidDataException("The queued invitation could not be verified.");
            var hasSchedule=p.TryGetProperty("expiryWorkId",out var schedule);var hasDeadline=p.TryGetProperty("signingDeadline",out var deadline);
            if(hasSchedule || hasDeadline)
            {
                if(!hasSchedule || !hasDeadline)throw SigningExpiryJobs.Invalid();
                if(envelope.ExpiresAt is DateTimeOffset due)
                {
                    var at=deadline.GetDateTimeOffset();var scheduled=schedule.GetGuid();
                    if(scheduled!=SigningExpiryJobs.WorkId(envelope.Id) || at.Offset!=TimeSpan.Zero || at!=due.ToUniversalTime())throw SigningExpiryJobs.Invalid();
                    var job=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==scheduled,ct);
                    if(job is null || !SigningExpiryJobs.Matches(envelope,job))throw SigningExpiryJobs.Invalid();
                }
                else if(schedule.ValueKind!=JsonValueKind.Null || deadline.ValueKind!=JsonValueKind.Null)throw SigningExpiryJobs.Invalid();
            }
            await RetentionSigningDeadline.VerifyEvidenceAsync(db,envelope,p,ct);
            return new(envelope.Id,envelope.PublicId,invitation,Convert.ToHexStringLower(envelope.SentPdfSha256),Convert.ToHexStringLower(envelope.ErsdSha256));
        }
        catch(Exception e) when(e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        { throw new InvalidDataException("The Send evidence could not be verified.",e); }
    }
}

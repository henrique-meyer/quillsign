using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Sender;

public sealed record SentDraft(Guid EnvelopeId,string PublicId,Guid InvitationWorkId,string DocumentHash,string DisclosureHash);

// The public handler adds CSRF and deliberate sender confirmation; this service owns atomic freeze and replay.
public sealed class SendDraftWorkflow(QuillSignDbContext db,IBlobStore storage,DocumentOptions documents,
    SignerSetupOptions signerOptions,FieldEditorOptions fieldOptions,PreparationOptions preparation,SenderPdfRenderer renderer,
    ElectronicRecordDisclosure disclosures,SignerInvitationOutbox outbox,WorkOptions workOptions,EmailOptions emailOptions,
    AuditWriter audit,TimeProvider time,ILogger<SendDraftWorkflow> logger)
{
    public async Task<SentDraft?> SendAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,bool exclusionsAcknowledged,
        bool sendAcknowledged,string? statementVersion,string? ip,string? userAgent,CancellationToken ct = default)
    {
        var identity = Identity(sender,publicId); if (identity is null) return null;
        if (!exclusionsAcknowledged) throw new DocumentRejectedException("Confirm that this transaction is suitable for electronic signing.");
        if(!sendAcknowledged || statementVersion!=SenderSendStatement.Version)throw new DocumentRejectedException("Confirm the reviewed Send statement.");
        if (expectedVersion is not { Length: 8 }) throw new DocumentConflictException();
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        DocumentBlob? created = null; var commitStarted = false; SentDraft? result = null;
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            var envelope = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {identity.Value.Id}")
                .AsNoTracking().SingleOrDefaultAsync(ct);
            if (envelope is null || envelope.PublicId != publicId || envelope.SenderEmail != identity.Value.Email || envelope.SenderVerifiedAt is null) return null;
            if(envelope.Status!=EnvelopeStatus.Draft) {
                var existing=await SenderSentStatus.ReadSentAsync(db,envelope,expectedVersion,ct);
                var queued=workOptions.Enabled && envelope.Status==EnvelopeStatus.Sent && (envelope.ExpiresAt is null || envelope.ExpiresAt>time.GetUtcNow()) &&
                    await db.WorkItems.AnyAsync(x=>x.Id==existing.InvitationWorkId && x.Status==WorkStatus.Queued,ct);
                await transaction.CommitAsync(ct); await transaction.DisposeAsync();
                if(queued)await outbox.PublishAsync(existing.InvitationWorkId,ct); return existing;
            }
            if(!envelope.RowVersion.AsSpan().SequenceEqual(expectedVersion))throw new DocumentConflictException();
            if(!workOptions.Enabled || !emailOptions.Enabled)throw new EmailDisabledException();
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
            var disclosure = disclosures.Build(envelope.PublicId,envelope.Title!,envelope.SenderEmail);
            envelope.Title = disclosure.Title; // Keep the persisted context identical to the canonical snapshot header.
            if (!Guid.TryParseExact(envelope.PdfBlob,"N",out var originalId) || originalId == Guid.Empty) throw new DocumentRejectedException("The confirmed PDF is unavailable.");
            using var source = new MemoryStream(); using var bounded = new BoundedDocumentStream(source,Math.Min(documents.MaximumBytes,64 * 1024 * 1024));
            var length = await storage.CopyToAsync(sender,new(envelope.Id,DocumentBlobKind.Normalized,originalId),bounded,ct);
            if (length != source.Length) throw new DocumentRejectedException("The saved PDF size changed.");
            var pages = JsonSerializer.Deserialize<List<PageGeometry>>(envelope.PageSizesJson!) ?? throw new DocumentRejectedException("The PDF page information is unavailable.");
            var rendered = renderer.Render(source.ToArray(),envelope.PdfSha256!,pages,fields.Where(x => x.SignerId is null).Select(x =>
                new SenderPrefillField(x.Id,null,x.Type.ToString(),x.Page,x.X,x.Y,x.Width,x.Height,x.Value)).ToArray());
            created = new(envelope.Id,DocumentBlobKind.Normalized,Guid.NewGuid());
            using (var frozen = new MemoryStream(rendered.Bytes)) await storage.WriteAsync(sender,created.Value,frozen,frozen.Length,ct);
            // Slow storage must not let a now-expired draft become Sent.
            if (envelope.ExpiresAt <= time.GetUtcNow()) throw new DocumentRejectedException("This draft has expired.");
            var now = time.GetUtcNow(); envelope.Status = EnvelopeStatus.Sent; envelope.SentAt = now; envelope.ExclusionsAckAt = now;
            envelope.SentPdfBlob = created.Value.ObjectId.ToString("N"); envelope.SentPdfSha256 = rendered.Sha256;
            envelope.ErsdVersion = disclosure.Version; envelope.ErsdText = disclosure.Text; envelope.ErsdSha256 = disclosure.Sha256;
            var changed = await db.Envelopes.Where(x => x.Id == envelope.Id && x.Status == EnvelopeStatus.Draft && x.RowVersion == expectedVersion)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.Status,EnvelopeStatus.Sent).SetProperty(x => x.SentAt,now).SetProperty(x => x.ExclusionsAckAt,now)
                    .SetProperty(x => x.SentPdfBlob,envelope.SentPdfBlob).SetProperty(x => x.SentPdfSha256,rendered.Sha256)
                    .SetProperty(x => x.Title,disclosure.Title).SetProperty(x => x.ErsdVersion,disclosure.Version).SetProperty(x => x.ErsdText,disclosure.Text).SetProperty(x => x.ErsdSha256,disclosure.Sha256),ct);
            if (changed != 1) throw new DocumentConflictException();
            var invitation = await outbox.PrepareAsync(envelope.Id,signers[0].Id,signers[0].Email,ct);
            var fieldSnapshot = JsonSerializer.SerializeToUtf8Bytes(fields.Select(x => new { x.Id,x.SignerId,x.Type,x.Page,x.X,x.Y,x.Width,x.Height,x.Required,x.Label,x.Value }));
            var documentHash = Convert.ToHexStringLower(rendered.Sha256); var disclosureHash = Convert.ToHexStringLower(disclosure.Sha256);
            await audit.AppendAsync(envelope.Id,"fields_finalized",envelope.SenderEmail,ip,userAgent,ct,JsonSerializer.Serialize(new {
                fieldSnapshotSha256 = Convert.ToHexStringLower(SHA256.HashData(fieldSnapshot)),fieldCount = fields.Count,documentSha256 = documentHash }));
            await audit.AppendAsync(envelope.Id,"sent",envelope.SenderEmail,ip,userAgent,ct,JsonSerializer.Serialize(new {
                documentSha256 = documentHash,sourceSha256 = Convert.ToHexStringLower(rendered.SourceSha256),disclosureVersion = disclosure.Version,
                disclosureSha256 = disclosureHash,invitationWorkId = invitation,dispatch = "queued",exclusionsAcknowledged,
                reviewedVersion=Convert.ToBase64String(expectedVersion),senderConfirmed=sendAcknowledged,
                senderStatementVersion=SenderSendStatement.Version,senderStatement=SenderSendStatement.Text,senderStatementSha256=SenderSendStatement.Sha256 }));
            result = new(envelope.Id,envelope.PublicId,invitation,documentHash,disclosureHash);
            commitStarted = true; await transaction.CommitAsync(ct);
        }
        catch
        {
            // A failed commit can have an unknown outcome. Preserve potentially referenced bytes.
            if (!commitStarted && created is DocumentBlob orphan)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try { await storage.DeleteAsync(sender,orphan,timeout.Token); }
                catch (Exception e) when (e is Azure.RequestFailedException or IOException or OperationCanceledException)
                { logger.LogWarning("Frozen PDF cleanup deferred ({FailureType}).",e.GetType().Name); }
            }
            throw;
        }
        await outbox.PublishAsync(result!.InvitationWorkId,ct); return result;
    }
    private static bool Name(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
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

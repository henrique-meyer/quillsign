using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Signing;

namespace QuillSign.Work;

public sealed class SignerCheckpointHandler(QuillSignDbContext db,SignerCheckpointState state,SignerCheckpointBlobs blobs,
    SignerInvitationOutbox invitations,AuditWriter audit,TimeProvider time,CompletionJobs? completion=null) : IWorkHandler
{
    public WorkKind Kind=>WorkKind.Rendering;
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        try
        {
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            var located=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
            if(lease.Kind!=Kind || located?.EnvelopeId is not Guid envelopeId || located.Kind!=Kind || located.PayloadJson.Length>1024)return new(WorkOutcome.Failed,"invalid-checkpoint-scope");
            SignerCheckpointPayload? payload;
            try { payload=JsonSerializer.Deserialize<SignerCheckpointPayload>(located.PayloadJson); } catch(JsonException) { return new(WorkOutcome.Failed,"invalid-checkpoint-payload"); }
            if(payload?.Version!=SignerCheckpointJobs.Version || payload.FinishId!=lease.Id)return new(WorkOutcome.Failed,"invalid-checkpoint-payload");
            await using var transaction=await db.Database.BeginTransactionAsync(ct);
            var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {envelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
            if(envelope is null || !await Owns(lease,located.PayloadJson,ct))return new(WorkOutcome.Retry,"checkpoint-lease-unavailable");
            var f=await db.SignerFinishAcceptances.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==payload.FinishId && x.EnvelopeId==envelopeId,ct);
            var signer=f is null ? null : await db.Signers.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==f.SignerId && x.EnvelopeId==envelopeId,ct);
            if(f is null || signer is null || envelope.ErsdVersion is null || envelope.ErsdText is null || envelope.Title is null || envelope.ErsdSha256 is not { Length:32 } ||
                !ElectronicRecordDisclosure.Verify(new(envelope.ErsdVersion,envelope.PublicId,envelope.Title,envelope.SenderEmail,envelope.ErsdText,envelope.ErsdSha256)) ||
                !SignerCheckpointState.Same(f.DisclosureSha256,envelope.ErsdSha256))return new(WorkOutcome.Failed,"checkpoint-evidence-unavailable");
            var source=await state.CurrentAsync(envelope,ct); if(source is null)return new(WorkOutcome.Failed,"checkpoint-chain-unavailable");
            var adopted=await state.AcceptanceAsync(f,signer,ct); if(adopted is null)return new(WorkOutcome.Failed,"checkpoint-evidence-unavailable");
            _=await blobs.PdfAsync(f,true,ct); _=await blobs.PdfAsync(f,false,ct); await blobs.AssetsAsync(f,adopted,ct);
            if(!await Owns(lease,located.PayloadJson,ct))return new(WorkOutcome.Retry,"checkpoint-lease-unavailable");
            if(f.ProcessedAt is not null)
            {
                var evidence=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId && x.Event=="signer_completed" && x.ActorId==signer.Id).ToArrayAsync(ct);
                if(signer.Status!=SignerStatus.Signed || signer.SignedAt!=f.FinishedAt || !SignerCheckpointState.PublishedEvidence(evidence,f,signer))return new(WorkOutcome.Failed,"checkpoint-evidence-unavailable");
                var recovered=completion is not null && !await db.Signers.AnyAsync(x=>x.EnvelopeId==envelopeId && x.Order>signer.Order,ct) ? await completion.PrepareAsync(envelopeId,ct) : null;
                await transaction.CommitAsync(ct); await transaction.DisposeAsync();
                if(recovered is Guid recoveredWork)await completion!.PublishAsync(recoveredWork,ct);
                return new(WorkOutcome.Completed);
            }
            if(!Accepted(envelope,f) || signer.Status!=SignerStatus.Viewed || signer.SignedAt is not null || source.ObjectId!=f.SourceObjectId ||
                !SignerCheckpointState.Same(source.Sha256,f.SourceSha256) || await db.Signers.AnyAsync(x=>x.EnvelopeId==envelopeId && x.Order<signer.Order && x.Status!=SignerStatus.Signed,ct))
                return new(WorkOutcome.Failed,"checkpoint-not-current");
            var next=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId && x.Order>signer.Order).OrderBy(x=>x.Order).FirstOrDefaultAsync(ct);
            if(next is not null && next.Status!=SignerStatus.Pending)return new(WorkOutcome.Failed,"next-signer-not-pending");
            var inviteNext=next is not null && (envelope.ExpiresAt is null || envelope.ExpiresAt>time.GetUtcNow());
            f.ProcessedAt=time.GetUtcNow(); f.NextInvitationId=inviteNext ? Guid.NewGuid() : null;
            var changed=await db.SignerFinishAcceptances.Where(x=>x.Id==f.Id && x.RowVersion==f.RowVersion && x.ProcessedAt==null)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ProcessedAt,f.ProcessedAt).SetProperty(x=>x.NextInvitationId,f.NextInvitationId),ct);
            if(changed!=1)return new(WorkOutcome.Retry,"checkpoint-conflict");
            var signerChanged=await db.Signers.Where(x=>x.Id==signer.Id && x.EnvelopeId==envelopeId && x.Status==SignerStatus.Viewed && x.RowVersion==signer.RowVersion)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Signed).SetProperty(x=>x.SignedAt,f.FinishedAt).SetProperty(x=>x.SignedIp,f.Ip).SetProperty(x=>x.SignedUa,f.UserAgent),ct);
            var envelopeChanged=await db.Envelopes.Where(x=>x.Id==envelopeId && x.RowVersion==envelope.RowVersion)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CurrentFinishId,f.Id).SetProperty(x=>x.CurrentCopyVersion,source.Version+1),ct);
            if(signerChanged!=1 || envelopeChanged!=1)return new(WorkOutcome.Retry,"checkpoint-conflict");
            await audit.AppendAsync(envelopeId,"signer_completed",signer.Email,f.Ip,f.UserAgent,ct,SignerCheckpointState.PublishedJson(f),PartyType.Signer,signer.Id);
            if(inviteNext)await invitations.PrepareAsync(envelopeId,next!.Id,next.Email,ct,f.NextInvitationId);
            var completionWork=next is null && completion is not null ? await completion.PrepareAsync(envelopeId,ct) : null;
            if(!Accepted(envelope,f) || inviteNext && envelope.ExpiresAt<=time.GetUtcNow() || !await Owns(lease,located.PayloadJson,ct))return new(WorkOutcome.Retry,"checkpoint-expired-during-publication");
            await transaction.CommitAsync(ct); await transaction.DisposeAsync();
            if(f.NextInvitationId is Guid invitation)await invitations.PublishAsync(invitation,ct);
            if(completionWork is Guid finalization)await completion!.PublishAsync(finalization,ct);
            return new(WorkOutcome.Completed);
        }
        catch(Exception e) when(e is IOException or Azure.RequestFailedException or HttpRequestException or EmailDisabledException)
        { return new(WorkOutcome.Retry,"checkpoint-storage-or-delivery-unavailable"); }
        catch(Exception e) when(e is InvalidDataException or SignatureImageRejectedException or DocumentRejectedException)
        { return new(WorkOutcome.Failed,"checkpoint-integrity-unavailable"); }
    }
    // The signer acted before the frozen deadline. Processing time must not discard
    // that acceptance, but later invitation issuance still requires a live deadline.
    private bool Accepted(Envelope envelope,SignerFinishAcceptance finish)=>envelope.Status==EnvelopeStatus.Sent && envelope.SenderVerifiedAt is not null &&
        envelope.SentAt<=finish.FinishedAt && finish.FinishedAt<=time.GetUtcNow() &&
        (envelope.ExpiresAt is null || finish.FinishedAt<envelope.ExpiresAt && finish.ReviewExpiresAt<=envelope.ExpiresAt);
    private async Task<bool> Owns(WorkLease lease,string payload,CancellationToken ct)
    {
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        return row is not null && row.Kind==Kind && row.Status==WorkStatus.Leased && row.LeaseOwner==lease.Owner && row.Attempts==lease.Attempt &&
            row.LeaseExpiresAt==lease.Until && row.LeaseExpiresAt>time.GetUtcNow() && row.PayloadJson==payload;
    }
}

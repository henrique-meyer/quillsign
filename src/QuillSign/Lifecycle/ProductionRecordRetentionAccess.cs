using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

internal sealed record ProductionRecordRetentionRead(ProductionEnrollmentKind Kind,
    VerifiedProductionRetention? Enrollment=null,ProductionRecordStage? Stage=null,DateTimeOffset? Deadline=null);

// Internal metadata boundary. The caller already authorizes the participant and
// holds its transaction; this result is not a session or destructive capability.
// No read enrolls a historical record or manufactures missing terminal evidence.
internal static class ProductionRecordRetentionAccess
{
    // Publication metadata verification also runs before a terminal anchor exists.
    // Keep that enrollment-only read separate to avoid recursive terminal checks.
    internal static async Task<VerifiedProductionRetention?> EnrollmentAsync(QuillSignDbContext db,Envelope supplied,
        TimeProvider time,CancellationToken ct=default)
    {
        await using var owned=db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var read=await new ProductionRetentionLedger(db,new(db,time),time).ReadLockedAsync(supplied.Id,ct);
        if(read.Kind==ProductionEnrollmentKind.MissingRecord)throw ProductionRetentionLedger.Invalid();
        if(read.Enrollment is not null) {
            var current=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==supplied.Id,ct);
            if(current.PublicId!=supplied.PublicId || current.SenderEmail!=supplied.SenderEmail || current.CreatedAt!=supplied.CreatedAt ||
                current.IsDemo!=supplied.IsDemo)throw ProductionRetentionLedger.Invalid();
        }
        if(owned is not null)await owned.CommitAsync(ct);
        return read.Enrollment;
    }

    internal static async Task<ProductionRecordRetentionRead> ReadLockedAsync(QuillSignDbContext db,Envelope supplied,
        TimeProvider time,CancellationToken ct=default)
    {
        var ledger=new ProductionRetentionLedger(db,new(db,time),time);
        var read=await ledger.ReadLockedAsync(supplied.Id,ct);
        if(read.Kind!=ProductionEnrollmentKind.Enrolled)return new(read.Kind);
        var saved=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==supplied.Id,ct);
        if(saved.PublicId!=supplied.PublicId || saved.SenderEmail!=supplied.SenderEmail || saved.IsDemo!=supplied.IsDemo ||
            saved.CreatedAt!=supplied.CreatedAt)throw ProductionRetentionLedger.Invalid();
        var enrollment=read.Enrollment!;
        var terminal=await ledger.ReadTerminalLockedAsync(saved.Id,ct);
        if(saved.Status is EnvelopeStatus.Draft or EnvelopeStatus.Sent)
        {
            if(terminal is not null)throw ProductionRetentionLedger.Invalid();
            if(saved.Status==EnvelopeStatus.Draft)return new(read.Kind,enrollment,ProductionRecordStage.Draft,
                ProductionRetentionPolicyContract.AddDays(enrollment.OriginalCreatedAt,enrollment.Snapshot.Policy.AbandonedDraftDays));
            var pending=await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==saved.Id && x.ProcessedAt==null,ct);
            var hasSigners=await db.Signers.AnyAsync(x=>x.EnvelopeId==saved.Id,ct);
            var allSigned=hasSigners && !await db.Signers.AnyAsync(x=>x.EnvelopeId==saved.Id && x.Status!=SignerStatus.Signed,ct);
            return new(read.Kind,enrollment,pending || allSigned ? ProductionRecordStage.Completing : ProductionRecordStage.Signing);
        }
        if(terminal is null)throw ProductionRetentionLedger.Invalid();
        var stage=saved.Status switch {
            EnvelopeStatus.Completed=>ProductionRecordStage.Completed,EnvelopeStatus.Expired=>ProductionRecordStage.Expired,
            EnvelopeStatus.Declined=>ProductionRecordStage.Declined,EnvelopeStatus.Voided=>ProductionRecordStage.Voided,
            _=>throw ProductionRetentionLedger.Invalid() };
        return new(read.Kind,enrollment,stage,ProductionRetentionLedger.ExactEligibleAt(enrollment,terminal));
    }

    // Only actual lifecycle transition commands call this before their commit.
    // Reads never manufacture an anchor or repair missing terminal provenance.
    internal static async Task AnchorLockedIfEnrolledAsync(QuillSignDbContext db,Guid id,TimeProvider time,CancellationToken ct=default)
    {
        var ledger=new ProductionRetentionLedger(db,new(db,time),time);
        if((await ledger.ReadLockedAsync(id,ct)).Kind==ProductionEnrollmentKind.Enrolled)
            _=await ledger.CaptureTerminalLockedAsync(id,ct);
    }
}

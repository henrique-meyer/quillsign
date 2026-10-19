using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed class EmailPilotSimulatorDelivery(QuillSignDbContext db,EmailPilotSimulatorAuthority authority,
    Func<EmailPilotSimulatorSender> sender,TimeProvider time)
{
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct=default)
    {
        var scope=await authority.ReadAsync(lease,ct);
        if(scope is null)return new(WorkOutcome.Failed,"pilot-simulator-unavailable");
        await using(var transaction=await db.Database.BeginTransactionAsync(ct)) {
            var work=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
            if(work is null || !EmailPilotSimulatorAuthority.Owned(work,lease,time.GetUtcNow()))return new(WorkOutcome.Failed,"pilot-simulator-unavailable");
            var current=await authority.ReadLockedAsync(lease,db,ct);
            if(current is null || current.SourceHash!=scope.SourceHash || current.RunId!=scope.RunId)return new(WorkOutcome.Failed,"pilot-simulator-unavailable");
            var row=await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
            if(row.SubmissionStartedAt is not null)return new(WorkOutcome.Ambiguous,"submission-ambiguous");
            var at=time.GetUtcNow();if(scope.Until<=at)return new(WorkOutcome.Failed,"pilot-simulator-unavailable");
            var changed=await db.EmailOutbox.Where(x=>x.Id==lease.Id && x.EnvelopeId==null && x.Status==EmailStatus.Queued && x.SubmissionStartedAt==null)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,at).SetProperty(x=>x.Attempts,lease.Attempt),ct);
            if(changed!=1)throw new InvalidOperationException("Simulator submission is no longer available.");
            if(scope.Until<=time.GetUtcNow())return new(WorkOutcome.Failed,"pilot-simulator-unavailable");
            await transaction.CommitAsync(ct);
        }
        try {
            var receipt=await sender().SendAsync(lease,ct);
            // Same normal receipt columns used by signed SES feedback. Preserve
            // feedback which raced this write; no synthetic feedback is invented.
            await db.EmailOutbox.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Provider,receipt.Provider)
                .SetProperty(x=>x.ProviderMessageId,receipt.MessageId).SetProperty(x=>x.Status,x=>x.Status==EmailStatus.Queued?EmailStatus.Sent:x.Status),ct);
            return new(WorkOutcome.Completed);
        }catch(EmailNotSubmittedException e) {
            // Only a definite rejection clears intent. Its consumed attempt is
            // never refunded; a later owned attempt needs its own reservation.
            await db.EmailOutbox.Where(x=>x.Id==lease.Id && x.Status==EmailStatus.Queued && x.Attempts==lease.Attempt)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SubmissionStartedAt,(DateTimeOffset?)null),ct);
            return new(e.Retryable?WorkOutcome.Retry:WorkOutcome.Failed,"provider-rejected");
        }catch(EmailPilotTransportRefusedException) {
            // Refusal/AlreadyConsumed may follow a prior successful invocation.
            // Retain intent and forbid resubmission, including a duplicated call.
            return new(WorkOutcome.Ambiguous,"pilot-simulator-submission-uncertain");
        }
        // Unknown provider/factory/receipt-write failures keep intent intact.
    }
}

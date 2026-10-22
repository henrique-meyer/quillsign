using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed record EmailPilotCloseoutOperatorStatus(DateTimeOffset Until,bool DeclineVerificationSaved,bool LookupSaved);

public sealed class EmailPilotCloseoutOperator(EmailPilotCloseoutOperatorBrowser browser,Func<EmailPilotCloseout> closeout,
    Func<QuillSignDbContext> database,Func<EmailOutboxWriter> outbox,Func<EmailPilotCloseoutLookup> lookup,Func<IWorkSignals> signals,TimeProvider time)
{
    private void Demand(EmailPilotCloseoutOperatorSession s)
    {if(!browser.Live(s))throw new EmailDisabledException();}
    public async Task<EmailPilotCloseoutCommittedReceipt> ReadCommittedReceiptAsync(EmailPilotCloseoutOperatorSession s,CancellationToken ct=default)
    {
        void Check(){if(!browser.LiveReceipt(s))throw new EmailDisabledException();}
        Check();var db=database();if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())throw EmailPilotProtection.Invalid();
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(ct);stop.CancelAfter(TimeSpan.FromSeconds(15));
        await db.Database.OpenConnectionAsync(stop.Token);Check();
        await using var tx=await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable,stop.Token);
        EmailPilotCloseoutCommittedReceipt result;
        try {
            await db.Database.ExecuteSqlRawAsync("SET LOCK_TIMEOUT 5000",stop.Token);Check();
            result=await closeout().ReadCommittedReceiptLockedAsync(db,s.AuthorizationId,stop.Token);Check();
        } finally {await tx.RollbackAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));}
        Check();return result;
    }
    public async Task<EmailPilotOperatorNotice> StartAsync(EmailPilotCloseoutOperatorSession s,CancellationToken ct=default)
    {
        Demand(s);var saved=await closeout().CreateAsync(s.Capability,ct);Demand(s);if(saved.AuthorizationId!=s.AuthorizationId)throw EmailPilotProtection.Invalid();
        foreach(var id in saved.CompletionWork.Concat(saved.VoidWork)) {
            Demand(s);var db=database();var w=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id,ct);var m=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
            if(w.Status!=WorkStatus.Queued || w.Attempts!=0 || w.LeaseOwner is not null || w.LeaseExpiresAt is not null ||
                m.Status!=EmailStatus.Queued || m.Attempts!=0 || m.SubmissionStartedAt is not null || m.Provider is not null || m.ProviderMessageId is not null)continue;
            Demand(s);await signals().PutHintAsync(id,w.AvailableAt,ct);Demand(s);await signals().PublishAsync(id,TimeSpan.Zero,ct);Demand(s);
        }
        return EmailPilotOperatorNotice.EnvelopeSaved;
    }
    public async Task<EmailPilotCloseoutOperatorStatus?> ReadAsync(EmailPilotCloseoutOperatorSession s,CancellationToken ct=default)
    {
        Demand(s);var db=database();await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using var tx=await db.Database.BeginTransactionAsync(ct);var saved=await closeout().ReadLockedAsync(db,ct);
        if(saved is null)return null;if(saved.AuthorizationId!=s.AuthorizationId)throw EmailPilotProtection.Invalid();
        var verification=await closeout().ReadStepLockedAsync(db,saved,EmailPilotCloseoutStep.DeclineVerification,ct);
        var request=await closeout().ReadStepLockedAsync(db,saved,EmailPilotCloseoutStep.Lookup,ct);
        Demand(s);await tx.CommitAsync(ct);Demand(s);return new(saved.Until,verification is not null,request is not null);
    }
    // New ordinary verification for the SAME existing unverified draft. No
    // SenderVerifiedAt/session is seeded; only the real mailbox link can verify.
    public async Task<EmailPilotOperatorNotice> VerifyDeclineAsync(EmailPilotCloseoutOperatorSession s,CancellationToken ct=default)
    {
        Demand(s);var db=database();if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Closeout verification requires a clean context.");
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);Guid work;
        try {
            await using(var tx=await db.Database.BeginTransactionAsync(ct)) {
                var saved=await closeout().ReadLockedAsync(db,ct)??throw EmailPilotProtection.Invalid();
                if(saved.AuthorizationId!=s.AuthorizationId)throw EmailPilotProtection.Invalid();
                var existing=await closeout().ReadStepLockedAsync(db,saved,EmailPilotCloseoutStep.DeclineVerification,ct);
                if(existing is {} id)work=id;
                else {
                    var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={saved.DeclineRecord}").AsNoTracking().SingleOrDefaultAsync(ct);
                    if(e is null || !e.IsDemo || e.Status!=EnvelopeStatus.Draft || e.SenderVerifiedAt is not null || e.SenderEmail!=saved.Mailboxes.Sender ||
                        await db.Suppressions.AnyAsync(x=>x.Email==e.SenderEmail,ct))throw EmailPilotProtection.Invalid();
                    var scope=new EmailPilotAdmissionScope(db,e.Id,e.SenderEmail,()=>{Demand(s);if(!closeout().CanAdmit||saved.Until<=time.GetUtcNow())throw EmailPilotProtection.Invalid();});
                    work=closeout().HostOptions.HostRole==EmailPilotCloseoutHostRole.Legacy?await outbox().PreparePilotVerificationAsync(e.Id,e.SenderEmail,scope,ct):await outbox().PrepareCloseoutVerificationAsync(e.Id,e.SenderEmail,scope,closeout().HostOptions,ct);
                    await closeout().BindNewWorkLockedAsync(db,saved,EmailPilotCloseoutStep.DeclineVerification,work,ct);
                }
                Demand(s);await tx.CommitAsync(ct);
            }
        }catch {db.ChangeTracker.Clear();throw;}
        Demand(s);var item=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==work,ct);var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==work,ct);
        if(item.Status!=WorkStatus.Queued || item.Attempts!=0 || item.LeaseOwner is not null || item.LeaseExpiresAt is not null ||
            mail.Status!=EmailStatus.Queued || mail.Attempts!=0 || mail.SubmissionStartedAt is not null || mail.Provider is not null || mail.ProviderMessageId is not null)return EmailPilotOperatorNotice.EnvelopeSaved;
        Demand(s);var published=await outbox().PublishCommittedAsync(work,ct);Demand(s);
        return published.WakeupPublished?EmailPilotOperatorNotice.EnvelopeSaved:EmailPilotOperatorNotice.WakePending;
    }
    public async Task<EmailPilotOperatorNotice> LookupAsync(EmailPilotCloseoutOperatorSession s,string? ip,CancellationToken ct=default)
    {Demand(s);var result=await lookup().RequestAsync(s.AuthorizationId,ip,ct);Demand(s);return result?EmailPilotOperatorNotice.LookupSaved:EmailPilotOperatorNotice.WakePending;}
}

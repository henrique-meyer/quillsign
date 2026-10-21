using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Lifecycle;

namespace QuillSign.Work;

public sealed class SignerReminderJobs(QuillSignDbContext db,SignerAccess access,InvitationLineage lineage,
    InvitationSuccessorProtection protection,SignerReminderOptions options,WorkOptions work,EmailOptions email,
    Func<IWorkSignals> signals,AuditWriter audit,TimeProvider time):IInvitationSuccessorPolicy
{
    internal IProductionWorkAdmission? HoldAdmission {get;init;}
    public InvitationSuccessorReason Reason=>InvitationSuccessorReason.Reminder;
    public bool Enabled=>options.Enabled && work.Enabled && email.Enabled;

    // Joins Send/checkpoint's parent transaction. No scanner or SQL timer exists.
    public async Task<IReadOnlyList<ScheduledSignerReminder>> PrepareCurrentLockedAsync(Guid envelopeId,CancellationToken ct,
        Func<Guid,DateTimeOffset,CancellationToken,Task>? demandHint=null)
    {
        RequireTransaction();var parent=await ParentAsync(envelopeId,ct);if(parent is null)return [];
        var epoch=await CurrentEpochAsync(parent,ct);if(epoch is null)return [];
        var rows=await SignerReminderEvidence.RowsAsync(db,parent.Id,SignerReminderEvidence.ScheduleEvent,100,ct);
        ReminderEpoch? saved=null;
        foreach(var row in rows) {
            var e=SignerReminderEvidence.Read<ReminderSchedule>(row,SignerReminderEvidence.ScheduleEvent).Epoch;SignerReminderEvidence.Validate(e);
            if(e.EnvelopeId!=parent.Id || row.At<e.InvitedAt || row.At>time.GetUtcNow())throw Invalid();
            if(e.InvitationId==epoch.InvitationId) {if(saved is not null || e!=epoch)throw Invalid();saved=e;}
        }
        var schedule=SignerReminderEvidence.Days(epoch).Select(day=>new ScheduledSignerReminder(SignerReminderEvidence.WorkId(epoch,day),day,
            SignerReminderEvidence.Due(epoch,day),SignerReminderEvidence.Digest(epoch))).ToArray();
        if(schedule.Length==0)return [];
        foreach(var entry in schedule) {
            var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==entry.WorkId,ct);
            if(saved is null) {
                if(row is not null)throw Invalid();
                db.WorkItems.Add(new() {Id=entry.WorkId,EnvelopeId=parent.Id,Kind=WorkKind.Reminder,AvailableAt=entry.DueAt,PayloadJson=SignerReminderEvidence.Payload(epoch,entry.Day)});
            }
            else if(row is null || !Matches(row,epoch,entry.Day))throw Invalid();
        }
        if(saved is null) {
            await db.SaveChangesAsync(ct);
            await audit.AppendAsync(parent.Id,SignerReminderEvidence.ScheduleEvent,null,null,null,ct,SignerReminderEvidence.Canonical(new ReminderSchedule(epoch)),PartyType.System);
        }
        var pending=new List<ScheduledSignerReminder>();
        foreach(var entry in schedule) {
            var item=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==entry.WorkId,ct);
            if(item.Status is WorkStatus.Failed or WorkStatus.Completed)continue;
            var due=item.Status==WorkStatus.Leased && item.LeaseExpiresAt>item.AvailableAt ? item.LeaseExpiresAt!.Value : item.AvailableAt;
            if(demandHint is not null)await demandHint(item.Id,due,ct);
            await signals().PutHintAsync(item.Id,due,ct);
            if(demandHint is not null)await demandHint(item.Id,due,ct);
            pending.Add(entry with {DueAt=due});
        }
        return pending;
    }
    internal async Task PublishAsync(IEnumerable<ScheduledSignerReminder> schedule,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Commit before publishing reminder work.");
        foreach(var item in schedule)try {await signals().PublishAsync(item.WorkId,TimeSpan.FromSeconds(Math.Clamp((item.DueAt-time.GetUtcNow()).TotalSeconds,0,7*86400)),ct);}
        catch(Exception e) when(e is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { /* durable hint */ }
    }

    internal async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        var located=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct);
        if(lease.Kind!=WorkKind.Reminder || located?.EnvelopeId is not {} envelopeId || located.Kind!=WorkKind.Reminder || located.PayloadJson.Length>512)return new(WorkOutcome.Failed,"invalid-reminder-scope");
        Guid? publish=null;
        await using(var tx=await db.Database.BeginTransactionAsync(ct)) {
            async Task<WorkResult> Completed(string code)
            {
                if(HoldAdmission is not null)
                {
                    await HoldAdmission.PrepareHandlerOutcomeLockedAsync(db,lease,envelopeId,ct);
                    var owned=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,ct);
                    if(!Owns(owned,lease))throw new ProductionWorkBlockedException();
                    await tx.CommitAsync(ct);
                }
                return new(WorkOutcome.Completed,code);
            }
            var parent=await ParentAsync(envelopeId,ct);if(parent is null)return await Completed("reminder-request-closed");
            if(HoldAdmission is not null)await HoldAdmission.DemandLockedAsync(db,lease.Id,envelopeId,lease.Kind,lease.Owner,lease.Attempt,false,ct);
            // Shared order with correction/manual resend: parent -> cap lock -> evidence.
            await InvitationResendRules.LockAsync(db,ct);
            var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
            if(!Owns(row,lease))return new(WorkOutcome.Retry,"reminder-lease-unavailable");
            var epoch=await FindEpochAsync(parent,row,ct);
            var current=await CurrentEpochAsync(parent,ct);
            if(!Enabled || current is null || epoch!=current)return await Completed("reminder-no-longer-current");
            var day=SignerReminderEvidence.Days(epoch).Single(d=>SignerReminderEvidence.WorkId(epoch,d)==row.Id);
            var due=SignerReminderEvidence.Due(epoch,day);var now=time.GetUtcNow();
            if(now<due)return new(WorkOutcome.Retry,"reminder-not-due");
            // At most the latest overdue offset can create a new message.
            if(SignerReminderEvidence.Days(epoch).Where(d=>SignerReminderEvidence.Due(epoch,d)<=now).Max()!=day)
                return await Completed("reminder-overdue-offset-coalesced");
            var id=SignerReminderEvidence.EmailId(row.Id);
            var previousAdmission=await FindAdmissionAsync(parent.Id,id,ct);
            if(previousAdmission is not null) {
                if(previousAdmission.WorkId!=row.Id || previousAdmission.EpochSha256!=SignerReminderEvidence.Digest(epoch))throw Invalid();
                await CheckSavedAsync(previousAdmission,ct);publish=id;
            }
            else {
                var contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(parent,ct);
                var history=await lineage.ReadLockedAsync(parent,epoch.SignerId,contacts,ct)??throw Invalid();
                if(!await lineage.SettledLockedAsync(history.Latest,ct))return new(WorkOutcome.Retry,"reminder-predecessor-unsettled");
                if(await db.Suppressions.AnyAsync(x=>x.Email==epoch.Recipient,ct))return await Completed("reminder-recipient-suppressed");
                var end=SignerReminderEvidence.DayEnd(now);var retention=await DocumentRetentionAccess.ReadAsync(db,parent,time,ct);
                // Keep every actual-day cap reservation until that day ends.
                if(retention<end)return await Completed("reminder-retention-too-short");
                if(parent.ExpiresAt is {} expires && expires<end)end=expires;
                var admission=new ReminderAdmission(SignerReminderEvidence.Version,row.Id,SignerReminderEvidence.Digest(epoch),day,due,id,parent.Id,epoch.SignerId,
                    history.Latest.Id,epoch.Contact,epoch.Recipient,epoch.SenderEmail,epoch.DocumentId,epoch.DocumentSha256,epoch.DisclosureSha256,epoch.PolicySha256,now,end);
                if(!await WithinCapsAsync(admission,false,ct))return await Completed("reminder-daily-limit");
                if(await db.EmailOutbox.AnyAsync(x=>x.Id==id,ct) || await db.WorkItems.AnyAsync(x=>x.Id==id,ct))throw Invalid();
                var scope=SignerReminderEvidence.Scope(admission);
                db.EmailOutbox.Add(new() {Id=id,EnvelopeId=parent.Id,To=scope.Recipient,Template=InvitationSuccessorProtection.Template,AvailableAt=now,PayloadJson=protection.Protect(new(scope))});
                db.WorkItems.Add(new() {Id=id,EnvelopeId=parent.Id,Kind=WorkKind.Email,AvailableAt=now,PayloadJson=JsonSerializer.Serialize(new {emailId=id})});
                await db.SaveChangesAsync(ct);
                await audit.AppendAsync(parent.Id,SignerReminderEvidence.AdmissionEvent,null,null,null,ct,SignerReminderEvidence.Canonical(admission),PartyType.System);
                await audit.AppendAsync(parent.Id,InvitationSuccessorProtection.Event,null,null,null,ct,InvitationSuccessorProtection.Canonical(scope),PartyType.System);
                if(!Owns(row,lease) || !await ValidateLockedAsync(parent,scope,ct))throw Invalid();
                await signals().PutHintAsync(id,now,ct);publish=id;
            }
            if(!Owns(row,lease))return new(WorkOutcome.Retry,"reminder-lease-unavailable");
            if(HoldAdmission is not null)await HoldAdmission.PrepareHandlerOutcomeLockedAsync(db,lease,envelopeId,ct);
            if(!Owns(row,lease))throw new ProductionWorkBlockedException();
            await tx.CommitAsync(ct);
        }
        if(publish is {} mail)try {await signals().PublishAsync(mail,TimeSpan.Zero,ct);}
        catch(Exception e) when(e is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { }
        return new(WorkOutcome.Completed);
    }
    public async Task<bool> ValidateLockedAsync(Envelope parent,InvitationSuccessorScope scope,CancellationToken ct)
    {
        RequireTransaction();options.Validate();
        if(!Enabled || scope.Reason!=Reason || scope.EnvelopeId!=parent.Id || scope.Deadline<=time.GetUtcNow() || parent.Status!=EnvelopeStatus.Sent || parent.ExpiresAt<=time.GetUtcNow())return false;
        var a=await FindAdmissionAsync(parent.Id,scope.Id,ct)??throw Invalid();
        if(SignerReminderEvidence.Scope(a)!=scope)throw Invalid();await CheckSavedAsync(a,ct);
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==a.WorkId,ct)??throw Invalid();
        var epoch=await FindEpochAsync(parent,row,ct);var current=await CurrentEpochAsync(parent,ct);
        if(current is null || current!=epoch || a.EpochSha256!=SignerReminderEvidence.Digest(epoch) || a.Day is <1 or >30 ||
            !SignerReminderEvidence.Days(epoch).Contains(a.Day) || a.WorkId!=SignerReminderEvidence.WorkId(epoch,a.Day) || a.DueAt!=SignerReminderEvidence.Due(epoch,a.Day) ||
            scope.SignerId!=epoch.SignerId || scope.Contact!=epoch.Contact || scope.Recipient!=epoch.Recipient || scope.SenderEmail!=epoch.SenderEmail ||
            scope.DocumentId!=epoch.DocumentId || scope.DocumentSha256!=epoch.DocumentSha256 || scope.DisclosureSha256!=epoch.DisclosureSha256 ||
            a.PolicySha256!=epoch.PolicySha256 || await db.Suppressions.AnyAsync(x=>x.Email==scope.Recipient,ct))return false;
        var retention=await DocumentRetentionAccess.ReadAsync(db,parent,time,ct);
        if(retention<SignerReminderEvidence.DayEnd(a.AdmittedAt))return false;DocumentRetentionAccess.Check(retention,time);
        var contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(parent,ct);
        var history=await lineage.ReadLockedAsync(parent,epoch.SignerId,contacts,ct)??throw Invalid();
        return history.Latest.Id==scope.Id && await WithinCapsAsync(a,true,ct);
    }
    private async Task<ReminderEpoch?> CurrentEpochAsync(Envelope parent,CancellationToken ct)
    {
        if(parent.IsDemo || parent.Status!=EnvelopeStatus.Sent || parent.ExpiresAt<=time.GetUtcNow())return null;
        // Absence is a deliberately inert compatibility bridge. Older signing
        // fixtures/installations need no new invitation-index shape merely to
        // publish a checkpoint. Presence still requires the full verified Send.
        var sentQuery=db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==parent.Id && x.Event=="sent");
        var sentSizes=await sentQuery.Select(x=>EF.Functions.DataLength(x.DataJson)).Take(2).ToArrayAsync(ct);
        if(sentSizes.Length==0)return null;
        if(sentSizes.Length!=1 || sentSizes[0] is null or <1 or >24000)throw Invalid();
        var sentJson=await sentQuery.Select(x=>x.DataJson).SingleAsync(ct);
        try {using var evidence=JsonDocument.Parse(sentJson);
            if(evidence.RootElement.ValueKind!=JsonValueKind.Object)throw Invalid();
            if(!evidence.RootElement.TryGetProperty("reminderSchedulingVersion",out _))return null;
        }catch(JsonException) {throw Invalid();}
        var sent=await SenderSentStatus.ReadSentAsync(db,parent,null,ct);
        if(sent.ReminderSchedulingVersion!=SignerReminderEvidence.Version || sent.Reminders is not {} policy || policy.Days.IsEmpty)return null;
        var contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(parent,ct);
        var signed=await db.Signers.Where(x=>x.EnvelopeId==parent.Id && x.Status==SignerStatus.Signed).Select(x=>x.Id).ToArrayAsync(ct);
        var party=contacts.Current.OrderBy(x=>x.Order).FirstOrDefault(x=>!signed.Contains(x.Id));
        if(party is null)return null;
        var context=await access.GetEligibleLockedAsync(parent.Id,party.Id,ct);if(context is null)return null;
        var history=await lineage.ReadLockedAsync(parent,party.Id,contacts,ct)??throw Invalid();var root=history.Entries[0];
        // Correction explicitly retires the old schedule. No restart policy has
        // been reviewed, so a later generation cannot inherit its clock/consent.
        if(root.Contact!=party.Epoch || root.Recipient!=party.Email || history.Latest.Contact!=party.Epoch || history.Latest.Recipient!=party.Email)return null;
        if(root.DocumentId!=context.Identity.DocumentId || root.DocumentSha256!=context.Identity.DocumentHash || root.DisclosureSha256!=context.Identity.DisclosureHash)throw Invalid();
        var retention=await DocumentRetentionAccess.ReadAsync(db,parent,time,ct);DocumentRetentionAccess.Check(retention,time);
        var epoch=new ReminderEpoch(SignerReminderEvidence.Version,parent.Id,party.Id,root.Id,party.Epoch,party.Email,parent.SenderEmail,root.DocumentId,
            root.DocumentSha256,root.DisclosureSha256,policy.CanonicalJson,policy.Sha256,root.AdmittedAt,parent.ExpiresAt?.ToUniversalTime(),retention?.ToUniversalTime());
        SignerReminderEvidence.Validate(epoch);return epoch;
    }
    private Task<ReminderEpoch> FindEpochAsync(Envelope parent,WorkItem workItem,CancellationToken ct)
        =>ReadWorkEpochLockedAsync(db,parent.Id,workItem,time,ct);
    internal static async Task<ReminderEpoch> ReadWorkEpochLockedAsync(QuillSignDbContext db,Guid recordId,WorkItem workItem,TimeProvider time,CancellationToken ct)
    {
        ReminderEpoch? found=null;
        foreach(var row in await SignerReminderEvidence.RowsAsync(db,recordId,SignerReminderEvidence.ScheduleEvent,100,ct)) {
            var epoch=SignerReminderEvidence.Read<ReminderSchedule>(row,SignerReminderEvidence.ScheduleEvent).Epoch;SignerReminderEvidence.Validate(epoch);
            if(epoch.EnvelopeId!=recordId || row.At<epoch.InvitedAt || row.At>time.GetUtcNow())throw Invalid();
            foreach(var day in SignerReminderEvidence.Days(epoch))if(SignerReminderEvidence.WorkId(epoch,day)==workItem.Id) {
                if(found is not null || !Matches(workItem,epoch,day))throw Invalid();found=epoch;
            }
        }
        return found??throw Invalid();
    }
    private async Task<ReminderAdmission?> FindAdmissionAsync(Guid envelope,Guid id,CancellationToken ct)
    {
        ReminderAdmission? found=null;
        foreach(var row in await SignerReminderEvidence.RowsAsync(db,envelope,SignerReminderEvidence.AdmissionEvent,200,ct)) {
            var a=SignerReminderEvidence.ReadAdmission(row);if(a.Id!=id)continue;if(found is not null)throw Invalid();found=a;
        }
        return found;
    }
    private async Task CheckSavedAsync(ReminderAdmission a,CancellationToken ct)
    {
        var row=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==a.Id,ct)??throw Invalid();
        var workItem=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==a.Id,ct)??throw Invalid();
        if(protection.Read(row).Scope!=SignerReminderEvidence.Scope(a) || workItem.Kind!=WorkKind.Email || workItem.EnvelopeId!=a.EnvelopeId ||
            workItem.PayloadJson!=JsonSerializer.Serialize(new {emailId=a.Id}))throw Invalid();
    }
    private async Task<bool> WithinCapsAsync(ReminderAdmission candidate,bool existing,CancellationToken ct)
    {
        options.Validate();if(!Enabled)return false;var end=SignerReminderEvidence.DayEnd(candidate.AdmittedAt);var start=end.AddDays(-1);
        var query=db.AuditEvents.AsNoTracking().Where(x=>x.Event==SignerReminderEvidence.AdmissionEvent && x.At>=start && x.At<end);
        var sizes=await query.Select(x=>EF.Functions.DataLength(x.DataJson)).Take(1001).ToArrayAsync(ct);
        if(sizes.Length>1000 || sizes.Any(x=>x is null or <1 or >24000))throw Invalid();
        var rows=await query.Take(1001).ToArrayAsync(ct);if(rows.Length!=sizes.Length)throw Invalid();
        var admissions=new List<ReminderAdmission>();var ids=new HashSet<Guid>();
        foreach(var row in rows) {var a=SignerReminderEvidence.ReadAdmission(row);if(!ids.Add(a.Id) || a.AdmittedAt<start || a.AdmittedAt>=end)throw Invalid();await CheckSavedAsync(a,ct);admissions.Add(a);}
        if(existing && admissions.Count(x=>x==candidate)!=1 || !existing && ids.Contains(candidate.Id))throw Invalid();
        var add=existing ? 0 : 1;
        return admissions.Count+add<=options.DailyRequests && admissions.Count(x=>x.SenderEmail==candidate.SenderEmail)+add<=options.DailySenderRequests &&
            admissions.Count(x=>x.Recipient==candidate.Recipient)+add<=options.DailyAddressRequests;
    }
    private Task<Envelope?> ParentAsync(Guid id,CancellationToken ct)=>db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
    private bool Owns(WorkItem row,WorkLease lease)=>row.Kind==WorkKind.Reminder && row.Status==WorkStatus.Leased && row.LeaseOwner==lease.Owner && row.Attempts==lease.Attempt &&
        row.LeaseExpiresAt==lease.Until && row.LeaseExpiresAt>time.GetUtcNow();
    private static bool Matches(WorkItem row,ReminderEpoch epoch,int day)=>row.Kind==WorkKind.Reminder && row.EnvelopeId==epoch.EnvelopeId && row.PayloadJson==SignerReminderEvidence.Payload(epoch,day) &&
        Enum.IsDefined(row.Status) && row.Attempts>=0 && row.AvailableAt>=SignerReminderEvidence.Due(epoch,day) &&
        (row.Status!=WorkStatus.Leased || row.LeaseOwner is not null && row.LeaseExpiresAt is not null);
    private void RequireTransaction() {if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Reminder authority requires the envelope transaction.");}
    private static InvalidDataException Invalid()=>SignerReminderEvidence.Invalid();
}

public sealed class SignerReminderHandler(SignerReminderJobs reminders):IWorkHandler
{
    public WorkKind Kind=>WorkKind.Reminder;
    public async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        try {return await reminders.ExecuteAsync(lease,ct);}
        catch(InvalidDataException) {return new(WorkOutcome.Failed,"reminder-evidence-unavailable");}
        catch(System.Security.Cryptography.CryptographicException) {return new(WorkOutcome.Retry,"reminder-payload-unavailable");}
        catch(DocumentRetentionExpiredException) {return new(WorkOutcome.Completed,"reminder-retention-ended");}
        catch(Exception e) when(e is IOException or Azure.RequestFailedException or HttpRequestException) {return new(WorkOutcome.Retry,"reminder-commit-unconfirmed");}
    }
}

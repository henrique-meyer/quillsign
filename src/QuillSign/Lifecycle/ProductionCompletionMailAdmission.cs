using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// SQL-only preflight. The kernel separately authenticates its own captured pair
// before reservation; this helper grants no dispatch or storage capability.
internal sealed class ProductionCompletionMailAdmission(IDataProtectionProvider keys,TimeProvider time)
{
    internal CompletionNotificationPayload Read(string value)
    {
        try {
            if(value.Length is <1 or >8192 || Encoding.UTF8.GetByteCount(value)>8192)throw Invalid();
            var wrapper=JsonSerializer.Deserialize<ProtectedWorkPayload>(value)??throw Invalid();
            if(JsonSerializer.Serialize(wrapper)!=value)throw Invalid();
            var plain=keys.CreateProtector("QuillSign.CompletionNotification.v1").Unprotect(wrapper.Protected);
            if(plain.Length>8192 || Encoding.UTF8.GetByteCount(plain)>8192)throw Invalid();
            var payload=JsonSerializer.Deserialize<CompletionNotificationPayload>(plain)??throw Invalid();
            if(JsonSerializer.Serialize(payload)!=plain || !CompletionNotificationJobs.Shape(payload))throw Invalid();
            return payload;
        } catch(Exception e) when(e is CryptographicException or JsonException or ArgumentException or FormatException) {throw new ProductionWorkBlockedException(e);}
    }

    internal async Task DemandInitialAsync(QuillSignDbContext db,EmailOutbox mail,CancellationToken ct)
    {
        if(mail.EnvelopeId is not {} id || mail.Template!=CompletionNotificationJobs.Template || mail.Status!=EmailStatus.Queued ||
            mail.Attempts!=0 || mail.SubmissionStartedAt is not null || mail.Provider is not null || mail.ProviderMessageId is not null ||
            mail.LastError is not null || mail.AttachmentsJson!="[]")throw Invalid();
        if(db.Database.CurrentTransaction is null) {
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleAsync(ct);
            var current=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==mail.Id,ct);
            if(JsonSerializer.Serialize(current)!=JsonSerializer.Serialize(mail))throw Invalid();
            await DemandInitialAsync(db,mail,ct);await tx.RollbackAsync(ct);return;
        }
        var payload=Read(mail.PayloadJson);if(payload.LastTokenId is not null || payload.IsDemo)throw Invalid();
        var saved=await CompletionDownloadState.ReadAsync(db,id,time,ct)??throw Invalid();
        if(saved.PurgeAfter<=time.GetUtcNow() || payload.EnvelopeId!=id || payload.PublicationId!=saved.Id || CompletionNotificationJobs.Id(payload)!=mail.Id ||
            payload.Recipe!=CompletionNotificationJobs.Hex(saved.Recipe) || payload.Revision!=Convert.ToBase64String(saved.Revision) ||
            payload.ExecutedReference!=CompletionNotificationJobs.Hex(DownloadPublication.Reference(saved.Executed)) ||
            payload.CertificateReference!=CompletionNotificationJobs.Hex(DownloadPublication.Reference(saved.Certificate)))throw Invalid();
        var roster=await CompletionNotificationJobs.FreezeRosterLockedAsync(db,id,ct);
        var member=roster.SingleOrDefault(x=>x.Type==payload.Party&&x.Id==payload.PartyId&&x.Email==mail.To)??throw Invalid();
        var party=CompletionAccessState.PartyProjection(saved,member.Type,member.Id,member.Email,member.Name,member.Order);
        if(CompletionNotificationJobs.Hex(party.Sha256)!=payload.PartyHash ||
            await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==id&&x.Purpose==TokenPurpose.CompletionAccess&&x.PartyType==payload.Party&&x.PartyId==payload.PartyId,ct))throw Invalid();
        var work=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==mail.Id,ct);
        if(work is null || work.EnvelopeId!=id || work.Kind!=WorkKind.Email || work.PayloadJson!=CompletionNotificationJobs.WorkJson(mail.Id) ||
            work.Status is not (WorkStatus.Queued or WorkStatus.Leased) || work.LastError is not null)throw Invalid();
        var proof=CompletionNotificationJobs.Queued(mail.Id,mail.To,payload);
        var auditBytes=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={id} AND [Event]='completion_notification_queued'").SingleAsync(ct);
        if(auditBytes>2*1024*1024)throw Invalid();
        var audits=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==id&&x.Event=="completion_notification_queued").Take(202).ToArrayAsync(ct);
        var matches=audits.Where(x=>x.DataJson==proof).ToArray();
        if(audits.Length>201 || matches.Length!=1 || matches[0].ActorType!=PartyType.System || matches[0].ActorId is not null || matches[0].ActorEmail is not null ||
            matches[0].Ip is not null || matches[0].UserAgent is not null || matches[0].At>time.GetUtcNow() || matches[0].Sequence<=saved.AuditSequence ||
            !matches[0].Hash.AsSpan().SequenceEqual(AuditHash.Compute(matches[0])))throw Invalid();
    }
    private static ProductionWorkBlockedException Invalid()=>new();
}

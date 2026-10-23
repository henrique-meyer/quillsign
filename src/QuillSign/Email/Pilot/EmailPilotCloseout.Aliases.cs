using System.Security.Cryptography;
using System.Data.Common;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotCloseout
{
    private QuillSignDbContext AliasDatabase=>database();
    private TimeProvider AliasTime=>time;
    internal Func<CompletionNotificationJobs>? CompletionJobs { get; init; }
    internal Func<VoidNotificationJobs>? VoidJobs { get; init; }
    internal Func<VoidNotificationProtection>? VoidPayloads { get; init; }

    // Factual identity translation only. Every use reacquires the authenticated
    // current header and original pair in the caller's existing transaction.
    internal sealed class AliasFact
    {
        private AliasFact(EmailPilotCloseout owner,QuillSignDbContext db,WorkLease lease,Guid authorizationId, Guid originalId, Guid aliasId, Guid recordId,
            string template, string recipient, DateTimeOffset until)
        { Owner=owner;Database=db;Lease=lease;Transaction=db.Database.CurrentTransaction!.GetDbTransaction();Connection=Transaction.Connection??throw Invalid();
            AuthorizationId=authorizationId;OriginalId=originalId;AliasId=aliasId;RecordId=recordId;Template=template;Recipient=recipient;Until=until; }
        private EmailPilotCloseout Owner { get; }
        private QuillSignDbContext Database { get; }
        private WorkLease Lease { get; }
        private DbTransaction Transaction { get; }
        private DbConnection Connection { get; }
        internal void DemandLocked(QuillSignDbContext db,Guid aliasId,string recipient,string template)
        {
            if(!ReferenceEquals(db,Database)||db.Database.CurrentTransaction is not {} tx||!ReferenceEquals(tx.GetDbTransaction(),Transaction)||
                !ReferenceEquals(Transaction.Connection,Connection)||Connection.State!=System.Data.ConnectionState.Open||
                aliasId!=AliasId||recipient!=Recipient||template!=Template||!Owner.Available||Until<=Owner.Now||Lease.Until<=Owner.Now)throw Invalid();
        }
        internal Guid AuthorizationId { get; }
        internal Guid OriginalId { get; }
        internal Guid AliasId { get; }
        internal Guid RecordId { get; }
        internal string Template { get; }
        internal string Recipient { get; }
        internal DateTimeOffset Until { get; }
        internal static async Task<AliasFact?> ReadAsync(EmailPilotCloseout owner,QuillSignDbContext db,WorkLease lease,string recipient,CancellationToken ct)
        {
        if(!ReferenceEquals(db,owner.AliasDatabase)||db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw Invalid();
        if(!owner.ConfiguredNotice(lease.Id)) {
            if(await RecognizesWorkAsync(db,lease.Id,ct))throw Invalid();
            return null;
        }
        var current=await owner.ReadLockedAsync(db,ct)??throw Invalid();
        var pair=current.Manifest.Queue.SingleOrDefault(x=>x.WorkId==lease.Id)??throw Invalid();
        var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,ct);
        var item=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,ct);
        if(lease.Kind!=WorkKind.Email||lease.Attempt!=1||lease.Until.Offset!=TimeSpan.Zero||lease.Until<=owner.Now||current.Until<=owner.Now||
            item.Status!=WorkStatus.Leased||item.Attempts!=1||item.LeaseOwner!=lease.Owner||item.LeaseExpiresAt!=lease.Until||
            mail.Status!=EmailStatus.Queued||mail.Attempts is <0 or >1||mail.Provider is not null||mail.ProviderMessageId is not null||
            mail.To!=recipient||mail.AvailableAt>owner.Now||item.AvailableAt>owner.Now||await db.Suppressions.AnyAsync(x=>x.Email==mail.To,ct))throw Invalid();
        DemandOriginalQueue(pair,mail,item,pair.Step<=EmailPilotCloseoutStep.CompletionRecipient?owner.CompletionPayloads?.Invoke():null);
        var originalMail=System.Text.Json.JsonSerializer.Deserialize<EmailOutbox>(pair.OriginalMailJson!,Json)??throw Invalid();
        var originalWork=System.Text.Json.JsonSerializer.Deserialize<WorkItem>(pair.OriginalWorkJson!,Json)??throw Invalid();
        await owner.DemandCanonicalOriginalLockedAsync(db,originalMail,originalWork,ct);
        var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==pair.RecordId,ct);
        var retained=await Documents.DocumentRetentionAccess.ReadAsync(db,e,owner.AliasTime,ct);Documents.DocumentRetentionAccess.Check(retained,owner.AliasTime);
        var until=new[]{current.Until,lease.Until,retained??DateTimeOffset.MaxValue}.Min();if(until<=owner.Now||!owner.Available)throw Invalid();
        return new(owner,db,lease,current.AuthorizationId,pair.OriginalId,pair.WorkId,pair.RecordId,mail.Template,mail.To,until);
        }
    }

    internal static Guid AliasId(Guid authorization,Guid original)
    {
        if(authorization==Guid.Empty||original==Guid.Empty)throw Invalid();
        return new(SHA256.HashData(Encoding.ASCII.GetBytes($"failed-notice-closeout-v1:{authorization:N}:{original:N}")).AsSpan(0,16));
    }

    private bool ConfiguredNotice(Guid id)
    {
        if(!Guid.TryParseExact(options.AuthorizationId,"N",out var authorization)||authorization==Guid.Empty)return false;
        return options.CompletionWorkIds.Concat(options.VoidWorkIds).Any(raw=>Guid.TryParseExact(raw,"N",out var original)&&
            original!=Guid.Empty&&(id==original||id==AliasId(authorization,original)));
    }

    internal static void FailedBeforeProvider(EmailOutbox mail,WorkItem item,Guid record,string template)
    {
        if(mail.Id==Guid.Empty||mail.To!=EmailAddress.Normalize(mail.To)||mail.PayloadJson.Length is <1 or >8192||
            mail.Id!=item.Id||mail.EnvelopeId!=record||item.EnvelopeId!=record||mail.Template!=template||mail.AttachmentsJson!="[]"||
            mail.Status!=EmailStatus.Failed||item.Status!=WorkStatus.Failed||item.Kind!=WorkKind.Email||mail.Attempts!=0||item.Attempts!=1||
            mail.SubmissionStartedAt is not null||mail.Provider is not null||mail.ProviderMessageId is not null||mail.LeaseOwner is not null||
            mail.LeaseExpiresAt is not null||item.LeaseOwner is not null||item.LeaseExpiresAt is not null||
            mail.LastError!="pilot-delivery-unavailable"||item.LastError!="pilot-delivery-unavailable"||mail.RowVersion.Length!=8||item.RowVersion.Length!=8||
            item.PayloadJson!=(template==CompletionNotificationJobs.Template?CompletionNotificationJobs.WorkJson(item.Id):
                template==VoidNotificationJobs.Template?VoidNotificationJobs.WorkJson(item.Id):throw Invalid()))throw Invalid();
    }

    internal static (EmailOutbox Mail,WorkItem Work) NewAliasPair(Guid authorization,EmailOutbox original,WorkItem workItem,DateTimeOffset at)
    {
        if(original.EnvelopeId is not Guid record||at.Offset!=TimeSpan.Zero||at==default)throw Invalid();
        FailedBeforeProvider(original,workItem,record,original.Template);
        var id=AliasId(authorization,original.Id);if(id==original.Id)throw Invalid();
        return (new(){Id=id,EnvelopeId=record,To=original.To,Template=original.Template,PayloadJson=original.PayloadJson,AttachmentsJson=original.AttachmentsJson,AvailableAt=at},
            new(){Id=id,EnvelopeId=record,Kind=WorkKind.Email,PayloadJson=original.Template==CompletionNotificationJobs.Template?
                CompletionNotificationJobs.WorkJson(id):VoidNotificationJobs.WorkJson(id),AvailableAt=at});
    }

    internal static async Task<EmailPilotCloseoutQueue> InsertAliasPairLockedAsync(QuillSignDbContext db,Guid authorization,
        EmailPilotCloseoutStep step,EmailOutbox originalMail,WorkItem originalWork,DateTimeOffset at,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges()||step>EmailPilotCloseoutStep.VoidSigner||!Enum.IsDefined(step)||
            originalMail.Template!=(step<=EmailPilotCloseoutStep.CompletionRecipient?CompletionNotificationJobs.Template:VoidNotificationJobs.Template))throw Invalid();
        var oldMail=Raw(originalMail);var oldWork=Raw(originalWork);var aliases=NewAliasPair(authorization,originalMail,originalWork,at);
        if(await db.EmailOutbox.AnyAsync(x=>x.Id==aliases.Mail.Id,ct)||await db.WorkItems.AnyAsync(x=>x.Id==aliases.Work.Id,ct))throw Invalid();
        db.EmailOutbox.Add(aliases.Mail);db.WorkItems.Add(aliases.Work);await db.SaveChangesAsync(ct);
        return new(step,originalMail.EnvelopeId!.Value,aliases.Mail.Id,Raw(aliases.Mail),Raw(aliases.Work),originalMail.Id,oldMail,oldWork);
    }

    private static async Task DemandFailedOriginalLockedAsync(QuillSignDbContext db,EmailPilotCloseoutQueue pair,CancellationToken ct)
    {
        var mail=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==pair.OriginalId,ct)??throw Invalid();
        var workItem=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==pair.OriginalId,ct)??throw Invalid();
        FailedBeforeProvider(mail,workItem,pair.RecordId,pair.Step<=EmailPilotCloseoutStep.CompletionRecipient?CompletionNotificationJobs.Template:VoidNotificationJobs.Template);
        if(Raw(mail)!=pair.OriginalMailJson||Raw(workItem)!=pair.OriginalWorkJson)throw Invalid();
    }

    private async Task DemandCanonicalOriginalLockedAsync(QuillSignDbContext db,EmailOutbox mail,WorkItem item,CancellationToken ct)
    {
        if(mail.Template==CompletionNotificationJobs.Template) {
            var payload=(CompletionPayloads?.Invoke()??throw Invalid()).Read(mail.PayloadJson);
            var publication=await CompletionDownloadState.ReadAsync(db,payload.EnvelopeId,time,ct)??throw Invalid();
            if(payload.LastTokenId is not null||CompletionNotificationJobs.Id(payload)!=mail.Id||
                await (CompletionJobs?.Invoke()??throw Invalid()).ResolveLocked(publication,mail.Id,mail.To,payload,ct) is null)throw Invalid();
        } else {
            var payload=(VoidPayloads?.Invoke()??throw Invalid()).Read(mail.PayloadJson);
            if(VoidNotificationJobs.Id(payload)!=mail.Id||await (VoidJobs?.Invoke()??throw Invalid()).ResolveLocked(mail.Id,mail.To,payload,ct) is null)throw Invalid();
        }
        if(item.Id!=mail.Id)throw Invalid();
    }

    internal Task<AliasFact?> ReadAliasLockedAsync(QuillSignDbContext db,WorkLease lease,string recipient,CancellationToken ct=default)
        =>AliasFact.ReadAsync(this,db,lease,recipient,ct);
}

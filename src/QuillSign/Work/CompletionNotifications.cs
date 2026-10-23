using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Work;

internal sealed record CompletionNotificationPayload(string Version,Guid EnvelopeId,Guid PublicationId,string Recipe,string Revision,
    PartyType Party,Guid? PartyId,string PartyHash,string ExecutedReference,string CertificateReference,bool IsDemo,Guid? LastTokenId=null);

public sealed class CompletionNotificationProtection(IDataProtectionProvider provider)
{
    private readonly IDataProtector protector=provider.CreateProtector("QuillSign.CompletionNotification.v1");
    internal string Protect(CompletionNotificationPayload value) {
        var result=JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(JsonSerializer.Serialize(value))));
        return result.Length<=8192 ? result : throw new InvalidDataException("Completion notification exceeds its bound.");
    }
    internal CompletionNotificationPayload Read(string value) {
        if(value.Length>8192)throw new InvalidDataException("Completion notification exceeds its bound.");
        var wrapped=JsonSerializer.Deserialize<ProtectedWorkPayload>(value);
        var p=JsonSerializer.Deserialize<CompletionNotificationPayload>(protector.Unprotect(wrapped?.Protected??throw new JsonException()))??throw new JsonException();
        if(!CompletionNotificationJobs.Shape(p))throw new InvalidDataException("Invalid completion notification scope.");return p;
    }
}

// Queue intent is atomic with publication. Actual files and link issuance are verified at dispatch.
public sealed class CompletionNotificationJobs(QuillSignDbContext db,CompletionAccessState state,CompletionNotificationProtection protection,
    Func<IWorkSignals> signals,WorkOptions work,AuditWriter audit,TimeProvider time)
{
    public const string Version="completion-notification-v1",Template="completion-ready";
    internal bool Enabled=>work.Enabled;
    internal bool UsesContext(QuillSignDbContext value)=>ReferenceEquals(db,value);
    internal static Guid Id(CompletionNotificationPayload p)=>Id(p.PublicationId,p.Party,p.PartyId);
    internal static Guid Id(Guid publicationId,PartyType type,Guid? partyId)=>new(SHA256.HashData(Encoding.UTF8.GetBytes(Version+":"+publicationId.ToString("N")+":"+type+":"+(partyId?.ToString("N")??"sender"))).AsSpan(0,16));
    internal static string Digest(CompletionNotificationPayload p)=>Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(p with {LastTokenId=null})));
    internal static string WorkJson(Guid id)=>JsonSerializer.Serialize(new {version=Version,notificationId=id});
    internal static string Queued(Guid id,string to,CompletionNotificationPayload p)=>JsonSerializer.Serialize(new {version=Version,notificationId=id,
        publicationId=p.PublicationId,scopeSha256=Digest(p),recipient=to,meaning="Notification queued; submission and delivery are not confirmed."});

    internal static CompletionNotificationPayload Payload(DownloadPublication saved,CompletionAccessParty member,bool isDemo)
        =>Payload(saved.EnvelopeId,saved.Id,saved.Recipe,saved.Revision,saved.Executed,saved.Certificate,member,isDemo);
    internal static CompletionNotificationPayload Payload(Guid envelopeId,Guid publicationId,byte[] recipe,byte[] revision,
        FinalStoredDocument executed,FinalStoredDocument certificate,CompletionAccessParty member,bool isDemo)
        =>new(Version,envelopeId,publicationId,Hex(recipe),Convert.ToBase64String(revision),member.Type,member.Id,
            Hex(member.Sha256),Hex(DownloadPublication.Reference(executed)),Hex(DownloadPublication.Reference(certificate)),isDemo);
    internal static async Task<CompletionNotificationRosterMember[]> FreezeRosterLockedAsync(QuillSignDbContext db,Guid envelopeId,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Frozen notification parties require their parent transaction.");
        var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelopeId,ct);
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        var recipients=await db.Recipients.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId).OrderBy(x=>x.Id).Take(101).ToArrayAsync(ct);
        if(signers.Length is <1 or >100||recipients.Length>100)throw Invalid();
        var all=new List<CompletionNotificationRosterMember>{new(PartyType.Sender,null,e.SenderName,e.SenderEmail,null)};
        all.AddRange(signers.Select(x=>new CompletionNotificationRosterMember(PartyType.Signer,x.Id,x.FullName,x.Email,x.Order)));
        all.AddRange(recipients.Select(x=>new CompletionNotificationRosterMember(PartyType.Recipient,x.Id,x.Name,x.Email,null)));
        return all.GroupBy(x=>x.Email,StringComparer.OrdinalIgnoreCase).Select(x=>x.First()).ToArray();
    }

    internal async Task<Guid[]> PrepareLockedAsync(Guid envelopeId,CancellationToken ct,
        Func<Guid,DateTimeOffset,CancellationToken,Task>? demandHint=null,DateTimeOffset? recordedAt=null)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Completion notification preparation requires its parent's transaction.");
        if(!work.Enabled)return [];
        var saved=await CompletionDownloadState.ReadAsync(db,envelopeId,time,ct);if(saved is null || saved.PurgeAfter<=time.GetUtcNow())throw Invalid();
        await state.RecheckLockedAsync(saved,ct);var isDemo=await db.Envelopes.Where(x=>x.Id==envelopeId).Select(x=>x.IsDemo).SingleAsync(ct);
        if(recordedAt is {} at&&(at.Offset!=TimeSpan.Zero||at>time.GetUtcNow()))throw Invalid();
        var writer=recordedAt is {} fixedAt?new AuditWriter(db,new CompletionRecordedTime(fixedAt)):audit;
        var ids=new List<Guid>();
        foreach(var member in await MembersLocked(saved,ct)) {
            var p=Payload(saved,member,isDemo);
            var id=Id(p);var email=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
            var item=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
            if(email is null && item is null) {
                email=new() {Id=id,EnvelopeId=envelopeId,To=member.Email,Template=Template,PayloadJson=protection.Protect(p),AvailableAt=recordedAt??time.GetUtcNow()};
                item=new() {Id=id,EnvelopeId=envelopeId,Kind=WorkKind.Email,PayloadJson=WorkJson(id),AvailableAt=email.AvailableAt};
                db.EmailOutbox.Add(email);db.WorkItems.Add(item);await db.SaveChangesAsync(ct);
                await writer.AppendAsync(envelopeId,"completion_notification_queued",null,null,null,ct,Queued(id,member.Email,p),PartyType.System);
            } else {
                if(email is null || item is null || email.EnvelopeId!=envelopeId || email.To!=member.Email || email.Template!=Template || email.AttachmentsJson!="[]" ||
                    item.EnvelopeId!=envelopeId || item.Kind!=WorkKind.Email || item.PayloadJson!=WorkJson(id) || Digest(protection.Read(email.PayloadJson))!=Digest(p) ||
                    !await QueueEvidence(id,member.Email,p,ct))throw Invalid();
            }
            // Preserve terminal outcomes and existing leases, including ambiguous submissions.
            if(item.Status is WorkStatus.Completed or WorkStatus.Failed)continue;
            var due=item.Status==WorkStatus.Leased&&item.LeaseExpiresAt is DateTimeOffset until?until:item.AvailableAt;
            if(demandHint is not null)await demandHint(id,due,ct);
            await signals().PutHintAsync(id,due,ct);
            if(demandHint is not null)await demandHint(id,due,ct);
            ids.Add(id);
        }
        await state.RecheckLockedAsync(saved,ct);return ids.ToArray();
    }

    public async Task<int> ResumeAsync(Guid envelopeId,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Standalone completion notification resume requires a clean unit of work.");
        try {return await ResumeCore(envelopeId,ct);}catch {db.ChangeTracker.Clear();throw;}
    }
    private async Task<int> ResumeCore(Guid envelopeId,CancellationToken ct)
    {
        if(!work.Enabled)throw new InvalidOperationException("Durable completion notification work is disabled.");
        var prepared=await state.PrepareAsync(envelopeId,ct);if(prepared is null)return 0;Guid[] ids;
        await using(var tx=await db.Database.BeginTransactionAsync(ct)) {
            await state.RecheckLockedAsync(prepared.Saved,ct);ids=await PrepareLockedAsync(envelopeId,ct);
            if(prepared.Until<=time.GetUtcNow())throw Invalid();await tx.CommitAsync(ct);
        }
        await PublishAsync(ids,ct);return ids.Length;
    }
    internal async Task PublishAsync(IEnumerable<Guid> ids,CancellationToken ct) {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Commit before publishing notification wakeups.");
        foreach(var id in ids)try {await signals().PublishAsync(id,TimeSpan.Zero,ct);}
            catch(Exception e) when(e is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { /* committed hints recover */ }
    }

    internal Task<CompletionAccessParty?> ResolveLocked(DownloadPublication saved,Guid id,string to,CompletionNotificationPayload p,CancellationToken ct)
        =>ResolveCanonicalLocked(saved,id,to,p,ct);
    internal Task<CompletionAccessParty?> ResolveCloseoutLocked(DownloadPublication saved,Guid id,string to,CompletionNotificationPayload p,
        Email.Pilot.EmailPilotCloseout.AliasFact alias,CancellationToken ct)
    {
        alias.DemandLocked(db,id,to,Template);
        if(db.Database.CurrentTransaction is null||alias.AliasId!=id||alias.OriginalId!=Id(p)||alias.RecordId!=saved.EnvelopeId||
            alias.RecordId!=p.EnvelopeId||alias.Template!=Template||alias.Recipient!=to||alias.Until<=time.GetUtcNow())return Task.FromResult<CompletionAccessParty?>(null);
        return ResolveCanonicalLocked(saved,alias.OriginalId,to,p,ct);
    }
    private async Task<CompletionAccessParty?> ResolveCanonicalLocked(DownloadPublication saved,Guid id,string to,CompletionNotificationPayload p,CancellationToken ct)
    {
        await state.RecheckLockedAsync(saved,ct);
        if(!Shape(p) || Id(p)!=id || p.EnvelopeId!=saved.EnvelopeId || p.PublicationId!=saved.Id || p.Recipe!=Hex(saved.Recipe) || p.Revision!=Convert.ToBase64String(saved.Revision) ||
            p.ExecutedReference!=Hex(DownloadPublication.Reference(saved.Executed)) || p.CertificateReference!=Hex(DownloadPublication.Reference(saved.Certificate)) ||
            p.IsDemo!=await db.Envelopes.Where(x=>x.Id==saved.EnvelopeId).Select(x=>x.IsDemo).SingleAsync(ct))return null;
        var member=(await MembersLocked(saved,ct)).SingleOrDefault(x=>x.Type==p.Party && x.Id==p.PartyId && x.Email==to && Hex(x.Sha256)==p.PartyHash);
        return member is not null && await QueueEvidence(id,to,p,ct) ? member : null;
    }
    private async Task<CompletionAccessParty[]> MembersLocked(DownloadPublication saved,CancellationToken ct)
    {
        var all=new List<CompletionAccessParty>();var sender=await state.PartyLockedAsync(saved,PartyType.Sender,null,ct)??throw Invalid();all.Add(sender);
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==saved.EnvelopeId).OrderBy(x=>x.Order).Select(x=>x.Id).Take(101).ToArrayAsync(ct);
        var recipients=await db.Recipients.AsNoTracking().Where(x=>x.EnvelopeId==saved.EnvelopeId).OrderBy(x=>x.Id).Select(x=>x.Id).Take(101).ToArrayAsync(ct);
        if(signers.Length is <1 or >100 || recipients.Length>100)throw Invalid();
        foreach(var id in signers)all.Add(await state.PartyLockedAsync(saved,PartyType.Signer,id,ct)??throw Invalid());
        foreach(var id in recipients)all.Add(await state.PartyLockedAsync(saved,PartyType.Recipient,id,ct)??throw Invalid());
        return all.GroupBy(x=>x.Email,StringComparer.OrdinalIgnoreCase).Select(x=>x.First()).ToArray();
    }
    private async Task<bool> QueueEvidence(Guid id,string to,CompletionNotificationPayload p,CancellationToken ct)
    {
        var key=id.ToString();var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={p.EnvelopeId} AND [Event]='completion_notification_queued' AND JSON_VALUE(CASE WHEN ISJSON([DataJson])=1 THEN [DataJson] ELSE '{{}}' END,'$.notificationId')={key}").SingleAsync(ct);
        if(size>16384)throw Invalid();
        var rows=await db.AuditEvents.FromSqlInterpolated($"SELECT TOP(2) * FROM [AuditEvents] WHERE [EnvelopeId]={p.EnvelopeId} AND [Event]='completion_notification_queued' AND JSON_VALUE(CASE WHEN ISJSON([DataJson])=1 THEN [DataJson] ELSE '{{}}' END,'$.notificationId')={key}").AsNoTracking().ToArrayAsync(ct);
        return rows.Length==1 && rows[0].ActorType==PartyType.System && rows[0].ActorId is null && rows[0].ActorEmail is null && rows[0].Ip is null && rows[0].UserAgent is null &&
            rows[0].At<=time.GetUtcNow() && CryptographicOperations.FixedTimeEquals(rows[0].Hash,AuditHash.Compute(rows[0])) && rows[0].DataJson==Queued(id,to,p);
    }
    internal static bool Shape(CompletionNotificationPayload p) {
        if(p.Version!=Version || p.EnvelopeId==Guid.Empty || p.PublicationId==Guid.Empty || p.LastTokenId==Guid.Empty ||
            (p.Party==PartyType.Sender ? p.PartyId is not null : p.Party is not (PartyType.Signer or PartyType.Recipient) || p.PartyId is null || p.PartyId==Guid.Empty) ||
            !new[]{p.Recipe,p.PartyHash,p.ExecutedReference,p.CertificateReference}.All(x=>x is {Length:64} && x.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f')))return false;
        try {return Convert.FromBase64String(p.Revision) is {Length:8} bytes && Convert.ToBase64String(bytes)==p.Revision;}catch(FormatException){return false;}
    }
    internal static string Hex(byte[] bytes)=>Convert.ToHexStringLower(bytes);
    internal static InvalidDataException Invalid()=>new("Completion notification scope could not be verified.");
}

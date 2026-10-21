using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;

namespace QuillSign.Work;

internal sealed record VoidNotificationPayload(string Version,Guid EnvelopeId,long VoidAuditId,string VoidHash,string Revision,
    PartyType Party,Guid? PartyId,string PartyHash,string RosterHash,bool IsDemo);
internal sealed record VoidNotificationMember(PartyType Type,Guid? Id,string? Name,string Email,string? Role,int? Order,string Hash);

public sealed class VoidNotificationProtection(IDataProtectionProvider provider)
{
    private readonly IDataProtector protector=provider.CreateProtector("QuillSign.VoidNotification.v1");
    internal string Protect(VoidNotificationPayload value) {
        var json=JsonSerializer.Serialize(new ProtectedWorkPayload(protector.Protect(JsonSerializer.Serialize(value))));
        return json.Length<=8192 ? json : throw VoidNotificationJobs.Invalid();
    }
    internal VoidNotificationPayload Read(string json) {
        if(json.Length>8192)throw VoidNotificationJobs.Invalid();
        var wrapper=JsonSerializer.Deserialize<ProtectedWorkPayload>(json);
        var value=JsonSerializer.Deserialize<VoidNotificationPayload>(protector.Unprotect(wrapper?.Protected??throw new JsonException()))??throw new JsonException();
        if(!VoidNotificationJobs.Shape(value))throw VoidNotificationJobs.Invalid();return value;
    }
}

// The producer is wired only together with its supported dispatcher. Source verification
// uses the canonical void record, without a sender session or a signing capability.
public sealed class VoidNotificationJobs(QuillSignDbContext db,SenderVoidState state,VoidNotificationProtection protection,
    Func<IWorkSignals> signals,WorkOptions work,AuditWriter audit,TimeProvider time)
{
    public const string Version="void-notification-v1",Template="envelope-voided";
    internal static Guid Id(VoidNotificationPayload p)=>new(SHA256.HashData(Encoding.UTF8.GetBytes(Version+":"+p.EnvelopeId.ToString("N")+":"+
        p.VoidAuditId.ToString(System.Globalization.CultureInfo.InvariantCulture)+":"+p.Party+":"+(p.PartyId?.ToString("N")??"sender"))).AsSpan(0,16));
    internal static string Digest(VoidNotificationPayload p)=>Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(p)));
    internal static string WorkJson(Guid id)=>JsonSerializer.Serialize(new {version=Version,notificationId=id});
    internal static string Queued(Guid id,string to,VoidNotificationPayload p)=>JsonSerializer.Serialize(new {version=Version,notificationId=id,
        voidAuditId=p.VoidAuditId,scopeSha256=Digest(p),recipient=to,meaning="Void notification queued; submission and delivery are not confirmed."});

    internal async Task<Guid[]> PrepareLockedAsync(Guid envelopeId,CancellationToken ct)
    {
        RequireTransaction();if(!work.Enabled)return [];
        var scope=await state.ReadLockedAsync(envelopeId,ct)??throw Invalid();if(!Retained(scope))return [];
        var roster=await Members(scope,ct);var ids=new List<Guid>();
        foreach(var member in roster.Members) {
            var p=Payload(scope,roster.Hash,member);var id=Id(p);
            var email=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
            var item=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
            if(email is null && item is null) {
                email=new() {Id=id,EnvelopeId=envelopeId,To=member.Email,Template=Template,PayloadJson=protection.Protect(p),AvailableAt=time.GetUtcNow()};
                item=new() {Id=id,EnvelopeId=envelopeId,Kind=WorkKind.Email,PayloadJson=WorkJson(id),AvailableAt=email.AvailableAt};
                db.EmailOutbox.Add(email);db.WorkItems.Add(item);await db.SaveChangesAsync(ct);
                await audit.AppendAsync(envelopeId,"void_notification_queued",null,null,null,ct,Queued(id,member.Email,p),PartyType.System);
            } else if(email is null || item is null || email.EnvelopeId!=envelopeId || email.To!=member.Email || email.Template!=Template || email.AttachmentsJson!="[]" ||
                item.EnvelopeId!=envelopeId || item.Kind!=WorkKind.Email || item.PayloadJson!=WorkJson(id) || protection.Read(email.PayloadJson)!=p || !await QueueEvidence(id,email.To,p,ct))throw Invalid();
            if(item.Status is WorkStatus.Completed or WorkStatus.Failed)continue;
            await signals().PutHintAsync(id,item.Status==WorkStatus.Leased && item.LeaseExpiresAt is DateTimeOffset until ? until : item.AvailableAt,ct);ids.Add(id);
        }
        var current=await state.ReadLockedAsync(envelopeId,ct)??throw Invalid();
        if(!Retained(current) || !SameScope(scope,current) || (await Members(current,ct)).Hash!=roster.Hash)throw Invalid();return ids.ToArray();
    }
    public async Task<int> ResumeAsync(Guid envelopeId,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Void notification resume requires a clean standalone unit of work.");
        if(!work.Enabled)throw new InvalidOperationException("Durable void notification work is disabled.");
        Guid[] ids;db.ChangeTracker.Clear();await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        try {await using(var tx=await db.Database.BeginTransactionAsync(ct)) {ids=await PrepareLockedAsync(envelopeId,ct);await tx.CommitAsync(ct);} }
        catch {db.ChangeTracker.Clear();throw;}
        await PublishAsync(ids,ct);return ids.Length;
    }
    internal async Task PublishAsync(IEnumerable<Guid> ids,CancellationToken ct) {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Commit before publishing void wakeups.");
        foreach(var id in ids)try {await signals().PublishAsync(id,TimeSpan.Zero,ct);}
            catch(Exception error) when(error is IOException or Azure.RequestFailedException or HttpRequestException or OperationCanceledException) { /* durable hints recover */ }
    }
    internal Task<SenderVoidScope?> ResolveLocked(Guid id,string to,VoidNotificationPayload p,CancellationToken ct)
        =>ResolveCanonicalLocked(id,to,p,ct);
    internal Task<SenderVoidScope?> ResolveCloseoutLocked(Guid id,string to,VoidNotificationPayload p,
        Email.Pilot.EmailPilotCloseout.AliasFact alias,CancellationToken ct)
    {
        alias.DemandLocked(db,id,to,Template);
        if(db.Database.CurrentTransaction is null||alias.AliasId!=id||alias.OriginalId!=Id(p)||alias.RecordId!=p.EnvelopeId||
            alias.Template!=Template||alias.Recipient!=to||alias.Until<=time.GetUtcNow())return Task.FromResult<SenderVoidScope?>(null);
        return ResolveCanonicalLocked(alias.OriginalId,to,p,ct);
    }
    private async Task<SenderVoidScope?> ResolveCanonicalLocked(Guid id,string to,VoidNotificationPayload p,CancellationToken ct)
    {
        RequireTransaction();if(!Shape(p) || Id(p)!=id)return null;
        var scope=await state.ReadLockedAsync(p.EnvelopeId,ct);if(scope is null || !Retained(scope))return null;
        var roster=await Members(scope,ct);var member=roster.Members.SingleOrDefault(x=>x.Type==p.Party && x.Id==p.PartyId && x.Email==to);
        return member is not null && Payload(scope,roster.Hash,member)==p && await QueueEvidence(id,to,p,ct) ? scope : null;
    }
    private static VoidNotificationPayload Payload(SenderVoidScope scope,string roster,VoidNotificationMember member)=>new(Version,scope.Envelope.Id,scope.Audit.Id,
        Hex(scope.Audit.Hash),Convert.ToBase64String(scope.Envelope.RowVersion),member.Type,member.Id,member.Hash,roster,scope.Envelope.IsDemo);
    private async Task<(VoidNotificationMember[] Members,string Hash)> Members(SenderVoidScope scope,CancellationToken ct)
    {
        var e=scope.Envelope;
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==e.Id).OrderBy(x=>x.Order).Take(101).ToArrayAsync(ct);
        var recipients=await db.Recipients.AsNoTracking().Where(x=>x.EnvelopeId==e.Id).OrderBy(x=>x.Id).Take(101).ToArrayAsync(ct);
        if(signers.Length is <1 or >100 || recipients.Length>100)throw Invalid();
        var hash=Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {e.SenderName,e.SenderEmail,
            signers=signers.Select(x=>new {x.Id,x.Order,x.FullName,x.Email,x.Role}),recipients=recipients.Select(x=>new {x.Id,x.Name,x.Email})})));
        VoidNotificationMember Member(PartyType type,Guid? id,string? name,string email,string? role,int? order) {
            if(EmailAddress.Normalize(email)!=email)throw Invalid();
            var memberHash=Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {version=Version,envelopeId=e.Id,voidAuditId=scope.Audit.Id,voidHash=Hex(scope.Audit.Hash),type,id,name,email,role,order})));
            return new(type,id,name,email,role,order,memberHash);
        }
        var members=new List<VoidNotificationMember> {Member(PartyType.Sender,null,e.SenderName,e.SenderEmail,null,null)};
        members.AddRange(signers.Select(x=>Member(PartyType.Signer,x.Id,x.FullName,x.Email,x.Role,x.Order)));
        return (members.GroupBy(x=>x.Email,StringComparer.OrdinalIgnoreCase).Select(x=>x.First()).ToArray(),hash);
    }
    private async Task<bool> QueueEvidence(Guid id,string to,VoidNotificationPayload p,CancellationToken ct)
    {
        var key=id.ToString();var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={p.EnvelopeId} AND [Event]='void_notification_queued' AND JSON_VALUE(CASE WHEN ISJSON([DataJson])=1 THEN [DataJson] ELSE '{{}}' END,'$.notificationId')={key}").SingleAsync(ct);
        if(size>16384)throw Invalid();
        var rows=await db.AuditEvents.FromSqlInterpolated($"SELECT TOP(2) * FROM [AuditEvents] WHERE [EnvelopeId]={p.EnvelopeId} AND [Event]='void_notification_queued' AND JSON_VALUE(CASE WHEN ISJSON([DataJson])=1 THEN [DataJson] ELSE '{{}}' END,'$.notificationId')={key}").AsNoTracking().ToArrayAsync(ct);
        return rows.Length==1 && rows[0].ActorType==PartyType.System && rows[0].ActorId is null && rows[0].ActorEmail is null && rows[0].Ip is null && rows[0].UserAgent is null &&
            rows[0].At<=time.GetUtcNow() && CryptographicOperations.FixedTimeEquals(rows[0].Hash,AuditHash.Compute(rows[0])) && rows[0].DataJson==Queued(id,to,p);
    }
    internal static bool Shape(VoidNotificationPayload p) {
        if(p.Version!=Version || p.EnvelopeId==Guid.Empty || p.VoidAuditId<1 || (p.Party==PartyType.Sender ? p.PartyId is not null : p.Party!=PartyType.Signer || p.PartyId is null || p.PartyId==Guid.Empty) ||
            !new[]{p.VoidHash,p.PartyHash,p.RosterHash}.All(x=>x is {Length:64} && x.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f')))return false;
        try {return Convert.FromBase64String(p.Revision) is {Length:8} bytes && Convert.ToBase64String(bytes)==p.Revision;}
        catch(ArgumentException){return false;}catch(FormatException){return false;}
    }
    private static bool SameScope(SenderVoidScope a,SenderVoidScope b)=>a.Audit.Id==b.Audit.Id && CryptographicOperations.FixedTimeEquals(a.Audit.Hash,b.Audit.Hash) && a.Envelope.RowVersion.AsSpan().SequenceEqual(b.Envelope.RowVersion);
    private bool Retained(SenderVoidScope scope)=>scope.Envelope.PurgeAfter is null || scope.Envelope.PurgeAfter>time.GetUtcNow();
    private void RequireTransaction() {if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Void notification scope requires its parent's transaction.");}
    internal static string Hex(byte[] bytes)=>Convert.ToHexStringLower(bytes);
    internal static InvalidDataException Invalid()=>new("Void notification scope could not be verified.");
}

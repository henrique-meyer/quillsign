using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;

namespace QuillSign.Work;

internal sealed record CanonicalResendAdmission(string Version,ResendRequest Request,SignerContactEpoch Contact,string StatementVersion,string StatementSha256);

internal static class CanonicalResendEvidence
{
    internal const string Event="invitation_resend_current_contact_requested";
    internal const string Version="resend-current-contact-v1";
    private static readonly JsonSerializerOptions Json=new() {PropertyNamingPolicy=JsonNamingPolicy.CamelCase,MaxDepth=6,
        UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    internal static string Canonical(CanonicalResendAdmission a)
    {
        InvitationResendProtection.Validate(a.Request);
        if(a.Version!=Version || a.Contact is null || a.Contact.Number is <0 or >SignerContactHistory.MaximumCorrections ||
            (a.Contact.Number==0)!=(a.Contact.RevisionId==Guid.Empty) || a.StatementVersion!=InvitationResendStatement.Version ||
            a.StatementSha256!=InvitationResendStatement.Sha256)throw Invalid();
        return JsonSerializer.Serialize(a,Json);
    }
    internal static string Digest(CanonicalResendAdmission a)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(a))));
    internal static InvitationSuccessorScope Scope(CanonicalResendAdmission a)
    {
        var p=a.Request;
        return new(InvitationSuccessorProtection.Version,p.Id,p.EnvelopeId,p.SignerId,p.PreviousId,a.Contact,InvitationSuccessorReason.ManualResend,
            p.Email,p.SenderEmail,p.DocumentId,p.DocumentSha256,p.DisclosureSha256,Digest(a),p.RequestedAt,p.Deadline);
    }
    internal static CanonicalResendAdmission Read(AuditEvent row)
    {
        if(row.Event!=Event || row.ActorType!=PartyType.Sender || row.ActorId is not null || row.DataJson is not {Length:>0 and <=12000} ||
            !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(row),row.Hash))throw Invalid();
        try {
            var a=JsonSerializer.Deserialize<CanonicalResendAdmission>(row.DataJson,Json)??throw Invalid();var p=a.Request;
            if(row.DataJson!=Canonical(a) || row.EnvelopeId!=p.EnvelopeId || row.ActorEmail!=p.SenderEmail || row.At<p.RequestedAt || row.At>=p.CounterUntil ||
                InvitationResendProtection.IpHash(row.Ip)!=p.IpHash)throw Invalid();return a;
        } catch(Exception e) when(e is JsonException or ArgumentException or InvalidOperationException) {throw Invalid();}
    }
    internal static async Task<CanonicalResendAdmission?> FindAsync(QuillSignDbContext db,Guid id,Guid envelope,CancellationToken ct)
    {
        var query=db.AuditEvents.FromSqlInterpolated($"""
            SELECT * FROM [AuditEvents] WHERE [EnvelopeId]={envelope} AND [Event]={Event}
            AND JSON_VALUE([DataJson],'$.request.id')={id.ToString()}
            """).AsNoTracking();
        var sizes=await query.Select(x=>EF.Functions.DataLength(x.DataJson)).Take(2).ToArrayAsync(ct);
        if(sizes.Length>1 || sizes.Any(x=>x>24000))throw Invalid();
        var rows=await query.Take(2).ToArrayAsync(ct);
        if(rows.Length>1)throw Invalid();return rows.Length==0 ? null : Read(rows[0]);
    }
    internal static InvalidDataException Invalid()=>new("Current-contact resend evidence could not be verified.");
}

// Both formats spend the same UTC-day reservations. A new producer cannot get
// another pool by changing its template/contact epoch or retrying an old ID.
internal sealed class InvitationResendReservations(QuillSignDbContext db,InvitationResendProtection legacy,
    InvitationSuccessorProtection? successors,InvitationResendOptions limits,TimeProvider time)
{
    internal async Task<bool> WithinAsync(ResendRequest candidate,bool reserved,CancellationToken ct)
    {
        limits.Validate();var start=candidate.CounterUntil.AddDays(-1);
        if(time.GetUtcNow()<start || time.GetUtcNow()>=candidate.CounterUntil)return false;
        var query=db.AuditEvents.AsNoTracking().Where(x=>(x.Event==InvitationResendProtection.Event || x.Event==CanonicalResendEvidence.Event) &&
            x.At>=start && x.At<candidate.CounterUntil);
        var sizes=await query.OrderBy(x=>x.Id).Select(x=>new {x.Id,Size=EF.Functions.DataLength(x.DataJson)}).Take(1001).ToArrayAsync(ct);
        if(sizes.Length>1000)return false;if(sizes.Any(x=>x.Size>24000))throw CanonicalResendEvidence.Invalid();
        var ids=sizes.Select(x=>x.Id).ToArray();var audits=await query.Where(x=>ids.Contains(x.Id)).ToArrayAsync(ct);
        if(audits.Length!=sizes.Length)throw CanonicalResendEvidence.Invalid();
        var requests=new List<ResendRequest>();var admissions=new Dictionary<Guid,CanonicalResendAdmission>();
        foreach(var row in audits) {
            if(row.Event==InvitationResendProtection.Event)requests.Add(InvitationResendProtection.ReadEvidence(row));
            else {var a=CanonicalResendEvidence.Read(row);requests.Add(a.Request);if(!admissions.TryAdd(a.Request.Id,a))throw CanonicalResendEvidence.Invalid();}
        }
        if(requests.Select(x=>x.Id).Distinct().Count()!=requests.Count)throw CanonicalResendEvidence.Invalid();
        var workIds=requests.Select(x=>x.Id).ToArray();
        var payloadSizes=await db.EmailOutbox.Where(x=>workIds.Contains(x.Id)).Select(x=>new {Payload=EF.Functions.DataLength(x.PayloadJson),Attachments=EF.Functions.DataLength(x.AttachmentsJson)}).ToArrayAsync(ct);
        if(payloadSizes.Length!=requests.Count || payloadSizes.Any(x=>x.Payload>24000 || x.Attachments!=4))throw CanonicalResendEvidence.Invalid();
        var rows=await db.EmailOutbox.AsNoTracking().Where(x=>workIds.Contains(x.Id)).ToDictionaryAsync(x=>x.Id,ct);
        var work=await db.WorkItems.AsNoTracking().Where(x=>workIds.Contains(x.Id)).ToDictionaryAsync(x=>x.Id,ct);
        if(rows.Count!=requests.Count || work.Count!=requests.Count)throw CanonicalResendEvidence.Invalid();
        foreach(var p in requests) {
            if(work[p.Id].EnvelopeId!=p.EnvelopeId || work[p.Id].Kind!=WorkKind.Email || work[p.Id].PayloadJson!=JsonSerializer.Serialize(new {emailId=p.Id}))throw CanonicalResendEvidence.Invalid();
            if(admissions.TryGetValue(p.Id,out var a)) {
                if(successors is null || successors.Read(rows[p.Id]).Scope!=CanonicalResendEvidence.Scope(a))throw CanonicalResendEvidence.Invalid();
            } else if(legacy.Read(rows[p.Id]).Request!=p)throw CanonicalResendEvidence.Invalid();
        }
        if(reserved && !requests.Contains(candidate))throw CanonicalResendEvidence.Invalid();
        var extra=reserved ? 0 : 1;
        return requests.Count+extra<=limits.DailyRequests && requests.Count(x=>x.Email==candidate.Email)+extra<=limits.DailyAddressRequests &&
            requests.Count(x=>x.SenderEmail==candidate.SenderEmail)+extra<=limits.DailySenderRequests && requests.Count(x=>x.IpHash==candidate.IpHash)+extra<=limits.DailyIpRequests;
    }
}

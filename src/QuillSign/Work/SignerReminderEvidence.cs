using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Work;

// This runtime epoch represents the verified legacy contact explicitly. It never
// mints a contact revision from an address; the earlier pure format is not authority.
public sealed record ReminderEpoch(string Version,Guid EnvelopeId,Guid SignerId,Guid InvitationId,SignerContactEpoch Contact,
    string Recipient,string SenderEmail,Guid DocumentId,string DocumentSha256,string DisclosureSha256,
    string Policy,string PolicySha256,DateTimeOffset InvitedAt,DateTimeOffset? SigningDeadline,DateTimeOffset? RetentionDeadline);
public sealed record ReminderSchedule(ReminderEpoch Epoch);
public sealed record ReminderWork(string Version,string EpochSha256,int Day);
public sealed record ReminderAdmission(string Version,Guid WorkId,string EpochSha256,int Day,DateTimeOffset DueAt,
    Guid Id,Guid EnvelopeId,Guid SignerId,Guid PreviousId,SignerContactEpoch Contact,string Recipient,string SenderEmail,
    Guid DocumentId,string DocumentSha256,string DisclosureSha256,string PolicySha256,DateTimeOffset AdmittedAt,DateTimeOffset Deadline);

public static class SignerReminderEvidence
{
    public const string Version="signer-reminder-runtime-v1";
    public const string ScheduleEvent="signer_reminders_scheduled";
    public const string AdmissionEvent="signer_reminder_admitted";
    private static readonly JsonSerializerOptions Json=new() {PropertyNamingPolicy=JsonNamingPolicy.CamelCase,MaxDepth=6,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    internal static string Canonical<T>(T value)=>JsonSerializer.Serialize(value,Json);
    internal static string Digest<T>(T value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(value))));
    internal static Guid Id(string purpose,string value)=>new(SHA256.HashData(Encoding.ASCII.GetBytes(Version+":"+purpose+":"+value)).AsSpan(0,16));
    internal static Guid WorkId(ReminderEpoch e,int day)=>Id("schedule",Digest(e)+":"+day.ToString(System.Globalization.CultureInfo.InvariantCulture));
    public static Guid EmailId(Guid work)=>Id("email",work.ToString("N"));
    internal static string Payload(ReminderEpoch e,int day)=>Canonical(new ReminderWork(Version,Digest(e),day));
    public static DateTimeOffset DayEnd(DateTimeOffset at)=>new DateTimeOffset(at.UtcDateTime.Date,TimeSpan.Zero).AddDays(1);
    internal static DateTimeOffset Due(ReminderEpoch e,int day)=>e.InvitedAt.AddDays(day);
    internal static IReadOnlyList<int> Days(ReminderEpoch e)
    {
        Validate(e);return SignerReminderPolicy.Read(e.Policy,e.PolicySha256).Days.Where(day=>
            (e.SigningDeadline is null || Due(e,day)<e.SigningDeadline) && (e.RetentionDeadline is null || Due(e,day)<e.RetentionDeadline)).ToArray();
    }
    internal static void Validate(ReminderEpoch e)
    {
        if(e.Version!=Version || e.EnvelopeId==Guid.Empty || e.SignerId==Guid.Empty || e.InvitationId==Guid.Empty || e.DocumentId==Guid.Empty ||
            e.Contact is null || e.Contact.Number is <0 or >SignerContactHistory.MaximumCorrections || (e.Contact.Number==0)!=(e.Contact.RevisionId==Guid.Empty) ||
            !Address(e.Recipient) || !Address(e.SenderEmail) || !SignerReminderPolicy.Hash(e.DocumentSha256) || !SignerReminderPolicy.Hash(e.DisclosureSha256) ||
            e.InvitedAt.Offset!=TimeSpan.Zero || e.InvitedAt>DateTimeOffset.MaxValue.AddDays(-31) ||
            e.SigningDeadline is {} end && (end.Offset!=TimeSpan.Zero || end<=e.InvitedAt) ||
            e.RetentionDeadline is {} cutoff && (cutoff.Offset!=TimeSpan.Zero || cutoff<=e.InvitedAt))throw Invalid();
        if(SignerReminderPolicy.Read(e.Policy,e.PolicySha256).Days.IsEmpty)throw Invalid();
    }
    internal static InvitationSuccessorScope Scope(ReminderAdmission a)=>new(InvitationSuccessorProtection.Version,a.Id,a.EnvelopeId,a.SignerId,
        a.PreviousId,a.Contact,InvitationSuccessorReason.Reminder,a.Recipient,a.SenderEmail,a.DocumentId,a.DocumentSha256,a.DisclosureSha256,Digest(a),a.AdmittedAt,a.Deadline);
    public static ReminderAdmission ReadAdmission(AuditEvent row)
    {
        var a=Read<ReminderAdmission>(row,AdmissionEvent);var p=Scope(a);_ = InvitationSuccessorProtection.Canonical(p);
        if(a.Version!=Version || a.WorkId==Guid.Empty || a.Id!=EmailId(a.WorkId) || a.EnvelopeId!=row.EnvelopeId ||
            a.Day is <1 or >30 || a.DueAt.Offset!=TimeSpan.Zero || a.DueAt>a.AdmittedAt || row.At<a.AdmittedAt || row.At>=a.Deadline ||
            !SignerReminderPolicy.Hash(a.EpochSha256) || !SignerReminderPolicy.Hash(a.PolicySha256))throw Invalid();return a;
    }
    internal static T Read<T>(AuditEvent row,string name)
    {
        if(row.Event!=name || row.ActorType!=PartyType.System || row.ActorId is not null || row.ActorEmail is not null || row.Ip is not null || row.UserAgent is not null ||
            row.Sequence<1 || row.At.Offset!=TimeSpan.Zero || row.DataJson is not {Length:>0 and <=12000} || row.Hash is not {Length:32} ||
            row.PrevHash is not null and not {Length:32} || !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(row),row.Hash))throw Invalid();
        try {var value=JsonSerializer.Deserialize<T>(row.DataJson,Json)??throw Invalid();if(Canonical(value)!=row.DataJson)throw Invalid();return value;}
        catch(JsonException) {throw Invalid();}
    }
    internal static async Task<AuditEvent[]> RowsAsync(QuillSignDbContext db,Guid? envelope,string name,int maximum,CancellationToken ct)
    {
        var query=db.AuditEvents.AsNoTracking().Where(x=>x.Event==name);
        if(envelope is {} id)query=query.Where(x=>x.EnvelopeId==id);
        var sizes=await query.OrderBy(x=>x.EnvelopeId).ThenBy(x=>x.Sequence).Select(x=>EF.Functions.DataLength(x.DataJson)).Take(maximum+1).ToArrayAsync(ct);
        if(sizes.Length>maximum || sizes.Any(x=>x is null or <1 or >24000))throw Invalid();
        var rows=await query.OrderBy(x=>x.EnvelopeId).ThenBy(x=>x.Sequence).Take(maximum+1).ToArrayAsync(ct);
        if(rows.Length!=sizes.Length)throw Invalid();return rows;
    }
    private static bool Address(string value) {try {return Email.EmailAddress.Normalize(value)==value;}catch(ArgumentException){return false;}}
    internal static InvalidDataException Invalid()=>new("Saved signer reminder authority could not be verified.");
}

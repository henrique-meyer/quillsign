using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed class EmailPilotAdmissionOptions
{
    // Hash of an operator-generated random 32-byte base64url capability. Keep
    // both values private; startup does not enable this backend yet.
    public string CapabilitySha256 { get; set; } = "";
}

public sealed record EmailPilotAdmissionResult(Guid EnvelopeId, Guid VerificationWorkId, bool Recovered, bool WakeupPublished = false);

public sealed class EmailPilotAdmission(EmailPilotOptions pilot, EmailPilotAdmissionOptions admission, EmailOptions email,
    WorkOptions work, SenderOptions sender, Func<SenderAvailability> availability, Func<EmailPilotLedger> getLedger,
    Func<EmailOutboxWriter> getOutbox, Func<EmailPayloadProtection> getPayloadProtection, TimeProvider time)
{
    public async Task<EmailPilotAdmissionResult?> RequestAsync(string capability, EmailPilotScenario scenario,
        string? ip=null,string? userAgent=null,CancellationToken ct=default)
    {
        if(!pilot.Enabled || email.Enabled || !work.Enabled || !Enum.IsDefined(scenario) ||
            !EmailPilotCanonical.Hash(admission.CapabilitySha256))return null;
        byte[] capabilityHash;
        try { capabilityHash=EmailPilotCanonical.Capability(capability); }
        catch(ArgumentException){return null;}
        if(!CryptographicOperations.FixedTimeEquals(capabilityHash,Convert.FromHexString(admission.CapabilitySha256)))return null;
        if(!availability().CanVerify)return null;
        var ledger=getLedger();await ledger.CreateAsync(capability,ct);
        var result=await ledger.AdmitAsync(capability,async(db,run,enrolled,scope,addEnrollment)=> {
            if(enrolled.SingleOrDefault(x=>x.Scenario==scenario) is { } existing)
                return await Recover(db,run,existing,ct);
            if(enrolled.Count>=3)return null;
            var recipient=run.Mailboxes.Sender;
            var lockName="sender-request:"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(recipient)));
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                DECLARE @result int;
                EXEC @result=sys.sp_getapplock @Resource={lockName},@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000;
                IF @result<0 THROW 50002,'Sender request is temporarily busy.',1;
                """,ct);
            var now=time.GetUtcNow().ToUniversalTime();var start=new DateTimeOffset(now.UtcDateTime.Date,TimeSpan.Zero);
            if(await db.Envelopes.CountAsync(x=>x.SenderEmail==recipient && x.CreatedAt>=start,ct)>=sender.DailyRequests ||
                await db.Suppressions.AnyAsync(x=>x.Email==recipient,ct))return null;
            var envelope=new Envelope{SenderEmail=recipient,CreatedAt=now,IsDemo=true};db.Envelopes.Add(envelope);await db.SaveChangesAsync(ct);
            var audit=new AuditWriter(db,time);
            await audit.AppendAtAsync(envelope.Id,"draft_created",recipient,ip,userAgent,ct,"{}",now);
            await audit.AppendAtAsync(envelope.Id,"sender_verification_requested",recipient,ip,userAgent,ct,"{}",now);
            var workId=await getOutbox().PreparePilotVerificationAsync(envelope.Id,recipient,scope(envelope.Id),ct);
            var outbox=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==workId,ct);
            var item=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==workId,ct);
            var binding=new EmailPilotVerificationBinding(workId,DraftHash(envelope),Hash(outbox.PayloadJson),Hash(item.PayloadJson));
            addEnrollment(new(run.RunId,envelope.Id,scenario,now,binding));
            return new(envelope.Id,workId,false);
        },ct);
        if(result is null)return null;
        var published=await getOutbox().PublishCommittedAsync(result.VerificationWorkId,ct);
        return result with { WakeupPublished=published.WakeupPublished };
    }

    private async Task<EmailPilotAdmissionResult?> Recover(QuillSignDbContext db,EmailPilotManifest run,EmailPilotEnrollment saved,CancellationToken ct)
    {
        if(saved.Verification is not { } binding)throw EmailPilotProtection.Invalid();
        var envelope=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==saved.SubjectEnvelopeId,ct);
        var outbox=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==binding.WorkId,ct);
        var item=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==binding.WorkId,ct);
        if(envelope is null || !envelope.IsDemo || envelope.SenderEmail!=run.Mailboxes.Sender || envelope.CreatedAt!=saved.EnrolledAt ||
            DraftHash(envelope)!=binding.DraftSha256 || outbox is null || outbox.EnvelopeId!=envelope.Id || outbox.To!=run.Mailboxes.Sender ||
            outbox.Template!="sender-verification" || outbox.AttachmentsJson!="[]" || outbox.AvailableAt.Offset!=TimeSpan.Zero ||
            outbox.AvailableAt<saved.EnrolledAt || outbox.AvailableAt>=run.ExpiresAt || Hash(outbox.PayloadJson)!=binding.EmailPayloadSha256 ||
            item is null || item.EnvelopeId!=envelope.Id || item.Kind!=WorkKind.Email || Hash(item.PayloadJson)!=binding.WorkPayloadSha256)
            throw EmailPilotProtection.Invalid();
        var payload=getPayloadProtection().Unprotect(outbox.PayloadJson);
        if(payload.TokenId==Guid.Empty || payload.Token is not { Length:43 } || payload.Token.Any(c=>!char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_'))
            throw EmailPilotProtection.Invalid();
        var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Sequence<=2).OrderBy(x=>x.Sequence).ToListAsync(ct);
        if(events.Count!=2 || events[0].Event!="draft_created" || events[1].Event!="sender_verification_requested" ||
            events.Where((x,i)=>x.Sequence!=i+1 || x.ActorType!=PartyType.Sender || x.ActorEmail!=run.Mailboxes.Sender || x.ActorId is not null ||
                x.At!=saved.EnrolledAt || x.DataJson!="{}" || !CryptographicOperations.FixedTimeEquals(x.Hash,AuditHash.Compute(x))).Any() ||
            events[0].PrevHash is not null || events[1].PrevHash is null || !CryptographicOperations.FixedTimeEquals(events[0].Hash,events[1].PrevHash))
            throw EmailPilotProtection.Invalid();
        return new(envelope.Id,binding.WorkId,true);
    }

    private static string DraftHash(Envelope value)=>Convert.ToHexStringLower(EmailPilotCanonical.Hash(new {value.Id,value.PublicId,value.SenderEmail,value.IsDemo,value.CreatedAt}));
    private static string Hash(string value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

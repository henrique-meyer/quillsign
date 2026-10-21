using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Factual, closed history, never a delivery/session capability. The original
// capture and its business fingerprint are retained in full. Older stage
// readers receive only this verified description of additional owned rows.
internal sealed class HoldInvitationHistory
{
    private readonly Guid record;
    private readonly VerifiedSignerContacts contacts;
    private readonly Dictionary<Guid, VerifiedInvitationLineage> lineages;
    private readonly Signer[] signers;
    private readonly (DateTimeOffset At, long Sequence, Guid PreviousRevision, Signer Signer)[] retired;
    private readonly SignerContactSession[] sessions;
    private readonly Dictionary<Guid, string> exactMail, exactWork, exactTokens;
    private readonly Dictionary<long, string> exactAudits;
    internal IReadOnlySet<Guid> MailIds => exactMail.Keys.ToHashSet();
    internal IReadOnlySet<Guid> WorkIds => exactWork.Keys.ToHashSet();
    internal IReadOnlySet<Guid> TokenIds => exactTokens.Keys.ToHashSet();
    internal IReadOnlySet<long> AuditSequences => exactAudits.Keys.ToHashSet();
    private static readonly JsonSerializerOptions Rows = new() { Converters = { new JsonStringEnumConverter() } };

    private HoldInvitationHistory(Guid record, VerifiedSignerContacts contacts,
        Dictionary<Guid, VerifiedInvitationLineage> lineages, Signer[] signers,
        (DateTimeOffset At, long Sequence, Guid PreviousRevision, Signer Signer)[] retired, SignerContactSession[] sessions, IEnumerable<EmailOutbox> mail,
        IEnumerable<WorkItem> work, IEnumerable<AuthToken> tokens, IEnumerable<AuditEvent> audits)
    {
        this.record=record;this.contacts=contacts;this.lineages=lineages;this.signers=signers;this.retired=retired;this.sessions=sessions;
        exactMail=mail.ToDictionary(x=>x.Id,x=>JsonSerializer.Serialize(x,Rows));
        exactWork=work.ToDictionary(x=>x.Id,x=>JsonSerializer.Serialize(x,Rows));
        exactTokens=tokens.ToDictionary(x=>x.Id,x=>JsonSerializer.Serialize(x,Rows));
        exactAudits=audits.ToDictionary(x=>(long)x.Sequence,x=>JsonSerializer.Serialize(x,Rows));
    }
    internal string OriginalEmail(Guid signer)=>contacts.Resolve(signer,SignerContactEpoch.Legacy)?.Email??throw Invalid();
    internal Signer SignerForSession(Guid signer,Guid sessionId,Signer current)
        =>ForEpoch(signer,sessions.SingleOrDefault(x=>x.SignerId==signer&&x.SessionId==sessionId)?.RevisionId??Guid.Empty,current);
    internal Signer SignerForPreview(SignaturePreview preview,Signer current)
        =>ForEpoch(preview.SignerId,sessions.SingleOrDefault(x=>x.SignerId==preview.SignerId&&x.SessionSha256.AsSpan().SequenceEqual(preview.SessionSha256))?.RevisionId??Guid.Empty,current);
    private Signer ForEpoch(Guid signer,Guid revision,Signer current)
    {
        var saved=retired.SingleOrDefault(x=>x.Signer.Id==signer&&x.PreviousRevision==revision).Signer;
        if(saved is not null)return saved;
        var party=contacts.Current.Single(x=>x.Id==signer);
        if(party.Epoch.RevisionId!=revision||current.Id!=signer||current.Email!=party.Email||current.FullName!=party.Name||current.Order!=party.Order)throw Invalid();
        return current;
    }
    internal (long Sequence,DateTimeOffset At)? CorrectionAfter(Guid signer,long sequence)
    {
        var next=retired.Where(x=>x.Signer.Id==signer&&x.Sequence>sequence).OrderBy(x=>x.Sequence).FirstOrDefault();
        return next.Signer is null?null:(next.Sequence,next.At);
    }
    internal HoldInitialSignerStage Stage(Guid signer)
    {
        var saved=signers.Single(x=>x.Id==signer);var current=contacts.Current.Single(x=>x.Id==signer);
        if(saved.ConsentAt is not null)return HoldInitialSignerStage.Consented;
        if(!lineages.TryGetValue(signer,out var lineage))return HoldInitialSignerStage.Queued;
        var entries=lineage.Entries.Where(x=>x.Contact==current.Epoch).ToArray();
        if(entries.Any(x=>x.TokenId is{} token&&exactTokens.TryGetValue(token,out var raw)&&JsonSerializer.Deserialize<AuthToken>(raw,Rows)!.UsedAt is not null))return HoldInitialSignerStage.Opened;
        return entries.Any(x=>x.Outbox.Status==EmailStatus.Sent)?HoldInitialSignerStage.Dispatched:HoldInitialSignerStage.Queued;
    }
    internal void DemandRoot(Guid signer,Guid root,Guid source,byte[] hash)
    {
        if(!lineages.TryGetValue(signer,out var lineage)||lineage.Entries[0].Id!=root||lineage.Entries.Any(x=>x.DocumentId!=source||x.DocumentSha256!=Convert.ToHexStringLower(hash)))throw Invalid();
    }
    internal void DemandProjection(JsonElement sql)
    {
        if(sql.GetProperty("RecordId").GetGuid()!=record)throw Invalid();
        var tables=sql.GetProperty("Tables").EnumerateArray().ToDictionary(x=>x.GetProperty("Table").GetString()!,x=>x.GetProperty("Rows"));
        Match<EmailOutbox>("EmailOutbox",exactMail,x=>x.Id);Match<WorkItem>("WorkItems",exactWork,x=>x.Id);Match<AuthToken>("AuthTokens",exactTokens,x=>x.Id);
        var audits=tables["AuditEvents"].Deserialize<AuditEvent[]>(Rows)??throw Invalid();
        foreach(var (sequence,raw) in exactAudits)if(JsonSerializer.Serialize(audits.Single(x=>x.Sequence==sequence),Rows)!=raw)throw Invalid();
        void Match<T>(string name,Dictionary<Guid,string> expected,Func<T,Guid> key)
        {var rows=tables[name].Deserialize<T[]>(Rows)??throw Invalid();foreach(var (id,raw) in expected)if(JsonSerializer.Serialize(rows.Single(x=>key(x)==id),Rows)!=raw)throw Invalid();}
    }
    internal static async Task<HoldInvitationHistory> ReadVerifiedLockedAsync(QuillSignDbContext db,JsonElement sql,
        IReadOnlyList<HoldObjectEvidence> objects,IDataProtectionProvider keys,HoldWitnessState state,TimeProvider time,CancellationToken ct=default)
    {
        try
        {
            if(db.Database.CurrentTransaction is null)throw Invalid();
            ProductionHoldAuditChain.Demand(sql);ProductionHoldInvitationReferences.Demand(sql,objects,keys);
            ProductionHoldConsentAuditReferences.Demand(sql,objects);
            var tables=sql.GetProperty("Tables").EnumerateArray().ToDictionary(x=>x.GetProperty("Table").GetString()!,x=>x.GetProperty("Rows"));
            if(tables.Values.Any(x=>x.ValueKind!=JsonValueKind.Array||x.GetArrayLength()>4096)||tables.Values.Sum(x=>x.GetArrayLength())>4096)throw Invalid();
            T[] Table<T>(string name)=>tables[name].Deserialize<T[]>(Rows)??throw Invalid();
            var id=sql.GetProperty("RecordId").GetGuid();var captured=sql.GetProperty("CapturedAt").GetDateTimeOffset();
            var e=Table<Envelope>("Envelopes").Single();var parties=Table<Signer>("Signers");var audits=Table<AuditEvent>("AuditEvents");
            var mail=Table<EmailOutbox>("EmailOutbox");var work=Table<WorkItem>("WorkItems");var tokens=Table<AuthToken>("AuthTokens");
            var revisions=Table<SignerContactRevisionRecord>("SignerContactRevisions");
            if(e.Id!=id||e.SentAt is null||e.IsDemo||e.Status==EnvelopeStatus.Draft||captured>time.GetUtcNow()||captured.Offset!=TimeSpan.Zero)throw Invalid();
            SameRows(parties,await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==id).ToArrayAsync(ct),x=>x.Id);
            SameRows(revisions,await db.SignerContactRevisions.AsNoTracking().Where(x=>x.EnvelopeId==id).ToArrayAsync(ct),x=>x.Id);
            SameRows(tokens,await db.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==id).ToArrayAsync(ct),x=>x.Id);
            var contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(e,ct);
            var reader=new InvitationLineage(db,new(keys),new(keys),new(keys),time);
            var lineages=new Dictionary<Guid,VerifiedInvitationLineage>();var ownedMail=new List<EmailOutbox>();var ownedWork=new List<WorkItem>();var ownedTokens=new List<AuthToken>();
            var proven=new HashSet<long>();
            foreach(var revision in revisions)
            {
                var a=audits.Single(x=>x.Event==SignerContactHistory.Event&&x.DataJson==revision.EvidenceJson);
                if(!proven.Add(a.Sequence))throw Invalid();
                var request=await SignerContactCorrectionPolicy.FindAsync(db,id,revision.Id,ct)??throw Invalid();
                var original=contacts.Revision(revision.Id)??throw Invalid();
                if(request.Review.SignerId!=original.SignerId||request.Review.NewEmail!=original.NewEmail||request.Review.ContactRevisionId!=original.PreviousRevisionId||
                    request.Review.ContactRevisionNumber+1!=original.Number||request.Review.Version!=original.ReviewedEnvelopeVersion||request.Review.SignerVersion!=original.ReviewedSignerVersion||
                    request.Review.DocumentId!=original.DocumentId||request.Review.DocumentSha256!=original.DocumentSha256||request.Review.DisclosureSha256!=original.DisclosureSha256||
                    request.AdmittedAt!=original.ChangedAt||request.RevisionSha256!=SignerContactHistory.Digest(original)||request.SenderTicketExpiresAt!=original.SenderTicketExpiresAt)throw Invalid();
                var reservation=audits.Single(x=>x.Event==SignerContactCorrectionPolicy.Event&&x.DataJson==SignerContactCorrectionPolicy.Canonical(request));
                if(reservation.Sequence!=a.Sequence+1||reservation.At!=a.At||!proven.Add(reservation.Sequence))throw Invalid();
            }
            foreach(var signer in parties.OrderBy(x=>x.Order))
            {
                var lineage=await reader.ReadLockedAsync(e,signer.Id,contacts,ct);if(lineage is null)continue;
                lineages.Add(signer.Id,lineage);
                foreach(var entry in lineage.Entries)
                {
                    var m=mail.Single(x=>x.Id==entry.Id);var w=work.Single(x=>x.Id==entry.Id);
                    if(JsonSerializer.Serialize(m,Rows)!=JsonSerializer.Serialize(entry.Outbox,Rows)||JsonSerializer.Serialize(w,Rows)!=JsonSerializer.Serialize(entry.Work,Rows)||
                        m.EnvelopeId!=id||m.To!=entry.Recipient||m.AttachmentsJson!="[]"||m.LastError is not null||m.LeaseOwner is not null||m.LeaseExpiresAt is not null||
                        w.LastError is not null||w.LeaseOwner is not null||w.LeaseExpiresAt is not null||m.AvailableAt!=entry.AdmittedAt)throw Invalid();
                    ownedMail.Add(m);ownedWork.Add(w);
                    if(entry.PreviousId is not null)
                    {
                        var admissionName=m.Template==InvitationResendProtection.Template?InvitationResendProtection.Event:InvitationSuccessorProtection.Event;
                        var a=audits.Single(x=>x.Event==admissionName&&AdmissionId(x)==entry.Id);if(!proven.Add(a.Sequence))throw Invalid();
                        if(m.Template==InvitationResendProtection.Template)_=InvitationResendProtection.ReadEvidence(a);
                        else
                        {
                            var scope=InvitationSuccessorProtection.ReadEvidence(a);
                            if(scope.Reason==InvitationSuccessorReason.ManualResend)
                            {var canonical=audits.Single(x=>x.Event==CanonicalResendEvidence.Event&&CanonicalResendEvidence.Read(x).Request.Id==entry.Id);if(!proven.Add(canonical.Sequence))throw Invalid();}
                        }
                    }
                    if(entry.TokenId is null)
                    {
                        if(m.Status!=EmailStatus.Queued||m.Attempts!=0||m.SubmissionStartedAt is not null||m.Provider is not null||m.ProviderMessageId is not null||
                            w.Status!=WorkStatus.Queued||w.Attempts!=0||w.AvailableAt!=m.AvailableAt)throw Invalid();
                        continue;
                    }
                    DemandCompleted(id,w,state,captured,true);
                    if(m.Status!=EmailStatus.Sent||m.Attempts!=1||m.SubmissionStartedAt is not{} submitted||submitted.Offset!=TimeSpan.Zero||submitted<entry.AdmittedAt||
                        !Provider(m.Provider,128)||!Provider(m.ProviderMessageId,512))throw Invalid();
                    var token=tokens.Single(x=>x.Id==entry.TokenId);ownedTokens.Add(token);
                    if(m.Template==InvitationSuccessorProtection.Template)
                    {var issued=new InvitationSuccessorProtection(keys).Read(m).Issued??throw Invalid();if(issued.Id!=token.Id||issued.Sha256!=Hex(token.TokenSha256)||token.ExpiresAt>issued.ExpiresAt)throw Invalid();}
                    if(m.Template==InvitationResendProtection.Template)
                    {var issued=new InvitationResendProtection(keys).Read(m).Issued??throw Invalid();if(issued.Id!=token.Id||issued.Sha256!=Hex(token.TokenSha256)||token.ExpiresAt>issued.ExpiresAt)throw Invalid();}
                    if(token.EnvelopeId!=id||token.PartyType!=PartyType.Signer||token.PartyId!=signer.Id||token.Purpose!=TokenPurpose.SignerAccess||
                        token.Email!=entry.Recipient||token.DocumentId!=entry.DocumentId||Hex(token.DocumentSha256)!=entry.DocumentSha256||Hex(token.DisclosureSha256)!=entry.DisclosureSha256||
                        token.SignerContactRevisionId!=(entry.Contact==SignerContactEpoch.Legacy?null:entry.Contact.RevisionId)||token.TokenSha256 is not{Length:32}||
                        token.ExpiresAt.Offset!=TimeSpan.Zero||e.ExpiresAt is{} end&&token.ExpiresAt>end||
                        token.CompletionPublicationId is not null||token.CompletionRecipeSha256 is not null||token.CompletionPartySha256 is not null||token.EmailPilotLookupRequestId is not null||token.Ip is not null)throw Invalid();
                    var name=m.Template switch {"signer-invitation"=>"invitation_submitted",InvitationResendProtection.Template=>"invitation_resend_submitted",_=>InvitationSuccessorProtection.ReceiptEvent};
                    var proof=audits.Single(x=>x.Event==name&&ReceiptId(x)==m.Id);
                    var expected=m.Template==InvitationSuccessorProtection.Template
                        ?JsonSerializer.Serialize(new{emailId=m.Id,tokenId=token.Id,documentSha256=entry.DocumentSha256,disclosureSha256=entry.DisclosureSha256,signerId=entry.SignerId,recipient=entry.Recipient,contact=entry.Contact,provider=m.Provider,providerMessageId=m.ProviderMessageId,meaning="provider_accepted_not_proof_of_delivery"})
                        :JsonSerializer.Serialize(new{emailId=m.Id,tokenId=token.Id,documentSha256=entry.DocumentSha256,disclosureSha256=entry.DisclosureSha256,signerId=entry.SignerId,recipient=entry.Recipient,provider=m.Provider,providerMessageId=m.ProviderMessageId,meaning="provider_accepted_not_proof_of_delivery"});
                    if(proof.DataJson!=expected||proof.ActorType!=PartyType.System||proof.ActorId is not null||proof.ActorEmail is not null||proof.Ip is not null||proof.UserAgent is not null||
                        proof.At<submitted||proof.At>captured||w.AvailableAt<proof.At||!proven.Add(proof.Sequence))throw Invalid();
                }
            }
            var invitationTemplates=new[]{"signer-invitation",InvitationResendProtection.Template,InvitationSuccessorProtection.Template};
            if(!mail.Where(x=>invitationTemplates.Contains(x.Template)).Select(x=>x.Id).ToHashSet().SetEquals(ownedMail.Select(x=>x.Id))||
                !tokens.Where(x=>x.Purpose==TokenPurpose.SignerAccess).Select(x=>x.Id).ToHashSet().SetEquals(ownedTokens.Select(x=>x.Id)))throw Invalid();
            DemandReminders(sql,e,audits,work,lineages,ownedWork,proven,state,captured);
            var known=new[]{SignerContactHistory.Event,SignerContactCorrectionPolicy.Event,InvitationResendProtection.Event,InvitationSuccessorProtection.Event,CanonicalResendEvidence.Event,
                "invitation_submitted","invitation_resend_submitted",InvitationSuccessorProtection.ReceiptEvent,SignerReminderEvidence.ScheduleEvent,SignerReminderEvidence.AdmissionEvent};
            if(audits.Any(x=>known.Contains(x.Event)&&!proven.Contains(x.Sequence)))throw Invalid();
            var retired=revisions.Select(x=>(x.ChangedAt,(long)audits.Single(a=>a.Event==SignerContactHistory.Event&&a.DataJson==x.EvidenceJson).Sequence,x.PreviousRevisionId??Guid.Empty,ProductionHoldObjectReferences.ReadRetired(JsonSerializer.SerializeToElement(x)).Signer)).ToArray();
            return new(id,contacts,lineages,parties,retired,Table<SignerContactSession>("SignerContactSessions"),ownedMail,ownedWork,ownedTokens,audits.Where(x=>proven.Contains(x.Sequence)));
        }
        catch(Exception error)when(error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException or OverflowException or NullReferenceException or CryptographicException)
        {throw new InvalidDataException("Owned invitation and reminder history could not be verified.",error);}
    }
    private static void DemandReminders(JsonElement sql,Envelope e,AuditEvent[] audits,WorkItem[] work,Dictionary<Guid,VerifiedInvitationLineage> lineages,
        List<WorkItem> ownedWork,HashSet<long> proven,HoldWitnessState state,DateTimeOffset captured)
    {
        using var sentBody=JsonDocument.Parse(audits.Single(x=>x.Event=="sent").DataJson);
        var sent=SignerReminderSendEvidence.Read(sentBody.RootElement,false);
        var schedules=audits.Where(x=>x.Event==SignerReminderEvidence.ScheduleEvent).ToArray();
        if(schedules.Length>100)throw Invalid();var epochs=new Dictionary<Guid,ReminderEpoch>();
        foreach(var row in schedules)
        {
            var epoch=SignerReminderEvidence.Read<ReminderSchedule>(row,SignerReminderEvidence.ScheduleEvent).Epoch;SignerReminderEvidence.Validate(epoch);
            var root=lineages[epoch.SignerId].Entries[0];
            if(epoch.EnvelopeId!=e.Id||epoch.InvitationId!=root.Id||epoch.Contact!=root.Contact||epoch.Recipient!=root.Recipient||epoch.SenderEmail!=e.SenderEmail||
                epoch.DocumentId!=root.DocumentId||epoch.DocumentSha256!=root.DocumentSha256||epoch.DisclosureSha256!=root.DisclosureSha256||epoch.InvitedAt!=root.AdmittedAt||
                epoch.Policy!=sent.CanonicalJson||epoch.PolicySha256!=sent.Sha256||epoch.SigningDeadline!=e.ExpiresAt||
                row.At<epoch.InvitedAt||row.At>captured||!epochs.TryAdd(root.Id,epoch)||!proven.Add(row.Sequence))throw Invalid();
            if(epoch.RetentionDeadline is not null)throw Invalid();
            foreach(var day in SignerReminderEvidence.Days(epoch))
            {
                var job=work.Single(x=>x.Id==SignerReminderEvidence.WorkId(epoch,day));ownedWork.Add(job);
                if(job.EnvelopeId!=e.Id||job.Kind!=WorkKind.Reminder||job.PayloadJson!=SignerReminderEvidence.Payload(epoch,day)||job.LastError is not null||job.LeaseOwner is not null||job.LeaseExpiresAt is not null)throw Invalid();
                if(job.Status==WorkStatus.Queued){if(job.Attempts!=0||job.AvailableAt!=SignerReminderEvidence.Due(epoch,day))throw Invalid();}
                else DemandCompleted(e.Id,job,state,captured,false);
            }
        }
        if(!work.Where(x=>x.Kind==WorkKind.Reminder).Select(x=>x.Id).ToHashSet().SetEquals(ownedWork.Where(x=>x.Kind==WorkKind.Reminder).Select(x=>x.Id)))throw Invalid();
        foreach(var row in audits.Where(x=>x.Event==SignerReminderEvidence.AdmissionEvent))
        {
            var admission=SignerReminderEvidence.ReadAdmission(row);var epoch=epochs.Values.Single(x=>SignerReminderEvidence.Digest(x)==admission.EpochSha256);
            var scope=SignerReminderEvidence.Scope(admission);var entry=lineages[epoch.SignerId].Entries.Single(x=>x.Id==admission.Id);
            var actual=InvitationSuccessorProtection.ReadEvidence(audits.Single(x=>x.Event==InvitationSuccessorProtection.Event&&AdmissionId(x)==entry.Id));
            var expectedDeadline=SignerReminderEvidence.DayEnd(admission.AdmittedAt);if(e.ExpiresAt is{} end&&end<expectedDeadline)expectedDeadline=end;
            if(actual!=scope||admission.WorkId!=SignerReminderEvidence.WorkId(epoch,admission.Day)||!SignerReminderEvidence.Days(epoch).Contains(admission.Day)||
                admission.DueAt!=SignerReminderEvidence.Due(epoch,admission.Day)||admission.PolicySha256!=epoch.PolicySha256||admission.Deadline!=expectedDeadline||
                epoch.RetentionDeadline<SignerReminderEvidence.DayEnd(admission.AdmittedAt)||
                SignerReminderEvidence.Days(epoch).Where(x=>SignerReminderEvidence.Due(epoch,x)<=admission.AdmittedAt).Max()!=admission.Day||
                work.Single(x=>x.Id==admission.WorkId).Status!=WorkStatus.Completed||!proven.Add(row.Sequence))throw Invalid();
        }
        foreach(var entry in lineages.Values.SelectMany(x=>x.Entries).Where(x=>x.Reason==InvitationSuccessorReason.Reminder))
            if(!audits.Any(x=>x.Event==SignerReminderEvidence.AdmissionEvent&&SignerReminderEvidence.ReadAdmission(x).Id==entry.Id))throw Invalid();
        // A nonempty frozen policy creates a schedule for each actually queued
        // root whose offsets fit the original deadlines. No current-clock reset.
        if(!sent.Days.IsEmpty)
            foreach(var lineage in lineages.Values)if(!epochs.ContainsKey(lineage.Entries[0].Id))
            {
                var root=lineage.Entries[0];
                var epoch=new ReminderEpoch(SignerReminderEvidence.Version,e.Id,root.SignerId,root.Id,root.Contact,root.Recipient,e.SenderEmail,root.DocumentId,root.DocumentSha256,root.DisclosureSha256,
                    sent.CanonicalJson,sent.Sha256,root.AdmittedAt,e.ExpiresAt,null);
                if(SignerReminderEvidence.Days(epoch).Count!=0)throw Invalid();
            }
    }
    private static void DemandCompleted(Guid id,WorkItem job,HoldWitnessState state,DateTimeOffset captured,bool dispatch)
    {
        var kind="work/"+((int)job.Kind).ToString(CultureInfo.InvariantCulture);var reference=$"{job.Id:N}/attempt/1";
        var op=state.Operations?.Values.SingleOrDefault(x=>x.Kind==kind&&x.Reference==reference)??throw Invalid();
        if(job.Status!=WorkStatus.Completed||job.Attempts!=1||job.AvailableAt>captured||state.HandlerOutcomes?.GetValueOrDefault(op.OperationId) is not{} handler||
            state.Outcomes?.GetValueOrDefault(op.OperationId) is not{} outcome||op.ReservationSequence>=handler.Sequence||handler.Sequence>=outcome.Sequence||
            dispatch&&(state.DispatchStarts?.GetValueOrDefault(op.OperationId) is not{} started||started.Sequence<=op.ReservationSequence||started.Sequence>=handler.Sequence))throw Invalid();
        var receipt=Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{Version="production-work-completed-v1",recordId=(Guid?)id,Id=job.Id,Owner=op.OperationId,Kind=job.Kind,Attempt=1,Work=job})));
        if(state.SettledOperations.GetValueOrDefault(op.OperationId)!=receipt)throw Invalid();
    }
    private static Guid AdmissionId(AuditEvent row){using var doc=JsonDocument.Parse(row.DataJson);return doc.RootElement.GetProperty("id").GetGuid();}
    private static Guid ReceiptId(AuditEvent row){using var doc=JsonDocument.Parse(row.DataJson);return doc.RootElement.GetProperty("emailId").GetGuid();}
    private static bool Provider(string? value,int maximum)=>!string.IsNullOrWhiteSpace(value)&&value.Length<=maximum&&!value.Any(char.IsControl);
    private static string Hex(byte[]? hash)=>hash is{Length:32}?Convert.ToHexStringLower(hash):throw Invalid();
    private static void SameRows<T>(IEnumerable<T> saved,IEnumerable<T> actual,Func<T,Guid> key)
    {if(JsonSerializer.Serialize(saved.OrderBy(key),Rows)!=JsonSerializer.Serialize(actual.OrderBy(key),Rows))throw Invalid();}
    private static InvalidDataException Invalid()=>new("Owned invitation and reminder history could not be verified.");
}

internal static class ProductionHoldInvitationHistoryReferences
{
    internal static Task<HoldInvitationHistory> ReadVerifiedLockedAsync(QuillSignDbContext db,JsonElement sql,IReadOnlyList<HoldObjectEvidence> objects,IDataProtectionProvider keys,HoldWitnessState state,TimeProvider time,CancellationToken ct=default)
        =>HoldInvitationHistory.ReadVerifiedLockedAsync(db,sql,objects,keys,state,time,ct);
}

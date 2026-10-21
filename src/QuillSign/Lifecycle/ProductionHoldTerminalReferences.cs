using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// The original terminal SQL is always archived. This private factual projection
// removes only validated terminal effects for the existing pre-terminal reader.
// Current generated rowversions are retained; no former rowversion is invented.
internal static class ProductionHoldTerminalReferences
{
    private static readonly JsonSerializerOptions Rows=new(){Converters={new JsonStringEnumConverter()}};
    internal static async Task<HoldReviewCheckpointHistory> ReadVerifiedLockedAsync(QuillSignDbContext db,JsonElement sql,
        IReadOnlyList<HoldObjectEvidence> objects,IDataProtectionProvider keys,IReadOnlyList<VerifiedReviewInput> inputs,
        HoldWitnessState state,TimeProvider time,CancellationToken ct=default,HoldInvitationHistory? invitationHistory=null)
    {
        try
        {
            if(db.Database.CurrentTransaction is null)throw Invalid();
            ProductionHoldAuditChain.Demand(sql);
            var tables=sql.GetProperty("Tables").EnumerateArray().ToDictionary(x=>x.GetProperty("Table").GetString()!,x=>x.GetProperty("Rows"));
            T[] Table<T>(string name)=>tables[name].Deserialize<T[]>(Rows)??throw Invalid();
            var envelope=Table<Envelope>("Envelopes").Single();var id=sql.GetProperty("RecordId").GetGuid();
            if(id!=envelope.Id||envelope.Status is not(EnvelopeStatus.Declined or EnvelopeStatus.Voided or EnvelopeStatus.Expired))throw Invalid();
            var actual=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
            if(!JsonElement.DeepEquals(JsonSerializer.SerializeToElement(actual,Rows),tables["Envelopes"][0]))throw Invalid();
            var ledger=new ProductionRetentionLedger(db,new(db,time),time);
            var terminal=await ledger.ReadTerminalLockedAsync(id,ct)??throw Invalid();
            var anchor=Table<ProductionRetentionTerminalRecord>("ProductionRetentionTerminals").Single();
            var audits=Table<AuditEvent>("AuditEvents");var action=audits.Single(x=>x.Sequence==terminal.SourceAuditSequence);
            if(anchor.Status!=envelope.Status||anchor.SourceAuditSequence!=action.Sequence||Hex(anchor.SourceAuditHash)!=terminal.SourceAuditHash||
                anchor.OriginalAt!=terminal.OriginalAt||anchor.ClockAt!=terminal.ClockAt||anchor.AuditSequence<=action.Sequence||
                audits.Single(x=>x.Sequence==anchor.AuditSequence).DataJson!=ProductionRetentionLedger.TerminalJson(anchor))throw Invalid();
            ProductionHoldNotificationReferences.Demand(sql,objects,keys);
            var mail=Table<EmailOutbox>("EmailOutbox");var work=Table<WorkItem>("WorkItems");
            var removed=new HashSet<Guid>();var proven=new HashSet<long>{action.Sequence,anchor.AuditSequence};
            var captured=sql.GetProperty("CapturedAt").GetDateTimeOffset();
            foreach(var notice in mail.Where(x=>x.Template==(envelope.Status==EnvelopeStatus.Voided?VoidNotificationJobs.Template:envelope.Status==EnvelopeStatus.Declined?"signer-declined":"__none__")))
            {
                if(!removed.Add(notice.Id))throw Invalid();
                var job=work.Single(x=>x.Id==notice.Id);
                if(notice.EnvelopeId!=id||job.EnvelopeId!=id||job.Kind!=WorkKind.Email||job.LeaseOwner is not null||job.LeaseExpiresAt is not null||
                    notice.LeaseOwner is not null||notice.LeaseExpiresAt is not null||job.LastError is not null||notice.LastError is not null||notice.AttachmentsJson!="[]")throw Invalid();
                VoidNotificationPayload? payload=null;
                if(envelope.Status==EnvelopeStatus.Voided)
                {
                    payload=new VoidNotificationProtection(keys).Read(notice.PayloadJson);
                    if(job.PayloadJson!=VoidNotificationJobs.WorkJson(notice.Id))throw Invalid();
                    var queued=audits.Single(x=>x.Event=="void_notification_queued"&&NoticeId(x)==notice.Id);proven.Add(queued.Sequence);
                }
                else if(job.PayloadJson!="{}")throw Invalid();
                if(notice.Status==EmailStatus.Queued&&notice.Attempts==0&&notice.SubmissionStartedAt is null&&notice.Provider is null&&notice.ProviderMessageId is null&&
                    job.Status==WorkStatus.Queued&&job.Attempts==0&&job.AvailableAt==notice.AvailableAt)continue;
                DemandCompleted(job,notice);
                if(payload is not null)
                {
                    var attempt=SystemProof("void_notification_attempt",JsonSerializer.Serialize(new{version=VoidNotificationJobs.Version,notificationId=notice.Id,scopeSha256=VoidNotificationJobs.Digest(payload),templateVersion=VoidEmailTemplate.Version,
                        meaning="Submission prepared; no provider acceptance or delivery is confirmed."}));
                    var submitted=SystemProof("void_notification_submitted",JsonSerializer.Serialize(new{version=VoidNotificationJobs.Version,notificationId=notice.Id,scopeSha256=VoidNotificationJobs.Digest(payload),
                        provider=notice.Provider,providerMessageId=notice.ProviderMessageId,templateVersion=VoidEmailTemplate.Version,meaning="Provider accepted the message; inbox delivery and receipt are not confirmed."}));
                    if(attempt.Sequence<=anchor.AuditSequence||attempt.At!=notice.SubmissionStartedAt||submitted.Sequence!=attempt.Sequence+1||submitted.At<attempt.At||job.AvailableAt<submitted.At)throw Invalid();
                }
            }
            WorkItem? expiry=null;
            if(envelope.ExpiresAt is not null)
            {
                expiry=work.Single(x=>x.Id==SigningExpiryJobs.WorkId(id));
                if(!SigningExpiryJobs.Matches(envelope,expiry)||expiry.LeaseOwner is not null||expiry.LeaseExpiresAt is not null||expiry.LastError is not null)throw Invalid();
                if(expiry.Status!=WorkStatus.Queued||expiry.Attempts!=0||expiry.AvailableAt!=envelope.ExpiresAt)
                {
                    if(envelope.Status!=EnvelopeStatus.Expired)throw Invalid();DemandCompleted(expiry,null);
                }
            }
            if(!proven.SetEquals(audits.Where(x=>x.Sequence>=action.Sequence).Select(x=>(long)x.Sequence)))throw Invalid();
            var node=JsonNode.Parse(sql.GetRawText())!.AsObject();
            JsonArray TableNode(string name)=>node["Tables"]!.AsArray().Single(x=>x!["Table"]!.GetValue<string>()==name)!["Rows"]!.AsArray();
            TableNode("Envelopes")[0]!["Status"]="Sent";
            if(envelope.Status==EnvelopeStatus.Declined)
            {
                var declined=TableNode("Signers").Single(x=>x!["Status"]!.GetValue<string>()=="Declined")!;
                declined["Status"]=declined["ConsentAt"] is null?"Notified":"Viewed";declined["DeclineReason"]=null;
            }
            foreach(var table in new[]{"EmailOutbox","WorkItems"})
            {
                var array=TableNode(table);foreach(var row in array.Where(x=>removed.Contains(x!["Id"]!.GetValue<Guid>())).ToArray())array.Remove(row);
            }
            if(expiry is not null)
            {
                var row=TableNode("WorkItems").Single(x=>x!["Id"]!.GetValue<Guid>()==expiry.Id)!;
                row["Status"]="Queued";row["Attempts"]=0;row["AvailableAt"]=envelope.ExpiresAt;row["LastError"]=null;
            }
            TableNode("ProductionRetentionTerminals").Clear();var tail=TableNode("AuditEvents");foreach(var row in tail.Where(x=>x!["Sequence"]!.GetValue<long>()>=action.Sequence).ToArray())tail.Remove(row);
            using var before=JsonDocument.Parse(node.ToJsonString());
            return ProductionHoldReviewCheckpointReferences.ReadVerified(before.RootElement,objects,keys,inputs,invitationHistory);

            AuditEvent SystemProof(string name,string data)
            {
                var a=audits.Single(x=>x.Event==name&&x.DataJson==data);
                if(a.ActorType!=PartyType.System||a.ActorId is not null||a.ActorEmail is not null||a.Ip is not null||a.UserAgent is not null||!proven.Add(a.Sequence))throw Invalid();return a;
            }
            void DemandCompleted(WorkItem job,EmailOutbox? notice)
            {
                var kind="work/"+((int)job.Kind).ToString(CultureInfo.InvariantCulture);var reference=$"{job.Id:N}/attempt/1";
                var operation=state.Operations?.Values.SingleOrDefault(x=>x.Kind==kind&&x.Reference==reference)??throw Invalid();
                if(job.Status!=WorkStatus.Completed||job.Attempts!=1||job.AvailableAt>captured||job.LeaseOwner is not null||job.LeaseExpiresAt is not null||
                    state.HandlerOutcomes?.GetValueOrDefault(operation.OperationId) is not{} handler||state.Outcomes?.GetValueOrDefault(operation.OperationId) is not{} outcome||
                    handler.Sequence>=outcome.Sequence||notice is not null&&(notice.Status!=EmailStatus.Sent||notice.Attempts!=1||notice.SubmissionStartedAt is null||
                        string.IsNullOrWhiteSpace(notice.Provider)||notice.Provider.Length>128||string.IsNullOrWhiteSpace(notice.ProviderMessageId)||notice.ProviderMessageId.Length>512||
                        state.DispatchStarts?.GetValueOrDefault(operation.OperationId) is not{} dispatch||dispatch.Sequence<=operation.ReservationSequence||dispatch.Sequence>=handler.Sequence))throw Invalid();
                var receipt=Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{Version="production-work-completed-v1",recordId=(Guid?)id,Id=job.Id,Owner=operation.OperationId,Kind=job.Kind,Attempt=1,Work=job})));
                if(state.SettledOperations.GetValueOrDefault(operation.OperationId)!=receipt)throw Invalid();
            }
        }
        catch(Exception e)when(e is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException or FormatException or NullReferenceException or OverflowException)
        {throw new InvalidDataException("Terminal preservation history could not be verified.",e);}
    }
    private static Guid NoticeId(AuditEvent a){using var d=JsonDocument.Parse(a.DataJson);return d.RootElement.GetProperty("notificationId").GetGuid();}
    private static string Hex(byte[] bytes)=>Convert.ToHexStringLower(bytes);
    private static InvalidDataException Invalid()=>new("Terminal preservation history could not be verified.");
}

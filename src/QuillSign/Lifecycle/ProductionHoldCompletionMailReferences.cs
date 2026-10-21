using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Factual, closed initial completion-mail history. It cannot grant a worker,
// token, provider request or participant session. Current SQL remains archived.
internal static class ProductionHoldCompletionMailReferences
{
    private static readonly JsonSerializerOptions Rows = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, Converters = { new JsonStringEnumConverter() } };
    private sealed record Facts(IReadOnlyDictionary<Guid,(string Mail,string Work)> Originals,HashSet<Guid> Tokens,HashSet<long> Audits);
    internal sealed class History
    {
        private readonly string sqlSha256;
        private readonly IReadOnlyDictionary<Guid,(string Mail,string Work)> originals;
        internal IReadOnlySet<Guid> TokenIds {get;}
        internal IReadOnlySet<long> AuditSequences {get;}
        private History(JsonElement sql,IReadOnlyDictionary<Guid,(string Mail,string Work)> originals,HashSet<Guid> tokens,HashSet<long> audits)
        {sqlSha256=Hash(sql.GetRawText());this.originals=originals;TokenIds=tokens;AuditSequences=audits;}
        internal static History FromCurrent(JsonElement sql,HoldWitnessState state,IDataProtectionProvider keys,IReadOnlyList<HoldObjectEvidence> objects)
        {var facts=Verify(sql,state,keys,objects);return new(sql,facts.Originals,facts.Tokens,facts.Audits);}
        internal JsonDocument ProjectOriginalRows(JsonElement sql)
        {
            if(Hash(sql.GetRawText())!=sqlSha256)throw Invalid();
            using var bytes=new MemoryStream();using(var writer=new Utf8JsonWriter(bytes))
            {
                writer.WriteStartObject();
                foreach(var property in sql.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    if(property.Name!="Tables"){property.Value.WriteTo(writer);continue;}
                    writer.WriteStartArray();
                    foreach(var table in property.Value.EnumerateArray())
                    {
                        var name=table.GetProperty("Table").GetString();writer.WriteStartObject();
                        foreach(var column in table.EnumerateObject())
                        {
                            writer.WritePropertyName(column.Name);
                            if(column.Name!="Rows"||name is not ("EmailOutbox" or "WorkItems")){column.Value.WriteTo(writer);continue;}
                            writer.WriteStartArray();
                            foreach(var row in column.Value.EnumerateArray())
                                if(originals.TryGetValue(row.GetProperty("Id").GetGuid(),out var old))writer.WriteRawValue(name=="EmailOutbox"?old.Mail:old.Work);
                                else row.WriteTo(writer);
                            writer.WriteEndArray();
                        }
                        writer.WriteEndObject();
                    }
                    writer.WriteEndArray();
                }
                writer.WriteEndObject();
            }
            return JsonDocument.Parse(bytes.ToArray());
        }
    }
    internal static History ReadVerified(JsonElement sql,HoldWitnessState state,IDataProtectionProvider keys,IReadOnlyList<HoldObjectEvidence> objects)
    {
        try{return History.FromCurrent(sql,state,keys,objects);}
        catch(Exception error)when(error is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException or FormatException or OverflowException or NullReferenceException)
        {throw new InvalidDataException("The preserved initial completion-mail history could not be verified.",error);}
    }
    private static Facts Verify(JsonElement sql,HoldWitnessState state,IDataProtectionProvider keys,IReadOnlyList<HoldObjectEvidence> objects)
    {
        Shape<EmailOutbox>(["Id","EnvelopeId","To","Template","PayloadJson","AttachmentsJson","Status","Provider","ProviderMessageId","SubmissionStartedAt","Attempts","LastError","AvailableAt","LeaseOwner","LeaseExpiresAt","RowVersion"]);
        Shape<WorkItem>(["Id","EnvelopeId","Kind","Status","PayloadJson","Attempts","LastError","AvailableAt","LeaseOwner","LeaseExpiresAt","RowVersion"]);
        Shape<AuthToken>(["Id","TokenSha256","DocumentId","DocumentSha256","DisclosureSha256","SignerContactRevisionId","EmailPilotLookupRequestId","CompletionPublicationId","CompletionRecipeSha256","CompletionPartySha256","Purpose","EnvelopeId","PartyType","PartyId","Email","ExpiresAt","UsedAt","Ip","RowVersion"]);
        if((state.CompletionMailBaselines?.Count??0)>201)throw Invalid();
        ProductionHoldAuditChain.Demand(sql);
        ProductionHoldCompletionNotificationReferences.Demand(sql,objects,keys);
        var id=sql.GetProperty("RecordId").GetGuid();var captured=sql.GetProperty("CapturedAt").GetDateTimeOffset();
        var tables=sql.GetProperty("Tables").EnumerateArray().ToDictionary(x=>x.GetProperty("Table").GetString()!,x=>x.GetProperty("Rows"));
        T[] Table<T>(string name)=>tables[name].Deserialize<T[]>(Rows)??throw Invalid();
        var result=Table<CompletionPublicationResult>("CompletionPublicationResults").Single();
        var envelope=Table<Envelope>("Envelopes").Single();
        var audits=Table<AuditEvent>("AuditEvents");var tokens=Table<AuthToken>("AuthTokens");
        var mails=Table<EmailOutbox>("EmailOutbox").Where(x=>x.Template==CompletionNotificationJobs.Template).ToArray();
        var work=Table<WorkItem>("WorkItems");
        var originals=new Dictionary<Guid,(string Mail,string Work)>();var usedTokens=new HashSet<Guid>();var proofs=new HashSet<long>();
        foreach(var pair in state.CompletionMailBaselines??new Dictionary<Guid,HoldWitnessCompletionMailBaseline>())
        {
            var baseline=pair.Value;ProductionCompletionMailBaselineContract.Demand(baseline,keys);
            if(baseline.Version!=ProductionCompletionMailBaselineContract.Version||pair.Key!=baseline.OperationId||baseline.RecordId!=id||baseline.PublicationId!=result.Id||baseline.Attempt!=1||
                baseline.RecipeSha256!=Hex(result.RecipeSha256)||baseline.PublicationRevision!=Convert.ToBase64String(result.RowVersion)||
                !originals.TryAdd(baseline.WorkId,(baseline.MailRowJson,baseline.WorkRowJson))||
                state.Operations?.GetValueOrDefault(pair.Key) is not {} operation||operation.Kind!="work/"+((int)WorkKind.Email).ToString(CultureInfo.InvariantCulture)||
                operation.Reference!=$"{baseline.WorkId:N}/attempt/1"||operation.RequestRevision!=baseline.RequestRevision||operation.RequestFenceHash!=baseline.RequestFenceHash||
                operation.ContentSha256!=baseline.ContentSha256||operation.SqlStateSha256!=baseline.SqlStateSha256||
                state.DispatchStarts?.GetValueOrDefault(pair.Key) is not {} dispatch||state.HandlerOutcomes?.GetValueOrDefault(pair.Key) is not {} handler||
                state.Outcomes?.GetValueOrDefault(pair.Key) is not {} outcome||state.SettledOperations.GetValueOrDefault(pair.Key) is not {} settled||
                operation.ReservationSequence>=dispatch.Sequence||dispatch.Sequence>=handler.Sequence||handler.Sequence>=outcome.Sequence)throw Invalid();
            if(baseline.ClaimUntil==default||baseline.ClaimUntil.Offset!=TimeSpan.Zero||baseline.MailRowJson is null||baseline.WorkRowJson is null||
                baseline.MailRowJson.Length>32768||baseline.WorkRowJson.Length>32768||
                System.Text.Encoding.UTF8.GetByteCount(baseline.MailRowJson)+System.Text.Encoding.UTF8.GetByteCount(baseline.WorkRowJson)>32768)throw Invalid();
            var mail=mails.Single(x=>x.Id==baseline.WorkId);var item=work.Single(x=>x.Id==baseline.WorkId);
            using var oldMailJson=JsonDocument.Parse(baseline.MailRowJson);using var oldWorkJson=JsonDocument.Parse(baseline.WorkRowJson);
            var oldMail=oldMailJson.RootElement.Deserialize<EmailOutbox>(Rows)??throw Invalid();var oldWork=oldWorkJson.RootElement.Deserialize<WorkItem>(Rows)??throw Invalid();
            if(oldMail.Id!=mail.Id||oldWork.Id!=mail.Id||oldMail.EnvelopeId!=id||oldWork.EnvelopeId!=id||oldMail.Template!=CompletionNotificationJobs.Template||
                oldMail.Status!=EmailStatus.Queued||oldMail.Attempts!=0||oldMail.SubmissionStartedAt is not null||oldMail.Provider is not null||oldMail.ProviderMessageId is not null||
                oldMail.LastError is not null||oldMail.LeaseOwner is not null||oldMail.LeaseExpiresAt is not null||oldMail.AttachmentsJson!="[]"||oldMail.RowVersion is not {Length:8}||
                oldWork.Kind!=WorkKind.Email||oldWork.Status!=WorkStatus.Queued||oldWork.Attempts!=0||oldWork.LeaseOwner is not null||oldWork.LeaseExpiresAt is not null||
                oldWork.LastError is not null||oldWork.RowVersion is not {Length:8}||oldWork.PayloadJson!=CompletionNotificationJobs.WorkJson(mail.Id)||
                oldMail.AvailableAt!=result.CompletedAt||oldWork.AvailableAt!=result.CompletedAt||
                mail.Status!=EmailStatus.Sent||mail.Attempts!=1||mail.SubmissionStartedAt is not {} submission||submission.Offset!=TimeSpan.Zero||mail.RowVersion is not {Length:8}||
                mail.RowVersion.AsSpan().SequenceEqual(oldMail.RowVersion)||string.IsNullOrWhiteSpace(mail.Provider)||mail.Provider.Length>128||
                string.IsNullOrWhiteSpace(mail.ProviderMessageId)||mail.ProviderMessageId.Length>512||item.Status!=WorkStatus.Completed||item.Attempts!=1||
                item.AvailableAt.Offset!=TimeSpan.Zero||item.LeaseOwner is not null||item.LeaseExpiresAt is not null||item.LastError is not null||item.RowVersion is not {Length:8}||
                item.RowVersion.AsSpan().SequenceEqual(oldWork.RowVersion))throw Invalid();
            SameRemainder(oldMail,mail,["Status","Attempts","SubmissionStartedAt","PayloadJson","Provider","ProviderMessageId","RowVersion"]);
            SameRemainder(oldWork,item,["Status","Attempts","AvailableAt","RowVersion"]);
            var original=ProductionCompletionInputRows.ReadPayload(keys,oldMail.PayloadJson);var current=ProductionCompletionInputRows.ReadPayload(keys,mail.PayloadJson);
            if(original.LastTokenId is not null||current.LastTokenId is not Guid tokenId||!usedTokens.Add(tokenId)||
                JsonSerializer.Serialize(current with{LastTokenId=null})!=JsonSerializer.Serialize(original))throw Invalid();
            var token=tokens.Single(x=>x.Id==tokenId);
            if(token.EnvelopeId!=id||token.Purpose!=TokenPurpose.CompletionAccess||token.PartyType!=current.Party||token.PartyId!=current.PartyId||token.Email!=mail.To||
                token.CompletionPublicationId!=result.Id||!Same(token.CompletionRecipeSha256,result.RecipeSha256)||Hex(token.CompletionPartySha256??[])!=current.PartyHash||
                token.ExpiresAt.Offset!=TimeSpan.Zero||token.TokenSha256 is not {Length:32}||token.RowVersion is not {Length:8}||token.UsedAt is not null||token.Ip is not null||token.DocumentId is not null||
                token.DocumentSha256 is not null||token.DisclosureSha256 is not null||token.SignerContactRevisionId is not null||token.EmailPilotLookupRequestId is not null)throw Invalid();
            var issued=Proof("completion_access_issued",CompletionAccess.Issued(token));
            var rawAttempt=audits.Single(x=>x.Event=="completion_notification_attempt"&&NotificationId(x.DataJson)==mail.Id);
            using var attemptData=JsonDocument.Parse(rawAttempt.DataJson,new(){MaxDepth=8});
            var linkOnly=attemptData.RootElement.GetProperty("linkOnly").GetBoolean();
            var attempt=Proof("completion_notification_attempt",CompletionNotificationDelivery.AttemptEvidence(mail.Id,current,token.ExpiresAt,linkOnly,envelope.FinalSha256!,envelope.CertificateSha256!));
            var submitted=Proof("completion_notification_submitted",CompletionNotificationDelivery.SubmittedEvidence(mail.Id,current,mail.Provider,mail.ProviderMessageId,linkOnly,envelope.FinalSha256!,envelope.CertificateSha256!));
            if(issued.At<result.CompletedAt||issued.Sequence+1!=attempt.Sequence||attempt.Sequence+1!=submitted.Sequence||issued.At>submission||
                attempt.At!=submission||submitted.At<submission||token.ExpiresAt<=submitted.At||token.ExpiresAt>issued.At.AddHours(168)||
                envelope.PurgeAfter is {} until&&token.ExpiresAt>until||issued.At>=baseline.ClaimUntil||submitted.At>=baseline.ClaimUntil||
                item.AvailableAt<submitted.At||item.AvailableAt>captured||item.AvailableAt>=baseline.ClaimUntil)throw Invalid();
            var receipt=Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {Version="production-work-completed-v1",recordId=(Guid?)id,
                Id=item.Id,Owner=operation.OperationId,Kind=WorkKind.Email,Attempt=1,Work=item})));
            if(settled!=receipt)throw Invalid();
        }
        if(!usedTokens.SetEquals(tokens.Where(x=>x.Purpose==TokenPurpose.CompletionAccess).Select(x=>x.Id)))throw Invalid();
        var names=new HashSet<string>(["completion_access_issued","completion_notification_attempt","completion_notification_submitted"],StringComparer.Ordinal);
        if(!proofs.SetEquals(audits.Where(x=>names.Contains(x.Event)).Select(x=>x.Sequence)))throw Invalid();
        return new Facts(originals,usedTokens,proofs);

        AuditEvent Proof(string name,string data)
        {
            var value=audits.Single(x=>x.Event==name&&x.DataJson==data);
            if(value.EnvelopeId!=id||value.ActorType!=PartyType.System||value.ActorId is not null||value.ActorEmail is not null||value.Ip is not null||value.UserAgent is not null||
                value.At>captured||!proofs.Add(value.Sequence))throw Invalid();
            return value;
        }
    }
    private static Guid NotificationId(string data)
    {
        if(data.Length>4096||System.Text.Encoding.UTF8.GetByteCount(data)>4096)throw Invalid();
        using var parsed=JsonDocument.Parse(data,new(){MaxDepth=8});return parsed.RootElement.GetProperty("notificationId").GetGuid();
    }
    private static void SameRemainder<T>(T original,T current,HashSet<string> mutable)
    {
        var before=JsonSerializer.SerializeToElement(original,Rows);var after=JsonSerializer.SerializeToElement(current,Rows);
        if(before.EnumerateObject().Where(x=>!mutable.Contains(x.Name)).Any(x=>!JsonElement.DeepEquals(x.Value,after.GetProperty(x.Name))))throw Invalid();
    }
    private static void Shape<T>(string[] names)
    {if(!typeof(T).GetProperties().Select(x=>x.Name).Order(StringComparer.Ordinal).SequenceEqual(names.Order(StringComparer.Ordinal)))throw Invalid();}
    private static bool Same(byte[]? a,byte[]? b)=>a is not null&&b is not null&&a.AsSpan().SequenceEqual(b);
    private static string Hex(byte[] bytes)=>Convert.ToHexStringLower(bytes);
    private static string Hash(string value)=>Hex(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));
    private static InvalidDataException Invalid()=>new("The preserved initial completion-mail history could not be verified.");
}

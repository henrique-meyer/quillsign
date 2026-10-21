using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Exact original SQL facts only. Strings own the original row lexemes, protected
// payload ciphertext and generated rowversions; no caller can use this as a
// worker/provider permit or reconstruct unrelated earlier SQL from its hashes.
internal sealed record HoldWitnessCompletionMailBaseline(string Version,Guid RecordId,Guid OperationId,Guid WorkId,int Attempt,
    Guid PublicationId,string RecipeSha256,string PublicationRevision,long RequestRevision,string? RequestFenceHash,
    long ControlSequence,string? ControlHash,string SqlStateSha256,string ContentSha256,string MailRowJson,string WorkRowJson,DateTimeOffset ClaimUntil);

internal static class ProductionCompletionMailBaselineContract
{
    internal const string Version="completion-notification-claim-baseline-v1";
    internal const int MaximumRawBytes=32*1024;
    internal static readonly string Kind="work/"+((int)WorkKind.Email).ToString(CultureInfo.InvariantCulture);
    private static readonly JsonSerializerOptions Rows=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,Converters={new JsonStringEnumConverter()}};
    private static readonly string[] MailColumns=["Id","EnvelopeId","To","Template","PayloadJson","AttachmentsJson","Status","Provider","ProviderMessageId","SubmissionStartedAt","Attempts","LastError","AvailableAt","LeaseOwner","LeaseExpiresAt","RowVersion"];
    private static readonly string[] WorkColumns=["Id","EnvelopeId","Kind","Status","PayloadJson","Attempts","LastError","AvailableAt","LeaseOwner","LeaseExpiresAt","RowVersion"];
    internal static string Reference(Guid work,int attempt)=>work.ToString("N")+"/attempt/"+attempt.ToString(CultureInfo.InvariantCulture);
    internal static bool IsCompletionMail(JsonElement sql,string kind,string reference)
    {
        if(kind!=Kind||reference.Length<32||!Guid.TryParseExact(reference.AsSpan(0,32),"N",out var work))return false;
        return Table(sql,"EmailOutbox").EnumerateArray().Any(x=>x.GetProperty("Id").GetGuid()==work&&x.GetProperty("Template").GetString()==CompletionNotificationJobs.Template);
    }
    internal static JsonElement Table(JsonElement sql,string table)=>sql.GetProperty("Tables").EnumerateArray().Single(x=>x.GetProperty("Table").GetString()==table).GetProperty("Rows");
    internal static JsonElement Select(JsonElement sql,string table,Guid id)=>Table(sql,table).EnumerateArray().Single(x=>x.GetProperty("Id").GetGuid()==id);
    internal static void Demand(HoldWitnessCompletionMailBaseline value,IDataProtectionProvider keys)
    {
        try {DemandCore(value,keys);}
        catch(Exception e)when(e is JsonException or ArgumentException or InvalidOperationException or FormatException or OverflowException or System.Security.Cryptography.CryptographicException)
        {throw new InvalidDataException("The exact original completion-mail baseline could not be verified.",e);}
    }
    private static void DemandCore(HoldWitnessCompletionMailBaseline value,IDataProtectionProvider keys)
    {
        if(value.Version!=Version||value.RecordId==Guid.Empty||value.OperationId==Guid.Empty||value.WorkId==Guid.Empty||value.Attempt!=1||value.PublicationId==Guid.Empty||
            !Hash(value.RecipeSha256)||!Hash(value.SqlStateSha256)||!Hash(value.ContentSha256)||value.RequestRevision is <0 or >512||
            (value.RequestRevision==0?value.RequestFenceHash is not null:!Hash(value.RequestFenceHash))||value.PublicationRevision is not {Length:12}||
            Convert.FromBase64String(value.PublicationRevision).Length!=8||Convert.ToBase64String(Convert.FromBase64String(value.PublicationRevision))!=value.PublicationRevision)throw Invalid();
        if(value.ClaimUntil==default||value.ClaimUntil.Offset!=TimeSpan.Zero)throw Invalid();
        ProductionHoldControls.ValidatePrefix(new(value.ControlSequence,value.ControlHash));
        if(value.MailRowJson is not {Length:>0 and <=MaximumRawBytes}||value.WorkRowJson is not {Length:>0 and <=MaximumRawBytes}||
            Encoding.UTF8.GetByteCount(value.MailRowJson)>MaximumRawBytes-Encoding.UTF8.GetByteCount(value.WorkRowJson))throw Invalid();
        using var mailDoc=Row(value.MailRowJson,MailColumns);using var workDoc=Row(value.WorkRowJson,WorkColumns);
        var mail=mailDoc.RootElement.Deserialize<EmailOutbox>(Rows)??throw Invalid();var work=workDoc.RootElement.Deserialize<WorkItem>(Rows)??throw Invalid();
        if(mail.Id!=value.WorkId||work.Id!=value.WorkId||mail.EnvelopeId!=value.RecordId||work.EnvelopeId!=value.RecordId||
            mail.Template!=CompletionNotificationJobs.Template||mail.Status!=EmailStatus.Queued||mail.Attempts!=0||mail.SubmissionStartedAt is not null||mail.Provider is not null||mail.ProviderMessageId is not null||
            mail.LeaseOwner is not null||mail.LeaseExpiresAt is not null||mail.LastError is not null||mail.AttachmentsJson!="[]"||mail.RowVersion is not {Length:8}||
            work.Kind!=WorkKind.Email||work.Status!=WorkStatus.Queued||work.Attempts!=0||work.LeaseOwner is not null||work.LeaseExpiresAt is not null||work.LastError is not null||
            work.RowVersion is not {Length:8}||work.PayloadJson!=CompletionNotificationJobs.WorkJson(work.Id)||work.AvailableAt!=mail.AvailableAt||mail.AvailableAt.Offset!=TimeSpan.Zero||
            mail.To is not {Length:>0 and <=320}||mail.To!=QuillSign.Email.EmailAddress.Normalize(mail.To))throw Invalid();
        var payload=ReadPayload(mail.PayloadJson,keys);
        if(payload.EnvelopeId!=value.RecordId||payload.PublicationId!=value.PublicationId||payload.Recipe!=value.RecipeSha256||payload.Revision!=value.PublicationRevision||
            payload.LastTokenId is not null||payload.IsDemo||CompletionNotificationJobs.Id(payload)!=value.WorkId)throw Invalid();
    }
    internal static CompletionNotificationPayload ReadPayload(string raw,IDataProtectionProvider keys)
    {
        if(raw is not {Length:>0 and <=8192}||Encoding.UTF8.GetByteCount(raw)>8192)throw Invalid();
        var wrapper=JsonSerializer.Deserialize<ProtectedWorkPayload>(raw)??throw Invalid();
        if(JsonSerializer.Serialize(wrapper)!=raw)throw Invalid();
        var plain=keys.CreateProtector("QuillSign.CompletionNotification.v1").Unprotect(wrapper.Protected);
        if(plain.Length>8192||Encoding.UTF8.GetByteCount(plain)>8192)throw Invalid();
        var payload=new CompletionNotificationProtection(keys).Read(raw);
        if(JsonSerializer.Serialize(payload)!=plain)throw Invalid();return payload;
    }
    private static JsonDocument Row(string raw,string[] columns)
    {
        var document=JsonDocument.Parse(raw,new(){MaxDepth=4});
        try
        {
            var names=document.RootElement.EnumerateObject().Select(x=>x.Name).ToArray();
            if(!names.SequenceEqual(columns.Order(StringComparer.Ordinal)))throw Invalid();
            return document;
        }
        catch{document.Dispose();throw;}
    }
    private static bool Hash(string? value)=>ProductionCompletionProtocol.Hash(value);
    private static InvalidDataException Invalid()=>new("The exact original completion-mail baseline could not be verified.");
}

internal sealed partial class ProductionRecordOperationAdmission
{
    internal async Task<ProductionRecordOperation> BeginCompletionNotificationAsync(Guid recordId,Guid operationId,Guid workId,int attempt,DateTimeOffset claimUntil,CancellationToken ct=default)
    {
        await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);
        var scope=await BeginCompletionNotificationLockedAsync(db,recordId,operationId,workId,attempt,claimUntil,ct);
        await tx.RollbackAsync(ct);return scope;
    }
    internal async Task<ProductionRecordOperation> BeginCompletionNotificationLockedAsync(QuillSignDbContext db,Guid recordId,Guid operationId,Guid workId,int attempt,DateTimeOffset claimUntil,CancellationToken ct=default)
    {
        var kind=ProductionCompletionMailBaselineContract.Kind;var reference=ProductionCompletionMailBaselineContract.Reference(workId,attempt);
        Tuple(recordId,operationId,kind,reference);
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges()||workId==Guid.Empty||attempt!=1)throw Invalid();
        var now=time.GetUtcNow();
        if(now.Offset!=TimeSpan.Zero||claimUntil.Offset!=TimeSpan.Zero||claimUntil<=now||claimUntil>now.AddHours(1))throw Invalid();
        var before=await witness.ReadAsync(recordId,ct);
        if(before.Operations?.ContainsKey(operationId)==true)
        {
            var replay=Scope(recordId,operationId,kind,reference,before);
            if(before.CompletionMailBaselines?.GetValueOrDefault(operationId) is not {} original||original.WorkId!=workId||original.Attempt!=attempt||original.ClaimUntil!=claimUntil)throw Invalid();
            // Only the ORIGINAL still-unmutated starting state may return a live
            // reservation. Historical readback below remains separately factual.
            await DemandStartingLockedAsync(db,replay,ct);return replay;
        }
        if(!before.Initialized||before.Frozen)throw Invalid();
        var requests=await Requests(db,recordId,ct);ProductionHoldWitnessJournal.DemandSql(before,requests);
        var sql=await Capture(db,recordId,requests,ct);var content=ContentDigest(sql,keys);
        if(content!=before.BusinessStateSha256||before.SqlStateSha256 is not null&&sql.StateSha256!=before.SqlStateSha256)throw Invalid();
        await DemandControls(db,recordId,before,ct);
        using var plain=ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql,keys);
        var rawMail=ProductionCompletionMailBaselineContract.Select(plain.RootElement,"EmailOutbox",workId);
        var rawWork=ProductionCompletionMailBaselineContract.Select(plain.RootElement,"WorkItems",workId);
        var saved=await DemandInitialCompletionMailLocked(db,recordId,workId,rawMail,rawWork,ct);
        var originalPair=new HoldWitnessCompletionMailBaseline(ProductionCompletionMailBaselineContract.Version,recordId,operationId,workId,attempt,saved.Id,
            Convert.ToHexStringLower(saved.Recipe),Convert.ToBase64String(saved.Revision),requests.Revision,requests.FenceHash,sql.Control!.Sequence,sql.Control.Hash,
            sql.StateSha256,content,rawMail.GetRawText(),rawWork.GetRawText(),claimUntil);
        ProductionCompletionMailBaselineContract.Demand(originalPair,keys);
        await witness.DemandCompletionMailHeadroomAsync(recordId,ct);
        var state=await witness.ReserveCompletionMailOperationAsync(originalPair,requests,Id(recordId,operationId,"reserve"),ct);
        var scope=Scope(recordId,operationId,kind,reference,state);DemandActive(scope,state);DemandCompletionMailLive(scope,state);return scope;
    }
    private async Task<DownloadPublication> DemandInitialCompletionMailLocked(QuillSignDbContext db,Guid recordId,Guid workId,JsonElement rawMail,JsonElement rawWork,CancellationToken ct)
    {
        var options=new JsonSerializerOptions{Converters={new JsonStringEnumConverter()}};
        var mail=rawMail.Deserialize<EmailOutbox>(options)??throw Invalid();var work=rawWork.Deserialize<WorkItem>(options)??throw Invalid();
        var saved=await CompletionDownloadState.ReadAsync(db,recordId,time,ct)??throw Invalid();DocumentRetentionAccess.Check(saved.PurgeAfter,time);
        var payload=ProductionCompletionMailBaselineContract.ReadPayload(mail.PayloadJson,keys);
        var roster=await CompletionNotificationJobs.FreezeRosterLockedAsync(db,recordId,ct);
        var member=roster.Single(x=>x.Type==payload.Party&&x.Id==payload.PartyId&&x.Email==mail.To);
        var party=CompletionAccessState.PartyProjection(saved,member.Type,member.Id,member.Email,member.Name,member.Order);
        var expected=CompletionNotificationJobs.Payload(saved,party,false);
        if(JsonSerializer.Serialize(payload)!=JsonSerializer.Serialize(expected)||mail.Id!=workId||work.Id!=workId||mail.AvailableAt!=saved.CompletedAt||
            work.AvailableAt>time.GetUtcNow()||work.AvailableAt!=mail.AvailableAt||await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==recordId&&x.Purpose==TokenPurpose.CompletionAccess&&x.PartyType==payload.Party&&x.PartyId==payload.PartyId,ct))throw Invalid();
        var queued=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==recordId&&x.Event=="completion_notification_queued"&&
            x.DataJson==CompletionNotificationJobs.Queued(workId,mail.To,payload)).Take(2).ToArrayAsync(ct);
        if(queued.Length!=1||queued[0].ActorType!=PartyType.System||queued[0].ActorId is not null||queued[0].ActorEmail is not null||queued[0].Ip is not null||queued[0].UserAgent is not null||
            queued[0].Sequence<=saved.Source.AuditSequence||queued[0].At<saved.CompletedAt||queued[0].At>time.GetUtcNow()||!queued[0].Hash.AsSpan().SequenceEqual(AuditHash.Compute(queued[0])))throw Invalid();
        return saved;
    }
    internal async Task<HoldWitnessCompletionMailBaseline> ReadCompletionMailBaselineAsync(Guid recordId,Guid operationId,CancellationToken ct=default)
    {
        var state=await witness.ReadAsync(recordId,ct);
        var value=state.CompletionMailBaselines?.GetValueOrDefault(operationId)??throw Invalid();
        if(value.RecordId!=recordId||value.OperationId!=operationId)throw Invalid();return value;
    }
    internal Task<HoldWitnessCompletionMailBaseline> ReadCompletionMailBaselineLockedAsync(QuillSignDbContext db,Guid recordId,Guid operationId,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw Invalid();
        return ReadCompletionMailBaselineAsync(recordId,operationId,ct); // no SQL recapture, settlement or permit.
    }
    private void DemandCompletionMailLive(ProductionRecordOperation scope,HoldWitnessState state)
    {
        if(state.CompletionMailBaselines?.GetValueOrDefault(scope.OperationId) is not {} baseline)return;
        var now=time.GetUtcNow();
        if(now.Offset!=TimeSpan.Zero||now>=baseline.ClaimUntil||baseline.RecordId!=scope.RecordId||baseline.OperationId!=scope.OperationId||
            scope.Kind!=ProductionCompletionMailBaselineContract.Kind||scope.Reference!=ProductionCompletionMailBaselineContract.Reference(baseline.WorkId,baseline.Attempt))throw Invalid();
    }
}

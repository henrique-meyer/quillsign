using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

public sealed class ProductionDeletionOptions
{
    public bool Enabled{get;set;}
    public string CompletedCommitmentStatement{get;set;}="";
    internal void Demand()
    {if(!Enabled||!ProductionOperatorAuthority.Text(CompletedCommitmentStatement,2048))throw ProductionDeletionProtocol.Invalid();}
}
internal sealed record ProductionDeletionStatus(Guid RecordId,Guid? DeletionId,string State,bool SqlRemoved,bool ActiveDataCleaned,
    DateTimeOffset? EligibleAt,long Sequence,string? HeadHash);
internal sealed record ProductionDeletionCompletedFacts(Guid PublicationId,string PublicationSha256,string FinalReceiptsSha256,Guid DeletionId=default);

// One irreversible external ordering for all production cleanup. A mutable
// scheduling hint, SQL absence or an old preservation receipt is never authority.
internal sealed partial class ProductionDeletionCoordinator(Func<QuillSignDbContext> open,IDataProtectionProvider keys,TimeProvider time,
    ProductionHoldWitnessJournal witness,ProductionHoldCoordinator holds,ProductionRecordOperationAdmission operations,
    IProductionDeletionStore storage,IProductionDeletionRecoveryIndex recovery,ProductionDeletionOptions options,
    WorkOptions workOptions,Func<IWorkSignals> signals):IProductionDeletionWorkAdmission
{
    private static readonly JsonSerializerOptions Rows=new(){Converters={new JsonStringEnumConverter()}};
    internal static Guid WorkId(Guid recordId,Guid deletionId)=>Id(recordId,"production-deletion-work/"+deletionId.ToString("N"));
    internal static Guid DeletionId(Guid recordId)=>Id(recordId,"production-deletion-v1");
    internal static Guid PreparationOperationId(Guid record)=>Id(DeletionId(record),"prepare-operation");
    internal static string PreparationReceipt(Guid record)=>ProductionDeletionProtocol.Digest(new{recordId=record,deletionId=DeletionId(record),workId=WorkId(record,DeletionId(record))});
    private static Guid Id(Guid parent,string purpose)=>new(SHA256.HashData(parent.ToByteArray().Concat(Encoding.UTF8.GetBytes(purpose)).ToArray()).AsSpan(0,16));
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid,long> observedUtc=new();
    private DateTimeOffset ObservedNow(Guid record)
    {
        var now=time.GetUtcNow();if(now.Offset!=TimeSpan.Zero)throw ProductionDeletionProtocol.Invalid();
        while(true){var floor=observedUtc.GetOrAdd(record,now.UtcTicks);if(now.UtcTicks<floor)throw ProductionDeletionProtocol.Invalid();
            if(now.UtcTicks==floor||observedUtc.TryUpdate(record,now.UtcTicks,floor))return now;}
    }
    private async Task<HoldWitnessState> Event(Guid record,ProductionDeletionTransition transition,string purpose,CancellationToken ct)
    {_=ObservedNow(record);var state=await witness.ChangeDeletionAsync(record,transition,Id(transition.DeletionId,purpose),ct);_=ObservedNow(record);return state;}

    // Preparing a job is an ordinary fully witnessed SQL mutation, not a
    // deletion reservation. It is safe to queue a completed record before its
    // separate per-record attestation: Claim remains blocked until that exists.
    internal async Task<Guid> PrepareAsync(Guid recordId,CancellationToken ct=default)
    {
        options.Demand();if(!workOptions.Enabled)throw ProductionDeletionProtocol.Invalid();
        var deletionId=DeletionId(recordId);var workId=WorkId(recordId,deletionId);
        var current=await witness.ReadAsync(recordId,ct);
        if(current.Deletion?.Reserved==true)return workId;
        var originalOperation=PreparationOperationId(recordId);
        if(current.Operations?.ContainsKey(originalOperation)==true){
            if(current.Outcomes?.ContainsKey(originalOperation)!=true&&!current.SettledOperations.ContainsKey(originalOperation))throw ProductionDeletionProtocol.Invalid();
            var saved=await operations.ResumeAsync(recordId,originalOperation,"maintenance/production-deletion-prepare",deletionId.ToString("N"),ct);
            await operations.CompleteAsync(saved,PreparationReceipt(recordId),ct);current=await witness.ReadAsync(recordId,ct);
        }
        var prepared=false;
        await using(var db=open()){
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            await holds.VerifyDeletionBaselineLockedAsync(db,recordId,current,ct);_=await Eligibility(db,recordId,ct);
            var existing=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId,ct);
            if(existing is not null){await DemandPreparedCompletedJob(db,current,recordId,ct);prepared=true;}
        }
        if(prepared){await WakeAsync(recordId,ct);return workId;}
        var operation=await operations.BeginAsync(recordId,Id(deletionId,"prepare-operation"),"maintenance/production-deletion-prepare",deletionId.ToString("N"),ct);
        await using(var db=open()){
            await using var tx=await db.Database.BeginTransactionAsync(ct);await operations.DemandStartingLockedAsync(db,operation,ct);
            var eligible=await Eligibility(db,recordId,ct);
            if(await db.WorkItems.AnyAsync(x=>x.Id==workId,ct))throw ProductionDeletionProtocol.Invalid();
            db.WorkItems.Add(new(){Id=workId,EnvelopeId=recordId,Kind=WorkKind.ProductionPurge,PayloadJson=ProductionDeletionProtocol.Payload(recordId,deletionId),AvailableAt=eligible.Deadline!.Value});
            await db.SaveChangesAsync(ct);await operations.PrepareOutcomeLockedAsync(db,operation,ct);await tx.CommitAsync(ct);
        }
        await operations.CompleteAsync(operation,ProductionDeletionProtocol.Digest(new{recordId,deletionId,workId}),ct);
        await WakeAsync(recordId,ct);return workId;
    }

    internal async Task WakeAsync(Guid recordId,CancellationToken ct=default)
    {
        options.Demand();var id=DeletionId(recordId);await using var db=open();
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==WorkId(recordId,id),ct);
        if(row is null)return;DemandPrepared(row,recordId,id);
        if(row.Status!=WorkStatus.Queued||row.Attempts!=0||row.LeaseOwner is not null||row.LeaseExpiresAt is not null)return;
        await signals().PutHintAsync(row.Id,row.AvailableAt,ct);await signals().PublishAsync(row.Id,TimeSpan.Zero,ct);
    }

    internal async Task<ProductionDeletionCompletedFacts> CompletedFactsAsync(Guid recordId,CancellationToken ct=default)
    {
        options.Demand();var state=await witness.ReadAsync(recordId,ct);await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);
        var sql=await holds.VerifyDeletionBaselineLockedAsync(db,recordId,state,ct);var retained=await Eligibility(db,recordId,ct);
        if(retained.Stage!=ProductionRecordStage.Completed)throw ProductionDeletionProtocol.Invalid();
        await DemandPreparedCompletedJob(db,state,recordId,ct);return CompletedFacts(sql,state) with{DeletionId=DeletionId(recordId)};
    }
    private async Task DemandPreparedCompletedJob(QuillSignDbContext db,HoldWitnessState state,Guid recordId,CancellationToken ct)
    {
        var deletion=DeletionId(recordId);var workId=WorkId(recordId,deletion);
        if(!state.SettledOperations.TryGetValue(Id(deletion,"prepare-operation"),out var receipt)||receipt!=ProductionDeletionProtocol.Digest(new{recordId,deletionId=deletion,workId}))throw ProductionDeletionProtocol.Invalid();
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==workId,ct)??throw ProductionDeletionProtocol.Invalid();
        DemandPrepared(row,recordId,deletion);
        if(row.EnvelopeId!=recordId||row.Status!=WorkStatus.Queued||row.Attempts!=0||row.LeaseOwner is not null||row.LeaseExpiresAt is not null||row.LastError is not null)throw ProductionDeletionProtocol.Invalid();
    }

    internal async Task AuthorizeCompletedAsync(ProductionOperatorAuthority authority,ProductionOperatorPolicy policy,Guid recordId,
        Guid authorizationId,string reviewedHead,string commitment,string purpose,DateTimeOffset reviewedAt,CancellationToken ct=default)
    {
        options.Demand();authority.Demand(policy,ProductionOperatorPermission.AuthorizeDeletion,time);
        if(commitment!=options.CompletedCommitmentStatement||!ProductionOperatorAuthority.Text(purpose,256)||authority.SessionId is null||reviewedAt.Offset!=TimeSpan.Zero||reviewedAt>time.GetUtcNow()||authority.ExpiresAt>reviewedAt.AddMinutes(2))throw ProductionDeletionProtocol.Invalid();
        var state=await witness.ReadAsync(recordId,ct);if(state.HeadHash!=reviewedHead)throw ProductionDeletionProtocol.Invalid();
        await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);
        var sql=await holds.VerifyDeletionBaselineLockedAsync(db,recordId,state,ct);var retained=await Eligibility(db,recordId,ct);
        if(retained.Stage!=ProductionRecordStage.Completed)throw ProductionDeletionProtocol.Invalid();
        var job=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==WorkId(recordId,DeletionId(recordId)),ct)??throw ProductionDeletionProtocol.Invalid();
        DemandPrepared(job,recordId,DeletionId(recordId));if(job.Status!=WorkStatus.Queued||job.Attempts!=0)throw ProductionDeletionProtocol.Invalid();
        await DemandPreparedCompletedJob(db,state,recordId,ct);var facts=CompletedFacts(sql,state);var now=time.GetUtcNow();
        var disposition=new ProductionDeletionDisposition(authorizationId,recordId,ProductionRetentionPolicyContract.Digest(retained.Enrollment!.Snapshot),facts.PublicationId,
            facts.PublicationSha256,facts.FinalReceiptsSha256,reviewedHead,commitment,authority.Issuer,authority.Subject,now,authority.ExpiresAt,purpose,authority.SessionId,authority.IssuedAt,reviewedAt);
        authority.Demand(policy,ProductionOperatorPermission.AuthorizeDeletion,time);
        _=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.DispositionAuthorized,authorizationId,Disposition:disposition),"disposition",ct);
        await tx.RollbackAsync(ct);
    }

    public async Task<WorkClaim> ClaimAsync(QuillSignDbContext db,Guid id,CancellationToken ct)
    {
        options.Demand();if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())throw ProductionDeletionProtocol.Invalid();
        var located=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        if(located is null)return new(null,null,true);
        var recordId=ReadPayload(located.PayloadJson).RecordId;var deletionId=DeletionId(recordId);DemandPrepared(located,recordId,deletionId);
        var state=await witness.ReadAsync(recordId,ct);
        if(state.Deletion?.WorkFinished==true)return new(null,null,true);
        if(state.Deletion?.SqlReserved==true){await ReconcileSql(recordId,ct);state=await witness.ReadAsync(recordId,ct);}
        if(state.Deletion?.Header is not null&&state.Deletion.Lease!.Until<=time.GetUtcNow()){
            // Unknown storage outcomes get readonly reconciliation first. No
            // lease epoch or recreated scope grants a second DELETE.
            foreach(var pending in state.Deletion.Effects!.Where(x=>x.Value.Result is null).ToArray()){
                var bits=pending.Key.Split('/');await ApplyStoragePhase(recordId,int.Parse(bits[0],System.Globalization.CultureInfo.InvariantCulture),
                    (ProductionDeletionPhase)int.Parse(bits[1],System.Globalization.CultureInfo.InvariantCulture),ct);
            }
            state=await witness.ReadAsync(recordId,ct);
        }
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var parent=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={recordId}").AsNoTracking().SingleOrDefaultAsync(ct);
        var row=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").SingleAsync(ct);
        if(state.Deletion?.Header is null){
            if(parent is null)throw ProductionDeletionProtocol.Invalid();
            var sql=await holds.VerifyDeletionBaselineLockedAsync(db,recordId,state,ct);var retained=await Eligibility(db,recordId,ct);
            if(row.Status!=WorkStatus.Queued||row.Attempts!=0||row.LeaseOwner is not null||row.AvailableAt>time.GetUtcNow())return new(null,row.AvailableAt,false);
            string? disposition=null;
            if(retained.Stage==ProductionRecordStage.Completed){
                var d=state.Deletion?.Disposition;var facts=CompletedFacts(sql,state);
                if(d is null||state.Deletion!.DispositionSequence!=state.Sequence||d.PolicySha256!=ProductionRetentionPolicyContract.Digest(retained.Enrollment!.Snapshot)||
                    d.PublicationId!=facts.PublicationId||d.PublicationSha256!=facts.PublicationSha256||d.FinalReceiptsSha256!=facts.FinalReceiptsSha256||
                    d.Commitment!=options.CompletedCommitmentStatement||d.ExpiresAt<=time.GetUtcNow())return new(null,time.GetUtcNow().AddMinutes(15),false);
                disposition=ProductionDeletionProtocol.Digest(d);
            }
            var controls=await new ProductionHoldControls(db,keys,time).ReadLockedAsync(recordId,ct);
            var prefixes=controls.Plans.Values.Select(p=>ProductionHoldBundlePlan.OpenVerified(p,keys,time))
                .Select(p=>$"production-holds/{recordId:N}/{p.HoldId:N}/{p.PlaceCommandId:N}/").Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            var now=time.GetUtcNow();var header=new ProductionDeletionHeader(recordId,deletionId,id,Guid.NewGuid(),1,now.AddSeconds(workOptions.LeaseSeconds),now,
                retained.Deadline!.Value,ProductionRetentionPolicyContract.Digest(retained.Enrollment!.Snapshot),Convert.ToBase64String(parent.RowVersion),
                ProductionDeletionProtocol.WorkRow(sql,keys,id).GetRawText(),sql.StateSha256,ProductionRecordOperationAdmission.ContentDigest(sql,keys),
                state.RequestRevision,state.RequestFenceHash,controls.Prefix,prefixes,disposition,ProductionDeletionProtocol.Remainder(sql,keys,id));
            state=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.Reserved,deletionId,Header:header),"reserve",ct);
        }
        var deletion=state.Deletion!;var h=deletion.Header!;
        if(deletion.SqlExpectedSha256 is not null){
            bool expected,original;
            if(deletion.SqlCommitted){var bytes=JsonSerializer.Serialize(await ReadDetached(db,h,ct),Rows);expected=bytes==deletion.ClaimWorkJson;original=bytes==deletion.Lease!.BeforeWorkJson;}
            else{var actual=await Capture(db,recordId,ct);var currentContent=ProductionRecordOperationAdmission.ContentDigest(actual,keys);
                expected=actual.StateSha256==deletion.SqlStateSha256&&currentContent==deletion.ContentSha256;
                original=actual.StateSha256==deletion.ClaimBeforeSqlSha256&&currentContent==deletion.ClaimBeforeContentSha256;
                if(expected)await DemandSql(db,state,ct);}
            if(!expected&&!original||(await witness.ReadAsync(recordId,ct)).HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
            await tx.RollbackAsync(ct);await tx.DisposeAsync();
            if(!expected){
                await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.ClaimNoEffect,deletionId,
                    SqlStateSha256:deletion.ClaimBeforeSqlSha256,ContentSha256:deletion.ClaimBeforeContentSha256),"claim/"+deletion.Lease!.Attempt+"/no-effect",ct);
                return new(null,deletion.Lease.Until,false);
            }
            state=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.ClaimAccepted,deletionId,
                SqlStateSha256:deletion.SqlStateSha256,ContentSha256:deletion.ContentSha256),"claim/"+deletion.Lease!.Attempt+"/ack",ct);
            deletion=state.Deletion!;
            if(deletion.Lease!.Until<=time.GetUtcNow())throw ProductionDeletionProtocol.Invalid();
            return new(new(h.WorkId,deletion.Lease.Owner,WorkKind.ProductionPurge,deletion.Lease.Attempt,deletion.Lease.Until),null,false);
        }
        if(deletion.ClaimRolledBack&&deletion.Lease!.Until>time.GetUtcNow())return new(null,deletion.Lease.Until,false);
        if(deletion.Lease!.Until<=time.GetUtcNow()){
            if(!deletion.ClaimAccepted&&!deletion.ClaimRolledBack||deletion.SqlReserved||deletion.FinishedWorkJson is not null)throw ProductionDeletionProtocol.Invalid();
            string before;
            if(deletion.SqlCommitted){
                before=JsonSerializer.Serialize(await ReadDetached(db,h,ct),Rows);
                if(before!=(deletion.ClaimWorkJson??deletion.SqlExpectedWorkJson))throw ProductionDeletionProtocol.Invalid();
            }else{var actual=await Capture(db,recordId,ct);
                if(actual.StateSha256!=deletion.SqlStateSha256||ProductionRecordOperationAdmission.ContentDigest(actual,keys)!=deletion.ContentSha256||
                    (await witness.ReadAsync(recordId,ct)).HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
                if(!deletion.ClaimRolledBack)ProductionDeletionProtocol.DemandClaim(deletion,actual,keys);
                before=ProductionDeletionProtocol.WorkRow(actual,keys,id).GetRawText();}
            var now=time.GetUtcNow();var next=new ProductionDeletionMaintenanceLease(Guid.NewGuid(),checked(deletion.Lease.Attempt+1),now.AddSeconds(workOptions.LeaseSeconds),before,deletion.SqlCommitted);
            await witness.DemandDeletionHeadroomAsync(recordId,0,0,ct);
            state=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.RecoveryReserved,deletionId,
                Body:JsonSerializer.Serialize(next,ProductionDeletionProtocol.Json),SqlStateSha256:deletion.SqlStateSha256,ContentSha256:deletion.ContentSha256),"lease/"+next.Attempt,ct);
            deletion=state.Deletion!;
        }
        var live=deletion.Lease!;
        if(deletion.ClaimAccepted&&!live.StorageOnly){
            if(deletion.SqlCommitted){if(JsonSerializer.Serialize(await ReadDetached(db,h,ct),Rows)!=(deletion.ClaimWorkJson??deletion.SqlExpectedWorkJson))throw ProductionDeletionProtocol.Invalid();}
            else await DemandSql(db,state,ct);
            await tx.RollbackAsync(ct);return new(new(h.WorkId,live.Owner,WorkKind.ProductionPurge,live.Attempt,live.Until),null,false);
        }
        if(live.Until<=time.GetUtcNow())throw ProductionDeletionProtocol.Invalid();
        if(deletion.SqlCommitted){if(JsonSerializer.Serialize(row,Rows)!=live.BeforeWorkJson)throw ProductionDeletionProtocol.Invalid();}
        else{var before=await Capture(db,recordId,ct);if(before.StateSha256!=deletion.SqlStateSha256||ProductionRecordOperationAdmission.ContentDigest(before,keys)!=deletion.ContentSha256)throw ProductionDeletionProtocol.Invalid();}
        row.Status=WorkStatus.Leased;row.Attempts=live.Attempt;row.LeaseOwner=live.Owner;row.LeaseExpiresAt=live.Until;await db.SaveChangesAsync(ct);
        string body,sqlHash,content;
        if(deletion.SqlCommitted){
            body=JsonSerializer.Serialize(await ReadDetached(db,h,ct),Rows);using var parsed=JsonDocument.Parse(body);ProductionDeletionProtocol.DemandClaimRow(h,live,parsed.RootElement);
            sqlHash=ProductionDeletionProtocol.Digest(body);content=deletion.ContentSha256!;
        }else{
            var after=await Capture(db,recordId,ct);ProductionDeletionProtocol.DemandClaim(deletion,after,keys);
            body=ProductionDeletionProtocol.WorkRow(after,keys,id).GetRawText();sqlHash=after.StateSha256;content=ProductionRecordOperationAdmission.ContentDigest(after,keys);
        }
        state=await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.ClaimExpected,deletionId,
            Body:body,SqlStateSha256:sqlHash,ContentSha256:content),"claim/"+live.Attempt+"/expected",ct);
        if(live.Until<=time.GetUtcNow())throw ProductionDeletionProtocol.Invalid();await tx.CommitAsync(ct);await tx.DisposeAsync();
        await using(var verify=open()){
            await using var read=await verify.Database.BeginTransactionAsync(ct);
            if(deletion.SqlCommitted){if(JsonSerializer.Serialize(await ReadDetached(verify,h,ct),Rows)!=body)throw ProductionDeletionProtocol.Invalid();}
            else await DemandSql(verify,state,ct);
            if((await witness.ReadAsync(recordId,ct)).HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
        }
        await Event(recordId,new(ProductionDeletionProtocol.Version,ProductionDeletionKind.ClaimAccepted,deletionId,
            SqlStateSha256:sqlHash,ContentSha256:content),"claim/"+live.Attempt+"/ack",ct);
        return new(new(h.WorkId,live.Owner,WorkKind.ProductionPurge,live.Attempt,live.Until),null,false);
    }

    private async Task<ProductionRecordRetentionRead> Eligibility(QuillSignDbContext db,Guid record,CancellationToken ct)
    {
        var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==record,ct);var retained=await ProductionRecordRetentionAccess.ReadLockedAsync(db,e,time,ct);
        if(retained.Kind!=ProductionEnrollmentKind.Enrolled||retained.Stage is ProductionRecordStage.Signing or ProductionRecordStage.Completing||
            retained.Deadline is not{} deadline||deadline>time.GetUtcNow())throw ProductionDeletionProtocol.Invalid();
        return retained;
    }
    private static void DemandPrepared(WorkItem row,Guid record,Guid deletion)
    {if(row.Id!=WorkId(record,deletion)||row.EnvelopeId!=record&&row.EnvelopeId is not null||row.Kind!=WorkKind.ProductionPurge||
        row.PayloadJson!=ProductionDeletionProtocol.Payload(record,deletion)||row.Attempts<0)throw ProductionDeletionProtocol.Invalid();}
    private static (Guid RecordId,Guid DeletionId) ReadPayload(string raw)
    {
        if(raw.Length>256)throw ProductionDeletionProtocol.Invalid();using var d=JsonDocument.Parse(raw);var r=d.RootElement.GetProperty("RecordId").GetGuid();var id=d.RootElement.GetProperty("DeletionId").GetGuid();
        if(r==Guid.Empty||id!=DeletionId(r)||raw!=ProductionDeletionProtocol.Payload(r,id))throw ProductionDeletionProtocol.Invalid();return(r,id);
    }
    private async Task<ProductionHoldSqlSnapshot> Capture(QuillSignDbContext db,Guid record,CancellationToken ct)
    {var requests=await new ProductionHoldRequests(db,keys,time).ReadLockedAsync(record,ct);return await new ProductionHoldSqlInventory(db,keys,time).CaptureAcknowledgementLockedAsync(record,requests.Revision,requests.FenceHash,ct:ct);}
    private async Task DemandSql(QuillSignDbContext db,HoldWitnessState state,CancellationToken ct)
    {
        var d=state.Deletion??throw ProductionDeletionProtocol.Invalid();var h=d.Header??throw ProductionDeletionProtocol.Invalid();
        var actual=await Capture(db,h.RecordId,ct);
        if(actual.StateSha256!=d.SqlStateSha256||ProductionRecordOperationAdmission.ContentDigest(actual,keys)!=d.ContentSha256||actual.Control!=h.Control)throw ProductionDeletionProtocol.Invalid();
        ProductionDeletionProtocol.DemandClaim(d,actual,keys);
        if((await witness.ReadAsync(h.RecordId,ct)).HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
    }
    private ProductionDeletionCompletedFacts CompletedFacts(ProductionHoldSqlSnapshot sql,HoldWitnessState state)
    {
        using var doc=ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql,keys);
        var tables=doc.RootElement.GetProperty("Tables").EnumerateArray().ToDictionary(x=>x.GetProperty("Table").GetString()!,x=>x.GetProperty("Rows"));
        var e=tables["Envelopes"].EnumerateArray().Single();var result=tables["CompletionPublicationResults"].EnumerateArray().Single();
        if(e.GetProperty("Status").GetString()!="Completed"||result.GetProperty("EnvelopeId").GetGuid()!=sql.RecordId)throw ProductionDeletionProtocol.Invalid();
        var executed=Guid.ParseExact(e.GetProperty("FinalBlob").GetString()!,"N");var certificate=Guid.ParseExact(e.GetProperty("CertificateBlob").GetString()!,"N");
        var finals=(state.Completions??throw ProductionDeletionProtocol.Invalid()).Values
            .SelectMany(x=>x.Slots?.Values??[]).SelectMany(x=>x.Receipts.Values).Where(x=>x.Final is not null).Select(x=>x.Final!)
            .Where(x=>x.Document.EnvelopeId==sql.RecordId&&(x.Document.ObjectId==executed||x.Document.ObjectId==certificate)).ToArray();
        if(finals.Length!=2||finals.Select(x=>x.Document.Kind).Distinct().Count()!=2||
            !finals.Single(x=>x.Document.Kind==FinalDocumentKind.Executed).Sha256.AsSpan().SequenceEqual(e.GetProperty("FinalSha256").GetBytesFromBase64())||
            !finals.Single(x=>x.Document.Kind==FinalDocumentKind.Certificate).Sha256.AsSpan().SequenceEqual(e.GetProperty("CertificateSha256").GetBytesFromBase64()))throw ProductionDeletionProtocol.Invalid();
        return new(result.GetProperty("Id").GetGuid(),ProductionDeletionProtocol.Digest(result),
            ProductionDeletionProtocol.Digest(finals.OrderBy(x=>x.Document.Kind).ToArray()));
    }
}

internal sealed partial class ProductionHoldCoordinator
{
    internal async Task<ProductionDeletionStatus> ReadRecordedDeletionStatusAsync(Guid recordId,CancellationToken ct=default)
        =>ProductionDeletionCoordinator.RecordedStatus(recordId,await witness.ReadAsync(recordId,ct));
    internal async Task<ProductionHoldSqlSnapshot> VerifyDeletionBaselineLockedAsync(QuillSignDbContext db,Guid recordId,HoldWitnessState state,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges()||state.Deletion?.Reserved==true||state.Frozen)throw ProductionDeletionProtocol.Invalid();
        var requests=await Verify(db,recordId,state,ct);
        var sql=await new ProductionHoldSqlInventory(db,keys,time).CaptureAcknowledgementLockedAsync(recordId,requests.Revision,requests.FenceHash,ct:ct);
        if(sql.StateSha256!=state.SqlStateSha256||ProductionRecordOperationAdmission.ContentDigest(sql,keys)!=state.BusinessStateSha256||
            (await witness.ReadAsync(recordId,ct)).HeadHash!=state.HeadHash)throw ProductionDeletionProtocol.Invalid();
        return sql;
    }
}

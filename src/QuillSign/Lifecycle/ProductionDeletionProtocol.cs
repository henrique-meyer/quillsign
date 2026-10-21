using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal enum ProductionDeletionKind { DispositionAuthorized, Reserved, ClaimExpected, ClaimAccepted, PlanChunk, PlanFrozen, ItemIntent, ItemRecorded, StorageVerified, SqlExpected, SqlCommitted, Terminal, RecoveryReserved, SqlReserved, SqlNoEffect, WorkFinishExpected, WorkFinished, ClaimNoEffect, WorkFinishNoEffect }
internal sealed record ProductionDeletionMaintenanceLease(Guid Owner,int Attempt,DateTimeOffset Until,string BeforeWorkJson,bool Detached,bool StorageOnly=false);
internal sealed record ProductionDeletionDisposition(Guid AuthorizationId,Guid RecordId,string PolicySha256,Guid PublicationId,
    string PublicationSha256,string FinalReceiptsSha256,string ReviewedHead,string Commitment,string Issuer,string Subject,
    DateTimeOffset At,DateTimeOffset ExpiresAt,string Purpose,string SessionId,DateTimeOffset IssuedAt,DateTimeOffset ReviewedAt);
internal sealed record ProductionDeletionHeader(Guid RecordId,Guid DeletionId,Guid WorkId,Guid Owner,int Attempt,DateTimeOffset Until,
    DateTimeOffset ReservedAt,DateTimeOffset EligibleAt,string PolicySha256,string ParentRowVersion,string OriginalWorkJson,
    string SqlStateSha256,string ContentSha256,long RequestRevision,string? FenceHash,ProductionHoldControlPrefix Control,
    string[] ArchivePrefixes,string? DispositionSha256,string RemainderSha256);
internal sealed record ProductionDeletionTransition(string Version,ProductionDeletionKind Kind,Guid DeletionId,
    ProductionDeletionHeader? Header=null,ProductionDeletionDisposition? Disposition=null,string? Body=null,int? Index=null,int? Count=null,
    string? Sha256=null,string? SqlStateSha256=null,string? ContentSha256=null,ProductionDeletionPhase? Phase=null);
internal sealed record ProductionDeletionItemState(ProductionDeletionInspection Inspection,ProductionDeletionPhase Phase,
    ProductionDeletionResult? Result,long IntentSequence);
internal sealed record ProductionDeletionPlan(int StartIndex,ProductionDeletionInspection[] Items,ProductionDeletionObject[]? Inactive=null);
internal sealed record HoldWitnessDeletionState(ProductionDeletionDisposition? Disposition=null,long DispositionSequence=0,
    ProductionDeletionHeader? Header=null,string? SqlStateSha256=null,string? ContentSha256=null,bool ClaimAccepted=false,
    string[]? Chunks=null,int? ChunkCount=null,string? PlanSha256=null,ProductionDeletionInspection[]? Items=null,
    IReadOnlyDictionary<string,ProductionDeletionItemState>? Effects=null,string? StorageReceiptSha256=null,
    string? SqlExpectedSha256=null,bool SqlCommitted=false,bool Terminal=false,ProductionDeletionMaintenanceLease? Lease=null,
    bool SqlReserved=false,string? SqlExpectedWorkJson=null,string? FinishedWorkJson=null,bool WorkFinished=false,string? ClaimWorkJson=null,ProductionDeletionObject[]? InactiveItems=null,int SqlRound=0,string? ClaimBeforeSqlSha256=null,string? ClaimBeforeContentSha256=null,bool ClaimRolledBack=false,int FinishRound=0)
{
    internal bool Reserved=>Header is not null;
}

// A CLOSED external protocol, not arbitrary journal JSON or provider authority.
// Every event remains inside the original 64KiB/16MiB witness bounds. Large
// exact plans are canonical, bounded chunks outside all deleted namespaces.
internal static class ProductionDeletionProtocol
{
    internal const string Version="production-deletion-v1";
    internal const int MaximumObjects=4096,MaximumPlanBytes=8*1024*1024,ChunkBytes=24576;
    internal static readonly JsonSerializerOptions Json=new(){MaxDepth=24,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    internal static string Digest<T>(T value)=>Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value,Json)));
    internal static bool Hash(string? value)=>value is{Length:64}&&value.All(char.IsAsciiHexDigitLower);
    internal static string EffectKey(int index,ProductionDeletionPhase phase)=>index.ToString(System.Globalization.CultureInfo.InvariantCulture)+"/"+(int)phase;
    internal static string Payload(Guid record,Guid deletion)=>JsonSerializer.Serialize(new{Version="production-delete-work-v1",RecordId=record,DeletionId=deletion});
    internal static HoldWitnessDeletionState Apply(HoldWitnessDeletionState? prior,ProductionDeletionTransition t,long sequence,
        DateTimeOffset at,HoldWitnessState predecessor)
    {
        var s=prior??new();
        if(t.Version!=Version||!Enum.IsDefined(t.Kind)||t.DeletionId==Guid.Empty||s.Terminal&&t.Kind is not(ProductionDeletionKind.WorkFinishExpected or ProductionDeletionKind.WorkFinished or ProductionDeletionKind.RecoveryReserved or ProductionDeletionKind.ClaimExpected or ProductionDeletionKind.ClaimAccepted or ProductionDeletionKind.ClaimNoEffect or ProductionDeletionKind.WorkFinishNoEffect))throw Invalid();
        ProductionDeletionTransition canonical=new(Version,t.Kind,t.DeletionId);
        if(t.Kind==ProductionDeletionKind.DispositionAuthorized){
            var d=t.Disposition??throw Invalid();
            if(s.Reserved||d.AuthorizationId!=t.DeletionId||d.RecordId==Guid.Empty||!Hash(d.PolicySha256)||d.PublicationId==Guid.Empty||
                !Hash(d.PublicationSha256)||!Hash(d.FinalReceiptsSha256)||d.ReviewedHead!=predecessor.HeadHash||
                !ProductionOperatorAuthority.Text(d.Commitment,2048)||!ProductionOperatorAuthority.Text(d.Issuer,2048)||
                !ProductionOperatorAuthority.Text(d.Subject,256)||!ProductionOperatorAuthority.Text(d.Purpose,256)||!Id(d.SessionId)||
                d.IssuedAt.Offset!=TimeSpan.Zero||d.ReviewedAt.Offset!=TimeSpan.Zero||d.IssuedAt>d.ReviewedAt||d.ReviewedAt>d.At||d.ExpiresAt>d.ReviewedAt.AddMinutes(2)||
                d.ExpiresAt-d.IssuedAt>ProductionOperatorAuthority.MaximumSession||d.At.Offset!=TimeSpan.Zero||d.At>at||d.ExpiresAt.Offset!=TimeSpan.Zero||d.ExpiresAt<=at||
                d.ExpiresAt-d.At>ProductionOperatorAuthority.MaximumSession||predecessor.Frozen)throw Invalid();
            s=s with{Disposition=d,DispositionSequence=sequence};canonical=canonical with{Disposition=d};
        }else if(t.Kind==ProductionDeletionKind.Reserved){
            var h=t.Header??throw Invalid();
            if(s.Reserved||!predecessor.Initialized||predecessor.Frozen||h.RecordId==Guid.Empty||h.DeletionId!=t.DeletionId||
                h.WorkId==Guid.Empty||h.Owner==Guid.Empty||h.Attempt<1||h.Until.Offset!=TimeSpan.Zero||h.Until<=at||h.Until-at>TimeSpan.FromHours(1)||
                h.ReservedAt.Offset!=TimeSpan.Zero||h.ReservedAt>at||h.EligibleAt.Offset!=TimeSpan.Zero||h.EligibleAt>h.ReservedAt||!Hash(h.PolicySha256)||
                !Hash(h.SqlStateSha256)||!Hash(h.ContentSha256)||!Hash(h.RemainderSha256)||h.SqlStateSha256!=predecessor.SqlStateSha256||
                h.ContentSha256!=predecessor.BusinessStateSha256||h.RequestRevision!=predecessor.RequestRevision||h.FenceHash!=predecessor.RequestFenceHash||
                h.OriginalWorkJson is not{Length:>0 and <=4096}||!RowVersion(h.ParentRowVersion)||
                h.ArchivePrefixes.Length>512||h.ArchivePrefixes.Distinct(StringComparer.Ordinal).Count()!=h.ArchivePrefixes.Length)throw Invalid();
            ProductionHoldControls.ValidatePrefix(h.Control);
            foreach(var p in h.ArchivePrefixes){var parts=p.Split('/');if(parts.Length!=5||parts[0]!="production-holds"||parts[1]!=h.RecordId.ToString("N")||parts[4]!=""||!Id(parts[2])||!Id(parts[3]))throw Invalid();}
            if(h.DispositionSha256 is not null&&(s.Disposition is null||s.DispositionSequence!=sequence-1||
                h.DispositionSha256!=Digest(s.Disposition)||s.Disposition.RecordId!=h.RecordId||s.Disposition.PolicySha256!=h.PolicySha256||s.Disposition.ExpiresAt<=at))throw Invalid();
            s=s with{Header=h,SqlStateSha256=h.SqlStateSha256,ContentSha256=h.ContentSha256,Effects=new Dictionary<string,ProductionDeletionItemState>(),
                Lease=new(h.Owner,h.Attempt,h.Until,h.OriginalWorkJson,false)};canonical=canonical with{Header=h};
        }else{
            var h=s.Header??throw Invalid();if(h.DeletionId!=t.DeletionId)throw Invalid();
            switch(t.Kind){
                case ProductionDeletionKind.RecoveryReserved:
                    var lease=Read<ProductionDeletionMaintenanceLease>(t.Body??throw Invalid());
                    if(s.Lease is not{} oldLease||oldLease.Until>at||lease.Owner==Guid.Empty||lease.Owner==oldLease.Owner||oldLease.Attempt==int.MaxValue||
                        lease.Attempt!=oldLease.Attempt+1||lease.Until.Offset!=TimeSpan.Zero||lease.Until<=at||lease.Until-at>TimeSpan.FromHours(1)||
                        lease.BeforeWorkJson is not{Length:>0 and <=4096}||lease.Detached!=s.SqlCommitted||lease.StorageOnly&&!s.SqlCommitted||s.SqlReserved||s.SqlExpectedSha256 is not null||
                        s.Effects!.Values.Any(x=>x.Result is null)||t.SqlStateSha256!=s.SqlStateSha256||t.ContentSha256!=s.ContentSha256)throw Invalid();
                    s=s with{Lease=lease,ClaimAccepted=lease.StorageOnly,ClaimWorkJson=null,ClaimRolledBack=false};canonical=canonical with{Body=t.Body,SqlStateSha256=t.SqlStateSha256,ContentSha256=t.ContentSha256};break;
                case ProductionDeletionKind.ClaimExpected:
                    if(s.ClaimAccepted&&!s.Lease!.StorageOnly||s.SqlExpectedSha256 is not null||!Hash(t.SqlStateSha256)||!Hash(t.ContentSha256)||t.Body is not{Length:>0 and <=4096}||s.Lease!.Until<=at)throw Invalid();
                    s=s with{ClaimBeforeSqlSha256=s.SqlStateSha256,ClaimBeforeContentSha256=s.ContentSha256,SqlStateSha256=t.SqlStateSha256,ContentSha256=t.ContentSha256,SqlExpectedSha256=t.SqlStateSha256,ClaimWorkJson=t.Body,Lease=s.Lease with{StorageOnly=false},ClaimRolledBack=false};
                    canonical=canonical with{SqlStateSha256=t.SqlStateSha256,ContentSha256=t.ContentSha256,Body=t.Body};break;
                case ProductionDeletionKind.ClaimNoEffect:
                    if(s.ClaimAccepted||s.SqlReserved||s.SqlExpectedSha256 is null||t.SqlStateSha256!=s.ClaimBeforeSqlSha256||t.ContentSha256!=s.ClaimBeforeContentSha256)throw Invalid();
                    s=s with{SqlStateSha256=t.SqlStateSha256,ContentSha256=t.ContentSha256,SqlExpectedSha256=null,ClaimWorkJson=null,ClaimRolledBack=true};
                    canonical=canonical with{SqlStateSha256=t.SqlStateSha256,ContentSha256=t.ContentSha256};break;
                case ProductionDeletionKind.ClaimAccepted:
                    if(s.ClaimAccepted||s.SqlExpectedSha256 is null||t.SqlStateSha256!=s.SqlStateSha256||t.ContentSha256!=s.ContentSha256)throw Invalid();
                    s=s with{ClaimAccepted=true,SqlExpectedSha256=null};canonical=canonical with{SqlStateSha256=t.SqlStateSha256,ContentSha256=t.ContentSha256};break;
                case ProductionDeletionKind.PlanChunk:
                    if(!s.ClaimAccepted||s.SqlExpectedSha256 is not null||t.Index is not>=0||t.Count is not(>=1 and <=384)||t.Index>=t.Count||
                        t.Body is not{Length:>0 and <=32768}||!Hash(t.Sha256)||t.Sha256!=Digest(t.Body)||
                        t.Index!=(s.Chunks?.Length??0)||s.ChunkCount is not null&&s.ChunkCount!=t.Count)throw Invalid();
                    s=s with{Chunks=(s.Chunks??[]).Append(t.Body).ToArray(),ChunkCount=t.Count,StorageReceiptSha256=null};
                    canonical=canonical with{Index=t.Index,Count=t.Count,Body=t.Body,Sha256=t.Sha256};break;
                case ProductionDeletionKind.PlanFrozen:
                    if(!s.ClaimAccepted||s.Chunks is null||s.Chunks.Length!=s.ChunkCount||!Hash(t.Sha256))throw Invalid();
                    var bytes=s.Chunks.SelectMany(Convert.FromBase64String).ToArray();
                    if(bytes.Length>MaximumPlanBytes||Convert.ToHexStringLower(SHA256.HashData(bytes))!=t.Sha256)throw Invalid();
                    var plan=Read<ProductionDeletionPlan>(Encoding.UTF8.GetString(bytes));CryptographicOperations.ZeroMemory(bytes);
                    if(plan.StartIndex!=(s.Items?.Length??0)||plan.Items.Length==0&&plan.StartIndex!=0||plan.Items.Length+plan.StartIndex>MaximumObjects)throw Invalid();
                    var all=(s.Items??[]).Concat(plan.Items).ToArray();
                    if(all.Select(x=>Identity(x.Item)).Distinct(StringComparer.Ordinal).Count()!=all.Length||all.Sum(x=>x.Item.Length)>256L*1024*1024)throw Invalid();
                    foreach(var i in plan.Items)DemandItem(h,i);
                    var inactive=(s.InactiveItems??[]).Concat(plan.Inactive??[]).ToArray();
                    if(inactive.Length+all.Length>MaximumObjects||inactive.Select(Identity).Concat(all.Select(x=>Identity(x.Item))).Distinct(StringComparer.Ordinal).Count()!=inactive.Length+all.Length)throw Invalid();
                    foreach(var i in inactive){if(!(i.Deleted||i.HasVersionsOnly)||i.Length is<0 or>64*1024*1024||
                        !ProductionDeletionObjectScope.Areas.Contains(i.Area,StringComparer.Ordinal)||!i.Name.StartsWith(h.RecordId.ToString("N")+"/",StringComparison.Ordinal)&&
                        !(i.Area=="final"&&h.ArchivePrefixes.Any(p=>i.Name.StartsWith(p,StringComparison.Ordinal))))throw Invalid();}
                    if(inactive.Sum(x=>x.Length)+all.Sum(x=>x.Item.Length)>256L*1024*1024)throw Invalid();
                    s=s with{Items=all,InactiveItems=inactive,Chunks=null,ChunkCount=null,PlanSha256=Digest(new{s.PlanSha256,ChunkSha256=t.Sha256}),StorageReceiptSha256=null};canonical=canonical with{Sha256=t.Sha256};break;
                case ProductionDeletionKind.ItemIntent:
                    if(!s.ClaimAccepted||s.Lease!.Until<=at||s.Chunks is not null||t.Index is not>=0||t.Index>=s.Items?.Length||t.Phase is not{} phase||!Enum.IsDefined(phase))throw Invalid();
                    var inspection=s.Items![t.Index.Value];if(t.Sha256!=Digest(inspection))throw Invalid();
                    var effect=EffectKey(t.Index.Value,phase);var effects=new Dictionary<string,ProductionDeletionItemState>(s.Effects!);
                    if(effects.ContainsKey(effect)||phase==ProductionDeletionPhase.RootDemotion&&(!inspection.Item.IsCurrent||inspection.Item.VersionId.Length==0))throw Invalid();
                    if(phase==ProductionDeletionPhase.HistoricalDelete&&inspection.Item.IsCurrent&&inspection.Item.VersionId.Length>0&&
                        (!effects.TryGetValue(EffectKey(t.Index.Value,ProductionDeletionPhase.RootDemotion),out var root)||root.Result?.RootAbsent!=true))throw Invalid();
                    effects.Add(effect,new(inspection,phase,null,sequence));s=s with{Effects=effects,StorageReceiptSha256=null};canonical=canonical with{Index=t.Index,Phase=phase,Sha256=t.Sha256};break;
                case ProductionDeletionKind.ItemRecorded:
                    if(t.Index is not>=0||t.Index>=s.Items?.Length||t.Phase is not{} recordedPhase||t.Body is null)throw Invalid();
                    var key=EffectKey(t.Index.Value,recordedPhase);if(!s.Effects!.TryGetValue(key,out var started)||started.Result is not null)throw Invalid();
                    var result=Read<ProductionDeletionResult>(t.Body);
                    if(result.Item!=started.Inspection.Item||result.Phase!=recordedPhase||recordedPhase==ProductionDeletionPhase.RootDemotion&&!result.RootAbsent||
                        recordedPhase==ProductionDeletionPhase.HistoricalDelete&&!result.Absent||t.Sha256!=Digest(result))throw Invalid();
                    var recorded=new Dictionary<string,ProductionDeletionItemState>(s.Effects){[key]=started with{Result=result}};
                    s=s with{Effects=recorded};canonical=canonical with{Index=t.Index,Phase=recordedPhase,Body=t.Body,Sha256=t.Sha256};break;
                case ProductionDeletionKind.StorageVerified:
                    if(s.PlanSha256 is null||s.Chunks is not null||s.Items is null||!Hash(t.Sha256)||
                        s.Items.Where((_,i)=>!s.Effects!.TryGetValue(EffectKey(i,ProductionDeletionPhase.HistoricalDelete),out var done)||done.Result?.Absent!=true).Any())throw Invalid();
                    s=s with{StorageReceiptSha256=t.Sha256};canonical=canonical with{Sha256=t.Sha256};break;
                case ProductionDeletionKind.SqlExpected:
                    if(s.SqlCommitted||!s.SqlReserved||s.Lease!.Until<=at||s.StorageReceiptSha256 is null||s.SqlExpectedSha256 is not null||!Hash(t.Sha256)||
                        t.Body is not{Length:>0 and <=4096}||Digest(t.Body)!=t.Sha256)throw Invalid();
                    s=s with{SqlExpectedSha256=t.Sha256,SqlExpectedWorkJson=t.Body};canonical=canonical with{Sha256=t.Sha256,Body=t.Body};break;
                case ProductionDeletionKind.SqlReserved:
                    if(s.SqlCommitted||s.SqlReserved||s.StorageReceiptSha256 is null||!s.ClaimAccepted||s.Lease!.Until<=at||t.Sha256!=s.StorageReceiptSha256)throw Invalid();
                    s=s with{SqlReserved=true,SqlRound=checked(s.SqlRound+1)};canonical=canonical with{Sha256=t.Sha256};break;
                case ProductionDeletionKind.SqlNoEffect:
                    if(s.SqlCommitted||!s.SqlReserved||t.SqlStateSha256!=s.SqlStateSha256||t.ContentSha256!=s.ContentSha256)throw Invalid();
                    s=s with{SqlReserved=false,SqlExpectedSha256=null,SqlExpectedWorkJson=null};canonical=canonical with{SqlStateSha256=t.SqlStateSha256,ContentSha256=t.ContentSha256};break;
                case ProductionDeletionKind.SqlCommitted:
                    if(s.SqlCommitted||s.SqlExpectedSha256 is null||t.Sha256!=s.SqlExpectedSha256)throw Invalid();
                    s=s with{SqlCommitted=true,SqlReserved=false,SqlExpectedSha256=null,ClaimWorkJson=s.SqlExpectedWorkJson};canonical=canonical with{Sha256=t.Sha256};break;
                case ProductionDeletionKind.Terminal:
                    if(!s.SqlCommitted||s.StorageReceiptSha256 is null||s.Chunks is not null||!Hash(t.Sha256))throw Invalid();
                    s=s with{Terminal=true};canonical=canonical with{Sha256=t.Sha256};break;
                case ProductionDeletionKind.WorkFinishExpected:
                    if(!s.Terminal||s.WorkFinished||s.FinishedWorkJson is not null||s.Lease!.Until<=at||t.Body is not{Length:>0 and <=4096}||t.Sha256!=Digest(t.Body))throw Invalid();
                    s=s with{FinishedWorkJson=t.Body,FinishRound=checked(s.FinishRound+1)};canonical=canonical with{Sha256=t.Sha256,Body=t.Body};break;
                case ProductionDeletionKind.WorkFinishNoEffect:
                    if(!s.Terminal||s.WorkFinished||s.FinishedWorkJson is null||t.Sha256!=Digest(s.ClaimWorkJson??s.SqlExpectedWorkJson??throw Invalid()))throw Invalid();
                    s=s with{FinishedWorkJson=null};canonical=canonical with{Sha256=t.Sha256};break;
                case ProductionDeletionKind.WorkFinished:
                    if(!s.Terminal||s.WorkFinished||s.FinishedWorkJson is null||t.Sha256!=Digest(s.FinishedWorkJson))throw Invalid();
                    s=s with{WorkFinished=true};canonical=canonical with{Sha256=t.Sha256};break;
                default:throw Invalid();
            }
        }
        if(JsonSerializer.Serialize(canonical,Json)!=JsonSerializer.Serialize(t,Json))throw Invalid();return s;
    }
    internal static T Read<T>(string json) where T:class
    {if(Encoding.UTF8.GetByteCount(json)>MaximumPlanBytes)throw Invalid();var value=JsonSerializer.Deserialize<T>(json,Json)??throw Invalid();if(JsonSerializer.Serialize(value,Json)!=json)throw Invalid();return value;}
    internal static string Identity(ProductionDeletionObject i)=>i.Area+"/"+i.Name+"?version="+i.VersionId+"&snapshot="+i.Snapshot;
    internal static JsonElement WorkRow(ProductionHoldSqlSnapshot sql,IDataProtectionProvider keys,Guid workId)
    {
        using var opened=ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql,keys);
        return opened.RootElement.GetProperty("Tables").EnumerateArray().Single(x=>x.GetProperty("Table").GetString()=="WorkItems")
            .GetProperty("Rows").EnumerateArray().Single(x=>x.GetProperty("Id").GetGuid()==workId).Clone();
    }
    internal static string Remainder(ProductionHoldSqlSnapshot sql,IDataProtectionProvider keys,Guid workId)
    {
        using var opened=ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql,keys);var root=opened.RootElement;
        return Digest(new{Version="production-deletion-claim-remainder-v1",sql.RecordId,PolicySha256=root.GetProperty("PolicySha256"),sql.Control,
            Tables=root.GetProperty("Tables").EnumerateArray().Select(t=>new{Table=t.GetProperty("Table"),Columns=t.GetProperty("Columns"),
                Rows=t.GetProperty("Rows").EnumerateArray().Where(r=>t.GetProperty("Table").GetString()!="WorkItems"||r.GetProperty("Id").GetGuid()!=workId).ToArray()}).ToArray()});
    }
    internal static void DemandClaim(HoldWitnessDeletionState d,ProductionHoldSqlSnapshot actual,IDataProtectionProvider keys)
    {
        var h=d.Header!;if(Remainder(actual,keys,h.WorkId)!=h.RemainderSha256)throw Invalid();
        DemandClaimRow(h,d.Lease!,WorkRow(actual,keys,h.WorkId));
    }
    internal static void DemandClaimRow(ProductionDeletionHeader h,ProductionDeletionMaintenanceLease lease,JsonElement row)
    {
        using var before=JsonDocument.Parse(lease.BeforeWorkJson);var old=before.RootElement;
        var initial=lease.Attempt==h.Attempt;
        if(old.GetProperty("Attempts").GetInt32()>=lease.Attempt||
            (initial?(old.GetProperty("Status").GetString()!="Queued"||old.GetProperty("LeaseOwner").ValueKind!=JsonValueKind.Null||old.GetProperty("LeaseExpiresAt").ValueKind!=JsonValueKind.Null):
                !(old.GetProperty("Status").GetString()=="Queued"&&old.GetProperty("Attempts").GetInt32()==0&&lease.BeforeWorkJson==h.OriginalWorkJson)&&
                (old.GetProperty("Status").GetString()!="Leased"||old.GetProperty("LeaseExpiresAt").GetDateTimeOffset()>=lease.Until||old.GetProperty("LeaseOwner").ValueKind!=JsonValueKind.String))||
            row.GetProperty("Id").GetGuid()!=h.WorkId||
            (lease.Detached?row.GetProperty("EnvelopeId").ValueKind!=JsonValueKind.Null:row.GetProperty("EnvelopeId").GetGuid()!=h.RecordId)||
            row.GetProperty("Kind").GetString()!="ProductionPurge"||row.GetProperty("Status").GetString()!="Leased"||
            row.GetProperty("Attempts").GetInt32()!=lease.Attempt||row.GetProperty("LeaseOwner").GetGuid()!=lease.Owner||
            row.GetProperty("LeaseExpiresAt").GetDateTimeOffset()!=lease.Until||row.GetProperty("PayloadJson").GetString()!=Payload(h.RecordId,h.DeletionId)||
            !RowVersion(row.GetProperty("RowVersion").GetString()!))throw Invalid();
        var mutable=new[]{"Attempts","LeaseExpiresAt","LeaseOwner","Status","RowVersion"};
        if(!row.EnumerateObject().Select(x=>x.Name).Order(StringComparer.Ordinal).SequenceEqual(old.EnumerateObject().Select(x=>x.Name).Order(StringComparer.Ordinal))||
            old.EnumerateObject().Any(p=>!mutable.Contains(p.Name,StringComparer.Ordinal)&&p.Value.GetRawText()!=row.GetProperty(p.Name).GetRawText()))throw Invalid();
    }
    private static bool Id(string value)=>Guid.TryParseExact(value,"N",out var id)&&id!=Guid.Empty&&id.ToString("N")==value;
    private static bool RowVersion(string value){try{return Convert.FromBase64String(value) is{Length:8} bytes&&Convert.ToBase64String(bytes)==value;}catch(FormatException){return false;}}
    private static void DemandItem(ProductionDeletionHeader h,ProductionDeletionInspection i)
    {
        var x=i.Item;var ordinary=x.Name.StartsWith(h.RecordId.ToString("N")+"/",StringComparison.Ordinal);
        if(!ProductionDeletionObjectScope.Areas.Contains(x.Area,StringComparer.Ordinal)||!ordinary&&!(x.Area=="final"&&h.ArchivePrefixes.Any(p=>x.Name.StartsWith(p,StringComparison.Ordinal)))||
            x.Length is<0 or>64*1024*1024||x.Deleted||x.HasVersionsOnly||!Hash(i.Sha256)||!ProductionDeletionObjectScope.Tag(x.ETag))throw Invalid();
    }
    internal static InvalidDataException Invalid()=>new("Production deletion recovery could not be verified.");
}

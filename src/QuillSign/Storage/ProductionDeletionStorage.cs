namespace QuillSign.Storage;

internal enum ProductionDeletionPhase { RootDemotion, HistoricalDelete }
internal sealed record ProductionDeletionObject(string Area,string Name,string VersionId,string Snapshot,string ETag,
    long Length,bool IsCurrent,bool Deleted,bool HasVersionsOnly);
internal sealed record ProductionDeletionPage(IReadOnlyList<ProductionDeletionObject> Objects,string? Continuation);
internal sealed record ProductionDeletionInspection(ProductionDeletionObject Item,string Sha256,bool LegalHold,
    DateTimeOffset? ImmutableUntil,string? ImmutableMode);
internal sealed record ProductionDeletionResult(ProductionDeletionObject Item,ProductionDeletionPhase Phase,bool Absent,
    bool RootAbsent,ProductionDeletionInspection? Remaining);
internal interface IProductionDeletionStore
{
    Task<ProductionDeletionPage> ListAsync(ProductionDeletionObjectScope scope,string area,string prefix,string? continuation,int maximum,CancellationToken ct=default);
    Task<ProductionDeletionInspection> InspectAsync(ProductionDeletionObjectScope scope,ProductionDeletionObject item,CancellationToken ct=default);
    Task<ProductionDeletionResult> DeleteAsync(ProductionDeletionObjectScope scope,ProductionDeletionInspection expected,ProductionDeletionPhase phase,CancellationToken ct=default);
    Task<ProductionDeletionResult> ReadDeleteOutcomeAsync(ProductionDeletionObjectScope scope,ProductionDeletionInspection expected,ProductionDeletionPhase phase,CancellationToken ct=default);
}

// Created only by the authenticated irreversible-reservation coordinator. Neither
// a provider descriptor nor a recovery index hint can create deletion authority.
internal sealed class ProductionDeletionObjectScope
{
    internal static readonly string[] Areas=["originals","normalized","previews","final"];
    private readonly string[] archives;
    private readonly TimeProvider time;
    private readonly DateTimeOffset until;
    private readonly Func<CancellationToken,Task> authenticate;
    private long observed;
    private int closed;
    private readonly HashSet<(ProductionDeletionObject,ProductionDeletionPhase)> started=[];
    private ProductionDeletionObjectScope(Guid record,Guid deletion,string[] prefixes,TimeProvider time,DateTimeOffset until,Func<CancellationToken,Task> authenticate)
    {RecordId=record;DeletionId=deletion;archives=prefixes;this.time=time;this.until=until;this.authenticate=authenticate;observed=time.GetUtcNow().Ticks;}
    internal Guid RecordId {get;}
    internal Guid DeletionId {get;}
    internal IReadOnlyList<string> ArchivePrefixes=>Array.AsReadOnly(archives);
    internal DateTimeOffset Now=>time.GetUtcNow();
    internal static ProductionDeletionObjectScope Create(Guid recordId,Guid deletionId,IReadOnlyList<string> exactArchivePrefixes,
        TimeProvider time,DateTimeOffset until,Func<CancellationToken,Task> authenticateCurrentReservation)
    {
        ArgumentNullException.ThrowIfNull(time);ArgumentNullException.ThrowIfNull(authenticateCurrentReservation);
        if(recordId==Guid.Empty||deletionId==Guid.Empty||exactArchivePrefixes is null||exactArchivePrefixes.Count>512||until.Offset!=TimeSpan.Zero||
            time.GetUtcNow().Offset!=TimeSpan.Zero||until<=time.GetUtcNow()||until>time.GetUtcNow().AddMinutes(10))throw Invalid();
        var owned=exactArchivePrefixes.ToArray();if(owned.Distinct(StringComparer.Ordinal).Count()!=owned.Length)throw Invalid();
        foreach(var prefix in owned)
        {
            var parts=prefix?.Split('/')??[];
            if(parts.Length!=5||parts[0]!="production-holds"||parts[1]!=recordId.ToString("N")||parts[4]!=""||
                !CanonicalId(parts[2])||!CanonicalId(parts[3]))throw Invalid();
        }
        return new(recordId,deletionId,owned,time,until,authenticateCurrentReservation);
    }
    internal void Close()=>Interlocked.Exchange(ref closed,1);
    internal async Task DemandAsync(CancellationToken ct=default)
    {DemandTime(ct);await authenticate(ct);DemandTime(ct);}
    private void DemandTime(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();var now=time.GetUtcNow();var prior=Interlocked.Read(ref observed);
        if(Volatile.Read(ref closed)!=0||now.Offset!=TimeSpan.Zero||now>=until||now.Ticks<prior)throw new UnauthorizedAccessException("The production deletion scope is unavailable.");
        while(now.Ticks>prior){var seen=Interlocked.CompareExchange(ref observed,now.Ticks,prior);if(seen==prior)break;prior=seen;if(now.Ticks<prior)throw Invalid();}
    }
    internal void DemandPrefix(string area,string prefix)
    {
        if(!Areas.Contains(area,StringComparer.Ordinal)||prefix!=$"{RecordId:N}/"&&
            !(area=="final"&&archives.Contains(prefix,StringComparer.Ordinal)))throw Invalid();
    }
    internal void DemandItem(ProductionDeletionObject item)
    {
        if(item is null||!Areas.Contains(item.Area,StringComparer.Ordinal)||item.Name is not {Length:>0 and <=1024})throw Invalid();
        var prefix=item.Name.StartsWith($"{RecordId:N}/",StringComparison.Ordinal)?$"{RecordId:N}/":
            item.Area=="final"?archives.SingleOrDefault(p=>item.Name.StartsWith(p,StringComparison.Ordinal)):null;
        if(prefix is null||item.Name.Length<=prefix.Length||item.Name[prefix.Length..].Split('/').Any(x=>x.Length==0||x.Any(c=>c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-')))||
            !Opaque(item.VersionId,true)||!Opaque(item.Snapshot,true)||item.VersionId.Length>0&&item.Snapshot.Length>0||item.Length is <0 or >64*1024*1024||
            !(item.Deleted||item.HasVersionsOnly)&&!Tag(item.ETag)||item.IsCurrent&&item.Snapshot.Length>0)throw Invalid();
    }
    internal void BeginMutation(ProductionDeletionObject item,ProductionDeletionPhase phase)
    {lock(started)if(!started.Add((item,phase)))throw new InvalidDataException("A deletion attempt must be reconciled without replaying its provider request.");}
    private static bool CanonicalId(string value)=>Guid.TryParseExact(value,"N",out var id)&&id!=Guid.Empty&&value==id.ToString("N");
    internal static bool Tag(string value)=>value is {Length:>=3 and <=256}&&value[0]=='"'&&value[^1]=='"'&&value[1..^1].All(c=>c is >' ' and <'~'&&c!='"');
    private static bool Opaque(string value,bool empty)=>value is not null&&value.Length<=256&&(empty||value.Length>0)&&value.All(c=>c is >=' ' and <='~')&&value!="*";
    internal static InvalidDataException Invalid()=>new("The exact production deletion object scope could not be verified.");
}

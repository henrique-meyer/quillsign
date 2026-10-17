namespace QuillSign.Storage;

public sealed record PurgeStorageCursor(Guid EnvelopeId,string PolicySha256,int Area,string? Continuation);
// ReachedEnd describes one observed pass only. Late writes and SQL removal need a durable coordinator.
public sealed record PurgeStorageBatch(int Examined,int Deleted,int Missing,int Protected,int Changed,bool ReachedEnd,PurgeStorageCursor? Next);
public interface IEnvelopePurgeStore
{
    Task<PurgeStorageBatch> SweepAsync(DemoPurgeAuthority authority,int maximumObjects,PurgeStorageCursor? cursor=null,CancellationToken ct=default);
}

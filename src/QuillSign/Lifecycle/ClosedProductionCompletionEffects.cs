using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Sealing;
namespace QuillSign.Lifecycle;
internal sealed class ClosedProductionCompletionEffects:IProductionCompletionEffects
{
    private static UnauthorizedAccessException Closed()=>new("Production completion protection is unavailable.");
    public Task<CompletionOwnedRowPlan> CandidateLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionCandidate row,PreparedCompletionPacket packet,CancellationToken ct)=>throw Closed();
    public Task<CompletionOwnedSeal> SealLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionCandidateData candidate,CompletionSealKind kind,CompletionSealTargets targets,byte[] source,CompletionSealData? executed,CancellationToken ct)=>throw Closed();
    public Task<CompletionOwnedRowPlan> IntentLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionPublicationIntent row,CancellationToken ct)=>throw Closed();
    public Task<CompletionPublicationFiles> PublicationLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionPublicationIntent intent,CompletionSealPair pair,DateTimeOffset recordedAt,DateTimeOffset? until,CancellationToken ct)=>throw Closed();
    public Task<CompletionOwnedRowPlan> ResultLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionPublicationTransition transition,CancellationToken ct)=>throw Closed();
}

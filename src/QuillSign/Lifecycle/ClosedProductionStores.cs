using System.Security.Claims;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// Inert typed dependencies keep the production barriers installed after disable.
// They cannot construct a transport or turn an absent provider into absence proof.
internal sealed class ClosedProductionStores:IProductionHoldWitnessStore,IProductionRecordUploadStore,IProductionRecordSendStore,
    IProductionSignaturePreviewStore,IProductionSignerReviewStore,IProductionCompletionObjectStore
{
    private static UnauthorizedAccessException Closed()=>new("Production record protection is unavailable.");
    public Task<IReadOnlyList<ProductionHoldWitnessObject>> ReadAsync(Guid recordId,CancellationToken ct=default)=>throw Closed();
    public Task<ProductionHoldWitnessObject> CreateAsync(ProductionHoldWitnessWrite write,CancellationToken ct=default)=>throw Closed();
    public Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope,ClaimsPrincipal sender,ProductionRecordWriteDescriptor item,Stream source,bool mayWrite,ProductionRecordWriteReceipt? saved,Func<CancellationToken,Task> demand,CancellationToken ct=default)=>throw Closed();
    public Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope,VerifiedSigner identity,ProductionRecordWriteDescriptor item,Stream source,bool mayWrite,ProductionRecordWriteReceipt? saved,Func<CancellationToken,Task> demand,CancellationToken ct=default)=>throw Closed();
    public Task<ProductionCompletionStored> WriteAsync(ProductionCompletionStoragePlan plan,IProductionCompletionStorageFence fence,CancellationToken ct=default)=>throw Closed();
    public Task<byte[]> ReadInputAsync(ProductionCompletionStoragePlan plan,ProductionCompletionStored stored,IProductionCompletionStorageFence fence,CancellationToken ct=default)=>throw Closed();
    public Task<ProductionCompletionStored> RecoverAsync(ProductionCompletionStoragePlan plan,IProductionCompletionStorageFence fence,ProductionCompletionStored? saved=null,CancellationToken ct=default)=>throw Closed();
}

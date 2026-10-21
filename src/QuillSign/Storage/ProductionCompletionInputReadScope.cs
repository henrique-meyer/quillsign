using System.Security.Claims;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Storage;

// No claims, cookie or ordinary document principal can recreate this exact
// internal target permission. Dynamic operation checks remain at every I/O.
internal sealed class CompletionInputCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity = new([], "QuillSign.InternalCompletionInput");
    private readonly DocumentBlob target;
    private readonly AssetOperation operation;
    private readonly DateTimeOffset expires;
    private readonly DateTimeOffset issued;
    private readonly TimeProvider time;
    private CompletionInputCapability(DocumentBlob target, AssetOperation operation, DateTimeOffset expires, TimeProvider time)
    { this.target = target; this.operation = operation; this.expires = expires; this.time = time; issued = time.GetUtcNow(); AddIdentity(identity); }
    internal static CompletionInputCapability Create(ProductionCompletionInput input, AssetOperation operation, TimeProvider time)
    {
        if (input.Descriptor.Blob.Kind != DocumentBlobKind.CompletionInput || operation is not (AssetOperation.Read or AssetOperation.Write)) throw Invalid();
        var now = time.GetUtcNow(); var until = input.Verified.Context.Until;
        if (until <= now || until.Offset != TimeSpan.Zero) throw Invalid();
        return new(input.Descriptor.Blob, operation, until, time);
    }
    internal void Demand(DocumentBlob blob, AssetOperation requested)
    {
        var all = Identities.ToArray();
        if (all.Length != 1 || !ReferenceEquals(all[0], identity) || !identity.IsAuthenticated || target != blob ||
            requested != operation || requested == AssetOperation.Delete || time.GetUtcNow() < issued || time.GetUtcNow() >= expires) throw Invalid();
    }
    private static UnauthorizedAccessException Invalid() => new("The exact internal completion input capability is invalid.");
}

internal interface IProductionCompletionInputSource
{
    Task<byte[]> ReadAsync(ProductionCompletionInputReadScope scope, CancellationToken ct = default);
}

// Mint from current authenticated hold inventory, not the historical worker's
// clock. The historical body remains evidence and creates no renewed authority.
internal sealed class ProductionCompletionInputReadScope
{
    private readonly ProductionHoldObjectScope current;
    private int closed;
    internal HoldObjectAddress Address { get; }
    internal string Sha256 { get; }
    private ProductionCompletionInputReadScope(ProductionHoldObjectScope current, HoldObjectEvidence item)
    { this.current = current; Address = item.Address; Sha256 = item.Sha256; }
    internal static ProductionCompletionInputReadScope FromHold(ProductionHoldObjectScope current,
        HoldWitnessCompletionContext context, CompletionInputKind kind, ProductionRecordWriteDescriptor descriptor,
        ProductionRecordWriteReceipt receipt, HoldObjectEvidence item)
    {
        var address = item.Address;
        ProductionCompletionInputCodec.DemandDescriptor(current.RecordId, context, kind, descriptor);
        if (receipt.Item != descriptor || address.Area != "normalized" ||
            address.Name != $"{current.RecordId:N}/completion-inputs/{descriptor.Blob.ObjectId:N}" ||
            string.IsNullOrEmpty(receipt.VersionId) || !string.IsNullOrEmpty(address.Snapshot) || address.VersionId != receipt.VersionId ||
            address.ETag != receipt.ETag || address.Length != descriptor.Length || item.Sha256 != descriptor.Sha256 ||
            address.Length > ProductionCompletionInputCodec.MaximumCipherBytes) throw ProductionCompletionInputCodec.Invalid();
        current.Demand(address, default); return new(current, item);
    }
    internal void Close() => Interlocked.Exchange(ref closed, 1);
    internal void Demand(CancellationToken ct = default)
    {
        if (Volatile.Read(ref closed) != 0) throw ProductionCompletionInputCodec.Invalid();
        current.Demand(Address, ct);
        if (Volatile.Read(ref closed) != 0) throw ProductionCompletionInputCodec.Invalid();
    }
}

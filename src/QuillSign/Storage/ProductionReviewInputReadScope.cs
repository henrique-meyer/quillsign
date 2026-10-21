using System.Security.Claims;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Storage;

// Not representable by claims/cookies. The new logical kind is rejected before
// ordinary sender/signer fallbacks; no capability grants deletion.
internal sealed class ReviewInputCapability : ClaimsPrincipal
{
    private readonly ClaimsIdentity identity = new([], "QuillSign.InternalReviewInput");
    private readonly DocumentBlob target; private readonly AssetOperation operation;
    private readonly DateTimeOffset expires; private readonly TimeProvider time;
    private ReviewInputCapability(DocumentBlob target, AssetOperation operation, DateTimeOffset expires, TimeProvider time)
    { this.target = target; this.operation = operation; this.expires = expires; this.time = time; AddIdentity(identity); }
    internal static ReviewInputCapability Create(VerifiedSigner signer, DocumentBlob blob, AssetOperation operation, TimeProvider time)
    {
        if (signer.EnvelopeId != blob.EnvelopeId || signer.SignerId == Guid.Empty || signer.SessionId == Guid.Empty || blob.ObjectId == Guid.Empty ||
            blob.ObjectId == signer.DocumentId || blob.Kind != DocumentBlobKind.ReviewInput || operation is not (AssetOperation.Read or AssetOperation.Write)) throw Invalid();
        var end = time.GetUtcNow().AddMinutes(2); if (signer.SessionExpiresAt < end) end = signer.SessionExpiresAt;
        return new(blob, operation, end, time);
    }
    internal void Demand(DocumentBlob blob, AssetOperation requested)
    {
        var all = Identities.ToArray(); if (all.Length != 1 || !ReferenceEquals(all[0], identity) || !identity.IsAuthenticated || target != blob ||
            requested != operation || requested == AssetOperation.Delete || time.GetUtcNow() >= expires) throw Invalid();
    }
    private static UnauthorizedAccessException Invalid() => new("The exact internal review input capability is invalid.");
}

internal interface IProductionReviewInputSource
{
    Task<byte[]> ReadAsync(ProductionReviewInputReadScope scope, CancellationToken ct = default);
}

internal sealed class ProductionReviewInputReadScope
{
    private readonly ProductionHoldObjectScope current;
    internal HoldObjectAddress Address { get; }
    internal string Sha256 { get; }
    private ProductionReviewInputReadScope(ProductionHoldObjectScope current, HoldObjectEvidence item)
    { this.current = current; Address = item.Address; Sha256 = item.Sha256; }
    internal static ProductionReviewInputReadScope FromHold(ProductionHoldObjectScope current, HoldWitnessReviewPlan plan,
        ProductionRecordWriteReceipt receipt, HoldObjectEvidence item)
    {
        ProductionRecordReviewWriteContract.Validate(plan); var descriptor = plan.Input; var address = item.Address;
        if (!ProductionRecordReviewWriteContract.Receipt(current.RecordId, receipt) || receipt.Item != descriptor ||
            address.Area != "normalized" || address.Name != $"{current.RecordId:N}/review-inputs/{descriptor.Blob.ObjectId:N}" ||
            address.VersionId != receipt.VersionId || !string.IsNullOrEmpty(address.Snapshot) || address.ETag != receipt.ETag ||
            address.Length != descriptor.Length || item.Sha256 != descriptor.Sha256 || address.Length > ProductionReviewInputCodec.MaximumCipherBytes) throw ProductionReviewInputCodec.Invalid();
        current.Demand(address, default); return new(current, item);
    }
    internal void Demand(CancellationToken ct = default) => current.Demand(Address, ct);
}

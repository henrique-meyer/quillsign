namespace QuillSign.Lifecycle;

// Provider facts only. The authenticated lifecycle coordinator must verify the
// command chain and current SQL fence before treating these as authority.
internal sealed record ProductionHoldWitnessObject(long Sequence, string Path, string VersionId, string ETag,
    long Length, string Sha256, byte[] ProtectedPayload, bool LegalHold);
internal sealed record ProductionHoldWitnessWrite(Guid RecordId, long Sequence, byte[] ProtectedPayload);
internal interface IProductionHoldWitnessStore
{
    Task<IReadOnlyList<ProductionHoldWitnessObject>> ReadAsync(Guid recordId, CancellationToken ct = default);
    Task<ProductionHoldWitnessObject> CreateAsync(ProductionHoldWitnessWrite write, CancellationToken ct = default);
}

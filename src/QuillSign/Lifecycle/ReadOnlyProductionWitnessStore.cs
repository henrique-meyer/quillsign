namespace QuillSign.Lifecycle;

// Retains the exact explicitly configured historical reader after operator
// authority is disabled. No append, absence simulation or alternative namespace.
internal sealed class ReadOnlyProductionWitnessStore(IProductionHoldWitnessStore source):IProductionHoldWitnessStore
{
    public Task<IReadOnlyList<ProductionHoldWitnessObject>> ReadAsync(Guid recordId,CancellationToken ct=default)
        =>source.ReadAsync(recordId,ct);
    public Task<ProductionHoldWitnessObject> CreateAsync(ProductionHoldWitnessWrite write,CancellationToken ct=default)
        =>throw new UnauthorizedAccessException("Production mutation is disabled.");
}

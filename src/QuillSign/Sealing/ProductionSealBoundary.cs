namespace QuillSign.Sealing;

// Per-call internal port. These immutable factual values carry no private key,
// provider authority or permission to retry. The composed completion operation
// owns its exact certificate/time/request and durably consumes the real request.
internal sealed record ProductionSealIdentity(string Provider, string CertificateDer,
    string CertificateSha256, DateTimeOffset SealedAt, string SourceSha256);
internal sealed record ProductionTimestampRequest(string AuthoritySha256, string Encoded,
    string Sha256, DateTimeOffset StartedAt);
internal sealed record ProductionTimestampResponse(string Encoded, string Sha256,
    string Token, string TokenSha256, DateTimeOffset At, string CertificateSha256, string Policy);

internal interface IProductionSealBoundary
{
    Task DemandAsync(CancellationToken ct);
    Task PrepareIdentityAsync(ProductionSealIdentity identity, CancellationToken ct);
    Task<IProductionTimestampPermit> BeginTimestampAsync(ProductionTimestampRequest request, CancellationToken ct);
}

internal interface IProductionTimestampPermit
{
    Task DemandSendAsync(ProductionTimestampRequest request, CancellationToken ct);
    Task RecordVerifiedAsync(ProductionTimestampRequest request, ProductionTimestampResponse response, CancellationToken ct);
}

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Documents;

namespace QuillSign.Lifecycle;

internal sealed class ProductionSignerBlockedException:Exception
{
    internal ProductionSignerBlockedException(Exception error):base("Signer work is unavailable pending reconciliation.",error){}
}

// Deliberately opt-in. The caller validates its original proof and owns the
// common parent transaction; this helper never creates or renews a session.
internal sealed class ProductionSignerMutationAdmission(ProductionRecordOperationAdmission operations)
{
    internal static void DemandStandalone(QuillSignDbContext db)
    {
        if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())throw new InvalidDataException("Signer admission requires a clean standalone caller.");
    }
    internal async Task<ProductionRecordOperation?> BeginLockedAsync(QuillSignDbContext db,Guid recordId,string kind,string reference,CancellationToken ct)
    {
        try
        {
            if(await operations.IsUnenrolledDemoAsync(db,recordId,ct))return null;
            return await operations.BeginLockedAsync(db,recordId,Guid.NewGuid(),kind,reference,ct);
        }
        catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or IOException or HttpRequestException or Azure.RequestFailedException or CryptographicException)
        {throw new ProductionSignerBlockedException(error);}
    }
    internal Task PrepareOutcomeLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CancellationToken ct)
        =>operations.PrepareOutcomeLockedAsync(db,scope,ct);
    internal Task CompleteAsync(ProductionRecordOperation scope,VerifiedSigner identity,string action,Guid proofId,CancellationToken ct)
        =>operations.CompleteAsync(scope,Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            Version="production-signer-committed-v1",scope.RecordId,scope.OperationId,Identity=identity,Action=action,ProofId=proofId
        }))),ct);
    internal Task<bool> IsUnenrolledDemoAsync(QuillSignDbContext db,Guid recordId,CancellationToken ct)
        =>operations.IsUnenrolledDemoAsync(db,recordId,ct);
    internal async Task DemandNewProofAsync(SignerReadContext context,CancellationToken ct)
    {
        try{await operations.DemandUnfrozenReadAsync(context.Identity.EnvelopeId,context.AccessExpiresAt,ct);}
        catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or CryptographicException)
        {throw new DocumentRejectedException("The saved signing document is unavailable.");}
    }
}

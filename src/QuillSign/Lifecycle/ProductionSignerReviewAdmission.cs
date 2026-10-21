using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// Internal opt-in composition only. The caller retains the same parent lock;
// no helper creates a participant session or retries an uncertain provider write.
internal sealed class ProductionSignerReviewAdmission(ProductionRecordOperationAdmission operations,
    IDataProtectionProvider keys,IProductionSignerReviewStore store,TimeProvider time)
{
    internal Task<bool> IsUnenrolledDemoLockedAsync(QuillSignDbContext db,Guid id,CancellationToken ct)
        =>operations.IsUnenrolledDemoAsync(db,id,ct);
    internal ProductionSignerReviewWrite Own(SignerReviewCandidate candidate,VerifiedSigner identity,DateTimeOffset access,
        string snapshot,SignerPdfRequest request,IReadOnlyList<PageGeometry> pages,RenderedSignerPdf rendered,
        long auditId,int sequence,byte[] auditHash,string? ip,string? ua)
        =>ProductionSignerReviewWrite.Own(keys,Guid.NewGuid(),Guid.NewGuid(),candidate,identity,access,snapshot,request,pages,rendered,auditId,sequence,auditHash,ip,ua);
    internal async Task<ProductionRecordOperation?> BeginReviewLockedAsync(QuillSignDbContext db,ProductionSignerReviewWrite write,CancellationToken ct)
    {
        try
        {
            if(await operations.IsUnenrolledDemoAsync(db,write.Identity.EnvelopeId,ct))return null;
            DemandTime(write);
            var scope=await operations.BeginLockedAsync(db,write.Identity.EnvelopeId,write.OperationId,"signer/review-prepare",write.CandidateId.ToString("N"),ct);
            await operations.PrepareReviewWritesLockedAsync(db,scope,write,ct);DemandTime(write);return scope;
        }
        catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or IOException or HttpRequestException or Azure.RequestFailedException or CryptographicException)
        {throw new ProductionSignerBlockedException(error);}
    }
    internal async Task WriteLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,ProductionSignerReviewWrite write,
        DocumentBlobKind kind,CancellationToken ct)
    {
        DemandTime(write);var item=kind==DocumentBlobKind.ReviewInput?write.Input:kind==DocumentBlobKind.Normalized?write.Pdf:throw new InvalidDataException("An exact review input/PDF pair is required.");
        var saved=await operations.ReadReviewWriteReceiptLockedAsync(db,scope,item,ct);DemandTime(write);
        var mayWrite=await operations.BeginReviewWriteLockedAsync(db,scope,item,ct);DemandTime(write);
        using var bytes=write.Open(kind);
        var receipt=await store.WriteAsync(scope,write.Identity,item,bytes,mayWrite,saved,async token=>{
            DemandTime(write);await operations.DemandReviewWriteLockedAsync(db,scope,item,token);DemandTime(write);
        },ct);
        DemandTime(write);await operations.RecordReviewWriteLockedAsync(db,scope,receipt,ct);DemandTime(write);
    }
    internal async Task<ProductionRecordOperation?> BeginMutationLockedAsync(QuillSignDbContext db,SignerReadContext context,string kind,string reference,CancellationToken ct)
    {
        try
        {
            if(await operations.IsUnenrolledDemoAsync(db,context.Identity.EnvelopeId,ct))return null;
            DemandTime(context);
            var scope=await operations.BeginLockedAsync(db,context.Identity.EnvelopeId,Guid.NewGuid(),kind,reference,ct);DemandTime(context);return scope;
        }
        catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or IOException or HttpRequestException or Azure.RequestFailedException or CryptographicException)
        {throw new ProductionSignerBlockedException(error);}
    }
    internal Task DemandMutationLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CancellationToken ct)
        =>operations.DemandLockedAsync(db,scope,ct);
    internal Task PrepareOutcomeLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CancellationToken ct)
        =>operations.PrepareOutcomeLockedAsync(db,scope,ct);
    internal Task CompleteAsync(ProductionRecordOperation scope,VerifiedSigner identity,string action,Guid proofId,CancellationToken ct)
        =>operations.CompleteAsync(scope,Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            Version="production-review-committed-v1",scope.RecordId,scope.OperationId,Identity=identity,Action=action,ProofId=proofId
        }))),ct);
    internal async Task DemandNewProofLockedAsync(QuillSignDbContext db,SignerReadContext context,CancellationToken ct)
    {
        try{await operations.DemandUnfrozenReadLockedAsync(db,context.Identity.EnvelopeId,context.AccessExpiresAt,ct);}
        catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or CryptographicException)
        {throw new DocumentRejectedException("The saved signing document is unavailable.");}
        DemandTime(context);
    }
    internal async Task DemandNewProofAsync(SignerReadContext context,CancellationToken ct)
    {
        try{await operations.DemandUnfrozenReadAsync(context.Identity.EnvelopeId,context.AccessExpiresAt,ct);}
        catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or CryptographicException)
        {throw new DocumentRejectedException("The saved signing document is unavailable.");}
        DemandTime(context);
    }
    internal void DemandTime(ProductionSignerReviewWrite write)
    {
        if(write.PreparedAt>time.GetUtcNow()||write.ExpiresAt<=time.GetUtcNow()||write.AccessExpiresAt<=time.GetUtcNow()||
            write.ProspectiveDate!=DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime))throw new DocumentRejectedException("The original review evidence has expired.");
    }
    private void DemandTime(SignerReadContext context)
    {DocumentRetentionAccess.Check(context.RetentionDeadline,time);if(context.AccessExpiresAt<=time.GetUtcNow())throw new DocumentRejectedException("The original signing evidence has expired.");}
}

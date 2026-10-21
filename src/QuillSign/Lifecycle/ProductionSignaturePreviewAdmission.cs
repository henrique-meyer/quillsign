using System.Security.Cryptography;
using System.Text.Json;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// The caller owns its common parent transaction throughout the pair. Every
// demand uses that context, and no error path deletes attempted mark versions.
internal sealed class ProductionSignaturePreviewAdmission(ProductionRecordOperationAdmission operations,
    IProductionSignaturePreviewStore store,TimeProvider time)
{
    internal Task<bool> IsUnenrolledDemoLockedAsync(QuillSignDbContext db,Guid recordId,CancellationToken ct)
        =>operations.IsUnenrolledDemoAsync(db,recordId,ct);
    internal async Task<ProductionRecordOperation?> BeginLockedAsync(QuillSignDbContext db,ProductionSignaturePreviewWrite write,CancellationToken ct)
    {
        try
        {
            if(await operations.IsUnenrolledDemoAsync(db,write.Identity.EnvelopeId,ct))return null;
            var scope=await operations.BeginLockedAsync(db,write.Identity.EnvelopeId,Guid.NewGuid(),
                ProductionRecordPreviewWriteContract.Kind,write.PreviewId.ToString("N"),ct);
            await operations.PreparePreviewWritesLockedAsync(db,scope,write,ct);
            DemandTime(write);return scope;
        }
        catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or IOException or HttpRequestException or Azure.RequestFailedException or CryptographicException)
        {throw new ProductionSignerBlockedException(error);}
    }

    internal async Task WriteLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,ProductionSignaturePreviewWrite write,
        DocumentBlobKind member,CancellationToken ct)
    {
        DemandTime(write);
        var item=member switch {DocumentBlobKind.Signature=>write.Signature,DocumentBlobKind.Initials=>write.Initials,
            _=>throw new InvalidDataException("A signature preview requires its exact two mark objects.")};
        var saved=await operations.ReadPreviewWriteReceiptLockedAsync(db,scope,item,ct);DemandTime(write);
        var mayWrite=await operations.BeginPreviewWriteLockedAsync(db,scope,item,ct);DemandTime(write);
        using var bytes=write.Open(member);
        var receipt=await store.WriteAsync(scope,write.Identity,item,bytes,mayWrite,saved,
            async token=>{DemandTime(write);await operations.DemandPreviewWriteLockedAsync(db,scope,item,token);DemandTime(write);},ct);
        DemandTime(write);await operations.RecordPreviewWriteLockedAsync(db,scope,receipt,ct);DemandTime(write);
    }

    internal async Task PrepareOutcomeLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,ProductionSignaturePreviewWrite write,CancellationToken ct)
    {DemandTime(write);await operations.PrepareOutcomeLockedAsync(db,scope,ct);DemandTime(write);}

    internal async Task CompleteAsync(ProductionRecordOperation scope,ProductionSignaturePreviewWrite write,CancellationToken ct)
    {
        DemandTime(write);
        var digest=Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            Version="production-preview-committed-v1",scope.RecordId,scope.OperationId,write.PreviewId,
            RowSha256=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(write.PreviewRowJson)))
        })));
        await operations.CompleteAsync(scope,digest,ct);DemandTime(write);
        // An admitted operation may drain after hold intent, but its completed
        // bytes are not permission to expose a fresh participant proof while held.
        try{await operations.DemandUnfrozenReadAsync(scope.RecordId,
            ProductionRecordPreviewWriteContract.Earlier(ProductionRecordPreviewWriteContract.ReadRow(write.PreviewRowJson).ExpiresAt,write.AccessExpiresAt),ct);}
        catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or CryptographicException)
        {throw new DocumentRejectedException("The saved signing document is unavailable.");}
        DemandTime(write);
    }

    private void DemandTime(ProductionSignaturePreviewWrite write)
    {
        var preview=ProductionRecordPreviewWriteContract.ReadRow(write.PreviewRowJson);
        if(write.AccessExpiresAt<=time.GetUtcNow()||preview.ExpiresAt<=time.GetUtcNow())
            throw new DocumentRejectedException("The original signature preview evidence has expired.");
    }
}

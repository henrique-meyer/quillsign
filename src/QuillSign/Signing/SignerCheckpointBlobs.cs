using System.Security.Cryptography;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Signing;

public sealed class SignerCheckpointBlobs(IBlobStore blobs,TimeProvider time)
{
    internal Task<byte[]> PdfAsync(SignerFinishAcceptance f,bool source,CancellationToken ct)=>ReadAsync(f,
        new(f.EnvelopeId,DocumentBlobKind.Normalized,source ? f.SourceObjectId : f.PdfObjectId),source ? f.SourceSha256 : f.PdfSha256,
        source ? null : f.PdfLength,64*1024*1024,null,ct);
    internal async Task AssetsAsync(SignerFinishAcceptance f,SignaturePreview p,CancellationToken ct)
    {
        foreach(var signature in new[]{true,false})
        {
            var bytes=await ReadAsync(f,new(f.EnvelopeId,signature ? DocumentBlobKind.Signature : DocumentBlobKind.Initials,signature ? p.SignatureObjectId : p.InitialsObjectId),
                signature ? p.SignatureSha256 : p.InitialsSha256,null,SignaturePng.MaximumBytes,p,ct);
            var image=SignaturePng.Normalize(bytes);
            if(!image.Bytes.AsSpan().SequenceEqual(bytes) || image.Width!=(signature ? p.SignatureWidth : p.InitialsWidth) || image.Height!=(signature ? p.SignatureHeight : p.InitialsHeight))
                throw new InvalidDataException("The accepted signature asset could not be verified.");
        }
    }
    private async Task<byte[]> ReadAsync(SignerFinishAcceptance f,DocumentBlob blob,byte[] hash,long? expected,long maximum,SignaturePreview? assets,CancellationToken ct)
    {
        using var memory=new MemoryStream(); using var bounded=new BoundedDocumentStream(memory,maximum);
        var length=await blobs.CopyToAsync(SignerCheckpointReadCapability.Create(f,blob,time,assets),blob,bounded,ct);
        if(length!=memory.Length || length<16 || expected is long size && length!=size ||
            !SignerCheckpointState.Same(hash,SHA256.HashData(memory.GetBuffer().AsSpan(0,checked((int)memory.Length)))))
            throw new InvalidDataException("The accepted checkpoint object could not be verified.");
        return memory.ToArray();
    }
}

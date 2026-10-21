using System.Security.Cryptography;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Annotations;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Signatures;
using QuillSign.Documents;
using QuillSign.Email.Pilot;

namespace QuillSign.Sealing;

// Explicit internal operation only. Finalization must authorize, stage and publish the returned bytes itself.
public sealed class PlatformPdfSeal(SealOptions options,ISealCertificateProvider certificates,TimestampAuthority timestamps,IHostEnvironment environment,TimeProvider time,
    PilotTimestampPolicy? pilotPolicy=null)
{
    private static readonly SemaphoreSlim gate=new(1,1);
    public Task<SealedPdf> SealAsync(byte[] source,byte[] expectedSha256,CancellationToken ct=default,CompletionTimestampArtifact? timestampContext=null)
        =>SealCore(source,expectedSha256,null,ct,timestampContext,null);
    public Task<SealedPdf> SealBoundAsync(byte[] source,byte[] expectedSha256,byte[] expectedCertificateSha256,CancellationToken ct=default,
        CompletionTimestampArtifact? timestampContext=null)
        =>SealCore(source,expectedSha256,expectedCertificateSha256 ?? throw new SealUnavailableException("A platform identity binding is required."),ct,timestampContext,null);
    internal Task<SealedPdf> SealAdmittedAsync(byte[] source,byte[] expectedSha256,IProductionSealBoundary admission,CancellationToken ct=default)
        =>SealCore(source,expectedSha256,null,ct,null,admission??throw new ArgumentNullException(nameof(admission)));
    internal Task<SealedPdf> SealBoundAdmittedAsync(byte[] source,byte[] expectedSha256,byte[] expectedCertificateSha256,
        IProductionSealBoundary admission,CancellationToken ct=default)
        =>SealCore(source,expectedSha256,expectedCertificateSha256??throw new ArgumentNullException(nameof(expectedCertificateSha256)),ct,null,
            admission??throw new ArgumentNullException(nameof(admission)));
    private async Task<SealedPdf> SealCore(byte[] source,byte[] expectedSha256,byte[]? expectedCertificateSha256,CancellationToken ct,
        CompletionTimestampArtifact? timestampContext,IProductionSealBoundary? admission)
    {
        if(pilotPolicy is not null && timestampContext is null)throw new PilotTimestampDeniedException();
        var address=options.Validate(environment.IsDevelopment());options.ValidateRequestCoordination(address);ct.ThrowIfCancellationRequested();
        if(expectedCertificateSha256 is not null && expectedCertificateSha256.Length!=32)throw new SealUnavailableException("Invalid platform identity binding.");
        var certificateBinding=expectedCertificateSha256?.ToArray();
        if(source is null || source.Length<16 || source.LongLength>options.MaximumBytes || expectedSha256 is not {Length:32})
            throw new DocumentRejectedException("The prepared PDF exceeds sealing limits.");
        var owned=source.ToArray();var expected=expectedSha256.ToArray();
        await gate.WaitAsync(ct);
        try {
            if(admission is not null)await admission.DemandAsync(ct);
            var sourceHash=SHA256.HashData(owned);
            if(!CryptographicOperations.FixedTimeEquals(sourceHash,expected))throw new DocumentRejectedException("The prepared PDF changed.");
            if(timestampContext is not null)await timestampContext.DemandAsync(sourceHash,ct);
            using var sourceInput=new MemoryStream(owned,false); using var normalized=new MemoryStream(); IReadOnlyList<PageGeometry> geometry;
            lock(SenderPdfRenderer.RenderGate)geometry=new PdfValidation(new() { MaximumBytes=options.MaximumBytes,MaximumPages=options.MaximumPages })
                .Rewrite(sourceInput,new BoundedDocumentStream(normalized,options.MaximumBytes));
            ct.ThrowIfCancellationRequested(); normalized.Position=0; using var document=PdfReader.Open(normalized,PdfDocumentOpenMode.Modify);
            var form=document.Internals.Catalog.Elements.GetDictionary("/AcroForm");
            if(form?.Elements.GetArray("/Fields")?.Elements.Count>0)throw new DocumentRejectedException("Flatten the completed document before sealing.");
            using var material=await certificates.AcquireAsync(ct); var now=time.GetUtcNow(); material.Validate(now);
            if(timestampContext is not null)await timestampContext.DemandAsync(sourceHash,ct);
            if(certificateBinding is not null && !CryptographicOperations.FixedTimeEquals(certificateBinding,SHA256.HashData(material.Certificate.RawData)))
                throw new SealUnavailableException("The selected platform signing identity changed.");
            if(admission is not null)
            {
                await admission.DemandAsync(ct);
                await admission.PrepareIdentityAsync(new(material.Provider,Convert.ToBase64String(material.Certificate.RawData),
                    Convert.ToHexStringLower(SHA256.HashData(material.Certificate.RawData)),now,Convert.ToHexStringLower(sourceHash)),ct);
                await admission.DemandAsync(ct);material.Validate(time.GetUtcNow());
            }
            DigitalSignatureHandler.ForDocument(document,new SealCms.Signer(options,material,timestamps,now,ct,timestampContext,admission),new DigitalSignatureOptions {
                Reason="QuillSign completion integrity seal",AppName="QuillSign",Rectangle=new XRect(0,0,0,0),AppearanceHandler=new InvisibleAppearance() });
            using var output=new MemoryStream();
            try { await document.SaveAsync(new BoundedDocumentStream(output,options.MaximumBytes),false); }
            catch(DocumentRejectedException) { throw new SealUnavailableException("The sealed PDF exceeds its output limit."); }
            ct.ThrowIfCancellationRequested();
            if(admission is not null)await admission.DemandAsync(ct);
            var bytes=output.ToArray(); var verified=await new SealCms(options,timestamps).VerifyAsync(bytes,material.Certificate,now,ct);
            material.Validate(time.GetUtcNow());
            if(admission is not null)await admission.DemandAsync(ct);
            if(!SenderPdfRenderer.GeometryMatches(verified.Geometry,geometry))throw new SealUnavailableException("The sealed PDF page geometry changed.");
            return new(bytes,SHA256.HashData(bytes),sourceHash,verified.PageCount,material.Provider,
                Convert.ToHexStringLower(SHA256.HashData(material.Certificate.RawData)),now,verified.Timestamp.At,verified.Timestamp.CertificateSha256,verified.Timestamp.Policy)
                {CertificateDer=material.Certificate.RawData.ToArray()};
        }
        catch(Exception e) when(e is CryptographicException or IOException or InvalidDataException or PdfReaderException or ArgumentException or
            InvalidOperationException or FormatException or OverflowException or Org.BouncyCastle.Tsp.TspException or Org.BouncyCastle.Security.GeneralSecurityException)
        { throw new SealUnavailableException("The prepared PDF could not be sealed and verified."); }
        finally { gate.Release(); }
    }
    private sealed class InvisibleAppearance : IAnnotationAppearanceHandler { public void DrawAppearance(XGraphics graphics,XRect rectangle) { } }
}

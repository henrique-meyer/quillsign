using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Org.BouncyCastle.X509;

namespace QuillSign.Sealing;

public sealed class SelfSignedSealCertificateProvider(Func<IProtectedSealStore> getStore,IDataProtectionProvider protection,SealOptions options,TimeProvider time) : ISealCertificateProvider
{
    private readonly IDataProtector protector=protection.CreateProtector("QuillSign.DemoSeal.Pkcs12.v1");
    public async Task<SealCertificateMaterial> AcquireAsync(CancellationToken ct)
    {
        if(options.SelfSigned is null || options.SelfSigned.ValidityDays is <7 or >3650)throw new SealUnavailableException("Invalid demo signing certificate configuration.");
        byte[]? generated=null;
        try {
            ct.ThrowIfCancellationRequested(); var store=getStore(); var saved=await store.ReadAsync(ct); if(saved is not null)return Read(saved,ct);
            ct.ThrowIfCancellationRequested(); using var key=RSA.Create(3072); var now=time.GetUtcNow();
            var request=new CertificateRequest("CN=QuillSign Demo Seal",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {new("1.3.6.1.5.5.7.3.36")},false));
            using var certificate=request.CreateSelfSigned(now.AddMinutes(-5),now.AddDays(options.SelfSigned.ValidityDays));
            generated=certificate.Export(X509ContentType.Pkcs12); var encrypted=protector.Protect(generated); ct.ThrowIfCancellationRequested();
            try { _=await store.TryCreateAsync(encrypted,ct); }
            catch(Exception e) when(e is Azure.RequestFailedException or IOException or HttpRequestException) {
                // A lost create response may already have persisted the shared identity. Never replace/delete it.
                var recovered=await store.ReadAsync(ct); if(recovered is not null)return Read(recovered,ct); throw;
            }
            return Read(await store.ReadAsync(ct) ?? throw new SealUnavailableException("The persisted demo signing identity could not be confirmed."),ct);
        }
        catch(Exception e) when(e is CryptographicException or Azure.RequestFailedException or IOException or InvalidDataException or HttpRequestException or
            ArgumentException or InvalidOperationException or QuillSign.Documents.DocumentRejectedException or Org.BouncyCastle.Security.GeneralSecurityException)
        { throw new SealUnavailableException("The persisted demo signing identity could not be loaded. Automatic replacement is disabled."); }
        finally { if(generated is not null)CryptographicOperations.ZeroMemory(generated); }
    }
    private SealCertificateMaterial Read(byte[] saved,CancellationToken ct)
    {
        if(saved.Length is <1 or >BlobProtectedSealStore.MaximumBytes)throw new SealUnavailableException("Protected signing material exceeds its limits.");
        var plain=protector.Unprotect(saved); SealCertificateMaterial? material=null;
        try {
            material=SealCertificateMaterial.Load(plain,null,"SelfSignedDemo",time.GetUtcNow()); using var key=material.Certificate.GetRSAPublicKey();
            var purpose=material.Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
            if(key?.KeySize!=3072 || material.Certificate.GetNameInfo(X509NameType.SimpleName,false)!="QuillSign Demo Seal" ||
                purpose is null || !purpose.EnhancedKeyUsages.Cast<Oid>().Any(x=>x.Value=="1.3.6.1.5.5.7.3.36") ||
                !material.Certificate.SubjectName.RawData.AsSpan().SequenceEqual(material.Certificate.IssuerName.RawData))throw new CryptographicException();
            var parsed=new X509CertificateParser().ReadCertificate(material.Certificate.RawData); parsed.Verify(parsed.GetPublicKey());
            ct.ThrowIfCancellationRequested(); var result=material; material=null; return result;
        }
        finally { CryptographicOperations.ZeroMemory(plain); material?.Dispose(); }
    }
}

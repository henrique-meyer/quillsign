using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace QuillSign.Sealing;

public interface ISealCertificateProvider
{
    Task<SealCertificateMaterial> AcquireAsync(CancellationToken ct);
}
// The operation owns this lease, including private-key handles. Never cache an operation signer.
public sealed class SealCertificateMaterial(string provider,X509Certificate2 certificate,IReadOnlyList<X509Certificate2>? chain=null) : IDisposable
{
    public string Provider { get; }=provider;
    public X509Certificate2 Certificate { get; }=certificate;
    public IReadOnlyList<X509Certificate2> Chain { get; }=chain ?? [];
    public void Dispose() { Certificate.Dispose(); foreach(var item in Chain)item.Dispose(); }
    internal static SealCertificateMaterial Load(byte[] bytes,string? password,string provider,DateTimeOffset now)
    {
        X509Certificate2Collection? certificates=null;
        try {
            if(bytes.Length is <1 or >2*1024*1024)throw new SealUnavailableException("Certificate material exceeds its limits.");
            certificates=X509CertificateLoader.LoadPkcs12Collection(bytes,password,X509KeyStorageFlags.EphemeralKeySet,
                new Pkcs12LoaderLimits { MaxKeys=1,MaxCertificates=8 });
            var keys=certificates.Cast<X509Certificate2>().Where(x=>x.HasPrivateKey).ToArray();
            if(keys.Length!=1)throw new SealUnavailableException("The provider must contain one signing identity.");
            var result=new SealCertificateMaterial(provider,keys[0],certificates.Cast<X509Certificate2>().Where(x=>!ReferenceEquals(x,keys[0])).ToArray());
            result.Validate(now); certificates=null; return result;
        }
        catch(Exception e) when(e is CryptographicException or ArgumentException)
        { throw new SealUnavailableException("The private signing material could not be loaded."); }
        finally { if(certificates is not null)foreach(var certificate in certificates)certificate.Dispose(); }
    }
    internal void Validate(DateTimeOffset now)
    {
        if(string.IsNullOrWhiteSpace(Provider) || Provider.Length>100 || !Certificate.HasPrivateKey || Chain.Count>8 ||
            Certificate.RawData.Length+Chain.Sum(x=>x.RawData.Length)>64*1024 || now<Certificate.NotBefore.ToUniversalTime() || now>=Certificate.NotAfter.ToUniversalTime())
            throw new SealUnavailableException("The platform signing certificate is unavailable or outside its validity period.");
        var constraints=Certificate.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages=Certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        var purposes=Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        if(constraints.Length>1 || constraints.Any(x=>x.CertificateAuthority) || usages.Length>1 || purposes.Length>1 ||
            usages.Any(x=>(x.KeyUsages&(X509KeyUsageFlags.DigitalSignature|X509KeyUsageFlags.NonRepudiation))==0) ||
            purposes.Any(x=>!x.EnhancedKeyUsages.Cast<Oid>().Any(o=>o.Value=="1.3.6.1.5.5.7.3.36")))
            throw new SealUnavailableException("Use a certificate suitable for document signing.");
        using var rsa=Certificate.GetRSAPrivateKey(); using var ec=Certificate.GetECDsaPrivateKey();
        if(rsa is null ? ec?.KeySize is not (256 or 384 or 521) : rsa.KeySize is <2048 or >8192)
            throw new SealUnavailableException("Use a supported platform signing key.");
    }
}
public sealed class PfxSealCertificateProvider(SealOptions options,TimeProvider time) : ISealCertificateProvider
{
    public async Task<SealCertificateMaterial> AcquireAsync(CancellationToken ct)
    {
        if(options.Pfx is null || options.Pfx.Password is null || options.Pfx.Password.Length>4096)
            throw new SealUnavailableException("Configure the private PFX signing material.");
        byte[]? bytes=null;
        try {
            bytes=await SealFiles.ReadAsync(options.Pfx.Path,2*1024*1024,ct);
            return SealCertificateMaterial.Load(bytes,options.Pfx.Password,"Pfx",time.GetUtcNow());
        }
        catch(Exception e) when(e is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
        { throw new SealUnavailableException("The configured PFX signing material could not be loaded."); }
        finally { if(bytes is not null)CryptographicOperations.ZeroMemory(bytes); }
    }
}

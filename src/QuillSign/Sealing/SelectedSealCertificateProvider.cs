namespace QuillSign.Sealing;

public sealed class KeyVaultSealOptions
{
    public string Uri { get; set; }="";
    public string CertificateName { get; set; }="";
    public string ManagedIdentityClientId { get; set; }="";
    public int TimeoutSeconds { get; set; }=15;
}
public sealed class SelfSignedSealOptions
{
    public string BlobName { get; set; }="demo-seal-v1.dp";
    public int ValidityDays { get; set; }=365;
}

public sealed class SelectedSealCertificateProvider(SealOptions options,Func<PfxSealCertificateProvider> pfx,
    Func<KeyVaultSealCertificateProvider> vault,Func<SelfSignedSealCertificateProvider> demo) : ISealCertificateProvider
{
    public Task<SealCertificateMaterial> AcquireAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); if(options.Pfx is null || options.KeyVault is null || options.SelfSigned is null)
            throw new SealUnavailableException("Invalid signing provider configuration.");
        var selected=options.Provider;
        if(selected=="Auto") {
            var hasPfx=!string.IsNullOrEmpty(options.Pfx.Path) || !string.IsNullOrEmpty(options.Pfx.Password);
            var hasVault=!string.IsNullOrEmpty(options.KeyVault.Uri) || !string.IsNullOrEmpty(options.KeyVault.CertificateName) || !string.IsNullOrEmpty(options.KeyVault.ManagedIdentityClientId);
            if(hasPfx && hasVault)throw new SealUnavailableException("Choose one configured signing provider explicitly.");
            selected=hasPfx ? "Pfx" : hasVault ? "KeyVault" : "SelfSigned";
        }
        // No exception path chooses another provider. Saved/configured identity failures require correction.
        return selected switch { "Pfx"=>pfx().AcquireAsync(ct),"KeyVault"=>vault().AcquireAsync(ct),"SelfSigned"=>demo().AcquireAsync(ct),
            _=>throw new SealUnavailableException("Choose Auto, Pfx, KeyVault or SelfSigned as the signing provider.") };
    }
}

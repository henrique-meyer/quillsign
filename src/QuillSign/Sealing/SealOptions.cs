using Microsoft.Extensions.DependencyInjection.Extensions;

namespace QuillSign.Sealing;

public sealed class SealOptions
{
    public long MaximumBytes { get; set; } = 64 * 1024 * 1024;
    public int MaximumPages { get; set; } = 200;
    // Ceiling for CMS reservation; each operation sizes its certificate profile and TSA bound.
    public int SignatureCapacityBytes { get; set; } = 128 * 1024;
    public string TsaUrl { get; set; } = "";
    public int TsaTimeoutSeconds { get; set; } = 15;
    public int TsaMaximumResponseBytes { get; set; } = 64 * 1024;
    public int TsaMaximumClockSkewSeconds { get; set; } = 120;
    public string[] TsaTrustedRootPaths { get; set; } = [];
    public TimestampCoordinationOptions TimestampCoordination { get; set; }=new();
    public PfxSealOptions Pfx { get; set; } = new();
    public string Provider { get; set; }="Auto";
    public KeyVaultSealOptions KeyVault { get; set; }=new();
    public SelfSignedSealOptions SelfSigned { get; set; }=new();
    internal Uri Validate(bool development)
    {
        if(MaximumBytes is <1024 or >64*1024*1024 || MaximumPages is <1 or >200 || SignatureCapacityBytes is <32*1024 or >256*1024 ||
            TsaTimeoutSeconds is <1 or >60 || TsaMaximumResponseBytes is <1024 or >128*1024 || TsaMaximumClockSkewSeconds is <0 or >300 ||
            TsaTrustedRootPaths is null || TsaTrustedRootPaths.Length>8 || TsaTrustedRootPaths.Any(x=>string.IsNullOrWhiteSpace(x) || !Path.IsPathFullyQualified(x)) ||
            TimestampCoordination is null || TimestampCoordination.Enabled && (TimestampCoordination.MinimumIntervalMilliseconds is <1000 or >10000 ||
                TimestampCoordination.AcquireTimeoutSeconds is <1 or >60 || TsaTimeoutSeconds>30) ||
            !Uri.TryCreate(TsaUrl,UriKind.Absolute,out var uri) || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) ||
            !(uri.Scheme=="https" || development && uri.Scheme=="http" && uri.IsLoopback))
            throw new SealUnavailableException("Configure valid seal limits and a timestamp service before sealing.");
        return uri;
    }
    internal static bool IsFreeTsa(Uri address)=>address.IdnHost.TrimEnd('.').Equals("freetsa.org",StringComparison.OrdinalIgnoreCase) ||
        address.IdnHost.TrimEnd('.').EndsWith(".freetsa.org",StringComparison.OrdinalIgnoreCase);
    internal void ValidateRequestCoordination(Uri address)
    {
        if(IsFreeTsa(address) && (!TimestampCoordination.Enabled || TsaTrustedRootPaths.Length==0))
            throw new SealUnavailableException("Configure shared timestamp coordination and explicit CA trust before using FreeTSA.");
    }
}
public sealed class PfxSealOptions { public string Path { get; set; }=""; public string Password { get; set; }=""; }
public sealed class SealUnavailableException(string message) : Exception(message);
public sealed record SealedPdf(byte[] Bytes,byte[] Sha256,byte[] SourceSha256,int PageCount,string Provider,string CertificateSha256,
    DateTimeOffset SealedAt,DateTimeOffset TimestampAt,string TimestampCertificateSha256,string TimestampPolicy)
{
    // Public leaf certificate only, copied from the verified operation; never private material.
    public byte[] CertificateDer {get;init;}=[];
}

public static class SealConfiguration
{
    // No certificate reads, network calls or database access occur during registration/startup.
    public static IServiceCollection AddPlatformPdfSeals(this IServiceCollection services,IConfiguration config)
    {
        services.TryAddSingleton(config.GetSection("Seal").Get<SealOptions>() ?? new());
        services.TryAddSingleton<PfxSealCertificateProvider>(); services.TryAddSingleton<KeyVaultSealCertificateProvider>(); services.TryAddSingleton<SelfSignedSealCertificateProvider>();
        services.TryAddSingleton<Func<PfxSealCertificateProvider>>(sp=>()=>sp.GetRequiredService<PfxSealCertificateProvider>());
        services.TryAddSingleton<Func<KeyVaultSealCertificateProvider>>(sp=>()=>sp.GetRequiredService<KeyVaultSealCertificateProvider>());
        services.TryAddSingleton<Func<SelfSignedSealCertificateProvider>>(sp=>()=>sp.GetRequiredService<SelfSignedSealCertificateProvider>());
        services.TryAddSingleton<ISealCertificateProvider,SelectedSealCertificateProvider>();
        services.TryAddSingleton<IKeyVaultSealClients,ManagedIdentitySealClients>(); services.TryAddSingleton<IKeyVaultSealSource,SdkKeyVaultSealSource>();
        services.TryAddSingleton<IProtectedSealStore>(sp=> {
            var provider=config["Storage:Provider"];
            if(provider is not ("Azure" or "Azurite") || sp.GetService<Azure.Storage.Blobs.BlobServiceClient>() is not { } client)
                throw new SealUnavailableException("Configure persistent protected storage for the demo seal identity.");
            return new BlobProtectedSealStore(client,provider=="Azurite",sp.GetRequiredService<SealOptions>().SelfSigned.BlobName);
        });
        services.TryAddSingleton<Func<IProtectedSealStore>>(sp=>()=>sp.GetRequiredService<IProtectedSealStore>());
        services.TryAddSingleton<ITimestampRequestCoordinator>(sp=> {
            var provider=config["Storage:Provider"];
            if(provider is not ("Azure" or "Azurite") || sp.GetService<Azure.Storage.Blobs.BlobServiceClient>() is not {} client)
                throw new SealUnavailableException("Configure persistent shared storage for timestamp coordination.");
            return new BlobTimestampRequestCoordinator(client.GetBlobContainerClient("keys"),sp.GetRequiredService<SealOptions>().TimestampCoordination,provider=="Azurite");
        });
        services.TryAddSingleton<Func<ITimestampRequestCoordinator>>(sp=>()=>sp.GetRequiredService<ITimestampRequestCoordinator>());
        services.TryAddSingleton<TimestampAuthority>(); services.TryAddSingleton<PlatformPdfSeal>(); services.TryAddSingleton<SealCms>(); return services;
    }
}

internal static class SealFiles
{
    public static async Task<byte[]> ReadAsync(string path,int maximum,CancellationToken ct)
    {
        if(string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))throw new SealUnavailableException("Configure an absolute certificate file path.");
        await using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,4096,FileOptions.Asynchronous);
        if(file.Length is <=0 || file.Length>maximum)throw new SealUnavailableException("Certificate material exceeds its limits.");
        using var memory=new MemoryStream();
        try { await file.CopyToAsync(new Documents.BoundedDocumentStream(memory,maximum),ct); }
        catch(Documents.DocumentRejectedException) { throw new SealUnavailableException("Certificate material exceeds its limits."); }
        return memory.ToArray();
    }
}

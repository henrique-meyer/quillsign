using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Sealing;

namespace QuillSign.Tests;

public sealed class SealCertificateProviderTests
{
    [Theory]
    [InlineData("Auto", "", "", "SelfSigned")]
    [InlineData("Auto", "configured", "", "Pfx")]
    [InlineData("Auto", "", "configured", "KeyVault")]
    [InlineData("SelfSigned", "configured", "configured", "SelfSigned")]
    [InlineData("Pfx", "", "configured", "Pfx")]
    [InlineData("KeyVault", "configured", "", "KeyVault")]
    public async Task Selection_resolves_only_the_chosen_provider_and_never_falls_back_after_failure(string provider,string pfx,string vault,string expected)
    {
        var selected=""; var options=new SealOptions {Provider=provider}; options.Pfx.Password=pfx; options.KeyVault.CertificateName=vault;
        var subject=new SelectedSealCertificateProvider(options,
            ()=> { selected="Pfx"; throw new SealUnavailableException("synthetic failure"); },
            ()=> { selected="KeyVault"; throw new SealUnavailableException("synthetic failure"); },
            ()=> { selected="SelfSigned"; throw new SealUnavailableException("synthetic failure"); });
        await Assert.ThrowsAsync<SealUnavailableException>(()=>subject.AcquireAsync(default)); Assert.Equal(expected,selected);
    }
    [Theory]
    [InlineData("Auto")][InlineData("unknown")][InlineData("")]
    public async Task Ambiguous_or_unknown_configuration_never_resolves_any_provider(string provider)
    {
        var options=new SealOptions {Provider=provider}; options.Pfx.Path="configured"; options.KeyVault.CertificateName="configured"; var calls=0;
        var subject=new SelectedSealCertificateProvider(options,()=> {calls++; throw new Exception();},()=> {calls++; throw new Exception();},()=> {calls++; throw new Exception();});
        await Assert.ThrowsAsync<SealUnavailableException>(()=>subject.AcquireAsync(default)); Assert.Equal(0,calls);
    }
    [Fact]
    public async Task Resolving_the_engine_without_storage_or_certificate_configuration_performs_no_io()
    {
        var services=new ServiceCollection(); services.AddSingleton<TimeProvider>(TimeProvider.System);
        services.AddSingleton<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>(new EnvironmentStub());
        services.AddSingleton<Microsoft.Extensions.Hosting.IHostEnvironment>(sp=>sp.GetRequiredService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>());
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()); services.AddPlatformPdfSeals(new ConfigurationBuilder().Build());
        services.AddPlatformPdfSeals(new ConfigurationBuilder().Build());
        using var scope=services.BuildServiceProvider(new ServiceProviderOptions {ValidateOnBuild=true,ValidateScopes=true});
        Assert.Single(scope.GetServices<PlatformPdfSeal>()); Assert.Single(scope.GetServices<TimestampAuthority>());
        Assert.NotNull(scope.GetRequiredService<PlatformPdfSeal>());
        // Only the explicit operation requests persistent storage; an unconfigured host cannot invent an identity.
        await Assert.ThrowsAsync<SealUnavailableException>(()=>scope.GetRequiredService<ISealCertificateProvider>().AcquireAsync(default));
    }
    [Fact]
    public async Task Concurrent_first_use_and_reconstructed_providers_converge_on_one_encrypted_identity()
    {
        var store=new MemoryStore(); var protection=new EphemeralDataProtectionProvider(); var time=new SealFixtures.Clock();
        SelfSignedSealCertificateProvider Provider()=>new(()=>store,protection,new SealOptions(),time);
        var leases=await Task.WhenAll(Enumerable.Range(0,4).Select(_=>Provider().AcquireAsync(default)));
        try {
            Assert.Single(leases.Select(x=>Convert.ToHexString(x.Certificate.RawData)).Distinct()); Assert.Equal(1,store.Created);
            Assert.All(leases,x=> {using var key=x.Certificate.GetRSAPublicKey(); Assert.Equal("SelfSignedDemo",x.Provider); Assert.Equal(3072,key!.KeySize); Assert.True(x.Certificate.HasPrivateKey);});
            Assert.ThrowsAny<CryptographicException>(()=>X509CertificateLoader.LoadPkcs12(store.Bytes!,null));
            using var restarted=await Provider().AcquireAsync(default); Assert.Equal(leases[0].Certificate.RawData,restarted.Certificate.RawData);
        }
        finally {foreach(var lease in leases)lease.Dispose();}
    }
    [Theory]
    [InlineData("tampered")][InlineData("wrong-key")][InlineData("expired")][InlineData("oversize")][InlineData("read-failure")]
    public async Task Saved_material_failures_never_generate_overwrite_or_rotate_the_identity(string kind)
    {
        var store=new MemoryStore(); IDataProtectionProvider protection=new EphemeralDataProtectionProvider(); var time=new SealFixtures.Clock();
        SelfSignedSealCertificateProvider Provider()=>new(()=>store,protection,new SealOptions(),time);
        using(var first=await Provider().AcquireAsync(default))Assert.True(first.Certificate.HasPrivateKey);
        if(kind=="tampered")store.Bytes![^1]^=1;
        if(kind=="wrong-key")protection=new EphemeralDataProtectionProvider();
        if(kind=="expired")time.Advance(TimeSpan.FromDays(366));
        if(kind=="oversize")store.Bytes=new byte[BlobProtectedSealStore.MaximumBytes+1];
        if(kind=="read-failure")store.FailRead=true;
        var previous=store.Bytes!.ToArray(); await Assert.ThrowsAsync<SealUnavailableException>(()=>Provider().AcquireAsync(default));
        Assert.Equal(1,store.Attempts); Assert.Equal(previous,store.Bytes);
    }
    [Theory]
    [InlineData("wrong-subject")][InlineData("weak")][InlineData("public-only")][InlineData("purpose")][InlineData("missing-purpose")]
    public async Task Even_authentically_protected_saved_material_requires_the_demo_private_certificate_profile(string kind)
    {
        var protection=new EphemeralDataProtectionProvider(); using var key=RSA.Create(kind=="weak" ? 2048 : 3072); var now=DateTimeOffset.UtcNow;
        var request=new CertificateRequest(kind=="wrong-subject" ? "CN=Synthetic other identity" : "CN=QuillSign Demo Seal",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        if(kind!="missing-purpose")request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {new(kind=="purpose" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.36")},false));
        using var certificate=request.CreateSelfSigned(now.AddMinutes(-1),now.AddDays(1)); using var publicOnly=kind=="public-only" ? X509CertificateLoader.LoadCertificate(certificate.RawData) : null;
        var pfx=(publicOnly ?? certificate).Export(X509ContentType.Pkcs12); var store=new MemoryStore();
        try {store.Bytes=protection.CreateProtector("QuillSign.DemoSeal.Pkcs12.v1").Protect(pfx);} finally {CryptographicOperations.ZeroMemory(pfx);}
        var previous=store.Bytes.ToArray(); await Assert.ThrowsAsync<SealUnavailableException>(()=>new SelfSignedSealCertificateProvider(()=>store,protection,new(),TimeProvider.System).AcquireAsync(default));
        Assert.Equal(0,store.Attempts); Assert.Equal(previous,store.Bytes);
    }
    [Theory]
    [InlineData(true)][InlineData(false)]
    public async Task Uncertain_conditional_write_recovers_only_the_persisted_identity(bool committed)
    {
        var store=new MemoryStore {LostResponse=true,Commit=committed}; var provider=new SelfSignedSealCertificateProvider(()=>store,new EphemeralDataProtectionProvider(),new(),TimeProvider.System);
        if(committed) {using var lease=await provider.AcquireAsync(default); Assert.True(lease.Certificate.HasPrivateKey); Assert.Equal(1,store.Created);}
        else {await Assert.ThrowsAsync<SealUnavailableException>(()=>provider.AcquireAsync(default)); Assert.Null(store.Bytes);}
        Assert.Equal(1,store.Attempts);
    }
    [Fact]
    public async Task Cancellation_does_not_request_storage_or_generate_keys()
    {
        var calls=0; var provider=new SelfSignedSealCertificateProvider(()=> {calls++; throw new Exception();},new EphemeralDataProtectionProvider(),new(),TimeProvider.System);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>provider.AcquireAsync(new CancellationToken(true))); Assert.Equal(0,calls);
    }
    [Fact]
    public async Task Persisted_identity_seals_real_PDFs_and_verifies_timestamps_across_provider_reconstruction()
    {
        await using var f=await SealFixtures.Create(); var store=new MemoryStore(); var protection=new EphemeralDataProtectionProvider(); var source=PdfFixtures.Create(text:"SYNTHETIC NO AGREEMENT");
        PlatformPdfSeal Engine()=>new(f.Options,new SelfSignedSealCertificateProvider(()=>store,protection,f.Options,f.Time),f.Timestamps,f.App.Environment,f.Time);
        var first=await Engine().SealAsync(source,SHA256.HashData(source)); var second=await Engine().SealAsync(source,SHA256.HashData(source));
        Assert.Equal("SelfSignedDemo",first.Provider); Assert.Equal(first.CertificateSha256,second.CertificateSha256); Assert.Equal(2,f.Requests); Assert.Equal(1,store.Created);
        using var material=await new SelfSignedSealCertificateProvider(()=>store,protection,f.Options,f.Time).AcquireAsync(default);
        _=await new SealCms(f.Options,f.Timestamps).VerifyAsync(first.Bytes,material.Certificate,first.SealedAt,default);
        _=await new SealCms(f.Options,f.Timestamps).VerifyAsync(second.Bytes,material.Certificate,second.SealedAt,default);
    }
    internal sealed class MemoryStore : IProtectedSealStore
    {
        private readonly object gate=new(); public byte[]? Bytes; public int Attempts,Created; public bool LostResponse,FailRead,Commit=true;
        public async Task<byte[]?> ReadAsync(CancellationToken ct) {await Task.Yield(); ct.ThrowIfCancellationRequested(); if(FailRead)throw new IOException("synthetic private storage location"); lock(gate)return Bytes?.ToArray();}
        public Task<bool> TryCreateAsync(byte[] bytes,CancellationToken ct) {
            ct.ThrowIfCancellationRequested(); lock(gate) {Attempts++; if(Bytes is not null)return Task.FromResult(false); if(Commit) {Bytes=bytes.ToArray(); Created++;}
                if(LostResponse)throw new IOException("synthetic unknown commit"); return Task.FromResult(true);}
        }
    }
    private sealed class EnvironmentStub : Microsoft.AspNetCore.Hosting.IWebHostEnvironment
    {
        public string EnvironmentName {get;set;}="Production"; public string ApplicationName {get;set;}="QuillSign.Tests";
        public string ContentRootPath {get;set;}=AppContext.BaseDirectory; public string WebRootPath {get;set;}=AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider {get;set;}=new Microsoft.Extensions.FileProviders.NullFileProvider();
        public Microsoft.Extensions.FileProviders.IFileProvider WebRootFileProvider {get;set;}=new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}

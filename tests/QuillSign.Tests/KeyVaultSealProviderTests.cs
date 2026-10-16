using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using QuillSign.Sealing;

namespace QuillSign.Tests;

public sealed class KeyVaultSealProviderTests
{
    [Theory]
    [InlineData("valid")][InlineData("mismatch")][InlineData("invalid")][InlineData("cancelled")]
    public async Task Returned_private_bytes_are_cleared_on_success_failure_and_cancellation(string kind)
    {
        await using var f=await SealFixtures.Create(); using var cancelled=new CancellationTokenSource();
        var bytes=kind=="invalid" ? new byte[]{1,2,3} : f.Seal.Export(X509ContentType.Pkcs12);
        var source=new ReturnedMaterial(new(kind=="mismatch" ? f.Root.RawData : f.Seal.RawData,bytes),kind=="cancelled" ? cancelled : null);
        var provider=new KeyVaultSealCertificateProvider(Options(),source,f.Time);
        if(kind=="valid") {using var lease=await provider.AcquireAsync(default); Assert.True(lease.Certificate.HasPrivateKey);}
        else if(kind=="cancelled")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>provider.AcquireAsync(cancelled.Token));
        else await Assert.ThrowsAsync<SealUnavailableException>(()=>provider.AcquireAsync(default));
        Assert.All(bytes,x=>Assert.Equal((byte)0,x));
    }
    [Fact]
    public async Task Real_SDK_fetches_exact_backing_version_and_seals_with_the_selected_identity()
    {
        await using var f=await SealFixtures.Create(); using var transport=new SyntheticVault(f);
        var source=new SdkKeyVaultSealSource(transport,f.Time); var options=Options(); var provider=new KeyVaultSealCertificateProvider(options,source,f.Time);
        using var lease=await provider.AcquireAsync(default); Assert.Equal("KeyVault",lease.Provider); Assert.Equal(f.Seal.RawData,lease.Certificate.RawData); Assert.True(lease.Certificate.HasPrivateKey);
        Assert.Equal(new[]{"/certificates/synthetic", "/secrets/synthetic/private-version"},transport.Paths);
        var pdf=PdfFixtures.Create(text:"SYNTHETIC NO AGREEMENT"); var engine=new PlatformPdfSeal(f.Options,provider,f.Timestamps,f.App.Environment,f.Time);
        var sealedPdf=await engine.SealAsync(pdf,SHA256.HashData(pdf)); Assert.Equal("KeyVault",sealedPdf.Provider);
        _=await new SealCms(f.Options,f.Timestamps).VerifyAsync(sealedPdf.Bytes,f.Seal,sealedPdf.SealedAt,default); Assert.Equal(1,f.Requests);
    }
    [Theory]
    [InlineData("cross-vault")][InlineData("wrong-name")][InlineData("wrong-kind")][InlineData("no-version")][InlineData("query")]
    [InlineData("certificate-id")][InlineData("disabled-certificate")][InlineData("expired-certificate")][InlineData("future-certificate")]
    [InlineData("secret-id")][InlineData("disabled-secret")][InlineData("expired-secret")][InlineData("future-secret")]
    [InlineData("mime")][InlineData("base64")][InlineData("public-only")][InlineData("mismatch")][InlineData("malformed-pfx")]
    [InlineData("not-found")][InlineData("redirect")][InlineData("large-header")][InlineData("large-certificate")][InlineData("large-secret")]
    public async Task Invalid_scope_metadata_private_binding_or_unbounded_transport_never_returns_material(string mode)
    {
        await using var f=await SealFixtures.Create(); using var transport=new SyntheticVault(f) {Mode=mode};
        var provider=new KeyVaultSealCertificateProvider(Options(),new SdkKeyVaultSealSource(transport,f.Time),f.Time);
        var failure=await Assert.ThrowsAsync<SealUnavailableException>(()=>provider.AcquireAsync(default));
        Assert.DoesNotContain("vault.azure.net",failure.ToString()); Assert.Null(failure.InnerException);
        Assert.Equal(0,f.Requests); Assert.InRange(transport.Paths.Count,1,2);
        if(mode is "cross-vault" or "wrong-name" or "wrong-kind" or "no-version" or "query" or "certificate-id" or "disabled-certificate" or "expired-certificate" or "future-certificate" or "not-found" or "redirect" or "large-header" or "large-certificate")Assert.Single(transport.Paths);
        else Assert.Equal(2,transport.Paths.Count);
        if(mode=="mismatch")Assert.Contains("does not match",failure.Message);
        if(mode is "large-certificate" or "large-secret")Assert.InRange(transport.BytesRead,1,3*1024*1024+65536+1);
    }
    [Theory]
    [InlineData("http://synthetic.vault.azure.net", "synthetic", "")]
    [InlineData("https://synthetic.vault.azure.net/keys", "synthetic", "")]
    [InlineData("https://synthetic.vault.azure.net/?private=value", "synthetic", "")]
    [InlineData("https://synthetic.vault.azure.net.attacker.invalid", "synthetic", "")]
    [InlineData("https://synthetic.vault.azure.net", "../secret", "")]
    [InlineData("https://synthetic.vault.azure.net", "synthetic", "not-an-identity")]
    public async Task Invalid_configuration_never_constructs_or_calls_an_SDK_client(string uri,string name,string identity)
    {
        var options=new KeyVaultSealOptions {Uri=uri,CertificateName=name,ManagedIdentityClientId=identity}; var factory=new NoClients();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>new SdkKeyVaultSealSource(factory,TimeProvider.System).ReadAsync(options,default)); Assert.Equal(0,factory.Calls);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Linked_deadline_and_caller_cancellation_abort_the_transport_without_returning_private_material(bool caller)
    {
        await using var f=await SealFixtures.Create(); using var transport=new SyntheticVault(f) {Mode="slow"}; var options=Options(); options.KeyVault.TimeoutSeconds=1;
        using var cancelled=new CancellationTokenSource(); if(caller)cancelled.CancelAfter(100);
        var operation=new KeyVaultSealCertificateProvider(options,new SdkKeyVaultSealSource(transport,f.Time),f.Time);
        if(caller)await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>operation.AcquireAsync(cancelled.Token));
        else await Assert.ThrowsAsync<SealUnavailableException>(()=>operation.AcquireAsync(default));
        Assert.Single(transport.Paths);
    }
    private static SealOptions Options()=>new() {KeyVault=new() {Uri="https://synthetic.vault.azure.net",CertificateName="synthetic"}};
    private sealed class ReturnedMaterial(KeyVaultSealMaterial material,CancellationTokenSource? cancelled) : IKeyVaultSealSource
    {public Task<KeyVaultSealMaterial> ReadAsync(KeyVaultSealOptions options,CancellationToken ct) {cancelled?.Cancel(); return Task.FromResult(material);}}
    private sealed class NoClients : IKeyVaultSealClients {public int Calls; public KeyVaultSealClients Create(Uri vault,KeyVaultSealOptions options) {Calls++; throw new Exception();}}

    // Actual Azure SDK JSON/pipeline exercised entirely through a fake transport; no identity endpoint or vault is contacted.
    private sealed class SyntheticVault : HttpMessageHandler,IKeyVaultSealClients
    {
        private readonly SealFixtures fixture; private readonly HttpClient client; public string Mode="valid"; public List<string> Paths=new(); public int BytesRead;
        public SyntheticVault(SealFixtures fixture) {this.fixture=fixture; client=new(this,false);}
        public KeyVaultSealClients Create(Uri vault,KeyVaultSealOptions options)
        {
            var certificates=new CertificateClientOptions(); var secrets=new SecretClientOptions();
            void Configure(ClientOptions value,int maximum) {value.Transport=new HttpClientTransport(client); value.Retry.MaxRetries=0; value.Diagnostics.IsLoggingEnabled=false; value.AddPolicy(new SealResponseLimit(maximum),HttpPipelinePosition.PerCall);}
            Configure(certificates,64*1024); Configure(secrets,3*1024*1024);
            return new(new CertificateClient(vault,new SyntheticCredential(),certificates),new SecretClient(vault,new SyntheticCredential(),secrets));
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            Assert.Equal("synthetic.vault.azure.net",request.RequestUri!.Host); var path=request.RequestUri.AbsolutePath; Paths.Add(path);
            if(Mode=="slow")await Task.Delay(10000,ct);
            var isCertificate=path=="/certificates/synthetic"; if(!isCertificate)Assert.Equal("/secrets/synthetic/private-version",path);
            if(Mode=="not-found")return new(HttpStatusCode.NotFound) {Content=new StringContent("{\"error\":{\"code\":\"SecretNotFound\",\"message\":\"synthetic private location\"}}")};
            if(Mode=="redirect")return new(HttpStatusCode.Redirect) {Headers={Location=new Uri("https://unexpected.invalid/")},Content=new StringContent("")};
            var now=fixture.Time.GetUtcNow(); var attributes=new Dictionary<string,object> { ["enabled"]=true,["nbf"]=now.AddMinutes(-1).ToUnixTimeSeconds(),["exp"]=now.AddDays(1).ToUnixTimeSeconds() };
            var values=new Dictionary<string,object>(); var origin="https://synthetic.vault.azure.net";
            if(isCertificate) {
                var sid=origin+"/secrets/synthetic/private-version";
                sid=Mode switch {"cross-vault"=>"https://other.vault.azure.net/secrets/synthetic/private-version","wrong-name"=>origin+"/secrets/other/private-version","wrong-kind"=>origin+"/keys/synthetic/private-version","no-version"=>origin+"/secrets/synthetic","query"=>sid+"?private=value",_=>sid};
                values["id"]=origin+"/certificates/"+(Mode=="certificate-id" ? "other" : "synthetic")+"/public-version"; values["sid"]=sid;
                values["cer"]=Convert.ToBase64String(fixture.Seal.RawData);
            }
            else {
                values["id"]=origin+"/secrets/synthetic/"+(Mode=="secret-id" ? "wrong-version" : "private-version"); values["contentType"]=Mode=="mime" ? "application/x-pem-file" : "application/x-pkcs12";
                using var publicOnly=Mode=="public-only" ? X509CertificateLoader.LoadCertificate(fixture.Seal.RawData) : null;
                using var alternativeKey=Mode=="mismatch" ? RSA.Create(2048) : null;
                using var alternative=alternativeKey is not null ? new CertificateRequest("CN=Synthetic alternative - NO AGREEMENT",alternativeKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1).CreateSelfSigned(now.AddMinutes(-1),now.AddDays(1)) : null;
                var pfx=(alternative ?? publicOnly ?? fixture.Seal).Export(X509ContentType.Pkcs12);
                try {values["value"]=Mode switch {"base64"=>"not base64", "malformed-pfx"=>Convert.ToBase64String(new byte[]{1,2,3}),_=>Convert.ToBase64String(pfx)};} finally {CryptographicOperations.ZeroMemory(pfx);}
            }
            var suffix=isCertificate ? "certificate" : "secret";
            if(Mode=="disabled-"+suffix)attributes["enabled"]=false;
            if(Mode=="expired-"+suffix)attributes["exp"]=now.AddMinutes(-1).ToUnixTimeSeconds();
            if(Mode=="future-"+suffix)attributes["nbf"]=now.AddMinutes(1).ToUnixTimeSeconds();
            values["attributes"]=attributes; var json=JsonSerializer.Serialize(values);
            if(Mode=="large-certificate" && isCertificate || Mode=="large-secret" && !isCertificate)json="{\"ignored\":\""+new string('x',4*1024*1024)+"\"}";
            var content=new StreamContent(new ObservedStream(Encoding.UTF8.GetBytes(json),count=>BytesRead+=count)); content.Headers.ContentType=new("application/json");
            if(Mode=="large-header")content.Headers.ContentLength=4*1024*1024;
            return new(HttpStatusCode.OK) {Content=content};
        }
        protected override void Dispose(bool disposing) {if(disposing)client.Dispose(); base.Dispose(disposing);}
        private sealed class SyntheticCredential : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext context,CancellationToken ct)=>new("synthetic-no-agreement",DateTimeOffset.UtcNow.AddHours(1));
            public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context,CancellationToken ct)=>ValueTask.FromResult(GetToken(context,ct));
        }
        private sealed class ObservedStream(byte[] bytes,Action<int> read) : MemoryStream(bytes,false)
        {
            public override bool CanSeek=>false;
            public override int Read(byte[] buffer,int offset,int count) {var result=base.Read(buffer,offset,count); read(result); return result;}
            public override int Read(Span<byte> buffer) {var result=base.Read(buffer); read(result); return result;}
            public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default) {ct.ThrowIfCancellationRequested(); return ValueTask.FromResult(Read(buffer.Span));}
        }
    }
}

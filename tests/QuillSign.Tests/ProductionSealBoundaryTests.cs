using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using QuillSign.Sealing;

namespace QuillSign.Tests;

public sealed class ProductionSealBoundaryTests
{
    [Theory]
    [InlineData("valid")][InlineData("ec")]
    public async Task Original_identity_and_actual_request_response_are_bound_to_one_local_timestamp(string key)
    {
        await using var f=await SealFixtures.Create(key);var source=PdfFixtures.Create();var hash=SHA256.HashData(source);var gate=new Boundary();
        var result=await f.Engine.SealBoundAdmittedAsync(source,hash,SHA256.HashData(f.Seal.RawData),gate);
        Assert.Equal(1,f.Requests);Assert.Equal(1,gate.Starts);Assert.Equal(1,gate.Sends);Assert.Equal(1,gate.Records);
        Assert.Equal(result.CertificateSha256,gate.Identity!.CertificateSha256);Assert.Equal(result.SealedAt,gate.Identity.SealedAt);
        Assert.Equal(Convert.ToHexStringLower(hash),gate.Identity.SourceSha256);
        using var leaf=X509CertificateLoader.LoadCertificate(Convert.FromBase64String(gate.Identity.CertificateDer));Assert.False(leaf.HasPrivateKey);
        Assert.Equal(f.Seal.RawData,leaf.RawData);var request=gate.Request!;var response=gate.Response!;
        Assert.Equal(f.RequestBodies.Single(),Convert.FromBase64String(request.Encoded));Assert.Equal(Hash(Convert.FromBase64String(request.Encoded)),request.Sha256);
        Assert.Equal(Hash(Convert.FromBase64String(response.Encoded)),response.Sha256);
        Assert.Equal(Hash(Convert.FromBase64String(response.Token)),response.TokenSha256);
        Assert.Equal(result.TimestampAt,response.At);Assert.Equal(result.TimestampPolicy,response.Policy);
        Assert.Equal(result.TimestampCertificateSha256,response.CertificateSha256);Assert.True(gate.Demands>10);
    }

    [Theory]
    [InlineData("identity",0)][InlineData("begin",0)][InlineData("send",0)]
    [InlineData("response",1)][InlineData("after-response",1)]
    public async Task Refusal_or_unknown_acknowledgment_returns_no_seal_and_never_repeats_the_request(string fault,int requests)
    {
        await using var f=await SealFixtures.Create();var source=PdfFixtures.Create();var gate=new Boundary{Fault=fault};
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAdmittedAsync(source,SHA256.HashData(source),gate));
        Assert.Equal(requests,f.Requests);gate.Fault=null;
        // Reusing a consumed factual context is not another timestamp permission.
        if(fault!="identity")
        {
            await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAdmittedAsync(source,SHA256.HashData(source),gate));
            Assert.Equal(requests,f.Requests);
        }
        Assert.Equal(fault=="after-response" ? 1 : 0,gate.Records);
    }

    [Fact]
    public async Task Wrong_bound_certificate_refuses_before_context_or_timestamp_effects()
    {
        await using var f=await SealFixtures.Create();var source=PdfFixtures.Create();var gate=new Boundary();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealBoundAdmittedAsync(source,SHA256.HashData(source),new byte[32],gate));
        Assert.Null(gate.Identity);Assert.Equal(0,gate.Starts);Assert.Equal(0,f.Requests);
    }

    [Fact]
    public async Task Local_signature_sizing_has_no_request_and_one_signer_cannot_timestamp_twice()
    {
        await using var f=await SealFixtures.Create();using var material=await f.Certificates.AcquireAsync(default);var gate=new Boundary();
        var signer=new SealCms.Signer(f.Options,material,f.Timestamps,f.Time.GetUtcNow(),default,admission:gate);
        Assert.Equal(await signer.GetSignatureSizeAsync(),await signer.GetSignatureSizeAsync());Assert.Equal(0,gate.Starts);Assert.Equal(0,f.Requests);
        Assert.NotEmpty(await signer.GetSignatureAsync(new MemoryStream([1,2,3])));Assert.Equal(1,f.Requests);
        await Assert.ThrowsAsync<SealUnavailableException>(()=>signer.GetSignatureAsync(new MemoryStream([1,2,3])));Assert.Equal(1,f.Requests);
    }

    [Theory]
    [InlineData("redirect")][InlineData("nonce")][InlineData("trailing")][InlineData("http")]
    public async Task Invalid_actual_response_cannot_be_recorded_or_redirected(string mode)
    {
        await using var f=await SealFixtures.Create();f.Mode=mode;var source=PdfFixtures.Create();var gate=new Boundary();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAdmittedAsync(source,SHA256.HashData(source),gate));
        Assert.Equal(1,f.Requests);Assert.Equal(0,f.RedirectRequests);Assert.Equal(0,gate.Records);Assert.Null(gate.Response);
    }

    private static string Hash(byte[] bytes)=>Convert.ToHexStringLower(SHA256.HashData(bytes));
    private sealed class Boundary:IProductionSealBoundary,IProductionTimestampPermit
    {
        internal string? Fault;internal ProductionSealIdentity? Identity;internal ProductionTimestampRequest? Request;
        internal ProductionTimestampResponse? Response;internal int Starts,Sends,Records,Demands;
        public Task DemandAsync(CancellationToken ct)
        {ct.ThrowIfCancellationRequested();Demands++;if(Fault=="after-response"&&Records!=0)throw new InvalidOperationException("Synthetic final fence refusal.");return Task.CompletedTask;}
        public Task PrepareIdentityAsync(ProductionSealIdentity identity,CancellationToken ct)
        {ct.ThrowIfCancellationRequested();if(Fault=="identity")throw new InvalidOperationException("Synthetic identity failure.");if(Identity is not null)Assert.Equal(Identity,identity);Identity=identity;return Task.CompletedTask;}
        public Task<IProductionTimestampPermit> BeginTimestampAsync(ProductionTimestampRequest request,CancellationToken ct)
        {ct.ThrowIfCancellationRequested();Starts++;if(Starts!=1)throw new InvalidOperationException("Synthetic consumed original request.");Request=request;if(Fault=="begin")throw new InvalidOperationException("Synthetic lost start acknowledgment.");return Task.FromResult<IProductionTimestampPermit>(this);}
        public Task DemandSendAsync(ProductionTimestampRequest request,CancellationToken ct)
        {ct.ThrowIfCancellationRequested();Assert.Equal(Request,request);if(Fault=="send")throw new InvalidOperationException("Synthetic request fence refusal.");if(++Sends!=1)throw new InvalidOperationException("Synthetic reused request.");return Task.CompletedTask;}
        public Task RecordVerifiedAsync(ProductionTimestampRequest request,ProductionTimestampResponse response,CancellationToken ct)
        {ct.ThrowIfCancellationRequested();Assert.Equal(Request,request);if(Fault=="response")throw new InvalidOperationException("Synthetic lost result acknowledgment.");Response=response;Records++;return Task.CompletedTask;}
    }
}

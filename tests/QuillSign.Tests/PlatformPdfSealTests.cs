using System.Security.Cryptography;
using System.Text;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Signatures;
using QuillSign.Documents;
using QuillSign.Sealing;

namespace QuillSign.Tests;

public sealed class PlatformPdfSealTests
{
    [Theory]
    [InlineData("valid")][InlineData("ec")]
    public async Task Reservation_sizes_local_CMS_without_timestamping_and_retains_old_padded_seal_verification(string kind)
    {
        await using var f=await SealFixtures.Create(kind);
        using var material=await f.Certificates.AcquireAsync(default);
        var signer=new SealCms.Signer(f.Options,material,f.Timestamps,f.Time.GetUtcNow(),default);
        var size=await signer.GetSignatureSizeAsync();
        Assert.Equal(size,await signer.GetSignatureSizeAsync()); Assert.Equal(0,f.Requests);
        Assert.InRange(size,f.Options.TsaMaximumResponseBytes+1024,76*1024);
        Assert.True(size<f.Options.SignatureCapacityBytes);
        // A pre-existing document may reserve the full configured ceiling. Verification
        // continues to require the exact full-file ByteRange, CMS and all-zero padding.
        using var document=PdfReader.Open(new MemoryStream(PdfFixtures.Create()),PdfDocumentOpenMode.Modify);
        DigitalSignatureHandler.ForDocument(document,new FixedReservationSigner(signer,f.Options.SignatureCapacityBytes),new DigitalSignatureOptions());
        using var output=new MemoryStream(); await document.SaveAsync(output,false);
        var legacy=output.ToArray();
        _=await new SealCms(f.Options,f.Timestamps).VerifyAsync(legacy,f.Seal,f.Time.GetUtcNow(),default);
        Assert.Equal(1,f.Requests);
        var source=PdfFixtures.Create(); var current=await f.Engine.SealAsync(source,SHA256.HashData(source));
        Assert.True(legacy.Length-current.Bytes.Length>90*1024); Assert.Equal(2,f.Requests);
    }

    [Fact]
    public async Task Reservation_accounts_for_embedded_chain_bytes_and_honors_the_configured_ceiling()
    {
        await using var f=await SealFixtures.Create();
        using var material=await f.Certificates.AcquireAsync(default);
        var ordinary=await new SealCms.Signer(f.Options,material,f.Timestamps,f.Time.GetUtcNow(),default).GetSignatureSizeAsync();
        using var key=RSA.Create(2048);
        var request=new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Synthetic chain test",key,
            HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension("1.2.3.4.9",new byte[16000],false));
        using var extra=request.CreateSelfSigned(f.Time.GetUtcNow().AddDays(-1),f.Time.GetUtcNow().AddDays(1));
        // Each lease owns distinct handles, including the public chain certificate.
        using var expanded=new SealCertificateMaterial("Synthetic",System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(
            f.Seal.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12),null),
            [System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(extra.RawData)]);
        var size=await new SealCms.Signer(f.Options,expanded,f.Timestamps,f.Time.GetUtcNow(),default).GetSignatureSizeAsync();
        Assert.True(size>=ordinary+12*1024); Assert.True(size<=f.Options.SignatureCapacityBytes);
        f.Options.SignatureCapacityBytes=32*1024;
        Assert.Equal(32*1024,await new SealCms.Signer(f.Options,expanded,f.Timestamps,f.Time.GetUtcNow(),default).GetSignatureSizeAsync());
        Assert.Equal(0,f.Requests);
    }

    [Fact]
    public async Task Large_valid_timestamp_fits_the_response_bound_without_sizing_network_calls()
    {
        await using var f=await SealFixtures.Create(); f.Mode="capacity";
        var source=PdfFixtures.Create(); var result=await f.Engine.SealAsync(source,SHA256.HashData(source));
        Assert.Equal(1,f.Requests);
        _=await new SealCms(f.Options,f.Timestamps).VerifyAsync(result.Bytes,f.Seal,result.SealedAt,default);
    }

    private sealed class FixedReservationSigner(IDigitalSigner inner,int capacity) : IDigitalSigner
    {
        public string CertificateName=>inner.CertificateName;
        public Task<int> GetSignatureSizeAsync()=>Task.FromResult(capacity);
        public Task<byte[]> GetSignatureAsync(Stream stream)=>inner.GetSignatureAsync(stream);
    }
    [Fact]
    public async Task Bound_seals_reject_identity_changes_before_timestamping_and_return_only_the_verified_public_leaf()
    {
        await using var f=await SealFixtures.Create(); var source=PdfFixtures.Create(); var hash=SHA256.HashData(source);
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealBoundAsync(source,hash,RandomNumberGenerator.GetBytes(32)));
        Assert.Equal(0,f.Requests);
        var result=await f.Engine.SealBoundAsync(source,hash,SHA256.HashData(f.Seal.RawData));
        Assert.Equal(f.Seal.RawData,result.CertificateDer); Assert.Equal(1,f.Requests);
        using var publicLeaf=System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(result.CertificateDer);
        Assert.False(publicLeaf.HasPrivateKey);
    }

    [Fact]
    public async Task Timestamp_responses_cannot_create_cookie_state_for_later_operations()
    {
        await using var f=await SealFixtures.Create(); f.Mode="cookie"; var source=PdfFixtures.Create();
        _=await f.Engine.SealAsync(source,SHA256.HashData(source)); _=await f.Engine.SealAsync(source,SHA256.HashData(source));
        Assert.Equal(2,f.Requests); Assert.Equal(0,f.CookieRequests);
    }
    [Fact]
    public async Task EC_private_keys_and_concurrent_operations_use_isolated_signers_and_one_timestamp_each()
    {
        await using var f=await SealFixtures.Create("ec"); var source=PdfFixtures.Create(); var hash=SHA256.HashData(source);
        var results=await Task.WhenAll(Enumerable.Range(0,3).Select(_=>f.Engine.SealAsync(source,hash)));
        Assert.Equal(3,f.Requests); Assert.Equal(3,f.Certificates.Calls); Assert.Equal(3,results.Select(x=>Convert.ToHexStringLower(x.Sha256)).Distinct().Count());
        foreach(var result in results) { Assert.Equal(hash,result.SourceSha256); _=await new SealCms(f.Options,f.Timestamps).VerifyAsync(result.Bytes,f.Seal,result.SealedAt,default); }
    }
    [Theory]
    [InlineData("weak")][InlineData("expired")]
    public async Task Timestamp_certificates_must_have_suitable_key_strength_and_validity(string kind)
    {
        await using var f=await SealFixtures.Create(tsaKind:kind); var source=PdfFixtures.Create();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source))); Assert.Equal(1,f.Requests);
    }
    [Fact]
    public async Task Output_limit_is_enforced_before_an_oversized_placeholder_can_be_timestamped()
    {
        await using var f=await SealFixtures.Create(); var source=PdfFixtures.Create(); f.Options.MaximumBytes=64*1024;
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source))); Assert.Equal(0,f.Requests);
    }

    [Fact]
    public async Task Seals_exact_prepared_source_once_with_verified_full_file_CMS_and_timestamp()
    {
        await using var f=await SealFixtures.Create(); var source=PdfFixtures.Create(text:"SYNTHETIC LOCAL TEST ONLY - NO AGREEMENT"); var preserved=source.ToArray();
        var result=await f.Engine.SealAsync(source,SHA256.HashData(source)); Assert.Equal(preserved,source); Assert.NotEqual(source,result.Bytes);
        Assert.Equal(SHA256.HashData(source),result.SourceSha256); Assert.Equal(SHA256.HashData(result.Bytes),result.Sha256); Assert.Equal(2,result.PageCount);
        Assert.Equal("Pfx",result.Provider); Assert.Equal(1,f.Requests); Assert.Equal(1,f.Certificates.Calls); Assert.Equal(f.Time.GetUtcNow(),result.SealedAt);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(f.Seal.RawData)),result.CertificateSha256); Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(f.Tsa.RawData)),result.TimestampCertificateSha256);
        var verified=await new SealCms(f.Options,f.Timestamps).VerifyAsync(result.Bytes,f.Seal,result.SealedAt,default);
        Assert.Equal(result.TimestampAt,verified.Timestamp.At); Assert.Equal("1.2.3.4.1",result.TimestampPolicy);
        using var pdf=PdfReader.Open(new MemoryStream(result.Bytes),PdfDocumentOpenMode.Import); Assert.False(pdf.SecuritySettings.IsEncrypted);
        // Optional ignored evidence for independent OpenSSL/rendering QA; no private key is exported here.
        if(Environment.GetEnvironmentVariable("QUILLSIGN_SEAL_ARTIFACTS") is {Length:>0} directory) {
            Directory.CreateDirectory(directory); await File.WriteAllBytesAsync(Path.Combine(directory,"source.pdf"),source); await File.WriteAllBytesAsync(Path.Combine(directory,"sealed.pdf"),result.Bytes);
            await File.WriteAllBytesAsync(Path.Combine(directory,"signature.der"),verified.Cms); await File.WriteAllBytesAsync(Path.Combine(directory,"signed-bytes.bin"),verified.SignedBytes);
            await File.WriteAllBytesAsync(Path.Combine(directory,"timestamp.der"),verified.Timestamp.Encoded); await File.WriteAllTextAsync(Path.Combine(directory,"tsa-root.crt"),f.Root.ExportCertificatePem());
            var cms=new System.Security.Cryptography.Pkcs.SignedCms(new System.Security.Cryptography.Pkcs.ContentInfo(verified.SignedBytes),true); cms.Decode(verified.Cms);
            await File.WriteAllBytesAsync(Path.Combine(directory,"signature-value.bin"),cms.SignerInfos[0].GetSignature());
        }
    }
    [Theory]
    [InlineData(0)][InlineData(90)][InlineData(180)][InlineData(270)]
    public async Task Sealing_preserves_page_geometry_text_and_source_hash(int rotation)
    {
        await using var f=await SealFixtures.Create(); var source=PdfFixtures.Create(rotation:rotation,media:"10 20 622 812",pageEntries:"/CropBox [25 35 600 780] /UserUnit 1.5",text:"SYNTHETIC NO AGREEMENT");
        var result=await f.Engine.SealAsync(source,SHA256.HashData(source));
        using var before=PdfReader.Open(new MemoryStream(source),PdfDocumentOpenMode.Import); using var after=PdfReader.Open(new MemoryStream(result.Bytes),PdfDocumentOpenMode.Import);
        for(var i=0;i<before.PageCount;i++) { Assert.Equal(before.Pages[i].MediaBox,after.Pages[i].MediaBox); Assert.Equal(before.Pages[i].CropBoxReadOnly,after.Pages[i].CropBoxReadOnly); Assert.Equal(before.Pages[i].Rotate,after.Pages[i].Rotate); Assert.Equal(1.5,after.Pages[i].Elements.GetReal("/UserUnit")); }
        using var text=UglyToad.PdfPig.PdfDocument.Open(result.Bytes); Assert.Contains("SYNTHETIC NO AGREEMENT",text.GetPage(1).Text);
    }
    [Theory]
    [InlineData("http")][InlineData("redirect")][InlineData("malformed")][InlineData("large")][InlineData("chunked-large")][InlineData("mime")][InlineData("trailing")]
    [InlineData("nonce")][InlineData("imprint")][InlineData("algorithm")][InlineData("stale")][InlineData("future")][InlineData("eku")][InlineData("signature")]
    public async Task Invalid_timestamp_transport_profile_or_binding_never_returns_a_seal(string mode)
    {
        await using var f=await SealFixtures.Create(); f.Mode=mode; var source=PdfFixtures.Create();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source))); Assert.Equal(1,f.Requests); Assert.Equal(0,f.RedirectRequests);
        f.Mode="valid"; Assert.NotEmpty((await f.Engine.SealAsync(source,SHA256.HashData(source))).Bytes); Assert.Equal(2,f.Requests);
    }
    [Theory]
    [InlineData("expired")][InlineData("future")][InlineData("usage")][InlineData("purpose")][InlineData("ca")][InlineData("weak")][InlineData("public")]
    public async Task Unusable_private_certificate_material_is_not_replaced_by_an_ephemeral_fallback(string kind)
    {
        await using var f=await SealFixtures.Create(kind); var source=PdfFixtures.Create();
        await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source))); Assert.Equal(0,f.Requests);
    }
    [Theory]
    [InlineData("missing")][InlineData("password")][InlineData("corrupt")][InlineData("size")]
    public async Task Pfx_loading_is_bounded_and_requires_the_configured_private_material(string kind)
    {
        await using var f=await SealFixtures.Create();
        if(kind=="missing")File.Delete(f.Options.Pfx.Path); if(kind=="password")f.Options.Pfx.Password=Guid.NewGuid().ToString();
        if(kind=="corrupt")await File.WriteAllBytesAsync(f.Options.Pfx.Path,[1,2,3]); if(kind=="size")await File.WriteAllBytesAsync(f.Options.Pfx.Path,new byte[2*1024*1024+1]);
        var source=PdfFixtures.Create(); await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source))); Assert.Equal(0,f.Requests);
    }
    [Theory]
    [InlineData("untrusted")][InlineData("capacity")][InlineData("timeout")][InlineData("cancel")]
    public async Task Trust_capacity_timeout_and_cancellation_fail_closed_and_release_the_operation_gate(string kind)
    {
        await using var f=await SealFixtures.Create(); var source=PdfFixtures.Create();
        if(kind=="untrusted")f.Options.TsaTrustedRootPaths=[]; if(kind=="capacity") { f.Options.SignatureCapacityBytes=32*1024; f.Mode="capacity"; }
        if(kind is "timeout" or "cancel") { f.Mode="slow"; f.Options.TsaTimeoutSeconds=1; }
        using var ct=new CancellationTokenSource(); if(kind=="cancel")ct.CancelAfter(TimeSpan.FromMilliseconds(100));
        if(kind=="cancel")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source),ct.Token));
        else await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,SHA256.HashData(source),ct.Token));
        Assert.Equal(0,f.RedirectRequests); f.Mode="valid"; f.Options.TsaTrustedRootPaths=[Path.Combine(Path.GetDirectoryName(f.Options.Pfx.Path)!,"synthetic-root.cer")];
        Assert.NotEmpty((await f.Engine.SealAsync(source,SHA256.HashData(source))).Bytes);
    }
    [Theory]
    [InlineData("missing-tsa")][InlineData("production-http")][InlineData("query")][InlineData("hash")][InlineData("size")][InlineData("malformed")][InlineData("encrypted")][InlineData("fields")]
    public async Task Missing_configuration_or_unprepared_source_is_rejected_before_private_key_or_timestamp_work(string kind)
    {
        await using var f=await SealFixtures.Create(); var source=kind=="encrypted" ? PdfFixtures.Encrypted(false) : kind=="fields" ? PdfFixtures.Create(catalog:"/AcroForm << /Fields [<< /FT /Tx /T (synthetic) /V (unflattened) >>] >>") : PdfFixtures.Create();
        var hash=SHA256.HashData(source);
        if(kind=="missing-tsa")f.Options.TsaUrl=""; if(kind=="production-http")f.App.Environment.EnvironmentName="Production"; if(kind=="query")f.Options.TsaUrl+="?credential=synthetic";
        if(kind=="hash")hash=new byte[32]; if(kind=="size")f.Options.MaximumBytes=1024; if(kind=="malformed") { source=[..source[..^20]]; hash=SHA256.HashData(source); }
        if(kind is "missing-tsa" or "production-http" or "query")await Assert.ThrowsAsync<SealUnavailableException>(()=>f.Engine.SealAsync(source,hash));
        else await Assert.ThrowsAsync<DocumentRejectedException>(()=>f.Engine.SealAsync(source,hash));
        Assert.Equal(0,f.Certificates.Calls); Assert.Equal(0,f.Requests);
    }
    [Theory]
    [InlineData("content")][InlineData("truncated")][InlineData("trailing")][InlineData("padding")][InlineData("certificate")][InlineData("already-signed")]
    public async Task Tampering_or_a_different_identity_cannot_pass_complete_output_verification(string kind)
    {
        await using var f=await SealFixtures.Create(); var source=PdfFixtures.Create(); var result=await f.Engine.SealAsync(source,SHA256.HashData(source)); var bytes=result.Bytes.ToArray();
        if(kind=="content") { var index=Encoding.Latin1.GetString(bytes).IndexOf("QuillSign completion integrity seal",StringComparison.Ordinal); Assert.True(index>0); bytes[index]^=1; }
        if(kind=="truncated")bytes=bytes[..^20]; if(kind=="trailing")bytes=[..bytes,..Encoding.ASCII.GetBytes("\n% unsigned later bytes\n")];
        if(kind=="padding") { var content=Encoding.Latin1.GetString(bytes); var gap=content.IndexOf("/ByteRange",StringComparison.Ordinal); Assert.True(gap>0); var start=content.LastIndexOf("/Contents",gap,StringComparison.Ordinal); Assert.True(start>0); var end=content.IndexOf('>',start); bytes[end-1]=(byte)'1'; }
        if(kind=="already-signed")await Assert.ThrowsAsync<DocumentRejectedException>(()=>f.Engine.SealAsync(bytes,SHA256.HashData(bytes)));
        else await Assert.ThrowsAsync<SealUnavailableException>(()=>new SealCms(f.Options,f.Timestamps).VerifyAsync(bytes,kind=="certificate" ? f.Tsa : f.Seal,result.SealedAt,default));
        Assert.Equal(1,f.Requests);
    }
}

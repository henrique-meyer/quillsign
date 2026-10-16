using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using QuillSign.Sealing;

namespace QuillSign.Tests;

// Synthetic loopback authority. Its clock/certificates are test inputs, not an operator TSA.
internal sealed class SealFixtures : IAsyncDisposable
{
    public SealOptions Options=new(); public Clock Time=new(); public WebApplication App=null!;
    public TimestampAuthority Timestamps=null!; public CountingProvider Certificates=null!; public PlatformPdfSeal Engine=null!;
    public X509Certificate2 Root=null!,Tsa=null!,Seal=null!,BadEku=null!; public RSA RootKey=null!,TsaKey=null!;
    public TimeStampTokenGenerator Tokens=null!; public string Mode="valid"; public int Requests,RedirectRequests,CookieRequests;
    private string directory="";
    public static async Task<SealFixtures> Create(string certificateKind="valid",string tsaKind="valid")
    {
        var f=new SealFixtures(); f.directory=Path.Combine(Path.GetTempPath(),"quillsign-seal-test-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(f.directory);
        f.RootKey=RSA.Create(2048); f.TsaKey=RSA.Create(tsaKind=="weak" ? 1024 : 2048); using var sealKey=RSA.Create(certificateKind=="weak" ? 1024 : 2048);
        using var ecKey=certificateKind=="ec" ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : null;
        var now=f.Time.GetUtcNow(); var rootRequest=new CertificateRequest("CN=QuillSign synthetic TSA root",f.RootKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        f.Root=rootRequest.CreateSelfSigned(now.AddDays(-2),now.AddDays(10));
        X509Certificate2 IssueTsa(bool eku) {
            var request=new CertificateRequest("CN=QuillSign synthetic TSA",f.TsaKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));
            if(eku)request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {new("1.3.6.1.5.5.7.3.8")},true));
            using var certificate=request.Create(f.Root,now.AddDays(-1),tsaKind=="expired" ? now.AddSeconds(-1) : now.AddDays(7),RandomNumberGenerator.GetBytes(16)); return certificate.CopyWithPrivateKey(f.TsaKey);
        }
        f.Tsa=IssueTsa(true); f.BadEku=IssueTsa(false);
        var sealRequest=ecKey is null ? new CertificateRequest("CN=QuillSign synthetic platform seal - NO AGREEMENT",sealKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1) :
            new CertificateRequest("CN=QuillSign synthetic EC platform seal - NO AGREEMENT",ecKey,HashAlgorithmName.SHA256);
        sealRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateKind=="ca",false,0,true));
        sealRequest.CertificateExtensions.Add(new X509KeyUsageExtension(certificateKind=="usage" ? X509KeyUsageFlags.KeyEncipherment : X509KeyUsageFlags.DigitalSignature,true));
        sealRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {new(certificateKind=="purpose" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.36")},false));
        f.Seal=sealRequest.CreateSelfSigned(certificateKind=="future" ? now.AddDays(1) : now.AddDays(-1),certificateKind=="expired" ? now.AddSeconds(-1) : now.AddDays(7));
        f.Options.Pfx.Path=Path.Combine(f.directory,"synthetic.pfx"); f.Options.Pfx.Password=Guid.NewGuid().ToString("N");
        var pfx=certificateKind=="public" ? new X509Certificate2Collection(X509CertificateLoader.LoadCertificate(f.Seal.RawData)).Export(X509ContentType.Pkcs12,f.Options.Pfx.Password)! : f.Seal.Export(X509ContentType.Pkcs12,f.Options.Pfx.Password);
        await File.WriteAllBytesAsync(f.Options.Pfx.Path,pfx); CryptographicOperations.ZeroMemory(pfx);
        var rootPath=Path.Combine(f.directory,"synthetic-root.cer"); await File.WriteAllBytesAsync(rootPath,f.Root.RawData); f.Options.TsaTrustedRootPaths=[rootPath];
        var bcCertificate=new X509CertificateParser().ReadCertificate(f.Tsa.RawData); var info=new SignerInfoGeneratorBuilder().Build(new Asn1SignatureFactory("SHA256WITHRSA",DotNetUtilities.GetRsaKeyPair(f.TsaKey).Private),bcCertificate);
        f.Tokens=new TimeStampTokenGenerator(info,Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256),new DerObjectIdentifier("1.2.3.4.1"),true);
        f.Tokens.SetCertificates(CollectionUtilities.CreateStore([bcCertificate,new X509CertificateParser().ReadCertificate(f.Root.RawData)]));
        var builder=WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName="Development" }); builder.Logging.ClearProviders(); builder.WebHost.UseUrls("http://127.0.0.1:0"); f.App=builder.Build();
        f.App.MapPost("/",f.Handle); f.App.MapPost("/redirect-target",()=> { Interlocked.Increment(ref f.RedirectRequests); return Results.Ok(); }); await f.App.StartAsync();
        f.Options.TsaUrl=f.App.Urls.Single(); f.Timestamps=new(f.Options,f.App.Environment,f.Time);
        f.Certificates=new(new PfxSealCertificateProvider(f.Options,f.Time)); f.Engine=new(f.Options,f.Certificates,f.Timestamps,f.App.Environment,f.Time); return f;
    }
    private async Task Handle(HttpContext context)
    {
        var serial=Interlocked.Increment(ref Requests); context.Response.ContentType="application/timestamp-reply";
        if(context.Request.Headers.Cookie.Count>0)Interlocked.Increment(ref CookieRequests);
        if(Mode=="cookie")context.Response.Cookies.Append("synthetic-tsa-session","synthetic-no-agreement");
        if(Mode=="http") { context.Response.StatusCode=503; return; }
        if(Mode=="redirect") { context.Response.Redirect(Options.TsaUrl+"/redirect-target"); return; }
        if(Mode=="slow") { await Task.Delay(TimeSpan.FromSeconds(10),context.RequestAborted); return; }
        if(Mode=="malformed") { await context.Response.Body.WriteAsync(new byte[]{1,2,3}); return; }
        if(Mode is "large" or "chunked-large") { if(Mode=="large")context.Response.ContentLength=Options.TsaMaximumResponseBytes+1; await context.Response.Body.WriteAsync(new byte[Options.TsaMaximumResponseBytes+1]); return; }
        using var memory=new MemoryStream(); await context.Request.Body.CopyToAsync(memory); var request=new TimeStampRequest(memory.ToArray());
        if(Mode is "imprint" or "nonce" or "algorithm") { var generator=new TimeStampRequestGenerator(); generator.SetCertReq(true);
            request=generator.Generate(Mode=="algorithm" ? TspAlgorithms.Sha384 : TspAlgorithms.Sha256,Mode=="imprint" ? new byte[32] : Mode=="algorithm" ? new byte[48] : request.GetMessageImprintDigest(),Mode=="nonce" ? request.Nonce.Add(Org.BouncyCastle.Math.BigInteger.One) : request.Nonce); }
        var at=Time.GetUtcNow()+(Mode=="stale" ? TimeSpan.FromMinutes(-10) : Mode=="future" ? TimeSpan.FromMinutes(10) : TimeSpan.Zero);
        var response=new TimeStampResponseGenerator(Tokens,[TspAlgorithms.Sha256,TspAlgorithms.Sha384]).Generate(request,Org.BouncyCastle.Math.BigInteger.ValueOf(serial),at.UtcDateTime);
        var encoded=response.GetEncoded();
        if(Mode is "eku" or "capacity" or "signature") {
            var cms=new SignedCms(); cms.Decode(response.TimeStampToken.ToCmsSignedData().GetEncoded());
            if(Mode=="eku") {
                var wrong=new SignedCms(new ContentInfo(cms.ContentInfo.ContentType,cms.ContentInfo.Content),false);
                var signer=new CmsSigner(BadEku) { DigestAlgorithm=new Oid(SealCms.Sha256),IncludeOption=X509IncludeOption.EndCertOnly };
                signer.SignedAttributes.Add(new AsnEncodedData(new Oid(SealCms.CertificateBindingOid),new SigningCertificateV2(new EssCertIDv2(SHA256.HashData(BadEku.RawData))).GetDerEncoded()));
                wrong.ComputeSignature(signer,true); cms=wrong;
            }
            else if(Mode=="capacity")cms.SignerInfos[0].AddUnsignedAttribute(new AsnEncodedData(new Oid("1.2.3.4.9"),new DerOctetString(new byte[40000]).GetDerEncoded()));
            var token=cms.Encode(); if(Mode=="signature") { var sig=cms.SignerInfos[0].GetSignature(); var index=token.AsSpan().LastIndexOf(sig); token[index]^=1; }
            var writer=new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER); writer.PushSequence(); writer.PushSequence(); writer.WriteInteger(0); writer.PopSequence(); writer.WriteEncodedValue(token); writer.PopSequence(); encoded=writer.Encode();
        }
        if(Mode=="mime")context.Response.ContentType="text/plain";
        if(Mode=="trailing")encoded=[..encoded,0];
        await context.Response.Body.WriteAsync(encoded);
    }
    public async ValueTask DisposeAsync()
    {
        Timestamps.Dispose(); await App.DisposeAsync(); Root.Dispose(); Tsa.Dispose(); Seal.Dispose(); BadEku.Dispose(); RootKey.Dispose(); TsaKey.Dispose();
        File.Delete(Path.Combine(directory,"synthetic.pfx")); File.Delete(Path.Combine(directory,"synthetic-root.cer")); Directory.Delete(directory,false);
    }
    public sealed class Clock : TimeProvider { private DateTimeOffset now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()); public override DateTimeOffset GetUtcNow()=>now; public void Advance(TimeSpan interval)=>now+=interval; }
    public sealed class CountingProvider(ISealCertificateProvider inner) : ISealCertificateProvider { public int Calls; public Task<SealCertificateMaterial> AcquireAsync(CancellationToken ct) { Calls++; return inner.AcquireAsync(ct); } }
}

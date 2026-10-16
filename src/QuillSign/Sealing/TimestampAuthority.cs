using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using QuillSign.Documents;

namespace QuillSign.Sealing;

public sealed record VerifiedTimestamp(byte[] Encoded,DateTimeOffset At,string CertificateSha256,string Policy);

public sealed class TimestampAuthority(SealOptions options,IHostEnvironment environment,TimeProvider time) : IDisposable
{
    private readonly HttpClient http=new(new HttpClientHandler { AllowAutoRedirect=false,UseCookies=false }) { Timeout=Timeout.InfiniteTimeSpan };
    public async Task<VerifiedTimestamp> RequestAsync(SignerInfo signature,DateTimeOffset startedAt,CancellationToken ct)
    {
        var address=options.Validate(environment.IsDevelopment());
        var request=Rfc3161TimestampRequest.CreateFromSignerInfo(signature,HashAlgorithmName.SHA256,
            nonce:RandomNumberGenerator.GetBytes(16),requestSignerCertificates:true);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(options.TsaTimeoutSeconds));
        try {
            using var body=new ByteArrayContent(request.Encode()); body.Headers.ContentType=new MediaTypeHeaderValue("application/timestamp-query");
            using var message=new HttpRequestMessage(HttpMethod.Post,address) { Content=body };
            using var response=await http.SendAsync(message,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
            if(response.StatusCode!=System.Net.HttpStatusCode.OK || !string.Equals(response.Content.Headers.ContentType?.MediaType,"application/timestamp-reply",StringComparison.OrdinalIgnoreCase) ||
                response.Content.Headers.ContentEncoding.Count!=0 || response.Content.Headers.ContentLength>options.TsaMaximumResponseBytes)
                throw new SealUnavailableException("The timestamp service did not return a bounded timestamp response.");
            await using var input=await response.Content.ReadAsStreamAsync(timeout.Token); using var memory=new MemoryStream();
            await input.CopyToAsync(new BoundedDocumentStream(memory,options.TsaMaximumResponseBytes),timeout.Token);
            var encoded=memory.ToArray(); var token=request.ProcessResponse(encoded,out var consumed);
            if(consumed!=encoded.Length)throw new CryptographicException();
            return await ValidateAsync(token.AsSignedCms().Encode(),signature,startedAt,timeout.Token);
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested) { throw new SealUnavailableException("The timestamp service timed out; no seal was returned."); }
        catch(Exception e) when(e is HttpRequestException or IOException or DocumentRejectedException or CryptographicException or Org.BouncyCastle.Tsp.TspException or Org.BouncyCastle.Security.GeneralSecurityException or ArgumentException)
        { throw new SealUnavailableException("The timestamp response could not be verified; no seal was returned."); }
    }
    public async Task<VerifiedTimestamp> ValidateAsync(byte[] encoded,SignerInfo signature,DateTimeOffset startedAt,CancellationToken ct)
    {
        options.Validate(environment.IsDevelopment()); ct.ThrowIfCancellationRequested();
        if(encoded.Length>options.TsaMaximumResponseBytes || !Rfc3161TimestampToken.TryDecode(encoded,out var token,out var consumed) || consumed!=encoded.Length ||
            token.TokenInfo.HashAlgorithmId.Value!=SealCms.Sha256 || !token.VerifySignatureForSignerInfo(signature,out var actual) || actual is null)
            throw new SealUnavailableException("Invalid timestamp signature, certificate binding or imprint.");
        var at=token.TokenInfo.Timestamp; var skew=TimeSpan.FromSeconds(options.TsaMaximumClockSkewSeconds);
        if(at<startedAt-skew || at>time.GetUtcNow()+skew)throw new SealUnavailableException("The timestamp is outside the permitted operation time.");
        using(var rsa=actual.GetRSAPublicKey())using(var ec=actual.GetECDsaPublicKey())
            if(rsa is null ? ec?.KeySize is not (256 or 384 or 521) : rsa.KeySize is <2048 or >8192)
                throw new SealUnavailableException("The timestamp uses an unsupported signing key.");
        var cms=token.AsSignedCms();
        if(cms.Certificates.Count is <1 or >16 || cms.Certificates.Cast<X509Certificate2>().Sum(x=>x.RawData.Length)>128*1024)
            throw new SealUnavailableException("Timestamp certificate material exceeds its limits.");
        // Independent signature/ESS binding and critical, sole timeStamping EKU validation.
        var bc=new TimeStampToken(new CmsSignedData(encoded)); bc.Validate(new X509CertificateParser().ReadCertificate(actual.RawData));
        var signer=bc.ToCmsSignedData().GetSignerInfos().GetSigners().Single();
        if(signer.DigestAlgorithmID.Algorithm.Id is not (SealCms.Sha256 or "2.16.840.1.101.3.4.2.2" or "2.16.840.1.101.3.4.2.3"))
            throw new SealUnavailableException("The timestamp uses an unsupported digest.");
        using var chain=new X509Chain(); chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads=true; chain.ChainPolicy.VerificationTime=at.UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.8")); chain.ChainPolicy.ExtraStore.AddRange(cms.Certificates);
        var roots=new List<X509Certificate2>();
        try {
            if(options.TsaTrustedRootPaths.Length>0) {
                chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
                foreach(var path in options.TsaTrustedRootPaths) {
                    var root=X509CertificateLoader.LoadCertificate(await SealFiles.ReadAsync(path,64*1024,ct)); roots.Add(root); chain.ChainPolicy.CustomTrustStore.Add(root);
                }
            }
            if(!chain.Build(actual))throw new SealUnavailableException("The timestamp authority chain is not trusted.");
        }
        finally { foreach(var root in roots)root.Dispose(); }
        ct.ThrowIfCancellationRequested(); return new(encoded,at,Convert.ToHexStringLower(SHA256.HashData(actual.RawData)),bc.TimeStampInfo.Policy);
    }
    public void Dispose()=>http.Dispose();
}

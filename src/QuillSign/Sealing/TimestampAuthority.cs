using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using QuillSign.Documents;
using QuillSign.Email.Pilot;

namespace QuillSign.Sealing;

public sealed record VerifiedTimestamp(byte[] Encoded,DateTimeOffset At,string CertificateSha256,string Policy);

public sealed class TimestampAuthority(SealOptions options,IHostEnvironment environment,TimeProvider time,Func<ITimestampRequestCoordinator>? coordinator=null,
    PilotTimestampPolicy? pilotPolicy=null) : IDisposable
{
    private readonly HttpClient http=new(new HttpClientHandler { AllowAutoRedirect=false,UseCookies=false }) { Timeout=Timeout.InfiniteTimeSpan };
    private readonly HttpClient restrictedHttp=new(new HttpClientHandler { AllowAutoRedirect=false,UseCookies=false,UseProxy=false }) { Timeout=Timeout.InfiniteTimeSpan };
    public Task<VerifiedTimestamp> RequestAsync(SignerInfo signature,DateTimeOffset startedAt,CancellationToken ct,
        CompletionTimestampArtifact? timestampContext=null)
        =>RequestCoreAsync(signature,startedAt,ct,timestampContext,null);
    internal Task<VerifiedTimestamp> RequestAdmittedAsync(SignerInfo signature,DateTimeOffset startedAt,IProductionSealBoundary admission,CancellationToken ct)
        =>RequestCoreAsync(signature,startedAt,ct,null,admission??throw new ArgumentNullException(nameof(admission)));
    private async Task<VerifiedTimestamp> RequestCoreAsync(SignerInfo signature,DateTimeOffset startedAt,CancellationToken ct,
        CompletionTimestampArtifact? timestampContext,IProductionSealBoundary? admission)
    {
        ct.ThrowIfCancellationRequested();
        if(pilotPolicy is not null && timestampContext is null)throw new PilotTimestampDeniedException();
        if(timestampContext is not null)await timestampContext.DemandAsync(timestampContext.SourceHash,ct);
        var address=options.Validate(environment.IsDevelopment());
        options.ValidateRequestCoordination(address);
        if(timestampContext?.Work.KnownPilot==true && (!options.TimestampCoordination.Enabled || options.TimestampCoordination.MinimumIntervalMilliseconds<1000))
            throw new PilotTimestampDeniedException();
        var request=Rfc3161TimestampRequest.CreateFromSignerInfo(signature,HashAlgorithmName.SHA256,
            nonce:RandomNumberGenerator.GetBytes(16),requestSignerCertificates:true);
        var encodedRequest=request.Encode();
        var factualRequest=admission is null ? null : new ProductionTimestampRequest(
            Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(address.AbsoluteUri))),
            Convert.ToBase64String(encodedRequest),Convert.ToHexStringLower(SHA256.HashData(encodedRequest)),startedAt);
        if(admission is not null)await admission.DemandAsync(ct);
        await using var lease=options.TimestampCoordination.Enabled
            ? await (coordinator?.Invoke() ?? throw new SealUnavailableException("Shared timestamp coordination is not configured.")).AcquireAsync(address,ct) : null;
        if(admission is not null)await admission.DemandAsync(ct);
        var remaining=timestampContext is null ? TimeSpan.Zero : timestampContext.Until-timestampContext.Clock.GetUtcNow();
        using var scopeDeadline=timestampContext is null ? null : new CancellationTokenSource(remaining>TimeSpan.Zero ? remaining : TimeSpan.Zero,timestampContext.Clock);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct,lease?.Token ?? CancellationToken.None,scopeDeadline?.Token ?? CancellationToken.None);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.TsaTimeoutSeconds));
        try {
            using var body=new ByteArrayContent(encodedRequest); body.Headers.ContentType=new MediaTypeHeaderValue("application/timestamp-query");
            using var message=new HttpRequestMessage(HttpMethod.Post,address) { Content=body };
            if(lease is not null)await lease.EnsureOwnedAsync(timeout.Token);
            if(timestampContext is not null)
            {
                var permit=await timestampContext.ReserveAsync(encodedRequest,timeout.Token);
                if(lease is not null)await lease.EnsureOwnedAsync(timeout.Token);
                await permit.DemandSendAsync(encodedRequest,timeout.Token);
            }
            IProductionTimestampPermit? admittedPermit=null;
            if(admission is not null)
            {
                admittedPermit=await admission.BeginTimestampAsync(factualRequest!,timeout.Token)
                    ??throw new SealUnavailableException("The exact timestamp request is not admitted.");
                if(lease is not null)await lease.EnsureOwnedAsync(timeout.Token);
                await admission.DemandAsync(timeout.Token);
                await admittedPermit.DemandSendAsync(factualRequest!,timeout.Token);
            }
            if(timestampContext?.Work.KnownPilot==true || admission is not null)
            {
                message.Version=System.Net.HttpVersion.Version11;message.VersionPolicy=HttpVersionPolicy.RequestVersionExact;
                message.Headers.ConnectionClose=true;
            }
            timeout.Token.ThrowIfCancellationRequested();
            using var response=await (timestampContext?.Work.KnownPilot==true || admission is not null ? restrictedHttp : http).SendAsync(message,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
            if(admission is not null)await admission.DemandAsync(timeout.Token);
            if(response.StatusCode!=System.Net.HttpStatusCode.OK || !string.Equals(response.Content.Headers.ContentType?.MediaType,"application/timestamp-reply",StringComparison.OrdinalIgnoreCase) ||
                response.Content.Headers.ContentEncoding.Count!=0 || response.Content.Headers.ContentLength>options.TsaMaximumResponseBytes)
                throw new SealUnavailableException("The timestamp service did not return a bounded timestamp response.");
            await using var input=await response.Content.ReadAsStreamAsync(timeout.Token); using var memory=new MemoryStream();
            if(admission is not null)await admission.DemandAsync(timeout.Token);
            if(admission is null)await input.CopyToAsync(new BoundedDocumentStream(memory,options.TsaMaximumResponseBytes),timeout.Token);
            else
            {
                var buffer=new byte[16*1024];var bounded=new BoundedDocumentStream(memory,options.TsaMaximumResponseBytes);
                while(true)
                {
                    await admission.DemandAsync(timeout.Token);
                    var count=await input.ReadAsync(buffer,timeout.Token);
                    await admission.DemandAsync(timeout.Token);
                    if(count==0)break;
                    await bounded.WriteAsync(buffer.AsMemory(0,count),timeout.Token);
                }
            }
            if(admission is not null)await admission.DemandAsync(timeout.Token);
            var encoded=memory.ToArray(); var token=request.ProcessResponse(encoded,out var consumed);
            if(consumed!=encoded.Length)throw new CryptographicException();
            var result=await ValidateAsync(token.AsSignedCms().Encode(),signature,startedAt,timeout.Token);
            if(timestampContext is not null)await timestampContext.DemandAsync(timestampContext.SourceHash,timeout.Token);
            if(admission is not null)
            {
                await admission.DemandAsync(timeout.Token);
                await admittedPermit!.RecordVerifiedAsync(factualRequest!,new(Convert.ToBase64String(encoded),
                    Convert.ToHexStringLower(SHA256.HashData(encoded)),Convert.ToBase64String(result.Encoded),
                    Convert.ToHexStringLower(SHA256.HashData(result.Encoded)),result.At,result.CertificateSha256,result.Policy),timeout.Token);
                await admission.DemandAsync(timeout.Token);
            }
            return result;
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
    public void Dispose(){http.Dispose();restrictedHttp.Dispose();}
}

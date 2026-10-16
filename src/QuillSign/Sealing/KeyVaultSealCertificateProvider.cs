using System.Collections.Concurrent;
using System.Security.Cryptography;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;

namespace QuillSign.Sealing;

public sealed record KeyVaultSealMaterial(byte[] Certificate,byte[] Pkcs12);
public interface IKeyVaultSealSource { Task<KeyVaultSealMaterial> ReadAsync(KeyVaultSealOptions options,CancellationToken ct); }
public sealed record KeyVaultSealClients(CertificateClient Certificates,SecretClient Secrets);
public interface IKeyVaultSealClients { KeyVaultSealClients Create(Uri vault,KeyVaultSealOptions options); }

public sealed class KeyVaultSealCertificateProvider(SealOptions options,IKeyVaultSealSource source,TimeProvider time) : ISealCertificateProvider
{
    public async Task<SealCertificateMaterial> AcquireAsync(CancellationToken ct)
    {
        KeyVaultSealMaterial? saved=null; SealCertificateMaterial? material=null;
        try {
            ct.ThrowIfCancellationRequested();
            saved=await source.ReadAsync(options.KeyVault,ct);
            if(saved.Certificate.Length is <1 or >64*1024)throw new SealUnavailableException("Invalid public signing certificate.");
            material=SealCertificateMaterial.Load(saved.Pkcs12,null,"KeyVault",time.GetUtcNow());
            if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(material.Certificate.RawData),SHA256.HashData(saved.Certificate)))
                throw new SealUnavailableException("The selected certificate does not match its private backing material.");
            ct.ThrowIfCancellationRequested(); var result=material; material=null; return result;
        }
        finally { material?.Dispose(); if(saved is not null)CryptographicOperations.ZeroMemory(saved.Pkcs12); }
    }
}

// The SDK reader retrieves only the selected certificate and its exact backing secret version.
public sealed class SdkKeyVaultSealSource(IKeyVaultSealClients factory,TimeProvider time) : IKeyVaultSealSource
{
    public async Task<KeyVaultSealMaterial> ReadAsync(KeyVaultSealOptions options,CancellationToken ct)
    {
        var vault=Validate(options); using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));
        try {
            var clients=factory.Create(vault,options); var certificate=(await clients.Certificates.GetCertificateAsync(options.CertificateName,timeout.Token)).Value;
            _=Identifier(certificate.Id,vault,"certificates",options.CertificateName);
            var secretVersion=Identifier(certificate.SecretId,vault,"secrets",options.CertificateName);
            var now=time.GetUtcNow();
            if(certificate.Properties.Enabled==false || certificate.Properties.NotBefore>now || certificate.Properties.ExpiresOn<=now || certificate.Cer is not {Length:>0 and <=64*1024})
                throw new SealUnavailableException("The selected signing certificate is unavailable.");
            var secret=(await clients.Secrets.GetSecretAsync(options.CertificateName,secretVersion,timeout.Token)).Value;
            if(Identifier(secret.Id,vault,"secrets",options.CertificateName)!=secretVersion || secret.Properties.Enabled==false ||
                secret.Properties.NotBefore>now || secret.Properties.ExpiresOn<=now || secret.Properties.ContentType!="application/x-pkcs12" ||
                secret.Value is not {Length:>0 and <=2796204})throw new SealUnavailableException("The exact private backing material is unavailable.");
            byte[]? bytes=Convert.FromBase64String(secret.Value);
            try {
                if(bytes.Length>2*1024*1024)throw new SealUnavailableException("Private backing material exceeds its limits.");
                timeout.Token.ThrowIfCancellationRequested(); var result=new KeyVaultSealMaterial(certificate.Cer.ToArray(),bytes); bytes=null; return result;
            }
            finally { if(bytes is not null)CryptographicOperations.ZeroMemory(bytes); }
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested) { throw new SealUnavailableException("Signing material retrieval timed out."); }
        catch(Exception e) when(e is RequestFailedException or AuthenticationFailedException or HttpRequestException or IOException or
            FormatException or ArgumentException or InvalidOperationException or System.Text.Json.JsonException)
        { throw new SealUnavailableException("The configured signing material could not be retrieved."); }
    }
    internal static Uri Validate(KeyVaultSealOptions options)
    {
        if(options is null || options.TimeoutSeconds is <1 or >60 || !Uri.TryCreate(options.Uri,UriKind.Absolute,out var vault) ||
            vault.Scheme!="https" || vault.Port!=443 || vault.AbsolutePath!="/" || vault.Query.Length!=0 || vault.Fragment.Length!=0 || vault.UserInfo.Length!=0 ||
            !System.Text.RegularExpressions.Regex.IsMatch(vault.Host,"^[a-zA-Z0-9-]+\\.vault\\.azure\\.net$") ||
            !System.Text.RegularExpressions.Regex.IsMatch(options.CertificateName??"","^[a-zA-Z0-9-]{1,127}$") ||
            !string.IsNullOrEmpty(options.ManagedIdentityClientId) && (!Guid.TryParse(options.ManagedIdentityClientId,out var id) || id==Guid.Empty))
            throw new SealUnavailableException("Configure the selected vault, certificate and managed identity correctly.");
        return vault;
    }
    private static string Identifier(Uri? identifier,Uri vault,string kind,string name)
    {
        if(identifier is null || identifier.Scheme!="https" || !string.Equals(identifier.Authority,vault.Authority,StringComparison.OrdinalIgnoreCase) ||
            identifier.Query.Length!=0 || identifier.Fragment.Length!=0 || identifier.UserInfo.Length!=0)throw new SealUnavailableException("Invalid certificate backing scope.");
        var parts=identifier.AbsolutePath.Split('/');
        if(parts.Length!=4 || parts[0]!="" || parts[1]!=kind || !string.Equals(parts[2],name,StringComparison.OrdinalIgnoreCase) ||
            !System.Text.RegularExpressions.Regex.IsMatch(parts[3],"^[a-zA-Z0-9-]{1,128}$"))throw new SealUnavailableException("Invalid certificate backing scope.");
        return parts[3];
    }
}

public sealed class ManagedIdentitySealClients : IKeyVaultSealClients,IDisposable
{
    private readonly HttpClient http=new(new HttpClientHandler {AllowAutoRedirect=false,UseCookies=false}) {Timeout=Timeout.InfiniteTimeSpan};
    private readonly ConcurrentDictionary<string,Lazy<KeyVaultSealClients>> cache=new();
    public KeyVaultSealClients Create(Uri vault,KeyVaultSealOptions options)
    {
        _=SdkKeyVaultSealSource.Validate(options);
        var key=vault.AbsoluteUri+"\n"+options.ManagedIdentityClientId+"\n"+options.TimeoutSeconds;
        if(cache.Count>=4 && !cache.ContainsKey(key))throw new SealUnavailableException("Restart after changing signing provider configuration.");
        return cache.GetOrAdd(key,_=>new Lazy<KeyVaultSealClients>(()=> {
            var identity=string.IsNullOrEmpty(options.ManagedIdentityClientId) ? ManagedIdentityId.SystemAssigned : ManagedIdentityId.FromUserAssignedClientId(options.ManagedIdentityClientId);
            var credentialOptions=new ManagedIdentityCredentialOptions(identity); credentialOptions.Diagnostics.IsLoggingEnabled=false;
            var credential=new ManagedIdentityCredential(credentialOptions);
            var certificateOptions=new CertificateClientOptions(); Configure(certificateOptions,64*1024,options.TimeoutSeconds);
            var secretOptions=new SecretClientOptions(); Configure(secretOptions,3*1024*1024,options.TimeoutSeconds);
            return new(new CertificateClient(vault,credential,certificateOptions),new SecretClient(vault,credential,secretOptions));
        })).Value;
    }
    private void Configure(ClientOptions options,int maximum,int timeout)
    {
        options.Diagnostics.IsLoggingEnabled=false; options.Diagnostics.IsLoggingContentEnabled=false; options.Diagnostics.IsDistributedTracingEnabled=false;
        options.Retry.MaxRetries=0; options.Retry.NetworkTimeout=TimeSpan.FromSeconds(timeout); options.Transport=new HttpClientTransport(http);
        options.AddPolicy(new SealResponseLimit(maximum),HttpPipelinePosition.PerCall);
    }
    public void Dispose()=>http.Dispose();
}

// Disable transport buffering before the request, then bound SDK JSON reads before deserialization.
public sealed class SealResponseLimit(int maximum) : HttpPipelinePolicy
{
    public override void Process(HttpMessage message,ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    { message.BufferResponse=false; ProcessNext(message,pipeline); Limit(message); }
    public override async ValueTask ProcessAsync(HttpMessage message,ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    { message.BufferResponse=false; await ProcessNextAsync(message,pipeline); Limit(message); }
    private void Limit(HttpMessage message)
    {
        if(message.Response.Headers.TryGetValue("Content-Length",out var value) && (!long.TryParse(value,out var length) || length<0 || length>maximum))
        { message.Response.Dispose(); throw new SealUnavailableException("Signing service response exceeds its limits."); }
        if(message.Response.ContentStream is { } stream)message.Response.ContentStream=new LimitedRead(stream,maximum);
    }
    private sealed class LimitedRead(Stream inner,long maximum) : Stream
    {
        private long count;
        private int LengthFor(int wanted) { if(count>maximum)throw new SealUnavailableException("Signing service response exceeds its limits."); return checked((int)Math.Min(wanted,maximum-count+1)); }
        private int Record(int length) { count+=length; if(count>maximum)throw new SealUnavailableException("Signing service response exceeds its limits."); return length; }
        public override int Read(byte[] buffer,int offset,int length)=>Record(inner.Read(buffer,offset,LengthFor(length)));
        public override int Read(Span<byte> buffer)=>Record(inner.Read(buffer[..LengthFor(buffer.Length)]));
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default)=>Record(await inner.ReadAsync(buffer[..LengthFor(buffer.Length)],ct));
        public override Task<int> ReadAsync(byte[] buffer,int offset,int length,CancellationToken ct)=>ReadAsync(buffer.AsMemory(offset,length),ct).AsTask();
        public override bool CanRead=>true; public override bool CanSeek=>false; public override bool CanWrite=>false;
        public override long Length=>throw new NotSupportedException(); public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override void Flush()=>throw new NotSupportedException(); public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long length)=>throw new NotSupportedException(); public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if(disposing)inner.Dispose(); base.Dispose(disposing); }
    }
}

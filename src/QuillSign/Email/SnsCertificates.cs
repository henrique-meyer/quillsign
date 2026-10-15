using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Memory;

namespace QuillSign.Email;

public sealed class InvalidSnsMessageException() : Exception("Invalid SNS notification.");
public sealed class FeedbackUnavailableException() : Exception("Feedback processing is temporarily unavailable.");

public interface ISnsCertificateTrust
{
    bool IsTrusted(X509Certificate2 certificate);
}

public sealed class SnsCertificateTrust : ISnsCertificateTrust
{
    public bool IsTrusted(X509Certificate2 certificate)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
        return chain.Build(certificate);
    }
}

public interface ISnsCertificateSource
{
    Task<byte[]> GetAsync(Uri uri, CancellationToken cancellationToken);
}

public sealed class SnsCertificateSource(IHttpClientFactory clients, ISnsCertificateTrust trust) : ISnsCertificateSource, IDisposable
{
    private readonly MemoryCache cache = new(new MemoryCacheOptions { SizeLimit = 32 });

    public async Task<byte[]> GetAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (cache.TryGetValue<byte[]>(uri.AbsoluteUri, out var saved)) return saved!;
        try
        {
            using var response = await clients.CreateClient("Sns").GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode == HttpStatusCode.TooManyRequests || (int)response.StatusCode >= 500)
                throw new FeedbackUnavailableException();
            if (response.StatusCode != HttpStatusCode.OK) throw new InvalidSnsMessageException();
            var bytes = await SnsEndpoint.ReadBoundedAsync(await response.Content.ReadAsStreamAsync(cancellationToken), 65536, cancellationToken);
            using var certificate = X509Certificate2.CreateFromPem(System.Text.Encoding.UTF8.GetString(bytes));
            using var rsa = certificate.GetRSAPublicKey();
            var now = DateTime.UtcNow;
            if (rsa is null || rsa.KeySize < 2048 || now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime() || !trust.IsTrusted(certificate))
                throw new InvalidSnsMessageException();
            var der = certificate.RawData;
            cache.Set(uri.AbsoluteUri, der, new MemoryCacheEntryOptions().SetSize(1)
                .SetAbsoluteExpiration(TimeSpan.FromMinutes(Math.Min(60, (certificate.NotAfter.ToUniversalTime() - now).TotalMinutes))));
            return der;
        }
        catch (HttpRequestException) { throw new FeedbackUnavailableException(); }
        catch (IOException) { throw new FeedbackUnavailableException(); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new FeedbackUnavailableException(); }
        catch (CryptographicException) { throw new InvalidSnsMessageException(); }
        catch (ArgumentException) { throw new InvalidSnsMessageException(); }
    }

    public void Dispose() => cache.Dispose();
}

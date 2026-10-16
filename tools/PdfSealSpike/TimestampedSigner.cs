using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.Ess;
using PdfSharp.Pdf.Signatures;

// Feasibility implementation only: in-memory keys, a pinned fixture TSA, and sequential use.
// Production requires provider abstraction, policy/trust/revocation checks, and bounded streaming.
sealed class TimestampedSigner(X509Certificate2 certificate, X509Certificate2 tsaCertificate, Uri tsaAddress)
    : IDigitalSigner, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private Task<int>? _size;
    public string CertificateName => certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

    public Task<int> GetSignatureSizeAsync() => _size ??= MeasureAsync();

    private async Task<int> MeasureAsync()
    {
        using var dummy = new MemoryStream([0]);
        // Allow DER/time/serial variations; PDFsharp fails closed if the real CMS exceeds its placeholder.
        return (await GetSignatureAsync(dummy)).Length + 1024;
    }

    public async Task<byte[]> GetSignatureAsync(Stream stream)
    {
        // RangedStream supports Position's setter but throws from CanSeek. Rewind explicitly;
        // a full-length Read also avoids its slow per-byte path. This fixture is intentionally small.
        var content = new byte[checked((int)stream.Length)];
        stream.Position = 0;
        var offset = 0;
        while (offset < content.Length)
        {
            var count = stream.Read(content, offset, content.Length - offset);
            if (count == 0) throw new EndOfStreamException("Incomplete PDF byte ranges");
            offset += count;
        }
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
        var binding = new SigningCertificateV2(new EssCertIDv2(SHA256.HashData(certificate.RawData)));
        signer.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), binding.GetDerEncoded()));
        cms.ComputeSignature(signer, silent: true);

        var request = Rfc3161TimestampRequest.CreateFromSignerInfo(cms.SignerInfos[0], HashAlgorithmName.SHA256,
            nonce: RandomNumberGenerator.GetBytes(16), requestSignerCertificates: true);
        using var body = new ByteArrayContent(request.Encode());
        body.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        using var response = await _http.PostAsync(tsaAddress, body);
        response.EnsureSuccessStatusCode();
        var encoded = await response.Content.ReadAsByteArrayAsync();
        var token = request.ProcessResponse(encoded, out var consumed);
        if (consumed != encoded.Length || !token.VerifySignatureForSignerInfo(cms.SignerInfos[0], out var actualTsa) ||
            actualTsa is null || !actualTsa.RawData.AsSpan().SequenceEqual(tsaCertificate.RawData))
            throw new CryptographicException("TSA signature, identity, or response binding failed");
        cms.SignerInfos[0].AddUnsignedAttribute(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.14"),
            token.AsSignedCms().Encode()));
        return cms.Encode();
    }

    public void Dispose() => _http.Dispose();
}

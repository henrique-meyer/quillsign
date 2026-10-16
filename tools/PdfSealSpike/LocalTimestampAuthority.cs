using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

enum TimestampMode { Valid, HttpFailure, Malformed, WrongImprint, WrongNonce }

// Loopback-only test fixture, not an operator TSA or a trusted source of time.
sealed class LocalTimestampAuthority : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly TimeStampTokenGenerator _tokens;
    private int _requests;
    public TimestampMode Mode { get; set; }
    public int RequestCount => Volatile.Read(ref _requests);
    public Uri Address => new(_app.Urls.Single());

    private LocalTimestampAuthority(WebApplication app, RSA signingRsa, X509Certificate2 certificate)
    {
        _app = app;
        var bcCertificate = new X509CertificateParser().ReadCertificate(certificate.RawData);
        var info = new SignerInfoGeneratorBuilder().Build(
            new Asn1SignatureFactory("SHA256WITHRSA", DotNetUtilities.GetRsaKeyPair(signingRsa).Private), bcCertificate);
        _tokens = new TimeStampTokenGenerator(info, Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256),
            new DerObjectIdentifier("1.2.3.4.1"), isIssuerSerialIncluded: true);
        _tokens.SetCertificates(CollectionUtilities.CreateStore([bcCertificate]));
    }

    public static async Task<LocalTimestampAuthority> StartAsync(RSA signingRsa, X509Certificate2 certificate)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var instance = new LocalTimestampAuthority(builder.Build(), signingRsa, certificate);
        instance._app.MapPost("/", instance.HandleAsync);
        await instance._app.StartAsync();
        return instance;
    }

    private async Task HandleAsync(HttpContext context)
    {
        var serial = Interlocked.Increment(ref _requests);
        if (Mode == TimestampMode.HttpFailure)
        {
            context.Response.StatusCode = 503;
            return;
        }
        context.Response.ContentType = "application/timestamp-reply";
        if (Mode == TimestampMode.Malformed)
        {
            await context.Response.Body.WriteAsync(new byte[] { 1, 2, 3 });
            return;
        }
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body);
        var request = new TimeStampRequest(body.ToArray());
        if (Mode is TimestampMode.WrongImprint or TimestampMode.WrongNonce)
        {
            var wrongRequest = new TimeStampRequestGenerator();
            wrongRequest.SetCertReq(true);
            request = wrongRequest.Generate(TspAlgorithms.Sha256,
                Mode == TimestampMode.WrongImprint ? new byte[32] : request.GetMessageImprintDigest(),
                Mode == TimestampMode.WrongNonce ? request.Nonce.Add(Org.BouncyCastle.Math.BigInteger.One) : request.Nonce);
        }
        var generator = new TimeStampResponseGenerator(_tokens, [TspAlgorithms.Sha256]);
        var response = generator.Generate(request, Org.BouncyCastle.Math.BigInteger.ValueOf(serial), DateTime.UtcNow);
        await context.Response.Body.WriteAsync(response.GetEncoded());
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

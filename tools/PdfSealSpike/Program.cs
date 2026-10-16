using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Annotations;
using PdfSharp.Pdf.Signatures;

// Developer-only, synthetic fixtures. No application state, private keys on disk, or public TSA calls.
var output = Path.GetFullPath(Path.Combine("artifacts", "pdf-seal-spike"));
Directory.CreateDirectory(output);
using var sealKey = RSA.Create(3072);
using var sealCertificate = Certificates.Create(sealKey, "QuillSign synthetic seal", timestamp: false);
using var tsaKey = RSA.Create(3072);
using var tsaCertificate = Certificates.Create(tsaKey, "QuillSign synthetic TSA", timestamp: true);
await using var tsa = await LocalTimestampAuthority.StartAsync(tsaKey, tsaCertificate);
var defaultSigner = new PdfSharpDefaultSigner(sealCertificate, PdfMessageDigestType.SHA256, tsa.Address);
var baseline = await SealAsync(defaultSigner);
var firstRequests = tsa.RequestCount;
Require(firstRequests == 2, "Fresh signer requests sizing and actual timestamps");
var baselineParts = SealInspection.Extract(baseline);
var baselineCms = new SignedCms(new ContentInfo(baselineParts.SignedBytes), detached: true);
baselineCms.Decode(baselineParts.Cms);
baselineCms.CheckSignature(verifySignatureOnly: true);
Require(baselineCms.SignerInfos[0].UnsignedAttributes.Cast<CryptographicAttributeObject>()
    .Any(a => a.Oid.Value == "1.2.840.113549.1.9.5"), "Built-in signer emits unsigned signing-time");
ExpectRejected(() => SealInspection.Verify(baseline, sealCertificate, tsaCertificate),
    "Built-in unsigned signing-time (BouncyCastle interoperability)");
await SealAsync(defaultSigner);
Require(tsa.RequestCount == firstRequests + 1, "Built-in signer caches placeholder size");

using var signer = new TimestampedSigner(sealCertificate, tsaCertificate, tsa.Address);
var beforeCustom = tsa.RequestCount;
var first = await SealAsync(signer);
var inspected = SealInspection.Verify(first, sealCertificate, tsaCertificate);
Require(tsa.RequestCount == beforeCustom + 2, "Custom signer sizes once and timestamps actual signature");
Console.WriteLine($"SubFilter: {inspected.SubFilter}; SigningCertificateV2: {inspected.HasSigningCertificateV2}");
Require(inspected.SubFilter == "adbe.pkcs7.detached", "Observed PDFsharp 6.2.4 SubFilter");
Require(inspected.HasSigningCertificateV2, "Custom signer includes signed certificate binding");

var second = await SealAsync(signer);
SealInspection.Verify(second, sealCertificate, tsaCertificate);
Require(tsa.RequestCount == beforeCustom + 3, "Reused custom signer caches placeholder size");

var altered = (byte[])first.Clone();
altered[10] ^= 1;
ExpectRejected(() => SealInspection.Verify(altered, sealCertificate, tsaCertificate), "Changed signed bytes");
ExpectRejected(() => SealInspection.Verify(first[..^12], sealCertificate, tsaCertificate), "Truncated PDF");
ExpectRejected(() => SealInspection.Verify([.. first, .. Encoding.ASCII.GetBytes("\n% later revision")], sealCertificate, tsaCertificate), "Appended bytes outside signed ranges");

using var wrongSealKey = RSA.Create(3072);
using var wrongSeal = Certificates.Create(wrongSealKey, "QuillSign unrelated seal", timestamp: false);
ExpectRejected(() => SealInspection.Verify(first, wrongSeal, tsaCertificate), "Unexpected seal identity");
using var wrongTsaKey = RSA.Create(3072);
using var wrongTsa = Certificates.Create(wrongTsaKey, "QuillSign unrelated TSA", timestamp: true);
ExpectRejected(() => SealInspection.Verify(first, sealCertificate, wrongTsa), "Unexpected timestamp identity");

foreach (var mode in new[] { TimestampMode.HttpFailure, TimestampMode.Malformed, TimestampMode.WrongImprint, TimestampMode.WrongNonce })
{
    tsa.Mode = mode;
    // Reuse avoids the sizing call: exercise failure during the actual document signature.
    await ExpectRejectedAsync(() => SealAsync(signer), $"TSA {mode}");
}
tsa.Mode = TimestampMode.Valid;
SealInspection.Verify(await SealAsync(signer), sealCertificate, tsaCertificate);
Require(true, "Signer recovers after definite TSA failures");

// A self-signed key can prove mathematical integrity without being publicly trusted.
using (var chain = new X509Chain())
{
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.DisableCertificateDownloads = true;
    Require(!chain.Build(sealCertificate), "Ephemeral seal is not publicly trusted");
}

File.WriteAllBytes(Path.Combine(output, "sealed.pdf"), first);
File.WriteAllBytes(Path.Combine(output, "built-in-signer.pdf"), baseline);
File.WriteAllBytes(Path.Combine(output, "altered.pdf"), altered);
File.WriteAllBytes(Path.Combine(output, "signature.der"), inspected.Cms);
File.WriteAllBytes(Path.Combine(output, "signed-bytes.bin"), inspected.SignedBytes);
File.WriteAllBytes(Path.Combine(output, "altered-signed-bytes.bin"), SealInspection.Extract(altered).SignedBytes);
File.WriteAllBytes(Path.Combine(output, "timestamp.der"), inspected.Timestamp);
File.WriteAllBytes(Path.Combine(output, "signature-value.bin"), inspected.SignatureValue);
File.WriteAllText(Path.Combine(output, "seal.crt"), sealCertificate.ExportCertificatePem());
File.WriteAllText(Path.Combine(output, "tsa.crt"), tsaCertificate.ExportCertificatePem());
Console.WriteLine($"PASS: CMS and timestamp independently verified with .NET and BouncyCastle. Synthetic output: {output}");

static async Task<byte[]> SealAsync(IDigitalSigner signer)
{
    using var document = new PdfDocument();
    document.Info.Title = "QuillSign synthetic seal feasibility";
    var page = document.AddPage();
    // Geometry-only content avoids platform fonts. Signature appearance is also geometry-only.
    using (var graphics = XGraphics.FromPdfPage(page))
    {
        graphics.DrawRectangle(XPens.Navy, 72, 72, 220, 100);
        graphics.DrawLine(XPens.DarkRed, 90, 150, 260, 95);
    }
    DigitalSignatureHandler.ForDocument(document, signer, new DigitalSignatureOptions
    {
        Reason = "Synthetic completion-seal test",
        Rectangle = new XRect(72, 200, 120, 35),
        AppearanceHandler = new SyntheticAppearance()
    });
    using var stream = new MemoryStream();
    await document.SaveAsync(stream, closeStream: false);
    return stream.ToArray();
}

static void Require(bool condition, string check)
{
    if (!condition) throw new InvalidOperationException($"FAIL: {check}");
    Console.WriteLine($"PASS: {check}");
}

static void ExpectRejected(Action action, string check)
{
    try { action(); }
    catch (Exception error) when (error is CryptographicException or InvalidDataException or
        Org.BouncyCastle.Security.GeneralSecurityException or Org.BouncyCastle.Cms.CmsException)
    {
        Console.WriteLine($"PASS: {check} rejected ({error.GetType().Name})");
        return;
    }
    throw new InvalidOperationException($"FAIL: {check} accepted");
}

static async Task ExpectRejectedAsync(Func<Task<byte[]>> action, string check)
{
    try { await action(); }
    catch (Exception error) when (error is CryptographicException or HttpRequestException or InvalidOperationException)
    {
        Console.WriteLine($"PASS: {check} rejected ({error.GetType().Name})");
        return;
    }
    throw new InvalidOperationException($"FAIL: {check} accepted");
}

sealed class SyntheticAppearance : IAnnotationAppearanceHandler
{
    public void DrawAppearance(XGraphics graphics, XRect rectangle) =>
        graphics.DrawRectangle(XPens.DarkRed, rectangle);
}

static class Certificates
{
    public static X509Certificate2 Create(RSA key, string name, bool timestamp)
    {
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        if (timestamp)
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") }, critical: true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
    }
}

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

sealed record SealInspection(byte[] Cms, byte[] SignedBytes, string SubFilter,
    byte[] Timestamp, byte[] SignatureValue, bool HasSigningCertificateV2)
{
    private const string TimestampOid = "1.2.840.113549.1.9.16.2.14";
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";

    public static SealInspection Verify(byte[] pdf, X509Certificate2 expectedSeal, X509Certificate2 expectedTsa)
    {
        var (cmsBytes, signedBytes, subFilter) = Extract(pdf);
        var cms = new SignedCms(new ContentInfo(signedBytes), detached: true);
        cms.Decode(cmsBytes);
        cms.CheckSignature(verifySignatureOnly: true);
        if (cms.SignerInfos.Count != 1 || cms.SignerInfos[0].Certificate is not { } seal ||
            !seal.RawData.AsSpan().SequenceEqual(expectedSeal.RawData))
            throw new CryptographicException("Unexpected seal certificate");
        var signer = cms.SignerInfos[0];

        // Verify the detached digest/signature independently from the .NET signer implementation.
        var bcCms = new CmsSignedData(new CmsProcessableByteArray(signedBytes), cmsBytes);
        var bcSigner = bcCms.GetSignerInfos().GetSigners().Single();
        if (!bcSigner.Verify(new X509CertificateParser().ReadCertificate(expectedSeal.RawData)))
            throw new CryptographicException("Independent CMS verification failed");

        var attribute = signer.UnsignedAttributes.Cast<CryptographicAttributeObject>()
            .SingleOrDefault(item => item.Oid.Value == TimestampOid);
        if (attribute?.Values.Count != 1) throw new CryptographicException("Missing timestamp");
        var timestamp = attribute.Values[0].RawData;
        if (!Rfc3161TimestampToken.TryDecode(timestamp, out var netToken, out var consumed) ||
            consumed != timestamp.Length || !netToken.VerifySignatureForSignerInfo(signer, out var tsaCertificate) ||
            tsaCertificate is null || !tsaCertificate.RawData.AsSpan().SequenceEqual(expectedTsa.RawData))
            throw new CryptographicException("Timestamp signature, binding, or identity failed");
        var bcToken = new TimeStampToken(new CmsSignedData(timestamp));
        bcToken.Validate(new X509CertificateParser().ReadCertificate(expectedTsa.RawData));
        if (bcToken.TimeStampInfo.MessageImprintAlgOid != "2.16.840.1.101.3.4.2.1" ||
            !bcToken.TimeStampInfo.GetMessageImprintDigest().AsSpan().SequenceEqual(SHA256.HashData(signer.GetSignature())))
            throw new CryptographicException("Independent timestamp imprint verification failed");
        return new(cmsBytes, signedBytes, subFilter, timestamp, signer.GetSignature(),
            signer.SignedAttributes.Cast<CryptographicAttributeObject>().Any(a => a.Oid.Value == SigningCertificateV2Oid));
    }

    // Deliberately restricted to this harness's single-signature, full-file PDF fixtures.
    // This regex-based extraction is NOT a parser for untrusted uploads or a production /verify endpoint.
    public static (byte[] Cms, byte[] SignedBytes, string SubFilter) Extract(byte[] pdf)
    {
        var text = Encoding.Latin1.GetString(pdf);
        var ranges = Regex.Matches(text, @"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (ranges.Count != 1) throw new InvalidDataException("Expected one ByteRange");
        var values = ranges[0].Groups.Cast<Group>().Skip(1).Select(g => long.Parse(g.Value,
            System.Globalization.CultureInfo.InvariantCulture)).ToArray();
        if (values[0] != 0 || values[1] < 1 || values[2] <= values[1] ||
            values[2] > pdf.Length || values[3] != pdf.Length - values[2])
            throw new InvalidDataException("ByteRange does not cover the complete final file");
        var firstEnd = checked((int)values[1]);
        var secondStart = checked((int)values[2]);
        if (pdf[firstEnd] != '<' || pdf[secondStart - 1] != '>')
            throw new InvalidDataException("Expected hex signature gap");
        var paddedCms = Convert.FromHexString(text[(firstEnd + 1)..(secondStart - 1)]);
        var reader = new AsnReader(paddedCms, AsnEncodingRules.BER);
        var cms = reader.ReadEncodedValue().ToArray();
        if (paddedCms.AsSpan(cms.Length).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Unexpected signature padding");
        var signed = new byte[firstEnd + pdf.Length - secondStart];
        pdf.AsSpan(0, firstEnd).CopyTo(signed);
        pdf.AsSpan(secondStart).CopyTo(signed.AsSpan(firstEnd));
        var subFilter = Regex.Match(text, @"/SubFilter\s*/([^\s/<>\[\]()]+)",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (!subFilter.Success) throw new InvalidDataException("Missing SubFilter");
        return (cms, signed, subFilter.Groups[1].Value);
    }
}

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using PdfSharp.Pdf;
using PdfSharp.Pdf.Advanced;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Signatures;
using QuillSign.Documents;
using QuillSign.Email.Pilot;

namespace QuillSign.Sealing;

public sealed record InspectedSeal(byte[] Cms,byte[] SignedBytes,int PageCount,VerifiedTimestamp Timestamp)
{
    internal IReadOnlyList<PageGeometry> Geometry { get; init; }=[];
}

public sealed class SealCms(SealOptions options,TimestampAuthority timestamp)
{
    public const string Sha256="2.16.840.1.101.3.4.2.1";
    public const string TimestampOid="1.2.840.113549.1.9.16.2.14";
    public const string CertificateBindingOid="1.2.840.113549.1.9.16.2.47";

    // This verifies the engine's single-seal, full-file output against its exact operation identity.
    // It is not a public upload/revision-chain verifier and grants no document access authority.
    public async Task<InspectedSeal> VerifyAsync(byte[] bytes,X509Certificate2 expected,DateTimeOffset startedAt,CancellationToken ct)
    {
        try {
            if(bytes.LongLength>options.MaximumBytes || bytes.Length<16)throw new InvalidDataException();
            using var input=new MemoryStream(bytes,false); using var document=PdfReader.Open(input,PdfDocumentOpenMode.Import);
            if(document.SecuritySettings.IsEncrypted || document.PageCount is <1 || document.PageCount>options.MaximumPages)throw new InvalidDataException();
            var pending=new Stack<PdfItem>(document.Internals.GetAllObjects()); pending.Push(document.Internals.Catalog);
            var visited=new HashSet<PdfItem>(ReferenceEqualityComparer.Instance); var signatures=new List<PdfDictionary>(); var signatureFields=0;
            while(pending.TryPop(out var item)) {
                ct.ThrowIfCancellationRequested(); if(!visited.Add(item))continue; if(visited.Count>50000)throw new InvalidDataException();
                if(item is PdfReference reference) { pending.Push(reference.Value); continue; }
                if(item is PdfDictionary dictionary) {
                    if(dictionary.Elements["/Type"] is PdfName {Value:"/Sig"} || dictionary.Elements.ContainsKey("/ByteRange"))signatures.Add(dictionary);
                    if(dictionary.Elements["/FT"] is PdfName fieldType) { if(fieldType.Value!="/Sig")throw new InvalidDataException(); signatureFields++; }
                    foreach(var value in dictionary.Elements.Values)if(value is not null)pending.Push(value);
                }
                else if(item is PdfArray array)foreach(var value in array.Elements)if(value is not null)pending.Push(value);
            }
            if(signatures.Count!=1 || signatureFields!=1)throw new InvalidDataException();
            var signature=signatures[0]; var ranges=signature.Elements.GetArray("/ByteRange");
            if(signature.Elements.GetName("/SubFilter")!="/adbe.pkcs7.detached" || ranges?.Elements.Count!=4)throw new InvalidDataException();
            static long Number(PdfItem item)=>item switch { PdfInteger i=>i.Value,PdfLongInteger l=>l.Value,_=>throw new InvalidDataException() };
            var r=ranges.Elements.Select(Number).ToArray();
            if(r[0]!=0 || r[1]<1 || r[2]<=r[1] || r[2]>bytes.Length || r[3]!=bytes.Length-r[2] || r[2]-r[1]>2L*options.SignatureCapacityBytes+2)
                throw new InvalidDataException();
            var first=checked((int)r[1]); var second=checked((int)r[2]);
            if(bytes[first]!='<' || bytes[second-1]!='>')throw new InvalidDataException();
            var padded=Convert.FromHexString(Encoding.ASCII.GetString(bytes,first+1,second-first-2));
            var contents=signature.Elements.GetString("/Contents");
            if(contents.Any(c=>c>255) || !Encoding.Latin1.GetBytes(contents).AsSpan().SequenceEqual(padded))throw new InvalidDataException();
            var reader=new AsnReader(padded,AsnEncodingRules.BER); var encoded=reader.ReadEncodedValue().ToArray();
            if(padded.AsSpan(encoded.Length).IndexOfAnyExcept((byte)0)>=0)throw new InvalidDataException();
            var signed=new byte[first+bytes.Length-second]; bytes.AsSpan(0,first).CopyTo(signed); bytes.AsSpan(second).CopyTo(signed.AsSpan(first));
            var cms=new SignedCms(new ContentInfo(signed),true); cms.Decode(encoded);
            if(!cms.Detached || cms.SignerInfos.Count!=1 || cms.SignerInfos[0].Certificate is not { } certificate ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(certificate.RawData),SHA256.HashData(expected.RawData)))throw new CryptographicException();
            cms.CheckSignature(true); var signer=cms.SignerInfos[0];
            if(signer.DigestAlgorithm.Value!=Sha256 || signer.UnsignedAttributes.Count!=1)throw new CryptographicException();
            var bc=new CmsSignedData(new CmsProcessableByteArray(signed),encoded);
            if(!bc.GetSignerInfos().GetSigners().Single().Verify(new X509CertificateParser().ReadCertificate(expected.RawData)))throw new CryptographicException();
            var binding=Attribute(signer.SignedAttributes,CertificateBindingOid);
            var ids=SigningCertificateV2.GetInstance(Asn1Object.FromByteArray(binding)).GetCerts();
            if(ids.Length!=1 || ids[0].HashAlgorithm.Algorithm.Id!=Sha256 || !CryptographicOperations.FixedTimeEquals(ids[0].GetCertHash(),SHA256.HashData(expected.RawData)))throw new CryptographicException();
            var signingTime=new Pkcs9SigningTime(Attribute(signer.SignedAttributes,"1.2.840.113549.1.9.5")).SigningTime.ToUniversalTime();
            if(Math.Abs((signingTime-startedAt.UtcDateTime).TotalSeconds)>=1)throw new CryptographicException();
            var verified=await timestamp.ValidateAsync(Attribute(signer.UnsignedAttributes,TimestampOid),signer,startedAt,ct);
            if(verified.At<expected.NotBefore.ToUniversalTime() || verified.At>=expected.NotAfter.ToUniversalTime())throw new CryptographicException();
            var geometry=document.Pages.Cast<PdfPage>().Select(page=> {
                var media=page.MediaBox; var crop=page.CropBoxReadOnly.IsZero ? media : page.CropBox;
                var left=Math.Max(media.X1,crop.X1); var bottom=Math.Max(media.Y1,crop.Y1); var right=Math.Min(media.X2,crop.X2); var top=Math.Min(media.Y2,crop.Y2);
                var unit=page.Elements.ContainsKey("/UserUnit") ? page.Elements.GetReal("/UserUnit") : 1;
                return new PageGeometry((right-left)*unit,(top-bottom)*unit,(page.Rotate%360+360)%360,unit,
                    [media.X1,media.Y1,media.X2,media.Y2],[left,bottom,right,top]);
            }).ToArray();
            return new(encoded,signed,document.PageCount,verified) { Geometry=geometry };
        }
        catch(Exception e) when(e is CryptographicException or InvalidDataException or AsnContentException or PdfReaderException or
            FormatException or ArgumentException or InvalidOperationException or OverflowException or IndexOutOfRangeException or NullReferenceException or NotImplementedException or
            Org.BouncyCastle.Tsp.TspException or Org.BouncyCastle.Security.GeneralSecurityException ||
            (e.GetType()==typeof(Exception) && e.TargetSite?.DeclaringType?.Assembly==typeof(PdfReader).Assembly))
        { throw new SealUnavailableException("The complete sealed PDF could not be verified; no seal was returned."); }
    }
    private static byte[] Attribute(CryptographicAttributeObjectCollection attributes,string oid)
    {
        var found=attributes.Cast<CryptographicAttributeObject>().Where(x=>x.Oid.Value==oid).ToArray();
        if(found.Length!=1 || found[0].Values.Count!=1)throw new CryptographicException(); return found[0].Values[0].RawData;
    }

    internal sealed class Signer(SealOptions options,SealCertificateMaterial material,TimestampAuthority authority,DateTimeOffset now,CancellationToken ct,
        CompletionTimestampArtifact? timestampContext=null) : IDigitalSigner
    {
        public string CertificateName=>"QuillSign platform seal";
        private int? reservedCapacity;
        public Task<int> GetSignatureSizeAsync()
        {
            ct.ThrowIfCancellationRequested();
            if(reservedCapacity is null) {
                // Size the same local CMS profile, including the configured certificate chain.
                // The timestamp token is smaller than its bounded RFC 3161 response. Allow
                // additional DER length fields and variable-length EC signatures; never call
                // the authority, consume a timestamp allowance or exceed the configured ceiling.
                var localBytes=CreateCms([0]).Encode().Length;
                var bounded=checked(localBytes+options.TsaMaximumResponseBytes+1024);
                reservedCapacity=Math.Min(options.SignatureCapacityBytes,checked((bounded+4095)/4096*4096));
            }
            return Task.FromResult(reservedCapacity.Value);
        }
        public async Task<byte[]> GetSignatureAsync(Stream stream)
        {
            ct.ThrowIfCancellationRequested(); if(stream.Length is <=0 || stream.Length>options.MaximumBytes)throw new SealUnavailableException("The signed byte ranges exceed their limits.");
            // PDFsharp's RangedStream throws from CanSeek. Rewind directly and read complete bounded ranges.
            var bytes=new byte[checked((int)stream.Length)]; stream.Position=0; var offset=0;
            while(offset<bytes.Length) { ct.ThrowIfCancellationRequested(); var read=stream.Read(bytes,offset,bytes.Length-offset); if(read==0)throw new EndOfStreamException(); offset+=read; }
            var capacity=await GetSignatureSizeAsync(); var cms=CreateCms(bytes);
            var timestamp=await authority.RequestAsync(cms.SignerInfos[0],now,ct,timestampContext);
            cms.SignerInfos[0].AddUnsignedAttribute(new AsnEncodedData(new Oid(TimestampOid),timestamp.Encoded));
            var result=cms.Encode(); if(result.Length>capacity)throw new SealUnavailableException("The seal exceeds its reserved signature capacity."); return result;
        }
        private SignedCms CreateCms(byte[] bytes)
        {
            var cms=new SignedCms(new ContentInfo(bytes),true); var signer=new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber,material.Certificate) {
                DigestAlgorithm=new Oid(Sha256),IncludeOption=X509IncludeOption.EndCertOnly };
            foreach(var certificate in material.Chain)signer.Certificates.Add(certificate);
            signer.SignedAttributes.Add(new Pkcs9SigningTime(now.UtcDateTime));
            signer.SignedAttributes.Add(new AsnEncodedData(new Oid(CertificateBindingOid),new SigningCertificateV2(new EssCertIDv2(SHA256.HashData(material.Certificate.RawData))).GetDerEncoded()));
            cms.ComputeSignature(signer,true); ct.ThrowIfCancellationRequested();
            return cms;
        }
    }
}

# Completion PDF seal feasibility

QUILS-18, reviewed 2026-10-15. This is a developer spike using synthetic records and ephemeral keys. It does not enable sealing in the application or certify legal compliance. See the [electronic-signature requirements](e-signature-requirements.md).

## Result

PDFsharp **6.2.4 (MIT)** can write a single completion signature with an RFC 3161 signature timestamp. The spike's custom `IDigitalSigner` output passes detached CMS verification and timestamp binding/signature verification in .NET, BouncyCastle, and OpenSSL. Tampered document bytes, truncation, trailing unsigned bytes, wrong expected certificates, and defective TSA replies are rejected.

The built-in `PdfSharpDefaultSigner` has an interoperability defect in this version: it emits the CMS `signing-time` attribute as **unsigned**. .NET's signature-only check accepts its mathematical signature, but BouncyCastle's certificate-based CMS verifier rejects the unsigned attribute. The [pinned source](https://github.com/empira/PDFsharp/blob/v6.2.4/src/foundation/src/PDFsharp/src/PdfSharp.Cryptography/Pdf.Signatures/PdfSharpDefaultSigner.cs) confirms the attribute placement. The harness preserves this as an expected failing baseline rather than accepting its output as the recommended integration.

The custom prototype puts signing time in signed attributes, adds a signed `SigningCertificateV2` binding, then adds the verified RFC 3161 token as an unsigned signature-timestamp attribute. It uses PDFsharp's existing extension point, without modifying or upgrading PDFsharp. A later production implementation should follow this approach and retain independent verification.

## Format and trust findings

| Observation | Consequence |
| --- | --- |
| PDFsharp writes `/SubFilter /adbe.pkcs7.detached`. | Call this a **PDF digital signature with an RFC 3161 timestamp**. The spike does not claim PAdES baseline conformance. Adding CMS attributes alone does not change the PDF container profile. |
| One `/ByteRange` covers the entire final PDF except `/Contents`. | Complete the final packet before sealing; subsequent modifications need a defined signed-revision policy. The harness rejects trailing bytes rather than interpreting incremental revisions. |
| Both signer implementations use one sizing timestamp plus one actual timestamp on first use; subsequent documents use one actual timestamp. | Reusing a signer can avoid repeated sizing calls. Sizing requests are real TSA operations, even though their dummy content is not a document. |
| Custom prototype adds 1 KiB beyond measured CMS length. | This is a fixture allowance, not a universal capacity guarantee. Production needs a bounded sizing policy accounting for the chosen certificate chain/TSA and must fail closed on overflow. |
| The synthetic self-signed seal is not publicly trusted. | Mathematical validity and signer identity/trust must be reported separately. Do not install fixture roots into a system trust store. |
| The TSA is a loopback fixture using the local clock and an ephemeral certificate. | These timestamps prove protocol/binding compatibility only. They are not independent evidence of real-world time, qualified timestamps, or validation of a public TSA's trust chain. |
| PDFsharp's `RangedStream.CanSeek` throws, and the supplied underlying position can be at end of file. | The prototype explicitly rewinds via `Position` and uses full-length reads, avoiding `Stream.CopyTo`'s capability probe and the library's slow per-byte path. Production must bound memory or implement streaming/prehashed CMS deliberately. |

No per-signer cryptographic signatures, incremental-save strategy, revocation evidence preservation, PAdES B-LT/B-LTA, qualified signer signature, or qualified platform seal is implemented by this spike. A platform certificate still does not identify each human signer or prove their intent.

## Reproduce

Install the .NET 10 SDK, PowerShell 7, and OpenSSL. Git for Windows includes an OpenSSL executable that the helper discovers automatically. From the repository root:

```powershell
pwsh -File scripts/dev/Test-PdfSealSpike.ps1
```

If necessary, provide its path with `-OpenSsl`. The helper runs the C# harness and independently verifies CMS and timestamp output with OpenSSL, including negative content/imprint checks. GitHub Actions runs the same helper on Windows and Linux. Package restore accesses NuGet; timestamping itself uses loopback only and needs no cloud credentials or public TSA.

The C# harness can also be run alone:

```sh
dotnet run --project tools/PdfSealSpike/PdfSealSpike.csproj -c Release
```

Outputs are generated under ignored `artifacts/pdf-seal-spike/` relative to the working directory. They include `sealed.pdf`, the built-in baseline, an altered PDF, detached CMS, the signed byte ranges, a timestamp token, signature bytes, and public fixture certificates. **Private keys remain in memory and are never exported.** Each run replaces the synthetic outputs; key material and bytes differ between runs. Do not commit generated artifacts or use these certificates for actual agreements.

For direct independent checks:

```sh
openssl cms -verify -binary -inform DER \
  -in artifacts/pdf-seal-spike/signature.der \
  -content artifacts/pdf-seal-spike/signed-bytes.bin \
  -noverify -out artifacts/pdf-seal-spike/verified-content.bin

openssl ts -verify -token_in \
  -in artifacts/pdf-seal-spike/timestamp.der \
  -data artifacts/pdf-seal-spike/signature-value.bin \
  -CAfile artifacts/pdf-seal-spike/tsa.crt
```

`cms -noverify` skips the certificate trust-chain decision; it still verifies the detached content/signature. The TSA command trusts only the explicitly supplied synthetic certificate for this fixture. Neither command establishes public trust. The C# harness also compares the expected certificates rather than accepting an arbitrary certificate embedded in CMS.

## Validation coverage

- Positive detached CMS verification in .NET and independently in BouncyCastle/OpenSSL.
- Positive RFC 3161 verification and signature-value hash binding in .NET, BouncyCastle, and OpenSSL.
- Correct signed certificate binding in the custom CMS; observed PDF SubFilter and default-signer incompatibility.
- Repeated signing and measured sizing/actual TSA call counts.
- Signed-byte alteration, truncation, and appended unsigned bytes.
- Unexpected document-seal and TSA certificates.
- TSA HTTP failure, malformed response, wrong imprint, and wrong nonce; successful signing after recovery.
- Self-signed seal rejected by the ordinary system-trust chain decision, with certificate downloads disabled.

`SealInspection` is intentionally a small, strict parser for **the generated single-signature fixtures**. Its regex extraction is not suitable for untrusted PDFs and must not be copied into a production `/verify` upload handler. Production verification needs a real PDF parser, precise revision/ByteRange rules, resource limits, and explicit trust/revocation policy.

## Completion integration follow-ups

1. Implement the production certificate-provider abstraction for local PFX, managed signing, and protected persistent self-signed fallback. This spike never accesses those resources.
2. Build and compare final accepted content/checkpoints and completion pages before sealing. Keep final-file hashes and audit roots free of circular self-reference.
3. Use a custom signer with signed CMS attributes and explicit TSA response validation. Add bounded memory, cancellation/timeouts, overflow handling, and concurrency-safe signer reuse; fixture behavior is sequential only.
4. Configure independent trust anchors/policies, revocation handling, and failure reporting. Distinguish human signing event time, platform completion time, TSA time, cryptographic integrity, and trusted identity.
5. Verify synthetic output in Acrobat and an EU DSS validator before claiming those products accept it. **Neither UI validation was observed in this spike.** Public TSA interoperability, viewer trust behavior, and any desired ETSI SubFilter/profile change remain integration gates; do not label them passed because the offline cryptographic checks pass.
6. Keep the single completion-seal design until a separately reviewed incremental-update/long-term-validation implementation exists. Do not cross PDFsharp's later licensing change to obtain features.

## References

- [PDFsharp signature extension and sizing documentation](https://docs.pdfsharp.net/PDFsharp/Topics/PDF-Features/Signatures.html).
- [PDFsharp 6.2.4 NuGet metadata and MIT license](https://www.nuget.org/packages/PDFsharp/6.2.4).
- [Pinned PDFsharp RangedStream implementation](https://github.com/empira/PDFsharp/blob/v6.2.4/src/foundation/src/PDFsharp/src/PdfSharp/Pdf.Signatures/RangedStream.cs).
- [BouncyCastle 2.6.2 package and license](https://www.nuget.org/packages/BouncyCastle.Cryptography/2.6.2).
- [RFC 3161 timestamp protocol](https://www.rfc-editor.org/rfc/rfc3161).
- [ETSI EN 319 142-1 V1.2.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf).

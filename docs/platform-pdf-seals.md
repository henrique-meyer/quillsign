# Internal timestamped platform PDF seals

QUILS-40 turns the [sealing feasibility findings](pdf-seal-feasibility.md) into an internal, bounded operation. `PlatformPdfSeal.SealAsync` consumes a prepared PDF and its expected SHA-256 and returns verified sealed bytes, source/output hashes, certificate identity and distinct server-seal/TSA times. It does not authorize signing, publish blobs, mark an envelope completed or send mail. Completion pages and their durable publication remain subsequent work.

## Certificate and source boundaries

The operation copies and hashes its bounded input, applies existing unsigned/unencrypted PDF validation and rejects unflattened form fields. It preserves source bytes and page geometry; the output hash identifies the newly serialized sealed file. No final-file hash is written recursively into that same file.

`ISealCertificateProvider` supplies an operation-owned lease. The current adapter loads one private signing identity from `Seal__Pfx__Path` and `Seal__Pfx__Password`, using ephemeral key handles, bounded PFX loading and default KDF limits. Paths must be absolute. Key material is disposed and temporary PFX buffers are cleared. The engine checks validity, signing key usage, non-CA status, RSA 2048–8192 or supported ECDSA curves. If EKU is present, it must include the [document-signing purpose defined by RFC 9336](https://www.rfc-editor.org/rfc/rfc9336.html).

Missing or unusable configured material fails closed. Persistent encrypted self-signed fallback and Key Vault adapters are separate provider slices; this engine never substitutes an ephemeral production certificate. Its certificate lease and per-operation signer contract leave those adapters pluggable. A platform certificate establishes the seal's cryptographic identity; it does not identify or express intent for individual human signers.

## Timestamp protocol and trust

`Seal__TsaUrl` has no default. Production requires HTTPS without credentials, query strings, fragments or redirects. Development additionally permits loopback HTTP for fixtures. The transport sends only a SHA-256 imprint of the CMS signature and a fresh 128-bit nonce; it sends no PDF, signer values or document title. Timeout, response length and content type are bounded. Failed, malformed, mismatched, stale/future or untrusted responses produce no returned seal.

Response validation checks the request nonce/imprint, token signature and signing-certificate binding, critical sole timestamping EKU, validity at TSA time, supported key/digest and a chain to OS trust roots or explicitly supplied private roots. Configure custom roots using `Seal__TsaTrustedRootPaths__0`, etc. Certificate downloads and revocation network lookups are disabled. These checks follow [RFC 3161's response-binding requirements](https://www.rfc-editor.org/rfc/rfc3161.html); .NET and BouncyCastle independently verify the token signature and binding. The returned timestamp policy is the authority's token policy, not an operator policy invented by QuillSign.

This slice does **not** check or preserve revocation evidence, supply LTV validation, establish Adobe trust, certify a qualified timestamp or claim PAdES/AdES/QES conformance. Production TSA interoperability and external viewer validation remain integration gates. Synthetic fixture roots are passed privately to the operation and never installed into system trust stores.

## Complete output verification

PDFsharp remains pinned to MIT-licensed 6.2.4. Its custom signer produces detached CMS with SHA-256, signed signing-time and `SigningCertificateV2`, and a verified RFC 3161 signature timestamp. A bounded fixed reservation avoids dummy sizing calls to the TSA; each successful operation makes one timestamp request and fails on capacity overflow. Signers are operation-local and a semaphore bounds concurrent sealing memory.

The engine parses its output through PDFsharp's object model rather than copying the spike's regex parser. It requires one signature field/dictionary, `/adbe.pkcs7.detached`, a complete four-number ByteRange with only the exact hex Contents gap, zero padding and no trailing uncovered bytes. It verifies the detached digest/signature in .NET and BouncyCastle, the exact acquired certificate, signed certificate/time attributes and the embedded timestamp. It also compares final page geometry before returning any bytes. This is a verifier for the engine's complete single-seal output, not a public untrusted-upload or incremental-revision verifier.

## Reproduce

Run `pwsh -File scripts/dev/Test-PlatformPdfSeal.ps1`. It needs .NET 10, Node.js for the existing asset build and OpenSSL; it needs no SQL, cloud credentials, public TSA or live email. Tests generate local ephemeral keys and a loopback authority. The helper independently verifies production CMS/timestamp output with OpenSSL and rejects changed signed bytes/imprints. `cms -noverify` verifies content/signature but deliberately does not assert public trust in the synthetic platform certificate. Timestamp verification trusts only the supplied synthetic root. Windows and Linux CI run the same helper.

Evidence stays under ignored `artifacts/platform-seal/`: source/sealed PDFs, detached CMS, signed bytes, timestamp, signature value and the public TSA root. Private keys are not exported there. Render both PDFs with Poppler for visual comparison; sealing adds no visible mark or new page. Actual TSA/certificate configuration remains empty in examples, and registration performs no certificate, network or database work at startup.

# Document conversion and sender upload

`GotenbergDocxConverter` sends one DOCX to the configured Gotenberg LibreOffice conversion route, then validates and normalizes the returned PDF with the same PDFsharp byte/page/geometry rules as PDF upload. It returns the exact normalized bytes, original SHA-256, normalized SHA-256 and page geometry. The caller keeps ownership of the original input stream.

`DocxDocumentWorkflow` joins package validation, conversion, original/PDF storage, audit and upload retention. The verified-sender upload handler selects this workflow only for a `.docx` filename when conversion is configured. Browser MIME labels grant no trust: the package gate validates the actual content before the ordinary Gotenberg HTTP request. The resulting normalized PDF is previewed/downloaded and requires explicit confirmation before preparation continues. No automatic Conversion work producer is used. Plain text has internal conversion support below; its public upload integration and other Office formats remain future work.

| Setting | Default / requirement |
| --- | --- |
| `Gotenberg__Enabled` | `false` |
| `Gotenberg__BaseUrl` | Empty; explicit private HTTPS origin when enabled |
| `Gotenberg__TimeoutSeconds` | 60; allowed range 1–120 |
| `Documents__MaximumBytes` | Bounds both DOCX input and returned/normalized PDF |
| `Documents__MaximumPages` | Bounds the validated converted PDF |

Plain HTTP is limited to loopback or the local `gotenberg` Compose service in Development. A configured origin cannot contain credentials, a path, query or fragment. The client uses the fixed `/forms/libreoffice/convert` route and a fixed multipart filename. Redirects, system proxies and automatic decompression are disabled on the registered client. There is no user-controlled target, callback, remote-download form field or automatic retry.

The linked cancellation deadline covers input copying, HTTP and response-body reads, and is checked before and after synchronous bounded PDF validation. Caller cancellation propagates. A non-PDF/encoded, truncated, oversized, encrypted, malformed or excessive-page response returns no conversion result. Application failures omit provider bodies, filenames, trace headers and endpoint details. The registered client removes default HTTP request loggers so its configured URL is excluded from those logs. HTTP 400 becomes a generic document rejection; service/transport failures remain recoverable generic errors.

The conversion request asks for flattened exported form fields and tagged PDF structure; it does not claim PDF/UA or archival conformance. See [Gotenberg's LibreOffice route](https://gotenberg.dev/docs/convert-with-libreoffice/convert-to-pdf). Operators still need the pinned, private conversion sidecar and its no-egress controls; client URL validation does not replace network isolation. The existing local Compose service has no published port, uses the conversion-only internal network, disables Chromium/download/webhook routes and denies LibreOffice outbound URLs.

Local verification uses generated synthetic documents with no agreement or personal data. The real pinned sidecar converted an explicit two-page DOCX; both normalized PDF pages were rendered and inspected, and original/normalized hashes and geometry matched. Hosted service enablement and resource changes are outside this slice.

## Internal plain-text conversion

`TextPdfConverter` accepts nonempty strict UTF-8 plain text, with an optional UTF-8 BOM. It rejects invalid UTF-8, binary/control characters other than tab and line endings, XML-incompatible characters, whitespace-only input and size mismatches before HTTP. UTF-16 and legacy encodings must be saved as UTF-8 or exported to PDF. The original hash covers the exact input bytes, including any BOM.

The converter serializes text into a minimal owned DOCX with escaped literal text, paragraphs and tabs, then validates that package through `DocxPackageValidation` and reuses the registered `GotenbergDocxConverter`. It never submits an untrusted `.txt` to format detection. HTML, XML, RTF instructions, formulas and URL-looking strings print literally; they cannot create relationships, fields, scripts or embedded objects. CRLF, CR and LF each produce paragraph boundaries, tabs remain tabs and leading/trailing spaces are preserved. Page layout and available fonts come from LibreOffice; this is a PDF conversion, not a promise to reproduce a text editor's layout.

Original text, generated package and normalized PDF must each fit `Documents__MaximumBytes`; the expanded wrapper XML is additionally capped at 8 MiB. The shared configured total deadline includes input copying, wrapper generation, package validation and HTTP/PDF processing. Existing PDF/page limits, private fixed endpoint, disabled redirects/proxies/request logging, safe errors and no automatic retry remain in force. Excessively large or complex text must be exported to PDF instead.

This is an internal service only: there is no TXT upload choice, persistence workflow, new configuration, schema change or hosted enablement. Future upload integration must preserve the original text separately, record both hashes and require exact PDF preview confirmation with the existing authority and fixed retention checks.

Local validation used the pinned isolated Gotenberg service: a three-page multilingual synthetic text and one-page HTML/RTF-looking examples retained their literal content and exact hashes. All five pages were rendered and inspected. A receiver on the same private test network saw zero callbacks; the converter had no default route and a direct external connection failed. These are local checks, not hosted conversion evidence.

## DOCX package gate

`DocxPackageValidation.ValidateAsync` makes a bounded owned copy and checks the declared and actual length, ZIP headers, CRCs, content types, main document and relationships. It extracts no files and performs no network or database work. `ValidatedDocx` exposes independent read-only streams and a copied original SHA-256; disposing it clears its own retained bytes without disposing the caller's stream. Conversion must use that validated copy rather than rereading mutable caller data.

The supported profile is unencrypted, non-macro DOCX with stored/deflated ZIP entries and ordinary document parts, headers, images and explicit HTTP/HTTPS/mailto hyperlinks. Hyperlinks are preserved without following them. ZIP64, alternate Unicode ZIP paths, duplicate/case aliases, filesystem links, unlisted local records, conflicting headers, unsafe paths, embedded packages/OLE/ActiveX, macros, signed packages, SVG, linked templates/subdocuments and external resources are rejected. XML disallows DTDs, external entity resolution and processing instructions. Conservative field-code validation permits page numbering and common inert/calculated fields; DDE and linked-content fields are rejected. Unsupported input must be exported to PDF by the sender.

| Package limit | Bound |
| --- | --- |
| Original bytes | `Documents__MaximumBytes` |
| Entries | 2,048 |
| One expanded part | 16 MiB |
| All expanded parts | 64 MiB |
| One XML part | 8 MiB |
| XML depth / total elements | 64 / 1,000,000 |
| Validation deadline | 15 seconds, including copying and decompression |

Actual decompression and parsing are bounded independently of declared ZIP sizes. Caller cancellation propagates; a validation deadline or unsupported/malformed package returns a generic rejection without uploaded names, paths, XML or inner exceptions. The isolated no-egress converter remains required: package validation is not a substitute for running LibreOffice with its existing network restrictions.

Synthetic validation covers normal and streaming ZIP packages, exact byte/hash ownership, traversal/aliases, alternate ZIP metadata, CRC/encryption/expansion limits, active content, fragmented field codes, XML entities/depth, cancellation and a local receiver that confirms resources/hyperlinks are never fetched. The same validated two-page source also passes through the real local Gotenberg service; both output pages are rendered and inspected.

## Sender document workflow

`DocxDocumentWorkflow.UploadAsync` checks the current sender, draft revision and verified retention deadline before reading the package or contacting the converter. It validates the owned DOCX and compares the client's original hash with the gate hash. After conversion it checks authority, revision and deadline again before writing new objects. No SQL connection or transaction is held during conversion; an already-open caller transaction is rejected.

The original DOCX and exact normalized PDF are stored separately. `OriginalMime` identifies the validated DOCX; the display/download title remains a sanitized `.pdf` name. The upload/replacement audit binds both hashes, page count and conversion provenance: sanitized original `.docx` name, source media, byte lengths and the application pipeline version `docx-gotenberg-v1`. That version identifies the application contract, not an attested LibreOffice build.

Storage and locked SQL publication share the existing PDF upload transaction. A successful replacement clears old preview confirmation, fields and stale suggestions; PDF uploads retain their existing audit shape. The first successful configured demo upload captures one fixed retention deadline, and replacements/settings changes do not reset it. Known failures clean only new operation-owned objects. Uncertain commit acknowledgements preserve potentially committed pairs; retrying the old revision fails before another conversion. The sender must still confirm the normalized PDF explicitly.

SQL Server/Azurite tests cover both replacement directions, immutable source/hash/media evidence, preview confirmation, concurrent revisions, revoked authority, cutoff crossings, rollback and uncertain commits. A real isolated Gotenberg capture supplies an exact synthetic source/response fixture for the persistence test, which runs the client's PDF normalization and verifies stored content, retention/audit and confirmation. Live converter transport and SQL persistence are tested at their separate boundaries; no combined live SQL/converter or hosted-flow claim is made.

## Public upload and preview

The verified-sender form accepts exactly one PDF, supported PNG/JPEG, or DOCX when a usable converter origin and supported limits are configured. Disabled or invalid converter configuration omits DOCX from the choices and returns a generic recoverable error for an attempted DOCX upload. Client extension/size checks are hints; the server retains authorization, CSRF, rate/body limits, actual content validation and row-version checks. It never falls back to another parser for invalid content.

Successful upload redirects to the clean draft URL and displays only the normalized PDF. Conversion failure preserves the previous source and preparation. Successful replacement clears the previous confirmation and fields, preserves the first upload's retention cutoff, and requires a new explicit confirmation. Original files have no public download route. Senders must inspect converted layout/fonts and export their own PDF if the supported profile does not produce a suitable result.

Browser checks exercise desktop/mobile/keyboard upload, both pages, zoom, verified download, explicit confirmation, failure preservation and deliberate recovery. The DOCX browser flow replays the exact response captured from the real isolated converter only after verifying the source bytes, while using actual package validation, normalization and SQL/Azurite persistence. Its downloaded PDF matches the persisted hash. This controls the external transport boundary; live combined converter connectivity and hosted end-to-end validation remain unverified.

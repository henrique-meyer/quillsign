# Document conversion and sender upload

The [hosted DOCX setup proposal](hosted-docx-setup.md) describes the isolated Azure pilot, scoped permissions, costs and approval gates. The pilot is complete. The selectable application transport below was enabled in the approved bounded demo rollout on 2026-10-18. Two real hosted synthetic DOCX uploads passed desktop/mobile preview, exact-byte download and affirmative keyboard confirmation. Email remains disabled; the operator seeded explicitly synthetic sender authority, so this does not demonstrate mailbox delivery. A third conversion deliberately failed before its delete requests in an unshipped operator helper. The existing SQL-free recovery job cleaned the protected pending operation; its successful output, empty final sandbox/snapshot/image inventory and idle ledger were verified. All three attempts remain counted under the four-attempt daily/monthly validation caps. The helper was removed, and a concurrent failed replacement preserved the saved source, preview confirmation and original seven-day deadline. This bounded run does not establish invoice totals or hosted mailbox signing/completion; storage/uncertain-commit fault coverage remains local automated coverage.

`GotenbergDocxConverter` sends one DOCX to the configured Gotenberg LibreOffice conversion route, then validates and normalizes the returned PDF with the same PDFsharp byte/page/geometry rules as PDF upload. It returns the exact normalized bytes, original SHA-256, normalized SHA-256 and page geometry. The caller keeps ownership of the original input stream.

`DocxDocumentWorkflow` joins package validation, conversion, original/PDF storage, audit and upload retention. The verified-sender upload handler selects this workflow only for a `.docx` filename when conversion is configured. Browser MIME labels grant no trust: the package gate validates the actual content before the ordinary Gotenberg HTTP request. The resulting normalized PDF is previewed/downloaded and requires explicit confirmation before preparation continues. No automatic Conversion work producer is used. Strict UTF-8 text has optional sender intake below; the static Office profiles have separately guarded sender intake below.

| Setting | Default / requirement |
| --- | --- |
| `Gotenberg__Enabled` | `false` |
| `Gotenberg__Transport` | `Http`; choose `Sandbox` explicitly for the isolated hosted transport below |
| `Gotenberg__BaseUrl` | Empty; explicit private HTTPS origin when enabled |
| `Gotenberg__TimeoutSeconds` | 60; allowed range 1–120 for HTTP, 1–180 for Sandbox |
| `Documents__MaximumBytes` | Bounds both DOCX input and returned/normalized PDF |
| `Documents__MaximumPages` | Bounds the validated converted PDF |

Plain HTTP is limited to loopback or the local `gotenberg` Compose service in Development. A configured origin cannot contain credentials, a path, query or fragment. The client uses the fixed `/forms/libreoffice/convert` route and a fixed multipart filename. Redirects, system proxies and automatic decompression are disabled on the registered client. There is no user-controlled target, callback, remote-download form field or automatic retry.

The linked cancellation deadline covers input copying, HTTP and response-body reads, and is checked before and after synchronous bounded PDF validation. Caller cancellation propagates. A non-PDF/encoded, truncated, oversized, encrypted, malformed or excessive-page response returns no conversion result. Application failures omit provider bodies, filenames, trace headers and endpoint details. The registered client removes default HTTP request loggers so its configured URL is excluded from those logs. HTTP 400 becomes a generic document rejection; service/transport failures remain recoverable generic errors.

The conversion request asks for flattened exported form fields and tagged PDF structure; it does not claim PDF/UA or archival conformance. See [Gotenberg's LibreOffice route](https://gotenberg.dev/docs/convert-with-libreoffice/convert-to-pdf). Operators still need the pinned, private conversion sidecar and its no-egress controls; client URL validation does not replace network isolation. The existing local Compose service has no published port, uses the conversion-only internal network, disables Chromium/download/webhook routes and denies LibreOffice outbound URLs.

Local verification uses generated synthetic documents with no agreement or personal data. The real pinned sidecar converted an explicit two-page DOCX; both normalized PDF pages were rendered and inspected, and original/normalized hashes and geometry matched. Hosted service enablement and resource changes are outside this slice.

## Isolated sandbox application transport

`Sandbox` reuses the same package gate, original/PDF storage, normalization, private preview and affirmative confirmation. It authenticates directly to the regional sandbox data plane with the configured managed identity. It never falls back to developer credentials, a public converter or the HTTP transport. Provider URLs, tokens, document names and error bodies are excluded from application HTTP logs and public errors. Existing `Azure.Identity` is reused; no new library dependency is added.

| Additional setting | Default / requirement |
| --- | --- |
| `Gotenberg__Sandbox__Region` | Empty; approved regional DNS label |
| `Gotenberg__Sandbox__SubscriptionId` | Empty; approved subscription GUID |
| `Gotenberg__Sandbox__ResourceGroup` | Empty; dedicated project resource group |
| `Gotenberg__Sandbox__GroupName` | Empty; approved dedicated sandbox group |
| `Gotenberg__Sandbox__ManagedIdentityClientId` | Empty; uses the existing storage identity when configured, otherwise system-assigned identity |
| `Gotenberg__Sandbox__MaximumDailyAttempts` | 10; server UTC, range 1–100 |
| `Gotenberg__Sandbox__MaximumMonthlyAttempts` | 50; server UTC, range 1–1,000 and at least the daily cap |
| `Gotenberg__Sandbox__MaintenanceEnabled` | `false`; enable only on the approved storage-only recovery job |

All actual scope and identity values belong in ignored configuration or runtime environment settings. The app identity and, separately, the recovery job require Data Owner access scoped to this group. The application does not assign roles or provision the group.

A protected, non-personal ledger in `originals/conversion-coordination/` shares one finite renewable blob lease across replicas. It contains only scope, UTC counters, random ownership nonce and provider resource IDs. Each attempt reserves quota before image import, including failed or uncertain attempts; cleanup never refunds it. Caps limit attempts, not the Azure invoice, and must complement the approved test budget and operator cost review. Idle maintenance reads only Blob Storage and makes no SQL or provider request.

Each admitted attempt imports the pinned Gotenberg image, starts one bounded 1-CPU/2-GiB sandbox and verifies actual runtime route restrictions, no credentials/environment/ports/volumes/connections, enforced deny-all egress with full inspection and a recorded denial of a benign HTTPS probe before uploading the DOCX. The input uses one fixed authenticated path, its remote SHA-256 must match the validated source, and conversion writes outside the root-owned upload directory. No user-controlled command, origin, callback or download URL is accepted. Import, conversion, response sizes and cleanup have separate finite bounds; normal provisioning/conversion is capped at 150 seconds and cleanup at a further 30 seconds. Provider auto-suspend/delete is a fallback, not evidence of cleanup.

The app deletes and verifies absence of its exact owned sandbox, snapshots and imported image before returning a successful PDF. Unrelated objects are never deleted. A lost creation acknowledgement is reconciled by exact nonce/profile; absence alone cannot prove that an unobserved create will never arrive, so unresolved evidence closes admission across restarts. Ownership loss cancels work. Cleanup retains its own short deadline when the upload caller disconnects. `work purge-recover` optionally recovers this same ledger after its ordinary storage-only purge pass; malformed maintenance settings report pending without skipping that purge pass. An unresolved state requires inspection of private provider evidence, not deleting the ledger or resetting counters.

Tests cover regional API scoping, authentication audience, no retries/redirects/body disclosure, policy/runtime/source mismatches, cancellation, quota persistence, unknown create/delete recovery and preservation of unrelated resources. Real Azurite tests cover separate owners, finite lease fencing, restart/tamper checks and scope aliases. SQL/Azurite upload tests exercise this coordinator through the actual sender handlers with a synthetic provider boundary; these do not claim live hosted connectivity.

## Optional plain-text upload and conversion

`TextPdfConverter` accepts nonempty strict UTF-8 plain text, with an optional UTF-8 BOM. It rejects invalid UTF-8, binary/control characters other than tab and line endings, XML-incompatible characters, whitespace-only input and size mismatches before HTTP. UTF-16 and legacy encodings must be saved as UTF-8 or exported to PDF. The original hash covers the exact input bytes, including any BOM.

The converter serializes text into a minimal owned DOCX with escaped literal text, paragraphs and tabs, then validates that package through `DocxPackageValidation` and reuses the registered `GotenbergDocxConverter`. It never submits an untrusted `.txt` to format detection. HTML, XML, RTF instructions, formulas and URL-looking strings print literally; they cannot create relationships, fields, scripts or embedded objects. CRLF, CR and LF each produce paragraph boundaries, tabs remain tabs and leading/trailing spaces are preserved. Page layout and available fonts come from LibreOffice; this is a PDF conversion, not a promise to reproduce a text editor's layout.

Original text, generated package and normalized PDF must each fit `Documents__MaximumBytes`; the expanded wrapper XML is additionally capped at 8 MiB. The shared configured total deadline includes input copying, wrapper generation, package validation and HTTP/PDF processing. Existing PDF/page limits, private fixed endpoint, disabled redirects/proxies/request logging, safe errors and no automatic retry remain in force. Excessively large or complex text must be exported to PDF instead.

The internal converter is always registered. TXT intake separately requires `Documents__EnableTextUploads=true` (default false) and a usable configured Gotenberg transport. A later image deployment therefore does not silently enable TXT on an existing instance. There is no schema or hosted-setting change. The authenticated private draft form shows TXT only when both gates pass; disabled requests return a recoverable unavailable response before conversion.

`TextDocumentWorkflow` first checks sender authority, draft revision and fixed retention, then copies the original once into bounded operation-owned temporary storage. Conversion uses that owned source, and its original hash must match before publication. The exact text bytes, including any BOM and original line endings, are stored as `text/plain` separately from the normalized PDF. Audit provenance uses `text-docx-gotenberg-v1`, source/PDF lengths, sanitized TXT name and both hashes. Shared atomic publication rechecks authority, revision and cutoff, preserves rollback/uncertain-commit behavior and clears preparation only on success. Replacements keep the first upload retention deadline. The generated DOCX is only a transport wrapper; its hash never replaces the original text hash. The sender reviews/downloads the exact normalized PDF and must explicitly confirm it. Unsupported encodings must be saved as UTF-8 or exported to PDF.

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

SQL Server/Azurite tests cover both replacement directions, immutable source/hash/media evidence, preview confirmation, concurrent revisions, revoked authority, cutoff crossings, rollback and uncertain commits. A real isolated Gotenberg capture supplies an exact synthetic source/response fixture for the persistence test, which runs the client's PDF normalization and verifies stored content, retention/audit and confirmation. Those local tests cover transport and persistence at separate boundaries. The bounded hosted rollout additionally verifies their combined path with synthetic data; its evidence and limits are described above.

## Public upload and preview

The verified-sender form accepts exactly one PDF, supported PNG/JPEG, DOCX when a usable converter and supported limits are configured, strict UTF-8 TXT when its separate intake gate is enabled, or one of the static Office profiles when its master/family/HTTP gates below pass. Disabled or invalid converter configuration omits DOCX from the choices and returns a generic recoverable error for an attempted DOCX upload. Client extension/size checks are hints; the server retains authorization, CSRF, rate/body limits, actual content validation and row-version checks. It never falls back to another parser for invalid content.

Successful upload redirects to the clean draft URL and displays only the normalized PDF. Conversion failure preserves the previous source and preparation. Successful replacement clears the previous confirmation and fields, preserves the first upload's retention cutoff, and requires a new explicit confirmation. Original files have no public download route. Senders must inspect converted layout/fonts and export their own PDF if the supported profile does not produce a suitable result.

Browser checks exercise desktop/mobile/keyboard upload, both pages, zoom, verified download, explicit confirmation, failure preservation and deliberate recovery. The DOCX browser flow replays the exact response captured from the real isolated converter only after verifying the source bytes, while using actual package validation, normalization and SQL/Azurite persistence. Its downloaded PDF matches the persisted hash. That local test controls the external transport boundary. The subsequent bounded hosted rollout used the actual managed-identity sandbox transport, hosted database and Blob Storage for two real synthetic uploads; neither path demonstrates mailbox delivery while email is disabled.

## Guarded static Office intake

PPTX, values-only XLSX, static ODT and literal-formatting RTF have private sender intake under QUILS-124. The master switch `Documents__EnableOfficeUploads` and each selected `OfficeConversion__PptxEnabled`, `OfficeConversion__XlsxEnabled`, `OfficeConversion__OdtEnabled` or `OfficeConversion__RtfEnabled` switch default to `false`. Both switches and a usable **HTTP** conversion transport are required before that family is shown or accepted. The existing hosted sandbox remains DOCX-only; it is never used as a fallback. Hosted support requires a separate source-kind rollout and owner-approved settings and validation.

`OfficeDocumentWorkflow` authorizes the sender, draft revision and retention cutoff before reading. It invokes the exact family content gate, owns the bounded original and verifies the conversion's source hash. Shared atomic publication rechecks authority, revision and cutoff after conversion, stores the original with its verified MIME separately from the normalized PDF and preserves the first upload's retention deadline. Storage/audit rollback and uncertain-commit recovery use the existing publication contract. Rejected input and failed replacements preserve the previous document and confirmation.

Audit provenance records the original filename/MIME/length, PDF length and independently hashed conversion-input length. The pipelines are `static-pptx-gotenberg-v1`, `values-xlsx-print-gotenberg-v1`, `static-odt-gotenberg-v1` and `literal-rtf-docx-gotenberg-v1`. XLSX uses a separately hashed print-profile copy; RTF becomes an independently validated literal DOCX. Neither replaces the exact original hash. These identifiers describe the application contract, not an attested importer build.

The sender must inspect every page, download if needed and explicitly confirm the exact normalized PDF before continuing. Profile limitations appear beside the upload control. Unsupported content is rejected rather than silently omitted or passed to another importer; export it to PDF. See [PPTX](static-pptx.md), [XLSX](values-xlsx.md), [ODT](static-odt.md) and [RTF](static-rtf.md) for their deliberately narrow profiles. Legacy [DOC remains unsupported](legacy-doc.md).

Local evidence covers all four real pinned-service upload/preview/zoom/two-page/download/keyboard-confirmation flows, desktop and mobile layouts, exact original/downloaded PDF hashes and preserved confirmation after disguised input or a converter outage, followed by explicit recovery. Scoped SQL/Azurite tests cover CSRF, stale revisions, authority/retention changes during conversion, cancellation, malformed/provider output, rollback, uncertain commits and immutable first retention. The converter has no default route and direct DNS/IP egress fails. This evidence makes no hosted availability claim and used no cloud conversion, email or timestamp call.

## Remaining Office formats

See the [family assessment and implementation gates](office-formats.md) for TXT, PPTX, XLSX, ODT, RTF and legacy DOC. Only independently validated profiles may be added; converter import support alone does not enable intake.

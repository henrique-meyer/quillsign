# Internal DOCX conversion foundation

`GotenbergDocxConverter` sends one DOCX to the configured Gotenberg LibreOffice conversion route, then validates and normalizes the returned PDF with the same PDFsharp byte/page/geometry rules as PDF upload. It returns the exact normalized bytes, original SHA-256, normalized SHA-256 and page geometry. The caller keeps ownership of the original input stream.

This is an internal transport component. Public upload remains PDF-only. `DocxPackageValidation` provides the separate package gate described below. A dependent intake slice must call that gate and enforce sender authority before conversion, then integrate original storage, audit, retention and deliberate sender preview. No public handler or supported Conversion work producer invokes it yet. Other Office/image formats remain future work.

| Setting | Default / requirement |
| --- | --- |
| `Gotenberg__Enabled` | `false` |
| `Gotenberg__BaseUrl` | Empty; explicit private HTTPS origin when enabled |
| `Gotenberg__TimeoutSeconds` | 60; allowed range 1–120 |
| `Documents__MaximumBytes` | Bounds both DOCX input and returned/normalized PDF |
| `Documents__MaximumPages` | Bounds the validated converted PDF |

Plain HTTP is limited to loopback or the local `gotenberg` Compose service in Development. A configured origin cannot contain credentials, a path, query or fragment. The client uses the fixed `/forms/libreoffice/convert` route and a fixed multipart filename. Redirects, system proxies and automatic decompression are disabled on the registered client. There is no user-controlled target, callback, remote-download form field or automatic retry.

The linked cancellation deadline covers input copying, HTTP and response-body reads, and is checked before and after synchronous bounded PDF validation. Caller cancellation propagates. A non-PDF/encoded, truncated, oversized, encrypted, malformed or excessive-page response returns no conversion result. Provider error bodies, filenames, trace headers and endpoint details are not logged or included in user-facing failures. HTTP 400 becomes a generic document rejection; service/transport failures remain recoverable generic errors.

The conversion request asks for flattened exported form fields and tagged PDF structure; it does not claim PDF/UA or archival conformance. See [Gotenberg's LibreOffice route](https://gotenberg.dev/docs/convert-with-libreoffice/convert-to-pdf). Operators still need the pinned, private conversion sidecar and its no-egress controls; client URL validation does not replace network isolation. The existing local Compose service has no published port, uses the conversion-only internal network, disables Chromium/download/webhook routes and denies LibreOffice outbound URLs.

Local verification uses generated synthetic documents with no agreement or personal data. The real pinned sidecar converted an explicit two-page DOCX; both normalized PDF pages were rendered and inspected, and original/normalized hashes and geometry matched. Hosted service enablement and resource changes are outside this slice.

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

Synthetic validation covers normal and streaming ZIP packages, exact byte/hash ownership, traversal/aliases, alternate ZIP metadata, CRC/encryption/expansion limits, active content, fragmented field codes, XML entities/depth, cancellation and a local receiver that confirms resources/hyperlinks are never fetched. The same validated two-page source also passes through the real local Gotenberg service; both output pages are rendered and inspected. Public DOCX intake and its sender confirmation remain dependent work.

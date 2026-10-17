# Internal DOCX conversion foundation

`GotenbergDocxConverter` sends one DOCX to the configured Gotenberg LibreOffice conversion route, then validates and normalizes the returned PDF with the same PDFsharp byte/page/geometry rules as PDF upload. It returns the exact normalized bytes, original SHA-256, normalized SHA-256 and page geometry. The caller keeps ownership of the original input stream.

This is an internal transport component. Public upload remains PDF-only. A dependent intake slice must validate DOCX packages, reject macros/unsupported formats and enforce sender authority before calling it, then integrate original storage, audit, retention and deliberate sender preview. No public handler or supported Conversion work producer invokes it yet. Other Office/image formats remain future work.

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

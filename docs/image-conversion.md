# Internal image-to-PDF conversion

`ImagePdfConverter` validates and decodes one supported PNG or JPEG into a one-page normalized PDF. It performs no SQL or network work. Public upload remains PDF-only; a dependent intake slice must enforce sender authority, store the original and normalized PDF, bind upload/retention evidence and require deliberate sender preview confirmation.

The converter uses pinned StbImageSharp 2.30.16 under its MIT option for managed pixel decoding, then the existing MIT PDFsharp 6.2.4 writer and PDF validator. It adds no native imaging runtime. The upstream MIT notice accompanies published builds; [upstream licensing and API](https://github.com/StbSharp/StbImageSharp/tree/125af70cb557033f2c46aec8e82eaaf72ac49817) and [package](https://www.nuget.org/packages/StbImageSharp/2.30.16) describe the decoder.

The supported profile is conservative:

- Static, noninterlaced PNG: grayscale, grayscale/alpha, indexed, RGB or RGBA at supported depths up to eight bits. PNG chunk CRCs, ordering and exact zlib expansion/checksum are verified before the general decoder runs. Standard sRGB gamma/chromaticities are supported; other embedded color profiles require export to PDF.
- Baseline or progressive eight-bit grayscale/three-component JPEG with up to 16 scans. Marker lengths and dimensions are checked before decoding. Embedded ICC profiles, multipicture containers and ambiguous/trailing content require export to PDF.
- All eight EXIF orientation values are applied, including mirrored forms, using a bounded TIFF orientation read. Unsupported, repeated or malformed orientation metadata is rejected. Other source metadata is excluded from the generated image/PDF.
- Transparency is composited over white. Decoded pixels are losslessly encoded into an ordinary RGB PNG for embedding, so a photographic JPEG can produce a larger PDF than its original compressed file.

One image is centered on a portrait or landscape Letter page with 24-point margins. The complete oriented image fits without cropping or stretching. Original DPI metadata does not change this layout. The returned page geometry describes the exact normalized PDF that the sender must review.

| Limit | Bound |
| --- | --- |
| Original and generated PDF bytes | `Documents__MaximumBytes` |
| Width or height | 12,000 pixels |
| Decoded area | 12 million pixels |
| PNG chunks / JPEG markers | 4,096 |
| Active conversion | One per application process |
| Input/queue deadline | 15 seconds |

The deadline includes input copying and waiting for process admission; cancellation is checked around bounded synchronous decoding, encoding and PDF validation. It cannot preempt an individual synchronous library call. PNG expansion is checked against actual dimensions before allocation by the general decoder. A queued conversion can cancel without reading its input. Caller cancellation propagates, and all error paths release admission. Rejections do not contain source metadata, filenames, decoder diagnostics or inner exceptions.

`ImagePdfConversion` owns the original and normalized PDF, their SHA-256 hashes, safe source MIME and oriented dimensions. It exposes independent read-only streams and copied hashes/geometry. Disposing it clears its own retained bytes; the caller retains ownership of its original input stream. A later intake must use these owned bytes rather than rereading mutable caller input.

Validation uses generated synthetic images only: actual embedded PDF pixels verify all eight orientations for both PNG and JPEG, grayscale/indexed conversion, white compositing, retained aspect and margins. Malformed/truncated images, active/unsupported profiles, decompression beyond the declared geometry, limits, cancellation and source ownership return no conversion result. Public format enablement and hosted settings are separate work.

# PDF field stamping feasibility (QUILS-22)

PDFsharp 6.2.4 can append upright text, checkboxes and image marks to the tested rotated and cropped pages using an explicit transform. The isolated harness passes on Windows and in the same minimal .NET 10 Linux runtime image used by the app. It does not mutate envelopes, freeze documents, accept signatures, send mail or establish legal validity. QUILS-24 also runs all nine geometry fixtures through the actual [sender-prefill renderer](sender-pdf-rendering.md), retaining the original prototype checks.

## Reproduce

With .NET 10, Python, PowerShell 7 and the normal Git checkout:

```powershell
pwsh -File scripts/dev/Test-PdfFieldSpike.ps1
```

The helper verifies the committed PDF.js/font hashes, restores the locked NuGet graph, and writes synthetic PDFs, rendered PNGs and `report.json` under ignored `artifacts/pdf-fields`. Initial restore requires registry access; after package restore the harness itself needs no network. Use `-OutputDirectory` for another ignored directory or a location outside the repository.

For the minimal Linux runtime, with Docker:

```powershell
docker build -f tools/PdfFieldSpike/Dockerfile -t quillsign-pdf-field-spike-test .
New-Item -ItemType Directory -Force artifacts/pdf-fields-linux
docker run --rm --network none --mount "type=bind,source=$((Resolve-Path artifacts/pdf-fields-linux).Path),target=/results" quillsign-pdf-field-spike-test /results
```

The container runs as the image's non-root app user, with no added operating-system packages. On Linux hosts, make the output directory writable by that user. CI also runs the helper on Windows and Ubuntu. This is a developer-only executable; PDFtoImage, SkiaSharp and PDFium are absent from the production web project's dependency graph. Production uses managed PdfPig for embedded-font cmap validation.

## Observed checks

Nine synthetic cases cover Letter, A4, landscape, rotations 90/180/270, an offset CropBox, a rotated offset CropBox, and rotation 270 with offset crop and UserUnit 2. All seven field types are exercised, including multiline text, names, dates, checked/unchecked boxes, and differently proportioned PNG signature/initials marks.

- PDFium rasterization through PDFtoImage independently locates the blue fiducial within 2.5 pixels at 72 dpi, preserves the original red content bounds, checks upright text and field bounds, distinguishes checkbox interiors, and checks image aspect ratios.
- PdfPig independently extracts every text value and the original embedded `BASE` text. Tested text includes accented Latin, Greek, Cyrillic and the euro symbol. Canonically equivalent accents normalize to NFC.
- A long fitting value independently extracts at 9.5 points, demonstrating the adaptive size path. A deliberately naive page transform fails the fiducial check, demonstrating that the geometry check detects that regression.
- Twenty-five negative cases reject invalid geometry/type/page, missing or oversized values, unreadable fields, overflow, unsupported scripts/glyphs/control characters, invalid dates/checkboxes/images, changed source bytes, changed page metadata, too many fields, oversized image dimensions, and changed font bytes.

Windows and offline Linux runs pass these checks. Output sizes are approximately 36 KB for these small fixtures; this is not a general size/performance benchmark. Renderers can differ in antialiasing, so these checks use measured bounds rather than byte-identical screenshots.

## Coordinates and fitting

Stored fields use fractions of the visible, rotated CropBox with a top-left origin. The renderer converts those fractions into **physical points** before drawing, so an 8–12 point font has the same physical size when `/UserUnit` differs from one. It temporarily sets `/Rotate` to zero, opens append-mode XGraphics, applies the matrix below, closes graphics, then restores the rotation. Existing content is retained.

For CropBox `[L,B,R,T]`, unrotated MediaBox height `H`, and `s = 1 / UserUnit`, the matrix coefficients `(a,b,c,d,e,f)` mapping visible physical points to PDFsharp's downward-Y graphics space are:

| Rotation | Matrix |
| --- | --- |
| 0 | `(s,0,0,s,L,H-T)` |
| 90 | `(0,-s,s,0,L,H-B)` |
| 180 | `(-s,0,0,-s,R,H-B)` |
| 270 | `(0,s,-s,0,R,H-T)` |

This is different from the raw PDF user-space rectangle returned by `FieldGeometry.ToPdfRectangle`; that helper describes a box before rotation/UserUnit rather than an upright drawing transform.

One important measurement: PDFium's page-size API reports **722 × 542** for the UserUnit-2 fixture, while its physical visible page is **1444 × 1084** points. The harness therefore supplies explicit raster width/height from verified page geometry instead of trusting that API's size interpretation. A local PDF.js browser preview independently rendered Letter, rotation-90 crop and rotation-270 crop/UserUnit-2 outputs; the latter reported 1444 × 1084 physical points with upright field text and preserved original content. App publish output also retained the exact font and license hashes.

Text uses embedded, hash-pinned Liberation Sans 2.1.5, two-point padding, explicit line breaks and font sizes from 12 down to 8 points in quarter-point steps. There is no automatic word wrapping. Values that cannot fit are rejected. Dates require valid `yyyy-MM-dd`; production signed dates must later come from trusted server events. Checkboxes use vectors. PNG marks are bounded and centered with their aspect ratios preserved; production capture and image validation remain separate work.

## Font licensing and remaining gates

The PDF.js npm package bundled older Liberation Sans fonts under GPL with a font exception. Vendoring now substitutes the four unmodified upstream Liberation 2.1.5 Sans fonts under OFL-1.1, including the complete copyright/reserved-name/license notice. The official archive and each file are hash-pinned. Other PDF.js assets and notices are unchanged. The prototype uses the same Regular font and never falls back to fonts installed on the host. An unembedded standard Helvetica fixture also rendered in PDF.js with system fonts disabled and no browser warnings/errors.

The current text profile deliberately rejects complex shaping scripts, CJK, emoji, remaining combining marks and unsupported cmap glyphs. Successful Greek/Cyrillic examples do not establish universal Unicode support. Broader language support requires a reviewed font and shaping strategy plus independent fixtures.

Before production integration, add immutable source/version binding within the envelope transaction, trusted identity/date/consent sources, sender prefill and optional-field semantics, image capture/decoding validation, storage failure recovery and completion/seal integration. Exercise realistic synthetic PDFs with complex existing fonts, transparency, annotations/forms and multiple pages; decide how form appearances and flattening are handled. Confirm output in additional viewers and establish golden render tolerances. The prototype has no authorization boundary and must not be exposed as an API.

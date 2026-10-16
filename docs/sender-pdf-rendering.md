# Sender-prefill PDF renderer (QUILS-24)

`SenderPdfRenderer` stamps sender-owned Text, Checkbox and Date fields into a bounded PDF result. It is a backend component with no endpoint, envelope mutation, storage write, queue or email operation. Sending/freezing remains a separate workflow.

## Contract

The caller supplies normalized PDF bytes, their expected SHA-256, the expected page metadata, and stable-ID sender fields. The renderer owns a bounded source copy, verifies the hash, applies the existing upload rejection policy again, and compares geometry derived from actual bytes with expected metadata. Encrypted, signed, XFA and malformed input is rejected even with a matching caller-supplied hash.

Only unassigned Text/Checkbox/Date fields are accepted. Every field needs a unique nonempty ID, valid page and in-bounds normalized rectangle. Every sender field must have a value, including optional fields; delete unused fields before sending. Checkboxes use `true`/`false`, and dates use a valid `yyyy-MM-dd`. Assigned or automatic signer fields are rejected by this component.

Rendering uses the configured storage byte cap, with an additional hard **64 MiB** ceiling for this in-memory implementation, the configured document page cap (at most 200), and the editor field cap (at most 200). Normalization and final serialization both use bounded streams. A result is returned only after complete successful serialization, with independent SHA-256 values for owned source bytes and output bytes. Callers own the returned arrays; persist and verify them before exposing a reference. Exceptions produce no successful or partial result.

## Text, geometry and dependencies

The exact upstream Liberation Sans 2.1.5 Regular font is embedded in the assembly and checked for size and SHA-256 on first use. Its full OFL-1.1 notice remains beside the public font assets in build/publish output. A single process-wide PDFsharp resolver initializes once and rejects unexpected font families/faces. Rendering is serialized per process to bound serialization work and avoid competing global font-cache operations. There is no font fallback to host-installed fonts.

Text normalizes to NFC, uses explicit line breaks and two physical points of padding, and fits from 12 down to 8 points in quarter-point steps. It rejects values that cannot fit. There is no automatic word wrapping or complex shaping. The profile supports mapped Latin, Greek and Cyrillic characters and selected punctuation/currency symbols; CJK, emoji, complex shaping scripts, remaining combining marks, controls and tabs are rejected. A valid sender date is rendered as supplied. No signer identity, consent, signature image or signed timestamp is accepted here.

The [verified transform](pdf-field-feasibility.md#coordinates-and-fitting) preserves upright field content on rotated visible CropBoxes with offset coordinates and non-default UserUnit. Existing page content is retained, rotation restored, and checkboxes drawn as vectors. No diagnostic fiducial is added to production output.

PDFsharp stays at MIT 6.2.4. Managed Apache-2.0 PdfPig 0.1.16 validates the embedded font's cmap. PDFium, PDFtoImage and SkiaSharp remain in the developer harness only and are absent from the web application's dependency graph.

## Verification and integration gates

Run `pwsh -File scripts/dev/Test-PdfFieldSpike.ps1` to exercise the actual production source across nine geometry cases, alongside all original prototype cases. Independent PDFium pixels verify upright in-bounds sender text, original content and checked/unchecked interiors; PdfPig extracts original and stamped text. The report includes `productionCases`, and generated `.sender.pdf`/`.sender.png` files stay ignored. The documented Linux container command runs the same checks offline in the minimal app runtime.

Application tests cover Unicode/NFC, output/source hashes, original multi-page text, invalid values/types/ownership/IDs/geometry, malformed/encrypted/signed/XFA input, source changes, byte/page/field limits and repeated/concurrent renderer instances. The shared upload validator also recognizes PDFsharp's plain parser exception for missing startxref as a document rejection rather than a server error.

Future sending must authorize the verified sender, compare the shared draft revision, rerun preparation and rendering checks against current locked data, verify private source storage, persist the rendered bytes immutably, and atomically commit the frozen hash/reference, sender-prefill audit evidence, state transition and invitation outbox/work. Handle competing sends, uncertain commits and orphan cleanup without deleting a committed PDF. Do not trust a previous review GET or caller-supplied identity/hash as authorization. Broader language support and complex original-PDF/form appearance fidelity still need fixtures and an explicit supported profile; this component alone establishes neither signature validity nor a complete signing workflow.

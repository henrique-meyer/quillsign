# Additional Office format support

This is a source implementation plan, not an announcement of hosted format availability. Public intake accepts PDF, supported PNG/JPEG and configured DOCX. QUILS-92 implements internal strict UTF-8 text conversion; QUILS-106 adds separately opt-in sender TXT intake with defaults disabled. QUILS-98 assessed the remaining families on 2026-10-18; the matched stories below are deliberately separate gates.

| Format | Current boundary | Next scoped story | Main constraint |
| --- | --- | --- | --- |
| TXT | Optional sender intake implemented; default disabled | QUILS-106 | Persist exact UTF-8 original and confirm normalized PDF; never format-sniff raw text |
| PPTX | Rejected | QUILS-107 | Static PresentationML part/relationship allowlist; exclude actions, media and embedded workbooks |
| XLSX | Rejected | QUILS-108 | Values-only cells with bounded print ranges; exclude every formula, refresh source and hidden-content ambiguity |
| ODT | Rejected | QUILS-109 | Independent ODF manifest, namespace and resource validation; not a renamed DOCX gate |
| RTF | Rejected | QUILS-110 | Grammar-aware literal/static subset serialized into owned DOCX; unknown destinations fail closed |
| DOC | Rejected | QUILS-111 | Defensible Compound File Binary/WordBinary parser decision before any enablement |

The order is TXT integration, PPTX, values-only XLSX, ODT, conservative RTF, then legacy DOC feasibility. A converter being able to import a suffix does not establish that the application safely accepts its content. Neither a MIME label nor a file signature is an acceptance rule.

## Shared acceptance contract

Each enabled family must own one bounded immutable copy before conversion and retain the original separately from the exact normalized PDF. SHA-256 values, source media, byte lengths, page geometry and a versioned pipeline contract bind the result. The first upload's retention cutoff remains fixed. Authority, revision and retention are checked before expensive work, after conversion, and under atomic publication. A failed validation, conversion, storage operation or stale request preserves the previous document and confirmation; only a successful replacement clears preparation. Ambiguous commits retain potentially winning blobs and require explicit recovery. Preview/download shows the exact PDF that the sender must affirmatively confirm.

ZIP families need exact local/central headers, CRC, decompression budgets, canonical member names, no duplicate/case/alternate aliases, consistent types and a closed relationship graph. XML readers prohibit DTD/entity resolution and processing instructions and enforce depth/elements/bytes before allocation. Unknown part types, namespaces or extension content must fail closed until reviewed. Shared primitives may be extracted from the existing DOCX gate only while preserving all of its adversarial cases. Its Word-specific content policy is not reusable for slides, spreadsheets or ODF.

Every family must reject encryption, macros, scripts, OLE, embedded packages, external resources and unreviewed active content before conversion. Network isolation is still required because parser/importer flaws and obscure resource mechanisms remain possible. Use the pinned isolated LibreOffice service, fixed route/name/parameters, no callback/download URL, no redirects/proxy/retry, bounded time/output/pages and independently verified no-egress. Preserve the existing sandbox's source restriction; do not broaden its command or path contract to accept arbitrary extensions. Literal/static formats can reuse an internally generated validated DOCX, whose own hash is distinct from the original upload hash.

## Family findings

**PPTX:** PresentationML is an OPC package, but ordinary decks can contain actions, external resources, audio/video, OLE, charts and embedded workbooks. The initial gate will permit finite slides/layouts/masters/themes, literal DrawingML text/shapes and internally verified raster images. It will reject unsupported extension markup and every action/media/embedding relationship. Slide count, shapes, image pixels, relationships and package expansion need independent bounds before LibreOffice work. Output must be checked for every slide's visible content, orientation and clipping. Notes and animations are outside the initial static profile; no claim of a full PowerPoint reproduction.

**XLSX:** SpreadsheetML needs bounds on actual cells and coordinates, not declared dimensions alone. A small ZIP can request huge sparse sheets or print ranges. The initial profile is static values, a finite style/shared-string table and bounded ranges; reject formula nodes, formula-bearing names, calculation chains, external links, connections/query tables, pivot caches, macros/dialog sheets and embedded objects. Cached formula results are not evidence that the calculation is harmless or current. Hidden sheets/rows/columns must initially be rejected rather than silently omitted. Print scaling, empty-page expansion and selected sheet behavior require explicit fidelity cases. Spreadsheet formulas are not converted into literal values silently.

**ODT:** ODF has its own mimetype and manifest rules, scripts/event listeners, xlink resources, forms, embedded objects and linked sections. Validate the exact stored mimetype and consistent member manifest before checking a closed static namespace/element profile. Both content and styles can refer to resources. Reject unknown active extensions, external paths/schemes and encrypted/signed members. Permit only bounded text/tables/styles and content-verified internal raster images initially. The DOCX OPC relationship checker cannot establish ODT safety.

**RTF:** Balanced braces and a header are insufficient. Escapes, Unicode fallback lengths, code pages, binary lengths, nested groups, destinations and ignorable controls require a real bounded tokenizer/parser. A blacklist for field/object words can be bypassed by alternate encodings or parser disagreement. Prefer a narrowly allowed literal/basic-formatting grammar that rejects all fields, objects, binary/picture/metafile data, HTML/XML/file destinations and unknown controls, then emits an owned minimal DOCX. Documents outside that profile must be exported to PDF. This intentionally sacrifices unsupported richness instead of stripping active instructions silently.

**DOC:** WordBinary uses OLE Compound File Binary plus table/FIB structures and separate macro, object and encryption mechanisms. A magic-byte check or scan for stream names cannot establish a safe file. Sector chains, mini streams, directory aliases, overlaps and Word-level offsets need bounded structural validation, with reject-on-unknown active content. No reviewed permissively licensed validator has been selected by this assessment. QUILS-111 is a parser go/no-go gate, not permission to pass raw legacy binaries to LibreOffice.

## Required evidence before each enablement

Use generated synthetic non-agreement fixtures only. Test truncated/contradictory containers, disguised extensions, aliases, decompression/structure/time limits, cancellation, direct and indirect resources, active content and format-specific escape paths. An HTTP callback receiver on the isolated test network must observe zero requests for rejected resource fixtures; also verify no default route and failed direct egress. Rejected input must make zero conversion calls. Convert accepted examples through the real pinned local service, inspect every rendered page, and record exact original/PDF hashes. Provider replay may test SQL/storage failure boundaries separately but must not be called a combined live conversion test.

Internal conversion comes before persistence/public intake for each new family. Public integration requires its own matched story, real desktop/mobile/keyboard upload-preview-download-confirmation flows, malicious/stale/CSRF replacement preservation, privacy/analytics/indexing regressions and ordinary PDF/image/DOCX compatibility. Hosted settings, provider attempts and cloud permissions remain a separate owner-approved rollout. No existing test budget authorizes those calls.

## Primary sources

- [Microsoft: Open XML package and relationship model](https://learn.microsoft.com/en-us/office/open-xml/about-the-open-xml-sdk).
- [Microsoft: Office format reference](https://learn.microsoft.com/en-us/office/compatibility/office-file-format-reference).
- [OASIS: ODF 1.3 package specification](https://docs.oasis-open.org/office/OpenDocument/v1.3/csprd02/part2-packages/OpenDocument-v1.3-csprd02-part2-packages.html) and [schema specification](https://docs.oasis-open.org/office/OpenDocument/v1.3/cs01/part3-schema/OpenDocument-v1.3-cs01-part3-schema.html).
- [Microsoft: WordBinary dependencies on CFB, macros and cryptography](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/47d4949b-fca8-4811-bb71-5b70a9165235) and [encryption/obfuscation](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/424cbebc-43ac-4c66-850b-d6320fa9a6a6).
- [Microsoft: RTF destination and encapsulation semantics](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfex/fc779a72-0af3-4d17-8a85-e0a6b08ed37b).
- [Gotenberg: LibreOffice imports and conversion](https://gotenberg.dev/docs/convert-with-libreoffice/convert-to-pdf), [configuration](https://gotenberg.dev/docs/configuration) and [outbound filtering](https://gotenberg.dev/docs/outbound-url-filtering).

The family profiles above are QuillSign engineering decisions inferred from these structures, not claims that the specifications define a universally safe subset. This assessment enables no new format and makes no new render/no-egress/hosted claim. Those demonstrations belong to the implementation gates.

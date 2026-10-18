# Legacy DOC support decision

QUILS-111 decision, 2026-10-18: **no-go for accepting legacy binary DOC in this release**. No parser or dependency was added. The upload boundary continues to reject DOC before conversion. Export the document to PDF in an application you trust, then upload and review that PDF. This is a scoped engineering decision; it does not mean that future safe DOC support is impossible.

## Why container recognition is insufficient

A legacy Word document has two validation layers. CFB allocation and directory structures must be bounded and unambiguous, including FAT/mini-FAT chains and small streams. Microsoft documents the mini-stream allocation separately from ordinary streams. A successful storage enumeration establishes neither Word content safety nor document fidelity. [Microsoft CFB mini-FAT specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/c5d235f7-b73c-4ec5-bf8d-5c08306cd023).

Word's FIB selects the table stream and carries encryption/obfuscation flags; encrypted documents also have format-specific unencrypted header regions. A signature match or absence of obvious macro stream names cannot establish consistent decoded text, formatting and resources. [Microsoft FibBase](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/26fb6c06-4e5c-4778-ab4e-edbf26a545bb), [binary RC4 layout](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/3e9a4e92-bdfe-4379-8144-74d033892ede).

QuillSign's inference is that a container library plus a macro-string scan would leave an unreviewed WordBinary parser boundary. Disabling LibreOffice macros or isolating its network remains defense in depth; neither replaces the source validation requirement.

## Reviewed options

| Candidate | Evidence | Decision for this slice |
| --- | --- | --- |
| OpenMcdf | Its maintained project is a structured-storage library and declares MPL-2.0. It does not claim a WordBinary content-safety gate. | Not selected: the owner requires permissive dependencies, and container parsing alone is insufficient. [Maintainer repository](https://github.com/openmcdf/openmcdf). |
| NPOI | The official README lists XLS, XLSX and DOCX support. Its current binary releases also declare additional maintenance-fee terms starting with 2.8.0. | Not selected as a reviewed legacy-DOC validator; no package or licensing exception is introduced. Any future candidate needs exact-version/source/binary license review. [Maintainer README](https://github.com/nissl-lab/npoi). |
| Apache POI HWPF | The Java project documents WordBinary reading and limited older-generation support. | A possible research input, not an established rejection gate. Adding a Java parser/runtime does not itself prove complete active-content rejection or bounded behavior and is outside the existing .NET conversion component. [HWPF documentation](https://poi.apache.org/components/document/index.html). |
| New bounded WordBinary reader | Could be limited to an explicitly defined generation and literal/static profile. | Separate substantial implementation and adversarial-corpus work; no defensible implementation was produced by this assessment. |

These are applicability decisions, not findings that a candidate is vulnerable. No third-party parser has been installed, vendored or invoked, and no commercial/provider service has been purchased.

## Evidence required to revisit the decision

A matched design and implementation story must first select a permissively licensed exact parser/version or specify the new reader. Its accepted generation and static subset must be explicit. The gate must account for all reachable content and reject unknown structures rather than strip them.

Required evidence includes:

- Bounded CFB headers, allocations, directory/mini-stream graphs and byte ranges; reject cycles, overlap, truncation, aliases, contradictory lengths and alternate/polyglot interpretations.
- Consistent FIB/version/table selection, piece/text mapping, formatting/style records and offsets; reject unsupported generations and encrypted/obfuscated content before conversion.
- Exhaustive rejection of macro/active/embedded objects and packages, external fields/resources/templates, hidden/unsupported content and unreviewed streams. Metadata is also a parsed, bounded structure, not an ignored arbitrary stream.
- Owned exact source bytes/hash and separately verified derived/normalized output. Prefer emitting a validated minimal DOCX from the accepted static semantics if that avoids handing a differently interpreted raw binary to another parser; unsupported richness must cause rejection, not silent loss.
- Generated synthetic valid and adversarial corpus, cancellation/expansion limits, zero converter calls for rejected inputs, independent no-egress checks and every rendered page inspected for accepted inputs. PDF byte/page/geometry limits and explicit sender review remain mandatory.
- Separate persistence/intake and hosted rollout gates, including retained original/PDF provenance, unchanged retention cutoff, replacement failure preservation, private browser flows and owner approval for any new resources, permissions or paid service.

## Availability boundary

TXT has a guarded sender workflow with its own default-false opt-in. PPTX, values-only XLSX, static ODT and literal-formatting RTF have separately gated internal implementation slices; their public persistence/intake integration remains a follow-on. Internal tests or a successful local converter run do not enable a hosted extension. DOC remains unsupported by design until the gate above is met.

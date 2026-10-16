# Completion certificate preparation

QUILS-42 adds `CompletionCertificateRenderer`, an internal pure renderer. It prepares a current checkpoint plus appended completion pages, and a separate certificate for later sealing. Durable evidence collection, final storage/publication, completed status and delivery remain subsequent workflow work. No HTTP endpoint accepts these rendering DTOs.

## Evidence contract

The caller must collect a complete, authorized immutable snapshot from stored accepted evidence, verify the canonical audit chain and every signer checkpoint, and supply exact accepted mark assets. [QUILS-43's internal collector](completion-evidence.md) provides that read-only boundary. This renderer validates structure and hash linkage; it cannot establish that arbitrary caller-supplied records are authentic. It never reads cookies, DB rows or private storage, changes envelope status, contacts a TSA or sends mail.

The typed snapshot contains document/envelope identifiers; original, converted, sent and current checkpoint SHA-256; sender email verification; ordered signer names, roles and addresses; recorded link verification, viewed-event, disclosure consent, actual Finish and checkpoint publication times; versioned disclosure hashes; accepted normalized signature/initial images and hashes; recorded Finish IP/user agent; recipients; and every audit event's sequence, recorded time/actor, IP/user agent and previous/current hash. Audit JSON and transport/session/review bearer material have no rendering field. Full canonical audit verification belongs to the caller before projection.

The renderer owns copies, normalizes text to NFC and times to UTC, and hashes that typed snapshot as shared evidence. This snapshot digest is not a substitute for the canonical audit anchor. It rejects missing mandatory records, non-contiguous signer/event order, inconsistent time/disclosure/checkpoint bindings, broken hash links, wrong image hashes and noncanonical PNG assets. Optional names, local time/zone and TSA friendly names appear as not recorded. The authentication description masks the email address and describes one-time email-link control; it asserts no government identity or optional OTP check. Party lists retain the intended addresses. The chronology is explicitly complete through the snapshot time; later seal/publication/delivery events remain external.

## Two forms and circular hashes

`PreparePacket` binds the actual source to the last checkpoint hash and verified page geometry, prepares the appendix and appends it to the source document. Keeping the source pages in their owning PDFsharp document preserves page settings such as `UserUnit` that page import otherwise drops. The renderer returns separate source, packet and shared-evidence hashes. It leaves source bytes unchanged.

The appendix records the source/current checkpoint and pre-seal audit anchor. It directs readers to the embedded platform signature and the standalone certificate for final-file hash/seal/timestamp details. It cannot embed its own eventual final-file hash without a circular dependency.

After `PlatformPdfSeal` returns verified executed bytes, `PrepareStandalone` requires the same evidence digest, packet hash/source/version, exact executed bytes/hash, source binding and page count. It includes that executed-file SHA-256, actual platform provider/certificate fingerprint and seal time, and verified timestamp time/certificate fingerprint/policy. It does not re-verify uploaded CMS or arbitrary claimed engine results: the internal caller must supply the actual verified engine result. The standalone output must then receive its own seal. Its own final sealed hash belongs in external durable evidence, not recursively inside itself. Neither form claims individual signer-held certificates, qualified signing, PAdES conformance or public CA/Adobe trust.

## Layout and bounds

PDFsharp and MigraDoc remain pinned to MIT-licensed 6.2.4. The renderer embeds the existing approved logo-mark PNG and pinned Liberation Sans font. It uses A4 completion pages, repeating party-table headers, bounded aspect-preserving marks, page numbers and grouped hashes/events. Existing document pages retain their own size, rotation, crop/media boxes and UserUnit.

Text is plain content, never markup. Unsupported glyphs and control/format characters are shown as explicit U+ escapes; wrapping preserves the recorded text rather than substituting an invented name. Demo and synthetic warnings come only from explicit snapshot flags. Mark bytes must match the existing `png-rgba-crop-v1` normalization contract before image rendering.

Limits are 20 signers, 50 additional recipients, 512 audit events and 128 KiB of aggregate input UTF-8 text. Individual bounds match preparation: 512-character names/roles/titles, 320-character addresses and 2048-character user agents. An expanded party row too large for its table directs readers to its complete details below. Output is bounded to 64 MiB, 200 combined pages and at most 64 certificate pages by default; callers can lower those ceilings. Upload/document limits must leave room for completion pages inside the final seal limit. Excess events/pages/text are rejected, never silently omitted. Cancellation is checked during validation, layout progress, page rendering and assembly; PDFsharp/font work shares the existing render gate.

## Validation

Run the focused `CompletionCertificateRendererTests`, or the full local SQL/Azurite suite. Tests use synthetic documents, generated local certificates and a loopback TSA. Both appended and standalone forms are sealed through the production engine. Coverage includes all source rotations/crop/UserUnit, identical source text, shared evidence/final-hash separation, twenty long signer rows and repeating headers, tall marks, malformed/stale/oversized evidence, source/output limits and cancellation. Windows and Linux CI run the same focused cases.

Set `QUILLSIGN_COMPLETION_ARTIFACTS` to an ignored directory during the positive test to retain source/appendix and two sealed synthetic PDFs for QA. Render every output page with Poppler and visually inspect it. Compare rendered source pages with the executed PDF's document pages; no private keys or real documents are exported or committed.

# Electronic-record disclosure snapshots (QUILS-25)

The versioned [plain-text ERSD template](../src/QuillSign/Legal/electronic-record-disclosure.txt) and `ElectronicRecordDisclosure` builder prepare an envelope-bound disclosure snapshot. This foundation exposes no consent or signing page and records no acceptance. Operators must review actual transactions and policies before use; a template or matching hash alone does not establish legal validity.

## Operator policy

Supply all seven `ElectronicRecords` settings through private runtime configuration. Committed examples intentionally leave them empty:

| Setting | Required content |
| --- | --- |
| `PaperCopyInstructions` | Actual paper alternative and how to request copies, including after electronic consent. |
| `PaperCopyFees` | Whether paper-copy fees apply and their actual terms. |
| `WithdrawalInstructions` | Functioning withdrawal procedure, including contact and handling after a signing step. |
| `WithdrawalConsequences` | Conditions, consequences and fees, or a truthful statement that none apply. |
| `ContactUpdateInstructions` | How electronic contact details can actually be corrected or updated. |
| `AccessRequirements` | Actual browser, PDF, email, download/storage or printing needs for access and retention. |
| `RetentionNotice` | Actual availability/purge policy and how parties retain copies. |

Environment names use `ElectronicRecords__...`. Missing, blank, oversized or invalid policy text causes snapshot construction to fail. The app does not silently promise free paper, immediate withdrawal, indefinite server storage or procedures the operator has not supplied. These settings do not enable mail or signing, and changing them does not alter stored snapshots.

The template follows the project's engineering acceptance targets. ESIGN's detailed consumer consent provisions apply when electronic records replace information legally required to be supplied to a consumer in writing; operators must determine applicability and other transaction/form/delivery rules. For that situation, the statutory subjects include paper options, withdrawal and its terms, scope, contact updates, copies/fees and access/retention requirements. Sources: [15 USC §7001(c)](https://www.govinfo.gov/content/pkg/USCODE-2024-title15/html/USCODE-2024-title15-chap96-subchapI-sec7001.htm), [current LII codification](https://www.law.cornell.edu/uscode/text/15/7001). See the broader [requirements guide](e-signature-requirements.md).

## Explicit synthetic-demo profile

Leave `ElectronicRecords__Profile` blank for operator-supplied policies. An instance intended solely for synthetic demonstrations may explicitly select `synthetic-demo-v1`, leaving the seven operator policy fields empty. Unknown profiles and mixed profile/operator-policy configuration fail snapshot construction. The committed examples select no profile.

Local Compose forwards these settings and optional `Demo__PurgeAfterDays` from private `.env` or process variables to the app and optional worker. Configure retention before the first upload: existing unenrolled documents require an explicit migration and cannot acquire a new deadline through this profile. Restart/recreate local services only when you deliberately want to apply changed settings. This does not configure the hosted instance.

The demo profile requires an authorized review or Send to supply the verified immutable first-upload retention context and verify the saved [purge schedule](demo-purge-coordinator.md) for an enrolled demo envelope. The public pure builder cannot infer enrollment from an identifier. Non-demo, historical unenrolled and unverifiable records cannot use this profile. Missing legacy jobs require explicit trusted resume; GET never schedules them. It uses saved retention days and the exact UTC deadline; later environment changes, replacement, Send and completion cannot extend that policy.

Its separate versioned text prohibits real-life contracts and describes the absence of paper-copy, consent-withdrawal and post-send contact-correction services without claiming a statutory waiver. It preserves decline before Finish and requires PDF access/download capability and a reader for saved copies. Version `synthetic-demo-2026-10-17.2` describes verified queued cleanup and possible physical-deletion delays, with no promise of instant backup, version, soft-delete or log erasure. The original version remains verifiable against its exact saved text/hash. No hosted configuration or delivery service is enabled by this code.

Review and Send use the same canonical demo text. Consent verifies the frozen saved body, version and hash, independently of later profile or operator-setting changes. The existing operator template and historical snapshot verification remain unchanged.

## Exact snapshot contract

The builder includes the disclosure version, exact public envelope identifier, trimmed document title and normalized runtime sender contact in the text header. Policy text and line endings normalize to NFC/LF without mutating the options. Inputs have explicit limits; title/context must stay on one line, and policies reject controls and hidden formatting characters. Each policy allows 4,000 UTF-16 code units; the completed body allows 32,768. UTF-8 hashing uses no BOM and rejects invalid Unicode. Placeholders expand once, so inserted markup or placeholder-like text remains literal plain text. A future HTML view must encode it.

The result contains the version, context, exact text and SHA-256. `Verify` binds the expected header/context and the exact text bytes. It can verify an older stored version without consulting today's template or policy. A golden test fixes the initial template's synthetic snapshot hash to catch unintended changes without an intentional version update. Hashes detect a mismatch against trusted evidence; they do not authenticate someone who can alter both the body and its stored hash.

`Envelope.ErsdText` is a new nullable, bounded text column beside `ErsdVersion` and `ErsdSha256`. The migration retains existing records with null snapshots. Building does not persist anything; the future send transaction must store the three fields with the immutable document binding, audit evidence and outbox/state transition. Later rendering must use that saved body and verify it against the envelope's saved context/hash, rather than re-render mutable current settings.

## Future consent integration

Before recording consent, display the saved disclosure, provide the representative PDF with a usable retention/download path, and capture a separate affirmative agreement plus access confirmation and honest access evidence. Do not treat a PDF placeholder, failed renderer or untested checkbox as automatic proof of access. Consent to electronic records must remain separate from the act adopting a signature for the document.

Declining before signing and withdrawal of consent are related but distinct procedures. The snapshot must match the operator's actual withdrawal handling. Prior properly supplied electronic records are not automatically undone by later withdrawal. Changes creating material access/retention risk require the applicable revised-disclosure/access procedure before reliance on subsequent electronic records. Sources: [ESIGN §7001(c)(1)(C)–(D), (4)](https://www.govinfo.gov/content/pkg/USCODE-2024-title15/html/USCODE-2024-title15-chap96-subchapI-sec7001.htm). Consent timestamps, IP/user agent, snapshot/document hashes and intent evidence belong to the later authorized workflow; this builder creates none of those events.

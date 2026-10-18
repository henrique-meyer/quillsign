# QuillSign

An open-source e-signature app being built around sequential signing, no accounts, and no subscriptions.

## Current status

QuillSign is under active development. The application implements verified-sender PDF preparation, sequential signer setup, manual field placement and sender prefill, reviewed Send, electronic-record consent, signature capture, deliberate field application, exact PDF review and Finish. Durable workers publish signer checkpoints and prepare, seal and publish the completed PDF and certificate of completion. Private downloads, completion emails, sender voiding, public uploaded-PDF verification and finite expiry maintenance are also implemented.

Synthetic end-to-end flows have local automated and browser coverage. The approved demo staging rollout on 2026-10-18 verified the synthetic electronic-record disclosure, seven-day first-upload retention, immutable final-version protection, persistent demo seal, coordinated FreeTSA timestamps and scheduled storage-only recovery. These are component checks; the full hosted sender-to-completion flow and naturally elapsed document purge remain unverified. Public email delivery remains disabled until separate SES/feedback readiness and launch validation are complete. The completed-document lookup release is also deployed, with its request form gated while email is disabled. The `/health` endpoint returns `{"status":"ok"}` without querying the database. See the [cloud infrastructure guide](infra/README.md) and [hosted demo rollout plan](docs/hosted-demo-rollout.md).

## Signing flow

1. Verify the sender's email through a single-use magic link.
2. Upload a document, review its PDF preview, add signers in order, and place fields.
3. Fill sender-owned fields before sending; each signer reviews, consents, and signs sequentially.
4. Append completion evidence, seal each final PDF once with a platform seal and timestamp, and deliver the executed document and standalone certificate to the sender, signers and completion recipients.

## Technology stack

Optional Google Analytics can measure visits to the public homepage without visible controls.
It is disabled by default and excluded from signing and document flows. See
[analytics configuration and verification](docs/analytics.md).

| Area | Technology |
| --- | --- |
| Application | .NET 10 LTS, C#, ASP.NET Core Razor Pages |
| Database | EF Core 10 with SQL Server; Azure SQL Database for hosting, SQL Server Developer locally |
| PDF viewer and editor | PDF.js, interact.js and signature_pad; assets are served locally |
| PDF rendering and evidence | PDFsharp/MigraDoc 6.2.4 (MIT), PdfPig and BouncyCastle for CMS seals and RFC 3161 timestamps |
| Timestamp authority | Provider-configurable RFC 3161 client; [FreeTSA](https://www.freetsa.org/index_en.php) is configured and component-tested in the demo |
| Files and final-record protection | Azure Blob Storage, with version-level immutable retention for hosted final PDFs; Azurite for local development |
| Sessions and secrets | ASP.NET Core Data Protection, Blob-persisted keys, Azure Key Vault and managed identity |
| Background work | SQL durable work/outbox records, Azure Storage Queues and Blob recovery hints; finite Container Apps jobs |
| Email | Amazon SES v2 and SMTP/Mailpit; ACS remains a future optional adapter |
| Hosting and delivery | Azure Container Apps Consumption, GitHub Actions, GHCR and Bicep; CloudFormation for AWS resources |
| Office conversion | Gotenberg/LibreOffice sidecar for validated DOCX packages when configured; sender upload, normalized PDF preview and explicit confirmation |
| Image conversion | [Validated PNG/JPEG sender upload and PDF preview](docs/image-conversion.md) with StbImageSharp (MIT) and PDFsharp |
| Deferred enhancement | Azure OpenAI suggestions, after the remaining project work is complete |

There is no CAPTCHA. Verified email, request limits, daily caps and bounce/complaint suppression provide abuse controls. Verified senders can upload PDF, supported [PNG/JPEG images](docs/image-conversion.md), and [DOCX documents](docs/document-conversion.md) when the isolated converter is configured. The sender must review and explicitly confirm the normalized PDF. Other Office formats remain future work; hosted conversion enablement is separate from implementation. AI field and signer-role suggestions, including heuristic automatic placement, are deferred until the remaining non-AI project work and hosted validation are complete. Manual field placement is the current workflow; AI is not required for project completion or demo release.

### Timestamp, immutable storage and retention setup

The seal engine requires an HTTPS RFC 3161 timestamp service and a trusted certificate chain. FreeTSA's public service has no subscription fee, permits application use, and allows at most one request per second per source IP. It is best-effort without an SLA. The client supports shared Blob-lease coordination across both final PDF seals and all workers, with a cooldown after each attempt. Self-hosters must configure the verified public CA and coordinator before enabling FreeTSA. Those components passed bounded hosted demo checks; a timestamp outage can still delay completion. See [FreeTSA's usage policy](https://www.freetsa.org/freetsa.html) and the [seal configuration guide](docs/platform-pdf-seals.md).

Immutable storage is a policy on ordinary Azure Blob Storage, not a separate compute or storage service. Hosted publication requires a private final-files container with version-level immutability enabled and actual blob protection covering the promised retention interval. Existing containers require migration; enabling support cannot be reversed, and locked retention cannot be shortened. Keep the deletion deadline and protection expiry aligned. The application verifies protection but does not provision or change hosted policies. See [Azure's version-level immutability documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-version-level-worm-policies) and [final publication](docs/final-publication.md).

Configure these values through environment variables or private settings, using [the example configuration](src/QuillSign/appsettings.example.json):

| Environment variable | Current purpose |
| --- | --- |
| `Seal__TsaUrl` | HTTPS RFC 3161 endpoint; FreeTSA publishes `https://freetsa.org/tsr` |
| `Seal__TsaTrustedRootPaths__0` | Absolute runtime path to a verified public TSA root certificate; indexed entries support multiple roots |
| `Seal__TimestampCoordination__Enabled` | Enable shared Blob-lease request coordination; required for FreeTSA |
| `Retention__CompletedDays` | Retention interval for completed ordinary requests |
| `Demo__PurgeAfterDays` | Positive demo interval; new uploads freeze an upload-based retention snapshot |

Retention settings remain unset by default for self-hosters. A configured demo upload freezes an exact [first-upload deadline](docs/document-retention.md) and atomically schedules [durable purge work](docs/demo-purge-coordinator.md); replacement, signing and setting changes cannot extend it. The public demo is configured for seven days. Final publication requires matching final-version protection. The worker uses guarded SQL cleanup and bounded object deletion, with persistent storage-only recovery for late writes. Ordinary/legacy completion-based intervals are unchanged and are not automatically scheduled for erasure by this demo worker. The demo's worker permissions and maintenance scheduling passed staging checks; a naturally elapsed enrolled purge remains a validation gate. A day count does not guarantee physical erasure of versions, backups, soft-deleted copies or logs.

## Run locally

Install the .NET 10 SDK, then run from the repository root:

```sh
dotnet run --project src/QuillSign/QuillSign.csproj --urls http://localhost:5080
```

Open <http://localhost:5080>. Check <http://localhost:5080/health> for the health response. The current bootstrap needs no database, cloud credentials, or email configuration. No solution file or Visual Studio installation is required.

To build and run the container with Docker:

```sh
docker build -t quillsign .
docker run --rm -p 8080:8080 quillsign
```

Open <http://localhost:8080>. The container runs as a non-root user.

### Development services

With Docker running Linux containers and PowerShell 7 installed, start the complete local stack:

```sh
pwsh -File scripts/dev/Initialize-LocalEnvironment.ps1
docker compose up -d --build --wait --wait-timeout 240
```

The initializer generates local SQL and Azurite credentials in ignored `.env` configuration, preserving existing values and process-variable precedence. Optional port settings are listed in `.env.example`. Initial image downloads can take several minutes; allow at least 6 GB of Docker memory. The SQL Server image requires Linux amd64; ARM hosts need compatible emulation. SQL Server Developer is for development/testing only.

| Service | Local endpoint | Container endpoint |
| --- | --- | --- |
| App | <http://localhost:5080> | `app:8080` |
| SQL Server | `localhost,14333` | `sql:1433` |
| Blob emulator | <http://localhost:10000/quillsigndev> | `azurite:10000/quillsigndev` |
| Mailpit inbox | <http://localhost:8025> | `mailpit:8025` |
| SMTP capture | `localhost:1025` | `mailpit:1025` |
| Gotenberg | Through the app container only | `gotenberg:3000` |

The app shows the verification form when database, storage, email, and background work are configured; otherwise it shows an email-unavailable notice. Verified senders can upload and review PDFs and supported images. DOCX upload also requires the configured, isolated converter; hosted DOCX conversion remains disabled.

Run `docker compose ps` to check health and `docker compose logs -f app` for application logs. `docker compose down` stops the stack while preserving SQL, blob, and captured-mail data. `docker compose down --volumes` resets **all local stack data**. Changing the generated SQL password requires resetting the SQL volume or changing the existing database password.

To run the same service, conversion/isolation, SMTP, and stop/start persistence checks as CI, install Python 3.12+ and run `python scripts/dev/smoke.py` with the stack running. This briefly stops and restarts the stack and leaves one synthetic message in Mailpit.

### Database development

EF Core 10 uses the SQL Server provider. The initial migration defines envelopes, signers, recipients, fields, hashed auth tokens, audit events, email outbox, leased work records, and suppression. With the local stack running:

```sh
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action Migrate
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action Test
```

The helper reads local SQL/Azurite settings through Compose and supplies credentials only to the child process. Migrate applies the committed migrations to `QuillSignDev`; Test creates and removes an isolated database and exercises SQL constraints, concurrency, private document streaming, and protected session persistence. SQL administrator credentials are for local development only.

For application database features, set `ConnectionStrings__Database` through environment variables or ignored `appsettings.Development.json`, using `appsettings.example.json` as a template. Container connections use the `sql` service hostname; host CLI connections use the published SQL port. Starting the app never applies migrations or connects to SQL, and `/health` stays database independent.

Restore the pinned EF CLI with `dotnet tool restore`. Generate migrations using `dotnet ef migrations add <Name> --project src/QuillSign/QuillSign.csproj`; CI rejects model changes without a matching migration. Audit events use a documented canonical hash format and reject tracked edits/deletes; database permission enforcement and privileged retention are separate work.

### Email development

Compose selects SMTP and captures messages in Mailpit using a synthetic sender. `Use-LocalDatabase.ps1 -Action Test` exercises sender verification, rendered HTML/text messages, local SMTP capture, simulated SES requests, signed SNS feedback, and suppression. No AWS credentials or live email are used by tests.

The adapters also support [bounded PDF attachments](docs/email-attachments.md), preserving exact supplied bytes with safe filenames and explicit MIME encoding. [Completion notifications](docs/completion-notifications.md) queue atomically with final publication and deliver the verified pair plus a private readonly backup link through finite email work. Live delivery remains disabled by default.

For sender verification and draft preparation using the local services, migrate first, then run these commands in separate terminals:

```powershell
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action RunApp -AppPort 5081
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action ListenWork -AppPort 5081 -NoBuild
```

Start `RunApp` first so it builds the application; `-NoBuild` lets the listener use that build while the app is running. Open <http://localhost:5081>, enter a synthetic address such as `sender@example.invalid`, and open the captured message in <http://localhost:8025>. Follow its verification link to the draft. Use the same `AppPort` in both terminals so worker-generated links reach the app. The helper configures local SQL, Azurite, and SMTP without printing credentials.

Verification links work once and expire 15 minutes after dispatch. Sender sessions last two hours without sliding renewal and only open their own draft. The default cap is five requests per address per UTC day, plus 20 HTTP requests per IP per ten-minute window. Configure these limits through the `Sender` section in `appsettings.example.json`. Suppressed and capped requests receive the same neutral inbox message. Browser notices appear once after a clean redirect; JSON clients receive the message body and still require antiforgery tokens for POST requests.

Outside Compose, email is disabled by default. Use the `Email` section of `appsettings.example.json` for provider, sender, base URL, SMTP, SES configuration set, and SNS topic settings. `Email:BaseUrl` builds verification links; templates render when dispatching. `/webhooks/ses` processes authenticated delivery feedback and suppresses permanent bounces and complaints. Transient bounces do not permanently suppress recipients. Feedback and subscription auto-confirmation are disabled by default. Public SES delivery remains gated on a confirmed feedback subscription, simulator validation and approved SES readiness.

### Background work

SQL stores durable work and email outbox records. Opaque queue messages wake a finite worker; Blob hints let recovery republish missed wakeups without querying an idle database. Verification payloads are protected with the persistent application key ring, and token validity begins at dispatch. Definite pre-send failures use bounded backoff. A possibly accepted send is recorded as ambiguous and requires explicit reconciliation before another submission.

With the local stack running, migrate first, then run one item or listen for local work:

```powershell
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action Migrate
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action WorkOnce
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action ListenWork
```

`RecoverWork` runs storage-only wakeup recovery; `VerifyWork` checks storage, database access, and payload protection, then queues a synthetic wakeup with no email. Run `WorkOnce` to consume it locally. The helper supplies local Compose settings without printing credentials. `ListenWork` is Development-only and polls the emulator queue, never idle SQL. The optional Compose `workers` profile runs the same listener when an application SQL connection is configured. Hosted jobs use `dotnet QuillSign.dll work once` and `work recover`; work is disabled by default outside configured environments.

### Document storage and application keys

Compose configures Azurite automatically. The `IBlobStore` adapter checks a verified sender's envelope scope before storage access, uses opaque document references, and streams bounded blocks. It never returns public document URLs. Uploads become readable only after their declared size is verified; existing objects cannot be overwritten.

After verifying through Mailpit, upload an unsigned, unencrypted PDF to the draft. The default limits are 10 MiB and 20 pages, configurable with `Documents:MaximumBytes` and `Documents:MaximumPages` within the storage limit. Malformed, encrypted, XFA, and already-signed PDFs are rejected. The app retains the original and a rewritten PDF with hashes and page geometry; PDF.js renders the stored preview with page navigation, zoom, selectable text, and a download fallback. Confirming the preview keeps the document as a draft. Replacing it clears prior confirmation, fields, and document suggestions. Stale tabs must reload before changing a newer version.

After confirming the PDF, choose **Set up signers**. Add each person's full name, email, and optional role; add yourself using the verified sender email; then edit, remove, or move signers earlier/later with keyboard-accessible controls. The default maximum is 10, configured through `Signing:MaximumSigners` (environment variable `Signing__MaximumSigners`). Duplicate email addresses and stale changes are rejected. A signer with assigned fields cannot be removed or given a different email until those fields are removed. Setup keeps the document in draft and sends no invitations.

Choose **Place document fields** to add signature, initials, full-name, date-signed, text, checkbox, and date fields. Drag/resize fields or select one from the document list and apply exact percentage positions, page, label, assignment, and required status. Sender fields allow only text, checkbox, and date values; signer values are collected during the signing flow. Changes autosave serially, using the current document and draft revision. A stale tab or failed save pauses saving while keeping local edits available for export before reload. The default cap is 200 fields (`FieldEditor:MaximumFields`, supported range 1–200). See [editor behavior and coordinate contract](docs/field-editor.md).

Open **Document details and recipients** to save a title and optional message, and add/edit/remove named completion recipients (CC). Recipients receive only the completed packet through the completion workflow; they do not sign or get invitations. Their list is optional, with a default cap of 20 (`Preparation:MaximumRecipients`, supported range 1–100), and normalized addresses must be unique within it. Setup sends no mail. Concurrent changes use the same draft revision as the PDF, signer list and editor. Validation errors retain attempted values; stale form submissions show the current saved details for review before retrying.

Choose **Review document preparation** to see the PDF, ordered signers, sender-filled values and completion recipients together. Missing confirmation, title/signers, invalid field placement/assignment or unfilled sender values produce corrective links. An unchecked sender checkbox counts as filled. Signers without a Signature field produce a warning only. Review reads one coherent draft revision, changes nothing and sends no invitations; passing these preparation checks does not establish legal validity or guarantee text fitting when stamping is integrated.

The [versioned electronic-record disclosures](docs/electronic-record-disclosure.md) bind exact text and hashes to Send and signer consent. With `ElectronicRecords__Profile` blank, operators must supply their actual paper-copy, withdrawal, contact-update, access and retention policies through private `ElectronicRecords__...` settings; empty examples fail snapshot construction. An explicitly selected `synthetic-demo-v1` profile provides the synthetic-only demo policy for verified, enrolled demo documents, using their saved upload-based retention deadline. New review/Send verifies the saved purge job before describing queued cleanup and possible physical-deletion delays. Earlier saved text remains verifiable. The profile cannot replace real-use policies or enable hosted services/email by itself.

The backend [signer-access foundation](docs/signer-access.md) provides single-use invitation redemption, isolated two-hour signer sessions and access scoped to the frozen PDF/disclosure. Invitation tokens are created at actual dispatch with a default 24-hour life, bounded by envelope expiry. The [signer consent flow](docs/signer-consent.md) adds a safe invitation landing, stored disclosure/PDF downloads, read-only preview, explicit access/consent confirmations and decline with durable sender notification. [Reviewed Send and private sender status](docs/sender-send.md) use the [atomic freeze backend](docs/send-freeze.md) to queue the first signer invitation, with tokens activated at dispatch. Actual operator disclosure policies and approved delivery configuration are required. Consented signers can [type, draw or upload their signature and initials](docs/signature-capture.md), review exact saved server previews and explicitly adopt them through the [adoption backend](docs/signature-adoption.md). The field screen supports deliberate per-field application and a saved-entry review, followed by exact PDF review and explicit Finish.

The [signature asset processor](docs/signature-assets.md) validates and normalizes bounded PNG marks for adoption previews. It provides image processing only; the separate adoption workflow authorizes storage and records explicit adoption.

The [signer field screens and backend](docs/signer-fields.md) record one deliberate owned-field application at a time, bound to the current adoption ID/image hash. Signers select fields, explicitly apply/save/clear each entry, and review server-saved values. Replacement makes older mark applications stale until each is reapplied or cleared. [Exact PDF review and Finish](docs/signer-review-finish.md) require explicit preparation, verified PDF access and affirmative review/intent before freezing entries. Confirmation offers the signer's exact checkpoint copy after processing; the completion worker handles final sealing, publication and delivery.

The internal [signer PDF renderer](docs/signer-pdf-rendering.md) turns a verified saved-field snapshot into a new hash-bound copy, preserving earlier contents and page geometry. It derives Full Name and Date Signed from server inputs and verifies applied mark bindings. The Finish transaction authorizes publication of these copies; rendering alone does not complete signing.

The internal [review-candidate backend](docs/signer-review-candidates.md) stages immutable exact PDFs bound to current saved fields, adoption, consent and session. Review receipts expire within ten minutes and before the next UTC date; a later explicit Finish must consume the reviewed copy and match its prospective server date.

The internal [Finish acceptance backend](docs/signer-finish.md) consumes that exact review on explicit intent, records actual server Date Signed and freezes signer entries atomically. Its durable [checkpoint worker](docs/signer-checkpoints.md) verifies/publishes the exact accepted PDF, records Signed state and advances the next signer against the verified current copy. Public review, Finish and confirmation integrate with the durable completion workflow.

PDFsharp is pinned to MIT-licensed 6.2.4; later releases changed licensing. PDF.js 6.4.299 is vendored locally, including its font/decoder assets and license notices. Its four Liberation Sans fonts are replaced with unmodified upstream 2.1.5 under OFL-1.1. CI verifies the committed asset hashes with `python scripts/dev/vendor_pdfjs.py --verify`; maintainers regenerate the pinned distribution with the same script without `--verify`. See [third-party notices](THIRD-PARTY-NOTICES.txt) for attribution.

The standalone [PDF field feasibility harness](docs/pdf-field-feasibility.md) checks stamping geometry, embedded text, checkboxes and image marks with independent rendering and text extraction. Run `pwsh -File scripts/dev/Test-PdfFieldSpike.ps1`; generated fixtures stay ignored. The harness does not enable production stamping or signing.

The internal [timestamped platform seal engine](docs/platform-pdf-seals.md) validates an exact prepared source, applies one detached CMS seal and verifies its RFC 3161 timestamp and complete output. Certificate providers support configured PFX, managed-identity Key Vault backing material and a persistent encrypted demo identity. Provider/TSA values remain private, and configured failures never silently replace an identity. Generated local tests run independently with OpenSSL on Windows and Linux; the completion worker integrates sealing with final publication and delivery.

The internal [completion-evidence collector](docs/completion-evidence.md) verifies the complete recorded signing/audit chain and exact stored sources/assets, then rechecks its database snapshot without restoring user authority. [Durable candidate preparation](docs/completion-candidates.md) freezes one exact unsigned packet and historical evidence snapshot with conditional storage and atomic audit recording. [Resumable sealing](docs/completion-seals.md) prepares both private timestamped outputs, pins their platform certificate identity and verifies actual stored CMS/timestamp evidence across retries. The [certificate renderer](docs/completion-certificates.md) includes bounded pagination, accepted marks, versioned consent and recorded times; the standalone form binds the executed-file hash without circular self-hashes. [Immutable final publication](docs/final-publication.md) reserves stable final targets, verifies explicit retention protection and commits Completed with canonical evidence. Its readonly verifier accounts for the owned transition and growing audit tails without private-key access. The supported [completion worker](docs/completion-worker.md) now queues atomically with the final signer checkpoint and resumes those stages through publication, with lease checks and storage-hint recovery. Existing live sender and accepted-signer sessions can download the verified final pair. [Completed-record retrieval](docs/completion-access.md) adds scanner-safe fragment/manual-code entry, explicit single-use link redemption and independent readonly final downloads for the frozen sender, signers and recipients after signing expiry. [Completion notifications](docs/completion-notifications.md) issue those links at dispatch, preserve exact attachments and prevent automatic resend after uncertain provider acceptance.

The private [sender void flow](docs/sender-void.md) confirms an original sender action on an unfinished sent request, stops subsequent signing progression and preserves prior signing evidence. Supported informative notices queue atomically for the sender and signers, with finite recovery and no access links or attachments.

The public **Verify a completed PDF** link opens `/verify`. Its [bounded upload verification](docs/uploaded-pdf-verification.md) matches supplied bytes to a unique retained completed artifact and verifies its publication, seal and timestamp evidence without granting record access. Uploads are processed in memory and are not saved. An unrecognized file alone does not prove an invalid signature; verification does not establish identity or legal validity.

Finite [signing-expiry maintenance](docs/signing-expiry.md) records due requests through `work expire`, preserving on-time accepted checkpoints and the final completion path. Trusted `work resume-signing-expiry` preparation adds a durable deadline job with storage-only future waits and lease-bound processing. New signer activity remains blocked at the deadline; automatic scheduling from Send and expiry notices remain separate work.

The backend [sender-prefill renderer](docs/sender-pdf-rendering.md) now shares these independent geometry checks. It validates source bytes and sender text/date/checkbox fields, embeds the pinned font, and returns bounded output and hashes. It is an internal component of the reviewed Send transaction, which freezes the sender-prefilled copy before inviting the first signer.

The .NET build restores interact.js 1.10.28 from its exact npm archive into an ignored `obj/browser-assets` cache, checks pinned SHA-512/SHA-256 hashes, and copies the browser script plus unmodified MIT license into build/publish output. No npm scripts run. First builds require registry access and `tar` (included with current Windows and the .NET SDK Linux image); cached builds work offline. Verify output with `python scripts/dev/verify_interact.py src/QuillSign/bin/Release/net10.0/wwwroot/vendor/interact`. The Docker build performs the same restore. Runtime browsers use local assets without a CDN.

For host-side development, configure `Storage:Provider` as `Azurite` and `Storage:ConnectionString` in ignored local settings, pointing to the published emulator endpoint. Hosted configuration uses `Azure`, `Storage:BlobServiceUri`, and optionally `Storage:ManagedIdentityClientId`; credentials come from managed identity. `Storage:MaximumBlobBytes` defaults to 25 MiB. See `appsettings.example.json` for the configuration keys; environment variables replace `:` with `__`.

Data Protection persists its key ring in the separate `keys` container. Hosted storage requires a versionless `DataProtection:KeyVaultKeyIdentifier` to wrap keys in Key Vault; retain older key versions so existing sessions remain readable. `DataProtection:ApplicationName` must match across replicas and remain stable across deployments; its default includes the ASP.NET Core environment name. Azurite is Development-only, with an unencrypted local key ring. Without storage configuration, the bootstrap remains usable; document/session workflows must require persistent storage. Hosted settings and permissions require approval before deployment.

## Build and deployment

CI builds the .NET app and Docker image, compiles Bicep, validates CloudFormation, and scans Git history with Gitleaks. Pull-request checks need no cloud credentials. Trusted push runs publish images tagged with the full commit SHA.

The manual **Deploy** workflow runs from `main` through the GitHub `production` environment after CI has published the matching image. It uses OIDC without an Azure client secret, creates a new app revision, and verifies readiness and the health response. See the [cloud infrastructure guide](infra/README.md#github-deployment) for setup and the stable Actions secret names.

## Remaining work

- Hosted readiness: operator disclosures, TSA configuration and rate coordination, immutable final storage, retention and end-to-end validation.
- Reminders and contact correction remain future work. Disabled-by-default [invitation resend](docs/invitation-resend.md) provides private sender review/confirmation, safe unused-link replacement, capped durable delivery and latest-invitation status while preserving redeemed sessions and signing evidence. Hosted enablement and live-mail validation remain separate. The [verified-mailbox lookup flow](docs/document-lookup.md) supports a gated public email-request form, scanner-safe private entry, a paged retained-document list, an explicit final-packet handoff, capped durable mail and scoped contact-data cleanup using the configured demo retention window. Its demo migration/grants and disabled-email navigation checks passed; hosted mailbox delivery and retained-packet retrieval still need separate enablement and validation.
- Remaining Office formats (DOC, ODT, RTF, TXT, PPTX and XLSX) and hosted conversion validation.
- A confirmed feedback subscription and SES production access before enabling public delivery.
- After the rest of the project is complete: optional, sender-approved AI field and signer-role suggestions.

See the [implementation plan](docs/plan.md) for tracked work. The SVG and PNG brand assets are in [assets](assets/).

## License and demo use

Copyright (c) 2026 Henrique Meyer. QuillSign is licensed under the [GNU Affero General Public License, version 3 or later](LICENSE) (`AGPL-3.0-or-later`).

Software is provided as-is. Operators are responsible for checking whether electronic signatures are suitable for their use case and jurisdiction. The public demo is for synthetic evaluation only, not real-life contracts. Per-document demo retention and queued cleanup are implemented, with seven days selected, but require approved hosted setup and validation before enablement. Participants must download copies before the displayed access deadline; physical deletion can be delayed and does not recall party-held copies.

See the [electronic-signature requirements and acceptance checklist](docs/e-signature-requirements.md) for US ESIGN/UETA and EU eIDAS rules, conditional consumer disclosures, evidence and retention targets, and unsupported uses. This guide describes requirements; it does not certify the current application or guarantee enforceability.

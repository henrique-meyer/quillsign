# QuillSign

An open-source e-signature app being built around sequential signing, no accounts, and no subscriptions.

## Current status

QuillSign is in early development. The .NET 10 ASP.NET Core Razor Pages app supports sender email verification, a session scoped to one draft, PDF upload/replacement, preview confirmation, signer setup with sequential ordering, manual field placement with sender prefill, document details/completion recipients, and a preparation review with corrective links. The `/health` endpoint returns `{"status":"ok"}` without querying the database. Sending and signing follow in later milestones.

The demo's cloud resources are provisioned: Azure hosts the app, data, and background work; Amazon SES provides email. Hosted SQL, storage, application keys, and worker execution are verified. Public email delivery remains disabled pending SES readiness. The full sender verification flow runs locally with Mailpit. Setup instructions are in the [cloud infrastructure guide](infra/README.md).

## Planned signing flow

1. Verify the sender's email through a single-use magic link.
2. Upload a document, review its PDF preview, add signers in order, and place fields.
3. Fill sender-owned fields before sending; each signer reviews, consents, and signs sequentially.
4. Seal the completed PDF once, record the audit trail, and deliver the executed document and certificate of completion to every party.

The editor uses PDF.js and interact.js. Planned stamping, sealing, and timestamp support uses PDFsharp and BouncyCastle; Gotenberg will handle Office conversion. Azure OpenAI will suggest signer roles and field locations for the sender to accept. Amazon SES v2 is the default email provider, SMTP supports local development, and ACS remains an optional future adapter. There is no CAPTCHA; verified email, rate limits, daily caps, and suppression form the planned abuse controls.

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

The app shows the verification form when database, storage, email, and background work are configured; otherwise it shows an email-unavailable notice. Verified senders can upload and review a PDF. Office conversion remains unavailable in the app.

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

For a complete browser flow using the local services, migrate first, then run these commands in separate terminals:

```powershell
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action RunApp -AppPort 5081
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action ListenWork -AppPort 5081 -NoBuild
```

Start `RunApp` first so it builds the application; `-NoBuild` lets the listener use that build while the app is running. Open <http://localhost:5081>, enter a synthetic address such as `sender@example.invalid`, and open the captured message in <http://localhost:8025>. Follow its verification link to the draft. Use the same `AppPort` in both terminals so worker-generated links reach the app. The helper configures local SQL, Azurite, and SMTP without printing credentials.

Verification links work once and expire 15 minutes after dispatch. Sender sessions last two hours without sliding renewal and only open their own draft. The default cap is five requests per address per UTC day, plus 20 HTTP requests per IP per ten-minute window. Configure these limits through the `Sender` section in `appsettings.example.json`. Suppressed and capped requests receive the same neutral inbox message. Browser notices appear once after a clean redirect; JSON clients receive the message body and still require antiforgery tokens for POST requests.

Outside Compose, email is disabled by default. Use the `Email` section of `appsettings.example.json` for provider, sender, base URL, SMTP, SES configuration set, and SNS topic settings. `Email:BaseUrl` builds verification links; templates render when dispatching. `/webhooks/ses` processes authenticated delivery feedback and suppresses permanent bounces and complaints. Transient bounces do not permanently suppress recipients. Feedback and subscription auto-confirmation are disabled by default. Public SES delivery remains gated on durable dispatch, a confirmed feedback subscription, and approved SES readiness.

### Background work

SQL stores durable work and email outbox records. Opaque queue messages wake a finite worker; Blob hints let recovery republish missed wakeups without querying an idle database. Verification payloads are protected with the persistent application key ring, and token validity begins at dispatch. Definite pre-send failures use bounded backoff. A possibly accepted send is recorded as ambiguous and requires explicit reconciliation/resend, rather than an automatic duplicate.

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

Choose **Place document fields** to add signature, initials, full-name, date-signed, text, checkbox, and date fields. Drag/resize fields or select one from the document list and apply exact percentage positions, page, label, assignment, and required status. Sender fields allow only text, checkbox, and date values; signer values are collected during the future signing flow. Changes autosave serially, using the current document and draft revision. A stale tab or failed save pauses saving while keeping local edits available for export before reload. The default cap is 200 fields (`FieldEditor:MaximumFields`, supported range 1–200). See [editor behavior and coordinate contract](docs/field-editor.md).

Open **Document details and recipients** to save a title and optional message, and add/edit/remove named completion recipients (CC). Recipients receive only the completed packet in the future completion workflow; they do not sign or get invitations. Their list is optional, with a default cap of 20 (`Preparation:MaximumRecipients`, supported range 1–100), and normalized addresses must be unique within it. Setup sends no mail. Concurrent changes use the same draft revision as the PDF, signer list and editor. Validation errors retain attempted values; stale form submissions show the current saved details for review before retrying.

Choose **Review document preparation** to see the PDF, ordered signers, sender-filled values and completion recipients together. Missing confirmation, title/signers, invalid field placement/assignment or unfilled sender values produce corrective links. An unchecked sender checkbox counts as filled. Signers without a Signature field produce a warning only. Review reads one coherent draft revision, changes nothing and sends no invitations; passing these preparation checks does not establish legal validity or guarantee text fitting when stamping is integrated.

The [versioned electronic-record disclosure foundation](docs/electronic-record-disclosure.md) builds exact envelope-bound text and hashes for a later send/consent transaction. Operators must supply actual paper-copy, withdrawal, contact-update, access and retention policies through private `ElectronicRecords__...` settings; empty examples fail snapshot construction. This foundation exposes no consent or signing UI.

The backend [signer-access foundation](docs/signer-access.md) provides single-use invitation redemption, isolated two-hour signer sessions and access scoped to the frozen PDF/disclosure. Invitation tokens are created at actual dispatch with a default 24-hour life, bounded by envelope expiry. The [signer consent flow](docs/signer-consent.md) adds a safe invitation landing, stored disclosure/PDF downloads, read-only preview, explicit access/consent confirmations and decline with durable sender notification. The internal [send/freeze foundation](docs/send-freeze.md) atomically freezes reviewed drafts and queues the first signer invitation, with tokens activated at dispatch. Consented signers can [type, draw or upload their signature and initials](docs/signature-capture.md), review exact saved server previews and explicitly adopt them through the [adoption backend](docs/signature-adoption.md). Public sender Send/confirmation, deliberate field filling, review and Finish remain pending.

The [signature asset processor](docs/signature-assets.md) validates and normalizes bounded PNG marks for adoption previews. It provides image processing only; the separate adoption workflow authorizes storage and records explicit adoption.

The internal [signer field backend](docs/signer-fields.md) records one deliberate owned-field application at a time, bound to the current adoption ID/image hash. Replacement makes older applications stale. The public field UI, review and Finish remain subsequent work.

The internal [signer PDF renderer](docs/signer-pdf-rendering.md) turns a verified saved-field snapshot into a new hash-bound copy, preserving earlier contents and page geometry. It derives Full Name and Date Signed from server inputs and verifies applied mark bindings. The later Finish transaction will authorize and publish these copies; rendering alone does not complete signing.

PDFsharp is pinned to MIT-licensed 6.2.4; later releases changed licensing. PDF.js 6.4.299 is vendored locally, including its font/decoder assets and license notices. Its four Liberation Sans fonts are replaced with unmodified upstream 2.1.5 under OFL-1.1. CI verifies the committed asset hashes with `python scripts/dev/vendor_pdfjs.py --verify`; maintainers regenerate the pinned distribution with the same script without `--verify`. See [third-party notices](THIRD-PARTY-NOTICES.txt) for attribution.

The standalone [PDF field feasibility harness](docs/pdf-field-feasibility.md) checks stamping geometry, embedded text, checkboxes and image marks with independent rendering and text extraction. Run `pwsh -File scripts/dev/Test-PdfFieldSpike.ps1`; generated fixtures stay ignored. The harness does not enable production stamping or signing.

The backend [sender-prefill renderer](docs/sender-pdf-rendering.md) now shares these independent geometry checks. It validates source bytes and sender text/date/checkbox fields, embeds the pinned font, and returns bounded output and hashes. It has no endpoint and does not yet freeze, send or sign drafts.

The .NET build restores interact.js 1.10.28 from its exact npm archive into an ignored `obj/browser-assets` cache, checks pinned SHA-512/SHA-256 hashes, and copies the browser script plus unmodified MIT license into build/publish output. No npm scripts run. First builds require registry access and `tar` (included with current Windows and the .NET SDK Linux image); cached builds work offline. Verify output with `python scripts/dev/verify_interact.py src/QuillSign/bin/Release/net10.0/wwwroot/vendor/interact`. The Docker build performs the same restore. Runtime browsers use local assets without a CDN.

For host-side development, configure `Storage:Provider` as `Azurite` and `Storage:ConnectionString` in ignored local settings, pointing to the published emulator endpoint. Hosted configuration uses `Azure`, `Storage:BlobServiceUri`, and optionally `Storage:ManagedIdentityClientId`; credentials come from managed identity. `Storage:MaximumBlobBytes` defaults to 25 MiB. See `appsettings.example.json` for the configuration keys; environment variables replace `:` with `__`.

Data Protection persists its key ring in the separate `keys` container. Hosted storage requires a versionless `DataProtection:KeyVaultKeyIdentifier` to wrap keys in Key Vault; retain older key versions so existing sessions remain readable. `DataProtection:ApplicationName` must match across replicas and remain stable across deployments; its default includes the ASP.NET Core environment name. Azurite is Development-only, with an unencrypted local key ring. Without storage configuration, the bootstrap remains usable; document/session workflows must require persistent storage. Hosted settings and permissions require approval before deployment.

## Build and deployment

CI builds the .NET app and Docker image, compiles Bicep, validates CloudFormation, and scans Git history with Gitleaks. Pull-request checks need no cloud credentials. Trusted push runs publish images tagged with the full commit SHA.

The manual **Deploy** workflow runs from `main` through the GitHub `production` environment after CI has published the matching image. It uses OIDC without an Azure client secret, creates a new app revision, and verifies readiness and the health response. See the [cloud infrastructure guide](infra/README.md#github-deployment) for setup and the stable Actions secret names.

## Remaining work

- Deliberate signer field application, review and Finish.
- Office conversion and document-processing workers.
- A confirmed feedback subscription and SES production access before enabling public delivery.
- PDF stamping, audit evidence, completion certificates, sealing, and verification.
- Optional AI suggestions.

See the [implementation plan](docs/plan.md) for tracked work. The SVG and PNG brand assets are in [assets](assets/).

## License and demo use

Copyright (c) 2026 Henrique Meyer. QuillSign is licensed under the [GNU Affero General Public License, version 3 or later](LICENSE) (`AGPL-3.0-or-later`).

Software is provided as-is. Operators are responsible for checking whether electronic signatures are suitable for their use case and jurisdiction. The public demo is intended for evaluation and periodic data purging; document lifecycle deletion is asynchronous, not an exact retention deadline.

See the [electronic-signature requirements and acceptance checklist](docs/e-signature-requirements.md) for US ESIGN/UETA and EU eIDAS rules, conditional consumer disclosures, evidence and retention targets, and unsupported uses. This guide describes requirements; it does not certify the current application or guarantee enforceability.

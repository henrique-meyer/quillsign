# QuillSign implementation plan

Tasks are recorded here and in Jira before implementation. Private deployment names, identifiers, domains, and personal configuration stay in ignored local files.

## QUILS-3: Create QuillSign SVG logos and matching PNG exports

Status: Done. Branding PRs merged and Jira story closed, including the coral-red product accent.

Create QuillSign branding inspired by the existing DocPilot assets, with a distinct signing motif and product accent. Keep the navy tile and cream document; use a coral-red feather with a darker red facet so QuillSign is visibly distinct from DocPilot's gold. Deliver `assets/logo.svg` as the app icon, `assets/logo-mark.svg` as a transparent header mark, and matching `assets/logo.png` and `assets/logo-mark.png` exports. This story covers asset creation and raster exports; application integration is separate work.

Validate SVG structure, visually inspect the assets at small and large sizes, and verify PNG dimensions and transparency. Scan for secrets, commit, push, open and merge a small PR, then close the Jira story.

Validation: Both self-contained SVGs parsed successfully and were visually inspected at 16, 32, 64, and 128 pixels plus full export size. The navy app icon is exported at 1024 x 1024 pixels; the transparent header mark is exported at 936 x 1008 pixels, preserving its 39:42 viewBox ratio. Both PNGs have RGBA transparency and match a fresh rasterization of their SVG sources exactly. The artwork uses a cream document, a coral-red quill (`#F26B5E` / `#D94343`), and a navy signature stroke.

## QUILS-1: Provision the free Azure SQL database foundation

Status: Done. Infrastructure PR merged and Jira story closed.

Provision the project's Azure SQL database using the free offer, with paid overflow disabled. Deliver Bicep, parameter examples, deployment instructions, and CI validation. Keep deployment values in ignored configuration.

Validation: Database provisioning, Bicep validation, and secret checks passed. The free offer pauses the database on allowance exhaustion.

## QUILS-2: Organize the project's AWS resources

Status: Done. Infrastructure PR merged and Jira story closed.

Create the dedicated AWS Resource Group and consistently tag project resources. Keep deployment values in ignored configuration and document reusable setup commands.

Validation: CloudFormation deployment and project resource grouping were verified. Secret checks passed.

## QUILS-4: Provision the demo hosting and deployment foundation

Status: Done. Infrastructure PRs merged and Jira story closed.

Provision the demo's application hosting, storage, configuration services, and GitHub deployment workflow. Deliver reusable Bicep and parameter examples. Integrate the existing branding and complete DNS/HTTPS setup. Keep deployment-specific settings in local notes.

Validation: The app revision, page/assets, health response, DNS/HTTPS, and GitHub deployment were verified. Build, infrastructure validation, and secret checks passed. Application features follow in subsequent stories.

## QUILS-5: Provision the transactional email foundation

Status: Done. Infrastructure PR merged and Jira story closed.

Provision the project's Amazon SES foundation and delivery-feedback integration. Deliver reusable CloudFormation and configuration examples. Keep sending disabled until application feedback handling, durable dispatch, and SES readiness are complete.

Validation: CloudFormation deployment and email configuration were verified. No live email was sent; application delivery remains a later step.

## QUILS-6: Refresh README with current project status and setup

Status: Documentation complete.

Refresh the public README with the implemented .NET 10 bootstrap, practical local commands, a concise Azure hosting/data and AWS email overview, CI/deployment, and clearly labeled planned signing features. Consolidate cloud setup into infra/README.md; remove standalone hosting and AWS/SES guides and repair links. Keep infrastructure documentation focused on reusable configuration, deployment, DNS/HTTPS, and email setup. Remove demo-specific network/storage/security settings, monitoring limits, role inventories, provisioning audit narratives, and repeated operational detail. Keep private deployment values out of git. No cloud or runtime changes.

Validate claims against repository files and deployment evidence, check Markdown links and secret scans, commit/push/merge the documentation PR, and close Jira in the same pass.

Validation: Local Markdown links resolve and whitespace checks pass. The README distinguishes implemented and planned behavior; infrastructure instructions are consolidated without the demo's operational inventory. No application or cloud resources changed.

## QUILS-7: Plan the application foundation and first sender workflow

Status: Planning complete.

Prepare the next milestone: a verified sender can upload one PDF and review its preview. Create ordered, nonduplicated Jira stories with acceptance criteria and dependencies for local development, persistence, hosted SQL connectivity, storage, email, background work, sender verification, and PDF upload/preview. Mirror them below and leave implementation stories To Do. Field editing, signing, sealing, Office conversion, and AI follow in later milestones. Planning does not authorize cloud changes.

Validate the plan and secret scans, commit/push/merge its PR, and close this planning story.

Validation: Native Jira reads verified all eight implementation stories as To Do, their acceptance criteria, and all fifteen directed dependency links. Story titles and the dependency graph were checked against this plan. The separate license follow-up is queued as QUILS-11. No implementation or cloud changes were made.

### Next milestone: verified sender, PDF upload, and preview

Implement the stories in this order, respecting their dependencies. Hosted rollout also requires QUILS-10; local feature development can continue independently of its approval gate. Cloud changes and live email tests require owner approval. This backlog does not approve additional resources or enable public email delivery.

| Order | Story | Work | Depends on |
| --- | --- | --- | --- |
| 1 | QUILS-8 | Local Docker Compose stack | Completed bootstrap |
| 2 | QUILS-9 | EF Core persistence and migrations | QUILS-8 |
| 3 | QUILS-10 | Hosted SQL connectivity and permissions | QUILS-9 |
| 4 | QUILS-12 | Blob storage and persistent Data Protection | QUILS-8, QUILS-9 |
| 5 | QUILS-13 | SES/SMTP adapters and SNS feedback | QUILS-8, QUILS-9 |
| 6 | QUILS-14 | Durable event-driven work and email dispatch | QUILS-9, QUILS-13 |
| 7 | QUILS-15 | Sender verification and scoped sessions | QUILS-9, QUILS-12, QUILS-13, QUILS-14 |
| 8 | QUILS-16 | PDF upload and preview confirmation | QUILS-9, QUILS-12, QUILS-15 |

Field editing, signer setup, sequential signing, sealing/verification, isolated Office conversion, retention maintenance, and AI remain later milestones. Perform the relevant PDF/seal and conversion feasibility spikes before implementing those features.

## QUILS-8: Set up the local Docker Compose development stack

Status: Implementation complete; full stack validation runs in CI.

Run the .NET 10 app, SQL Server Developer, Azurite, Gotenberg, and Mailpit locally with documented commands, ignored configuration, health checks, persistent development volumes, and reset instructions. A clean checkout must need no hosted services or credentials. SQL Server Developer is development/test only. Verify service startup, shutdown, and reachability; conversion must have no public internet access or Office uploads remain disabled. Application integrations follow in separate stories.

Validation: Local Compose configuration, Python syntax, initializer preservation/idempotence, and whitespace checks passed. CI starts all five services, checks app assets/health and SMTP capture, converts a synthetic document, verifies converter isolation, and checks SQL/blob/mail persistence after a stop/start. Docker Desktop was unavailable locally, so runtime checks use the Linux CI runner. No cloud changes.

## QUILS-9: Add EF Core SQL Server persistence and initial migrations

Status: Implementation complete. Depends on completed QUILS-8.

Implement the requirements' envelope, signer, recipient, field, auth-token, audit-event, outbox/work, and suppression records with EF Core 10 and SQL Server migrations. Represent relationships, case-insensitive party email uniqueness, unique token hashes and audit sequences, normalized field bounds, concurrency controls, append-only hash-chain support, and lease/retry metadata. Apply migrations to a fresh local database and document the separate migration command; do not auto-run privileged production migrations on web startup. Test meaningful constraints against SQL Server. Keep connection strings private and health checks independent of SQL.

Validation: All 21 tests passed against a freshly migrated local SQL Server database, covering constraints, ownership, concurrency, and canonical audit hashes. The migration also applied to the local development database, the model matches its migration, and the dependency vulnerability scan is clean. CI repeats migration/model and SQL integration checks. Runtime permissions remain QUILS-10; durable claims/dispatch remain QUILS-14.

## QUILS-10: Connect the hosted app to Azure SQL

Status: Implementation complete. Depends on completed QUILS-9.

Connect the application to its existing Azure SQL database, apply migrations, and verify database access. Preserve the free offer and idle auto-pause; startup and health checks do not query SQL. Provide practical bootstrap/deployment commands. Keep deployment security controls, IP-filtering details, and operational records in ignored local notes.

Validation: All 48 SQL/Azurite tests and hosted application connection checks passed. The schema is applied; the new app revision is Running and ready, and page/health responses pass. The deployment workflow applies migrations separately from application startup.

## QUILS-12: Integrate Blob storage and persistent Data Protection keys

Status: Implementation complete. Hosted configuration remains subject to approval. Depends on completed QUILS-8 and QUILS-9.

Add an application storage abstraction for Azure Blob and local Azurite with private envelope-scoped access and bounded streaming. Use managed identity when hosted. Persist Data Protection keys in Blob and protect hosted keys through Key Vault; keep the key ring separate from document purge. Verify protected sessions across restarts/replicas, unauthorized access, and storage failures. Keep the unconfigured bootstrap usable. Obtain approval before additional cloud settings or permissions change.

Validation: All 46 SQL/Azurite tests pass, including bounded nonseekable uploads, declared-size mismatch, interrupted/cancelled writes, overwrite prevention, private reads, envelope access, and storage failures. Protected authentication tickets survive provider restart and key rotation across replicas; other application names/purposes are rejected. The Compose app serves its page and health response, and package vulnerability scans are clean. Hosted configuration requires managed identity and Key Vault protection; no cloud resources or settings changed. Sender sessions are issued in QUILS-15, and document workflow state/validation remains QUILS-16.

## QUILS-13: Add SES and local SMTP adapters with SNS feedback handling

Status: To Do. Depends on QUILS-8 and QUILS-9.

Implement IEmailSender with SES v2 as default and SMTP/Mailpit locally, HTML/text verification templates, and configurable sender/base URL. ACS remains a later optional adapter. Validate SNS signatures and confirmation destinations; handle feedback idempotently and reject invalid messages without attacker-directed outbound requests. Persist bounce/complaint suppression and reject suppressed deliveries. Test invalid/duplicate feedback and suppression without live mail. Keep SES sending disabled until subscription, durable dispatch, and approved production access are ready; AWS changes and real sends need owner approval.

## QUILS-14: Implement durable event-driven work and email dispatch

Status: To Do. Depends on QUILS-9 and QUILS-13.

Record the wakeup/recovery design before worker implementation: SQL Server atomic leases, retry/backoff, lease expiry, crash recovery, provider ambiguity, and delivery semantics. Implement email dispatch with reusable work contracts and local tests for competing workers, duplicate wakeups, crashes, delayed mail, exhausted retries, and suppression. Start magic-link validity at actual dispatch and protect sensitive payloads. Idle workers must not poll SQL; maintenance is batched. Propose exact hosted wakeup resources, schedule, sizing, and cost for approval before deployment. Do not promise exactly-once SES delivery without supported deduplication, implicitly approve a queue, or enable public delivery.

## QUILS-15: Build sender email verification and envelope-scoped sessions

Status: To Do. Depends on QUILS-9, QUILS-12, QUILS-13, and QUILS-14. Hosted rollout also requires QUILS-10.

Implement no-account sender email entry, magic-link verification, and a short-lived session for one new draft. Use 256-bit tokens, hashed auth-token storage, 15-minute validity from dispatch, and atomic single use scoped to email/envelope/purpose. Reject invalid, expired, replayed, concurrently consumed, and cross-envelope access. Add secure HttpOnly sessions, antiforgery, neutral request responses, configurable rate limits/daily caps, suppression, and creation/verification audit events. No accounts, passwords, or CAPTCHA. Browser notices use short-lived HttpOnly cookies and clean redirects; JSON clients receive bodies. Exercise the Mailpit-to-draft browser flow and failure cases. Public delivery remains gated on SES readiness.

## QUILS-16: Build verified-sender PDF upload and preview confirmation

Status: To Do. Depends on QUILS-9, QUILS-12, and QUILS-15. Hosted rollout also requires QUILS-10.

Let the verified sender upload/read/replace one PDF in their own draft, preview it with PDF.js, and explicitly confirm it. Enforce content sniffing, configurable byte/page limits, bounded streaming, safe filenames, and access isolation. Reject malformed, encrypted, XFA, and already-signed PDFs; this slice excludes images and Office conversion. Record original/normalized hashes, page dimensions/count, and upload/confirmation audit events. Replacement clears obsolete confirmation/incompatible draft state; failures must not leave falsely completed records. Confirming the preview does not send or freeze a signing copy. Exercise the responsive/accessible browser flow, restarts, isolation, invalid/oversize inputs, and storage failures using synthetic fixtures.

## QUILS-11: Change the project license to AGPL-3.0-or-later

Status: License update complete. Owner-requested follow-up after completed QUILS-7 planning.

Replace the root license with the complete authoritative GNU AGPL version 3 text, preserve the existing copyright attribution in the README license notice, and update current project-license references. Include LICENSE in the container image and identify it with the OCI license label. Keep third-party dependency licenses accurate. Update ignored source-of-truth notes without committing them. Verify the text against the authoritative source, inspect references/container packaging, scan for secrets, pass CI, merge a small PR, and close the story. No application behavior or cloud changes.

Validation: LICENSE matched GNU's published text byte for byte. The README retains the existing copyright and selects AGPL-3.0-or-later; container packaging includes LICENSE and the matching OCI label. Reference and whitespace checks passed. Ignored local requirements/instructions reflect the decision and remain outside git.

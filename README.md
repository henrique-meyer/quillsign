# QuillSign

An open-source e-signature app being built around sequential signing, no accounts, and no subscriptions.

## Current status

QuillSign is in early development. The .NET 10 ASP.NET Core Razor Pages app currently serves a branded demo startup page and a database-independent `/health` endpoint returning `{"status":"ok"}`. Document upload, email verification, and signing are not implemented yet.

The demo's cloud resources are provisioned: Azure hosts the app and data, and Amazon SES provides email. Hosted SQL connectivity and migrations are verified. Blob storage, persistent application keys, email adapters, and delivery feedback have local integration tests. Hosted storage/key configuration and public email delivery are still pending. Setup instructions are in the [cloud infrastructure guide](infra/README.md).

## Planned signing flow

1. Verify the sender's email through a single-use magic link.
2. Upload a document, review its PDF preview, add signers in order, and place fields.
3. Fill sender-owned fields before sending; each signer reviews, consents, and signs sequentially.
4. Seal the completed PDF once, record the audit trail, and deliver the executed document and certificate of completion to every party.

The planned editor uses PDF.js and interact.js. PDFsharp and BouncyCastle provide stamping, sealing, and timestamp support; Gotenberg handles Office conversion. Azure OpenAI will suggest signer roles and field locations for the sender to accept. Amazon SES v2 is the default email provider, SMTP supports local development, and ACS remains an optional future adapter. There is no CAPTCHA; verified email, rate limits, daily caps, and suppression form the planned abuse controls.

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

The app still serves the bootstrap page. Persistence, storage, and email are exercised through integration tests; sender verification, upload, and conversion workflows follow in their own stories. Office uploads remain unavailable in the app.

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

Compose selects SMTP and captures messages in Mailpit using a synthetic sender. `Use-LocalDatabase.ps1 -Action Test` exercises rendered HTML/text verification messages, local SMTP capture, simulated SES requests, signed SNS feedback, and suppression. No AWS credentials or live email are used by tests. The sender verification page and durable dispatch are subsequent work.

Outside Compose, email is disabled by default. Use the `Email` section of `appsettings.example.json` for provider, sender, base URL, SMTP, SES configuration set, and SNS topic settings. `Email:BaseUrl` builds verification links; templates render when dispatching. `/webhooks/ses` processes authenticated delivery feedback and suppresses permanent bounces and complaints. Transient bounces do not permanently suppress recipients. Feedback and subscription auto-confirmation are disabled by default. Public SES delivery remains gated on durable dispatch, a confirmed feedback subscription, and approved SES readiness.

### Background work

SQL stores durable work and email outbox records. Opaque queue messages wake a finite worker; Blob hints let recovery republish missed wakeups without querying an idle database. Verification payloads are protected with the persistent application key ring, and token validity begins at dispatch. Definite pre-send failures use bounded backoff. A possibly accepted send is recorded as ambiguous and requires explicit reconciliation/resend, rather than an automatic duplicate.

With the local stack running, migrate first, then run one item or listen for local work:

```powershell
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action Migrate
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action WorkOnce
pwsh -File scripts/dev/Use-LocalDatabase.ps1 -Action ListenWork
```

`RecoverWork` runs storage-only wakeup recovery; `VerifyWork` checks storage, database access, and payload protection, then queues a synthetic wakeup with no email. Run `WorkOnce` to consume it locally. The helper supplies local Compose settings without printing credentials. `ListenWork` is Development-only and polls the emulator queue, never idle SQL. The optional Compose `workers` profile runs the same listener when an application SQL connection is configured. Hosted jobs use `dotnet QuillSign.dll work once` and `work recover`; work is disabled by default outside configured environments. Sender verification still follows in its own story.

### Document storage and application keys

Compose configures Azurite automatically. The `IBlobStore` adapter checks a verified sender's envelope scope before storage access, uses opaque document references, and streams bounded blocks. It never returns public document URLs. Uploads become readable only after their declared size is verified; existing objects cannot be overwritten. Sender verification and the upload UI are separate work.

For host-side development, configure `Storage:Provider` as `Azurite` and `Storage:ConnectionString` in ignored local settings, pointing to the published emulator endpoint. Hosted configuration uses `Azure`, `Storage:BlobServiceUri`, and optionally `Storage:ManagedIdentityClientId`; credentials come from managed identity. `Storage:MaximumBlobBytes` defaults to 25 MiB. See `appsettings.example.json` for the configuration keys; environment variables replace `:` with `__`.

Data Protection persists its key ring in the separate `keys` container. Hosted storage requires a versionless `DataProtection:KeyVaultKeyIdentifier` to wrap keys in Key Vault; retain older key versions so existing sessions remain readable. `DataProtection:ApplicationName` must match across replicas and remain stable across deployments; its default includes the ASP.NET Core environment name. Azurite is Development-only, with an unencrypted local key ring. Without storage configuration, the bootstrap remains usable; document/session workflows must require persistent storage. Hosted settings and permissions require approval before deployment.

## Build and deployment

CI builds the .NET app and Docker image, compiles Bicep, validates CloudFormation, and scans Git history with Gitleaks. Pull-request checks need no cloud credentials. Trusted push runs publish images tagged with the full commit SHA.

The manual **Deploy** workflow runs from `main` through the GitHub `production` environment after CI has published the matching image. It uses OIDC without an Azure client secret, creates a new app revision, and verifies readiness and the health response. See the [cloud infrastructure guide](infra/README.md#github-deployment) for setup and the stable Actions secret names.

## Remaining work

- Hosted storage/key configuration and the sender/signing workflows.
- Office conversion and background processing.
- A confirmed feedback subscription and SES production access before enabling public delivery.
- PDF stamping, audit evidence, completion certificates, sealing, and verification.
- Optional AI suggestions.

See the [implementation plan](docs/plan.md) for tracked work. The SVG and PNG brand assets are in [assets](assets/).

## License and demo use

Copyright (c) 2026 Henrique Meyer. QuillSign is licensed under the [GNU Affero General Public License, version 3 or later](LICENSE) (`AGPL-3.0-or-later`).

Software is provided as-is. Operators are responsible for checking whether electronic signatures are suitable for their use case and jurisdiction. The public demo is intended for evaluation and periodic data purging; document lifecycle deletion is asynchronous, not an exact retention deadline.

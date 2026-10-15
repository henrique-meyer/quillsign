# QuillSign

An open-source e-signature app being built around sequential signing, no accounts, and no subscriptions.

## Current status

QuillSign is in early development. The .NET 10 ASP.NET Core Razor Pages app currently serves a branded demo startup page and a database-independent `/health` endpoint returning `{"status":"ok"}`. Document upload, email verification, and signing are not implemented yet.

The demo's cloud resources are provisioned: Azure hosts the app and data, and Amazon SES provides email. Application database, storage, and email integration are still pending. Setup instructions are in the [cloud infrastructure guide](infra/README.md).

## Planned signing flow

1. Verify the sender's email through a single-use magic link.
2. Upload a document, review its PDF preview, add signers in order, and place fields.
3. Fill sender-owned fields before sending; each signer reviews, consents, and signs sequentially.
4. Seal the completed PDF once, record the audit trail, and deliver the executed document and certificate of completion to every party.

The planned editor uses PDF.js and interact.js. PDFsharp and BouncyCastle provide stamping, sealing, and timestamp support; Gotenberg handles Office conversion. Azure OpenAI will suggest signer roles and field locations for the sender to accept. Amazon SES v2 is the default email provider, with ACS and SMTP planned as optional adapters. There is no CAPTCHA; email verification, rate limits, daily caps, and suppression are planned abuse controls.

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

EF Core with the SQL Server provider is the chosen persistence layer. Local SQL Server Developer, Azurite, and Gotenberg containers are planned; a Compose development stack has not been added yet.

## Build and deployment

CI builds the .NET app and Docker image, compiles Bicep, validates CloudFormation, and scans Git history with Gitleaks. Pull-request checks need no cloud credentials. Trusted push runs publish images tagged with the full commit SHA.

The manual **Deploy** workflow runs from `main` through the GitHub `production` environment after CI has published the matching image. It uses OIDC without an Azure client secret, creates a new app revision, and verifies readiness and the health response. See the [cloud infrastructure guide](infra/README.md#github-deployment) for setup and the stable Actions secret names.

## Remaining work

- Application database connectivity and EF Core integration.
- Document storage, persistent application keys, and the sender/signing workflows.
- Office conversion and background processing.
- Signature-validated SNS feedback handling, email adapters, and SES production access before enabling delivery.
- PDF stamping, audit evidence, completion certificates, sealing, and verification.
- Optional AI suggestions.

See the [implementation plan](docs/plan.md) for tracked work. The SVG and PNG brand assets are in [assets](assets/).

## License and demo use

QuillSign is licensed under [MIT](LICENSE). Software is provided as-is. Operators are responsible for checking whether electronic signatures are suitable for their use case and jurisdiction. The public demo is intended for evaluation and periodic data purging; document lifecycle deletion is asynchronous, not an exact retention deadline.

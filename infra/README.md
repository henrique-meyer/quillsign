# Cloud infrastructure

Azure hosts the application and data services; AWS provides transactional email. Azure definitions use Bicep, and AWS definitions use CloudFormation.

Run commands from the repository root. Keep deployment names, identifiers, domains, addresses, and credentials in ignored configuration or secrets. Each deployment uses dedicated project resources. Preview changes and obtain owner approval before provisioning.

## Azure database

Parameter files may also live outside the checkout: copy an example anywhere private, change its `using` line to the template's path, and pass that file to `--parameters` (or `file://...` for AWS) in the commands below.

Copy `infra/main.bicepparam.example` to the ignored `infra/main.bicepparam` and fill in the required values. Set `AZURE_RESOURCE_GROUP` to the same group name. Choose a supported SQL region; it may differ from the resource group's location.

The template uses the Azure SQL free offer and pauses the database if its monthly allowance is exhausted rather than charging for overflow.

```powershell
az bicep build --file infra/main.bicep --stdout > $null
az deployment sub what-if --location $deploymentLocation --template-file infra/main.bicep --parameters infra/main.bicepparam
az deployment sub create --location $deploymentLocation --template-file infra/main.bicep --parameters infra/main.bicepparam
```

Set `$deploymentLocation` to the deployment region before running these commands. See Microsoft's [free-offer documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/free-offer) for eligibility and allowances.

### Database bootstrap and migrations

Build the app, then run the one-time bootstrap as the configured database administrator. Supply the variables through ignored local deployment configuration.

```powershell
dotnet build src/QuillSign/QuillSign.csproj -c Release
./scripts/cloud/Use-SqlAdministrator.ps1 -ResourceGroup $env:AZURE_RESOURCE_GROUP -ServerName $sqlServer -DatabaseName $sqlDatabase -RuntimeClientId $runtimeClientId -MigrationClientId $migrationClientId
```

The helper prepares the database and applies its initial migration. Future deployments apply migrations through the GitHub workflow.

Set `databaseConnectionSecretUri` in ignored web/hosting parameters to the configured connection secret. The app reads it through `ConnectionStrings__Database`. Web startup and `/health` never query SQL.

For private CLI error details, set `Database:DiagnosticFile` to an ignored local file. Console output omits connection endpoints and credentials.

## Hosting

Copy `infra/hosting.bicepparam.example` to the ignored `infra/hosting.bicepparam` and supply the required values. This template provisions app hosting, Blob storage, Key Vault, and supporting services in the project's Azure resource group.

```powershell
az bicep build --file infra/hosting.bicep --stdout > $null
az deployment group what-if --resource-group $env:AZURE_RESOURCE_GROUP --template-file infra/hosting.bicep --parameters infra/hosting.bicepparam
az deployment group create --resource-group $env:AZURE_RESOURCE_GROUP --template-file infra/hosting.bicep --parameters infra/hosting.bicepparam
```

For the initial deployment, set `deployWeb = false`. Once CI publishes a container image, make the GHCR package public in its package settings, set `image` to its full commit-SHA tag, and redeploy with `deployWeb = true`.

For app-only deployments, use `infra/web.bicepparam.example` with `infra/modules/web.bicep`, or use the GitHub workflow below.

### DNS and HTTPS

The deployment outputs `fqdn` and `domainVerificationId`. Use them to add the hostname's CNAME and `asuid` TXT records at your DNS provider. Keep the actual records in local deployment notes.

Set `customDomainName` and deploy the initial hostname binding. Then set `managedCertificateName` and `enableManagedCertificate = true`, preview, and deploy the managed certificate. Keep the app running during certificate issuance. Verify HTTPS and confirm `/health` returns `{"status":"ok"}`.

## AWS resource group

Copy `infra/aws/deployment.local.ps1.example` to the ignored `infra/aws/deployment.local.ps1` and fill in the required values. The group uses a project tag to organize supported AWS resources; use the same tag for email resources.

```powershell
. ./infra/aws/deployment.local.ps1
aws cloudformation validate-template --region $awsRegion --template-body file://infra/aws/resource-group.cfn.yaml
aws cloudformation deploy --region $awsRegion --stack-name $awsStackName --template-file infra/aws/resource-group.cfn.yaml --parameter-overrides "GroupName=$awsGroupName" "ProjectTagValue=$awsProjectTagValue" --tags "Project=$awsProjectTagValue" --no-fail-on-empty-changeset
```

## AWS email

Copy `infra/aws/ses.parameters.example.json` to the ignored `infra/aws/ses.parameters.local.json`. Set the sending subdomain, its child MAIL FROM domain, dedicated resource names, and the project tag. Set `$awsSesStackName` to the new email stack's name.

Preview a CloudFormation change set before deploying:

```powershell
aws cloudformation deploy --region $awsRegion --stack-name $awsSesStackName --template-file infra/aws/ses.cfn.yaml --parameter-overrides file://infra/aws/ses.parameters.local.json --capabilities CAPABILITY_NAMED_IAM --no-execute-changeset
```

Review and execute the approved change set. Add the DNS records supplied by SES: three DKIM CNAMEs, a MAIL FROM MX record with priority 10, and a MAIL FROM SPF TXT record. Verify domain, DKIM, and MAIL FROM status in SES.

Configure the application's AWS credentials through runtime secrets and environment variables, including `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`.

Email delivery is not enabled yet. The app includes durable dispatch, SES/SMTP adapters, and the `/webhooks/ses` feedback endpoint; practical application settings are in the root README and `appsettings.example.json`. Before enabling public delivery, configure and confirm the feedback subscription and obtain SES production access. Cloud changes and live sends require operator approval. See the [SES sandbox documentation](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html).

## Background execution

Copy `infra/work.bicepparam.example` to ignored `infra/work.bicepparam`. Supply the project's existing hosting/storage configuration and new work resource names. With `deployJobs = false`, preview and deploy the queue, hint container, and worker identity/access. Bootstrap its database access with `database provision-worker`, storing `Database:WorkerClientId` only in private configuration. Store its database connection in Key Vault.

Once the matching image is published and the schema is migrated, set the private database-secret reference and `deployJobs = true`, then preview/deploy `infra/work.bicep`. Configure the web application's storage/key-ring and `Work` settings through its private `applicationEnvironment` parameters. Use the same Data Protection application name and key ring for the web and dispatch processes. Keep email disabled until launch readiness is approved.

The dispatch job runs `work once`; hourly recovery runs `work recover` without SQL configuration. Run `work verify` explicitly to check the dispatch identity's database/storage/key-ring access, then verify job executions and application health. The manual Deploy workflow updates the app and both jobs to the matching commit image. Keep actual resource values and deployment records in local notes.

## Existing DOCX recovery permissions and configuration

After approval, `sandbox-cleanup-access.bicep` grants SandboxGroup Data Owner to the existing SQL-free purge-recovery job identity on the existing dedicated converter group only. The principal is resolved from that job by ARM reference. This template creates no identity, group or general subscription permission. Supply exact scope values in its ignored parameter file.

Use `sandbox-maintenance.bicep` for the narrow existing-job configuration update. It shares `modules/purge-recovery-job.bicep` with the original staging template, preserving hourly execution, finite timeout, zero retries and the SQL-free command. Enable maintenance only after its separate group grant is approved and verified. The web uses the same protected coordination ledger and its existing group-scoped identity; keep maintenance disabled on web. Set bounded daily/monthly attempt caps explicitly. A pending cleanup consumes no new conversion and counters are never refunded. These are attempt limits, not a provider billing cap.

For the app rollout, update only the checked image and approved DOCX settings while preserving unrelated live environment values, secret references, trust mounts, identities, scale and ingress. Record the exact image, readiness, custom health, role readback, synthetic browser results and final empty sandbox/snapshot/image inventory privately. Email and live timestamp requests require their own authorization. See [DOCX operations and limits](../docs/document-conversion.md#isolated-sandbox-application-transport).

## GitHub deployment

### Approved demo staging

After explicit resource approval, use `demo-staging.bicep` and private parameters to add the separate hourly `work purge-recover 32` job and its container/key-scoped permissions. It has no database or email credentials. Dispatch gains document-container access, with policy ownership limited to the final container. This template disables the reviewed single legacy age-based document lifecycle rule; compare the live policy first and preserve any unrelated operator rules. Soft-delete settings are unchanged. The Deploy workflow updates this job alongside dispatch and hint recovery.

For an existing final container, apply `final-inventory-access.bicep` only for approved temporary inventory access and remove its role assignment afterward. An empty, lease-free inventory is required before `final-migration-policy.bicep` and the explicit Azure version-support migration. The initial one-day default is unlocked; never lock it or shorten an existing locked version. After successful migration, record `finalVersionSupportEnabled=true` in private hosting parameters. Actual final publication sets and verifies the exact saved deadline on each version.

Web and dispatch accept an optional secure `tsaRootPem` parameter mounted read-only at `/app/trust/tsa-root.pem`. Supply verified public root material privately and configure `Seal__TsaTrustedRootPaths__0` to that path, the selected provider URL and shared request coordination. Retain historical roots when rotating. Keep email and hosted Office conversion disabled until their separate gates pass.

For a dispatch-only configuration rollout, use `modules/dispatch.bicep` with the existing project's private settings. The full `work.bicep` calls the same module when provisioning the foundation; the narrow module avoids reapplying queue, hint-container and existing role resources during an application-only update.

Historical version deletion requires the separate `deleteBlobVersion/action` permission. `modules/version-cleanup.bicep` defines only that data action and assigns it on document containers to dispatch and purge recovery; it grants no immutability-management permission. The full staging template calls this module after creating recovery. Use the narrow module for a permission-only update. Final-container policy ownership remains dispatch-only. Keep the custom role's display name private.

The explicit operator commands `staging storage` and `staging seal` require Azure storage, `ElectronicRecords__Profile=synthetic-demo-v1` and `Email__Enabled=false`. They register no SQL/email services. Storage checks one generated synthetic final version with a short probe-only lock, exact readback, early deletion rejection and cleanup after expiry. Seal checks perform two non-agreement seals using the configured persistent identity and coordinated TSA. For an explicitly inventoried failed probe, `staging cleanup <envelope-N> <object-N> <expected-SHA256>` checks the exact small unsigned synthetic PDF, hash, version/ETag and expired protection before deleting only its current pointer and retained version. It does not discover candidates or authorize ordinary/enrolled cleanup. These commands do not send mail, change default policies or prove the full enrolled purge flow. Run only with approved scoped credentials and a reviewed live-request budget; failures are reported without private identifiers. See the [rollout gates](../docs/hosted-demo-rollout.md).

CI builds the app and Docker image, validates the infrastructure templates, and scans for secrets. Trusted push runs publish GHCR images tagged with the full commit SHA. Pull-request checks require no cloud credentials.

Configure the GitHub `production` environment with these Actions secrets:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `AZURE_RESOURCE_GROUP`

Set `githubFederationSubject` in the ignored hosting parameters to the exact subject emitted by GitHub for that environment. Use the `azure/login` token diagnostics to check it; the subject may include immutable owner and repository IDs.

Run the manual **Deploy** workflow from `main` after CI succeeds for that commit. It uses OIDC authentication, applies migrations through the deployment identity, deploys the matching image, and checks revision readiness and `/health`. Complete the database identity bootstrap before the first migration-enabled deployment.

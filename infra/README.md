# Cloud infrastructure

Azure hosts the application and data services; AWS provides transactional email. Azure definitions use Bicep, and AWS definitions use CloudFormation.

Run commands from the repository root. Keep deployment names, identifiers, domains, addresses, and credentials in ignored configuration or secrets. Each deployment uses dedicated project resources. Preview changes and obtain owner approval before provisioning.

## Azure database

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

Email delivery is not enabled yet. The app includes SES/SMTP adapters and the `/webhooks/ses` feedback endpoint; practical application settings are in the root README and `appsettings.example.json`. Before enabling public delivery, complete durable dispatch, configure and confirm the feedback subscription, and obtain SES production access. Cloud changes and live sends require operator approval. See the [SES sandbox documentation](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html).

## GitHub deployment

CI builds the app and Docker image, validates the infrastructure templates, and scans for secrets. Trusted push runs publish GHCR images tagged with the full commit SHA. Pull-request checks require no cloud credentials.

Configure the GitHub `production` environment with these Actions secrets:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `AZURE_RESOURCE_GROUP`

Set `githubFederationSubject` in the ignored hosting parameters to the exact subject emitted by GitHub for that environment. Use the `azure/login` token diagnostics to check it; the subject may include immutable owner and repository IDs.

Run the manual **Deploy** workflow from `main` after CI succeeds for that commit. It uses OIDC authentication, applies migrations through the deployment identity, deploys the matching image, and checks revision readiness and `/health`. Complete the database identity bootstrap before the first migration-enabled deployment.

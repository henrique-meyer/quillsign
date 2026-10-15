# Database foundation

This subscription-scoped Bicep deployment creates one dedicated application resource group and a new SQL logical server/database inside it. It does not reference resources from other groups.

The database uses the Azure SQL free offer: General Purpose serverless, 0.5 minimum and 2 maximum vCores, 32 GiB maximum data storage, locally redundant backups, seven-day point-in-time retention, and idle auto-pause after 15 minutes. `useFreeLimit` is fixed to `true` and `freeLimitExhaustionBehavior` to `AutoPause`. The database becomes unavailable until next month if its allowance is exhausted; the template cannot opt into paid overages.

Administration uses Microsoft Entra-only authentication and TLS 1.2 or newer. Public network access starts disabled and no firewall rules are created. Application connectivity is subsequent approved work. The administrator values on the server are creation-time settings; changing an existing administrator requires the dedicated administrator API rather than relying on a server redeployment.

## Local configuration

1. Confirm the intended Azure subscription with `az account show`.
2. Check free-offer slots and any existing free-offer region constraint. The offer permits up to ten databases per subscription and may constrain their region. SQL provisioning can also be restricted by subscription even if validation succeeds. Set `sqlLocation` to an allowed region; `location` is the group's immutable metadata location and can differ. Do not convert an existing paid database or enable paid overflow as a workaround.
3. Copy `main.bicepparam.example` to `main.bicepparam` and fill its empty fields locally. The parameters contain real resource names and administrator identity, so the actual file stays ignored.
4. Set `AZURE_RESOURCE_GROUP` to the same dedicated group used in the ignored parameter file. It remains the stable CI/CD configuration name.

Compile without authenticating or accessing cloud resources:

```powershell
az bicep build --file infra/main.bicep --stdout > $null
```

For an approved deployment, use the deployment region from the local parameters and save command output outside tracked files:

```powershell
az deployment sub what-if --location $deploymentLocation --template-file infra/main.bicep --parameters infra/main.bicepparam
az deployment sub create --location $deploymentLocation --template-file infra/main.bicep --parameters infra/main.bicepparam
```

The preview is for verification; cloud changes require explicit approval before running `create`. Subscription-level resource-group creation permissions are needed in addition to SQL deployment permissions.

## Verification

Read the deployed database and verify `useFreeLimit: true`, exhaustion behavior `AutoPause`, 32 GiB maximum size, minimum capacity 0.5, maximum capacity 2, local backup redundancy, and auto-pause delay 15. Also check Entra-only administration, disabled public networking, no firewall rules, enabled transparent encryption, and seven-day backup retention.

Keep actual deployment results and cloud identifiers in ignored local notes. Before committing or pushing, scan tracked files and Git history with Gitleaks. Pull-request CI compiles Bicep and scans for secrets without cloud credentials. Application build, tests, and Docker checks will be added when the application exists.

Sources: [Azure SQL free offer](https://learn.microsoft.com/en-us/azure/azure-sql/database/free-offer), [free-offer FAQ](https://learn.microsoft.com/en-us/azure/azure-sql/database/free-offer-faq), [database resource schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.sql/2023-08-01/servers/databases).

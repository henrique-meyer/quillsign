# Hosting foundation

Copy `hosting.bicepparam.example` to the ignored `hosting.bicepparam`. Supply new names, the repository, location, and the current month's first day as `budgetStartDate`. The deployment targets the existing dedicated resource group; it neither creates nor reads other workload groups.

```powershell
az bicep build --file infra/hosting.bicep --stdout > $null
az deployment group what-if --resource-group $env:AZURE_RESOURCE_GROUP --template-file infra/hosting.bicep --parameters infra/hosting.bicepparam
az deployment group create --resource-group $env:AZURE_RESOURCE_GROUP --template-file infra/hosting.bicep --parameters infra/hosting.bicepparam
```

Deploy first with `deployWeb = false`. CI publishes the bootstrap image under its full commit SHA. Make the new GHCR package public once in package settings, then verify an anonymous manifest request using the registry bearer-token flow. Set `image` to that immutable SHA tag and `deployWeb = true`, preview, and deploy again. No registry credentials or placeholder image are used.

The environment deliberately omits workload profiles and a custom VNet, selecting legacy Consumption-only hosting. This keeps customer-managed network infrastructure out of additional resource groups. Verify the native environment response has no infrastructure resource group. This choice does not resolve future converter egress isolation or private SQL connectivity; those remain design and approval gates.

Storage uses LRS, TLS, Entra authentication, private containers, and disabled shared keys. Document blobs and older versions expire after seven days. Soft deletion retains deleted data for another seven days; lifecycle processing is asynchronous, so this is not an exact deletion deadline. The `keys` container is excluded from expiry. Do not change document retention independently of application/database retention when signing is implemented.

The runtime identity gets Blob Data Contributor on this project's storage, Secrets User on this vault, and Crypto Service Encryption User on the Data Protection key. The bootstrap does not yet consume those services or persist sessions. Key Vault is RBAC enabled, soft deleted and purge protected. Its authenticated public endpoint and Blob's authenticated public endpoint need no private endpoint at this stage.

Log Analytics retains 30 days and has a 0.1 GB daily cap. Workspace-based Application Insights is provisioned with sampling configured; application telemetry integration comes with application features. Daily caps are approximate ingestion controls, not a hard billing cap. The monthly resource-group budget is 15 in the subscription's billing currency. Empty `alertEmails` means portal tracking without email; supplying addresses enables actual 50/80/100% and forecast 100% notifications. Budgets do not stop resources.

Bootstrap role assignments are deployed by an authorized operator. The separate deployment identity has Contributor only on this group, without permanent role-assignment administration. Its federation subject exactly matches the repository and GitHub `production` environment. Store the four stable Actions secrets there: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, and `AZURE_RESOURCE_GROUP`. The manual Deploy workflow updates the existing web app using the SHA image built by CI. Run it only after CI succeeds for the same main commit.

After deploying, verify the revision is Running and `/health` returns `{"status":"ok"}`. Verify `/`, `/site.css`, and both brand SVGs. Health probes never contact SQL. Record resource identifiers and outputs in ignored local files. The `fqdn` and `domainVerificationId` outputs supply the CNAME and `asuid` TXT records; configure the owner's domain and free managed TLS certificate after DNS resolves.

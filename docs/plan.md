# QuillSign implementation plan

Tasks are recorded here and in Jira before implementation. Private deployment names, identifiers, domains, and personal configuration stay in ignored local files.

## QUILS-3: Create QuillSign SVG logos and matching PNG exports

Status: Done. Branding PRs merged and Jira story closed, including the coral-red product accent.

Create QuillSign branding inspired by the existing DocPilot assets, with a distinct signing motif and product accent. Keep the navy tile and cream document; use a coral-red feather with a darker red facet so QuillSign is visibly distinct from DocPilot's gold. Deliver `assets/logo.svg` as the app icon, `assets/logo-mark.svg` as a transparent header mark, and matching `assets/logo.png` and `assets/logo-mark.png` exports. This story covers asset creation and raster exports; application integration is separate work.

Validate SVG structure, visually inspect the assets at small and large sizes, and verify PNG dimensions and transparency. Scan for secrets, commit, push, open and merge a small PR, then close the Jira story.

Validation: Both self-contained SVGs parsed successfully and were visually inspected at 16, 32, 64, and 128 pixels plus full export size. The navy app icon is exported at 1024 x 1024 pixels; the transparent header mark is exported at 936 x 1008 pixels, preserving its 39:42 viewBox ratio. Both PNGs have RGBA transparency and match a fresh rasterization of their SVG sources exactly. The artwork uses a cream document, a coral-red quill (`#F26B5E` / `#D94343`), and a navy signature stroke.

## QUILS-1: Provision the free Azure SQL database foundation

Status: Done. Infrastructure PR merged and Jira story closed.

Create a dedicated application resource group, a new logical SQL server, and one Azure SQL General Purpose serverless database. Check the subscription's free-offer allocation and region first. Use the free offer with monthly exhaustion set to `AutoPause`, 32 GiB maximum storage, the smallest supported serverless minimum, idle auto-pause, locally redundant backups, and seven-day point-in-time retention.

Configure Microsoft Entra-only administration and TLS 1.2 or newer. Do not create broad firewall rules or paid database add-ons. All resources belong to the dedicated group; do not reuse resources from other groups.

Deliver reusable Bicep, parameter examples with empty private fields, deployment documentation, and CI for Bicep validation and secret scanning. Keep compiled templates, actual parameters, deployment logs, and cloud identifiers out of git. Verify deployed settings, scan before pushing, then merge the PR and move the story to Done.

Validation: Bicep compilation and Azure deployment succeeded. Native Azure reads confirmed the free offer, `AutoPause` exhaustion behavior, 32 GiB size limit, 0.5–2 vCore range, the free offer's required 60-minute idle delay, local backups, seven-day retention, enabled encryption, Entra-only administration, TLS 1.2, disabled public networking, and zero firewall rules. Gitleaks scans passed locally and CI checks compile Bicep and scan Git history. SQL's resource location can differ from the resource group's immutable metadata location when subscription provisioning policy requires it.

Other app, storage, vault, logging, email, AI, DNS, and converter resources require subsequent approved work. Background work must preserve database auto-pause; no recurring idle SQL polling. CAPTCHA is excluded.

## QUILS-2: Create the dedicated AWS resource group

Status: Done. Infrastructure PR merged and Jira story closed. CloudFormation lint, Bicep compilation, and secret-scan CI checks passed.

Create a new tag-based AWS Resource Group in the project's SES region using the owner-supplied name from ignored configuration. Tag project-owned resources consistently, use dedicated names and permissions, and document which resource types the group supports. Group membership organizes resources; IAM permissions provide security isolation.

Deliver a reusable infrastructure definition, local parameter example, and verification of the group/query. Keep real resource names and account identifiers out of git. Do not repurpose unrelated AWS resources. Email identities, IAM credentials, and event destinations are subsequent approved work. Scan, commit, push, merge the PR, then move the story to Done.

Validation: AWS CLI authentication and CloudFormation template validation succeeded. The new stack reached `CREATE_COMPLETE`. Native Resource Groups reads verified the requested name, the `TAG_FILTERS_1_0` query, the unique project filter, the group's own project tag, and zero unrelated members. Actual names, account identifiers, ARNs, and deployment output remain in ignored local files.

## QUILS-4: Provision the demo hosting, storage, security, and deployment foundation

Status: Done. Hosting foundation deployed and verified; the merged PR completes the Jira story. Owner selected portal budget tracking without email notifications.

Provision new resources in the dedicated group: a Container Apps environment using only the Consumption profile without a custom VNet, private Blob storage and lifecycle rules, RBAC Key Vault, runtime and deployment managed identities, scoped role assignments, GitHub production OIDC, capped monitoring, and a resource-group budget. Deploy a real .NET 10 Razor Pages bootstrap using the existing brand assets and a public GHCR image. Return exact DNS records through ignored deployment output. Preserve free SQL settings and keep health checks independent of SQL. Do not enable signing or uploads during this foundation step.

Validate Bicep, deployment scope and settings, build/image CI, the running app revision and distinctive health JSON, and the bootstrap browser page. Scan secrets, merge the PR, and close Jira. Converter/database networking and AI remain separately approved work; AWS SES gets its own story after sender configuration is supplied. Any owner DNS or package-visibility step must be recorded precisely.

Validation: The environment has no infrastructure resource group or custom VNet. Native reads verified private containers, disabled shared keys, scoped runtime and deployment permissions, RBAC/purge-protected Key Vault, capped monitoring, and the portal budget. Anonymous GHCR pull, the 0.5 CPU/1 GiB web app with 0..2 replicas, Running/Healthy revision, distinctive health JSON, browser page and assets, custom DNS, managed certificate, and HTTPS at the custom domain all passed. The GitHub production environment and four stable OIDC secrets are configured. Local build/publish, Bicep/Azure validation, deployment-script syntax, Docker CI, CloudFormation lint, and secret scanning passed. Signing, uploads, converter/database networking, background wakeups, and AI are subsequent work.
## QUILS-5: Provision isolated SES email identity and send-only credentials

Status: Done. Infrastructure PR merged and Jira story closed. All five owner-added DNS records resolve correctly, and SES verified DKIM and custom MAIL FROM. Sending remains disabled until the feedback handler and sandbox exit are ready.

Create a new domain identity with Easy DKIM and custom MAIL FROM, a configuration set with tracking disabled and suppression enabled, an SNS feedback destination, and a dedicated send-only IAM user scoped to the sender and identity. Tag supported resources into the project's AWS group. Store credentials only in the project's Key Vault and return actual DNS records privately. No email sends or production-access submission in this step; the HTTPS feedback subscription awaits its signature-validating application handler.

Validate CloudFormation, native SES/IAM/group state and credential storage, scan for secrets, merge the PR, then close Jira. DNS verification and SES sandbox exit are explicit launch gates.

Validation: CloudFormation reached CREATE_COMPLETE. Native reads verified the dedicated identity, DKIM and MAIL FROM configuration, disabled sending, suppression, excluded tracking, SNS destination, and supported-resource group membership. IAM simulation allowed the configured sender and denied another address; the user has no managed policies or group memberships. Credential values were verified in the project vault, and the temporary secrets-writing grant was removed. No email was sent. Account limits remain 200/day and one/second in the sandbox.

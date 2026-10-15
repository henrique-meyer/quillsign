# QuillSign implementation plan

Tasks are recorded here and in Jira before implementation. Private deployment names, identifiers, domains, and personal configuration stay in ignored local files.

## QUILS-1: Provision the free Azure SQL database foundation

Status: Done. Infrastructure PR merged and Jira story closed.

Create a dedicated application resource group, a new logical SQL server, and one Azure SQL General Purpose serverless database. Check the subscription's free-offer allocation and region first. Use the free offer with monthly exhaustion set to `AutoPause`, 32 GiB maximum storage, the smallest supported serverless minimum, idle auto-pause, locally redundant backups, and seven-day point-in-time retention.

Configure Microsoft Entra-only administration and TLS 1.2 or newer. Do not create broad firewall rules or paid database add-ons. All resources belong to the dedicated group; do not reuse resources from other groups.

Deliver reusable Bicep, parameter examples with empty private fields, deployment documentation, and CI for Bicep validation and secret scanning. Keep compiled templates, actual parameters, deployment logs, and cloud identifiers out of git. Verify deployed settings, scan before pushing, then merge the PR and move the story to Done.

Validation: Bicep compilation and Azure deployment succeeded. Native Azure reads confirmed the free offer, `AutoPause` exhaustion behavior, 32 GiB size limit, 0.5–2 vCore range, the free offer's required 60-minute idle delay, local backups, seven-day retention, enabled encryption, Entra-only administration, TLS 1.2, disabled public networking, and zero firewall rules. Gitleaks scans passed locally and CI checks compile Bicep and scan Git history. SQL's resource location can differ from the resource group's immutable metadata location when subscription provisioning policy requires it.

Other app, storage, vault, logging, email, AI, DNS, and converter resources require subsequent approved work. Background work must preserve database auto-pause; no recurring idle SQL polling. CAPTCHA is excluded.

## QUILS-2: Create the dedicated AWS resource group

Status: In Progress, following completed QUILS-1. CloudFormation lint, Bicep compilation, and secret-scan CI checks passed. Deployment awaits AWS CLI authentication.

Create a new tag-based AWS Resource Group in the project's SES region using the owner-supplied name from ignored configuration. Tag project-owned resources consistently, use dedicated names and permissions, and document which resource types the group supports. Group membership organizes resources; IAM permissions provide security isolation.

Deliver a reusable infrastructure definition, local parameter example, and verification of the group/query. Keep real resource names and account identifiers out of git. Do not repurpose unrelated AWS resources. Email identities, IAM credentials, and event destinations are subsequent approved work. Scan, commit, push, merge the PR, then move the story to Done.

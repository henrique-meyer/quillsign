# QuillSign implementation plan

Tasks are recorded here and in Jira before implementation. Private deployment names, identifiers, domains, and personal configuration stay in ignored local files.

## QUILS-1: Provision the free Azure SQL database foundation

Status: In Progress.

Create a dedicated application resource group, a new logical SQL server, and one Azure SQL General Purpose serverless database. Check the subscription's free-offer allocation and region first. Use the free offer with monthly exhaustion set to `AutoPause`, 32 GiB maximum storage, the smallest supported serverless minimum, idle auto-pause, locally redundant backups, and seven-day point-in-time retention.

Configure Microsoft Entra-only administration and TLS 1.2 or newer. Do not create broad firewall rules or paid database add-ons. All resources belong to the dedicated group; do not reuse resources from other groups.

Deliver reusable Bicep, parameter examples with empty private fields, deployment documentation, and CI for Bicep validation and secret scanning. Keep compiled templates, actual parameters, deployment logs, and cloud identifiers out of git. Verify deployed settings, scan before pushing, then merge the PR and move the story to Done.

Other app, storage, vault, logging, email, AI, DNS, and converter resources require subsequent approved work. Background work must preserve database auto-pause; no recurring idle SQL polling. CAPTCHA is excluded.

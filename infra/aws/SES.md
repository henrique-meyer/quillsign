# SES foundation

Create all resources in the project's AWS region. Copy `ses.parameters.example.json` to the ignored `ses.parameters.local.json` and supply private values. `IdentityDomain` is the sending subdomain; `MailFromDomain` is a child of it. `ProjectTagValue` must match the dedicated Resource Group query. Use new dedicated names only.

```powershell
aws cloudformation deploy --region $awsRegion --stack-name $awsSesStackName --template-file infra/aws/ses.cfn.yaml --parameter-overrides file://infra/aws/ses.parameters.local.json --capabilities CAPABILITY_NAMED_IAM
```

Preview a CloudFormation change set before execution. Easy DKIM creates three CNAME outputs. Custom MAIL FROM additionally requires an MX record to the region's SES feedback host (priority 10) and a TXT SPF value of `v=spf1 include:amazonses.com ~all`. Keep exact DNS names and outputs in ignored files. Do not alter unrelated root-domain mail records. A DMARC policy on the sending subdomain can start at `v=DMARC1; p=none` without report addresses.

Sending is deliberately disabled on this configuration set until domain/DKIM/MAIL FROM verification, sandbox restrictions, and the feedback handler are resolved. Open/click events and engagement metrics are excluded. The SNS topic policy permits only SES publishing from this configuration set in this account. The topic has no application subscription yet: add an HTTPS subscription only when the app can validate SNS signatures, confirm subscriptions safely, and process bounce/complaint suppression. Do not enable sending first.

The IAM user has no console password, no managed policies, and one inline policy permitting only SES send actions for the configured identity/configuration set and From address. Create its access key outside CloudFormation so the secret is never a template or stack output. Transfer it directly to the project's Key Vault using an authorized secrets-writing operator. Keep any necessary recovery copy encrypted locally and remove temporary operator grants afterward. Never print keys or store them in committed config. The runtime reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION` from Container Apps secrets backed by Key Vault when email code is enabled.

Verify native identity, configuration-set, SNS policy, IAM policy, and project group membership. IAM resources are dedicated and tagged, but are not members of the tag-based Resource Group's supported resource inventory. Record any account sandbox limit; do not claim unrestricted sending or submit a production-access request without an accurate approved submission. No test email is sent by this infrastructure step.

# Bounded SES sandbox test recipients

Use this operator bootstrap only for four explicitly approved, owner-controlled test mailboxes while SES remains sandboxed. It creates tagged email-address identities, each of which requests an AWS-managed verification message. It does not send application email, modify sender permissions, configure DNS, change SES production status, or enable the configuration set. The identities are deliberately managed by this bounded helper; do not duplicate them in CloudFormation or recreate them during rollback.

Copy [the empty configuration](test-recipients.example.json) to a private ignored file, fill the exact approved account, region, dedicated project tag, existing sending-disabled configuration set and four distinct normalized addresses. Keep both that input and the durable journal outside Git or explicitly ignored. The journal parent must already exist. PowerShell 7.2+, Git and an authenticated AWS CLI v2 are required. Do not put credentials in either file.

First inspect without requesting a verification message:

```powershell
./scripts/cloud/Initialize-SesTestRecipients.ps1 `
  -ConfigurationPath /private/test-recipients.json `
  -JournalPath /private/test-recipients.journal.jsonl
```

After the concrete four-address/message/cost scope is approved, repeat with `-Execute`. This switch performs the previously approved operator action; it is not authorization by itself. If production access is already granted, no identity creation is needed. Public application email must stay disabled throughout; the helper independently checks the exact tagged configuration set is still sending-disabled.

The helper checks all existing identities before any creation. Existing matching tagged email-address identities are read without re-requesting verification; unrelated identities fail closed. Every create has a flushed on-disk intent before the provider boundary. `AWS_MAX_ATTEMPTS=1` includes the initial request, so CLI automatic retries are disabled; prior process settings are restored afterward. Official regional HTTPS endpoints are explicit. An exclusive writer lock serializes competing helper processes against the same journal.

Any failed or uncertain create stops the run. Inspect using the same configuration and journal without `-Execute`. Even if the response was lost, an existing identity can be reconciled by reads. An unresolved intent, missing previously attempted identity, truncated journal or changed scope blocks further creation. Resume can create only addresses that have never had an intent, within the original four-address ceiling. Preserve the journal and original input: deleting, replacing or manually editing them defeats the operator ledger and is outside the supported workflow. Do not request another link, remove/recreate an identity, switch journals, or silently expand the list when a link expires or delivery is uncertain. An expired link requires a separately reviewed change to the request budget.

The owner must open each actual AWS verification link in their mailbox; no password or code belongs in source or chat. Repeat the read-only command to verify provider status afterward. Identity verification proves SES destination eligibility; it does not prove application mailbox verification, inbox delivery of later messages or completion of signing.

No fixed monthly service or paid validation product is added. Default verification-message pricing and wire size are not an application-controlled invoice guarantee; account for the four managed messages separately from simulator/application attempt budgets. Keep exact mailbox choices, costs, approval and outcome evidence private. Public launch and the restricted application pilot remain separate work.

Run the provider-free regressions with `./tests/scripts/Test-SesTestRecipients.ps1`. CI runs the same suite with a fake CLI and no AWS credentials or network calls.

Provider contracts: [CreateEmailIdentity](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateEmailIdentity.html), [GetEmailIdentity](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_GetEmailIdentity.html), and [AWS CLI retry limits](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-retries.html).

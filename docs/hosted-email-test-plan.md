# Hosted email feedback and bounded signing test plan

Prepared 2026-10-18. This is a preparation package, not authorization to deploy, subscribe, send or call providers. Public email remains disabled. No resource, setting, identity, credential or pricing plan was changed during preparation.

## Verified baseline

Read-only checks of the dedicated project confirm a verified SES domain, successful DKIM and custom MAIL FROM, an existing send-only identity restricted to the configured From address and configuration set, and an enabled SNS event destination. The configuration set has sending disabled; its topic has no subscription. The selected SES plan is Essentials. The web and dispatch processes have email disabled and lack the full SES runtime settings. Existing credential-secret metadata is enabled in the project vault, and the existing dispatch identity already has Secrets User access; no additional permission is proposed for the feedback phase. Secret values were not retrieved.

The application's feedback route authenticates signed SNS envelopes, exact topic, source and configuration set; it handles delivery evidence and permanent-bounce/complaint suppression. It can be enabled independently of sending. Its configuration also requires a valid From address, HTTPS base URL and SES configuration-set name; setting only the SNS flags is insufficient.

The current application has a global email switch and no private, budgeted recipient pilot. **Do not enable that global switch on the public app to run this plan.** SES sandbox restrictions are not an application access control: production approval can arrive during a test. Full browser testing must wait for an explicitly scoped pilot gate described below. Operator-seeded DOCX verification is not mailbox-delivery evidence.

## Needed test mailboxes

Ask the owner for four distinct, consenting, owner-controlled addresses or working aliases:

| Role | What the mailbox must receive |
| --- | --- |
| Sender | Verification link, completion packet, lookup and terminal notices |
| Signer 1 | First invitation, completion packet and a deliberate replacement invitation if exercised |
| Signer 2 | Invitation only after signer 1's checkpoint, plus completion packet |
| Completion-only recipient | Final packet and mailbox-bound retrieval; no signing authority |

The owner can control all four. A separate human per role is unnecessary. Do not request passwords or MFA codes. Use mailbox UI access or owner-opened links. Until SES production access is granted, every destination must be SES-verified individually or covered by an existing verified domain; app magic-link verification does not satisfy SES identity verification. Plus-addressing must really deliver, and its SES eligibility must be checked rather than assumed. Any SES address-verification message itself needs owner authorization and belongs in the run's send accounting. Prefer already verified mailboxes so the bounded application test needs no extra identity creation.

## Phase A: feedback configuration only

Requires owner approval of the exact private resource/configuration diff. No mail or timestamp calls in this phase.

1. Refresh only the dedicated project state and preserve unrelated values. Confirm the selected checked image, existing secrets/identities, SQL free-offer protection, retention, trust mounts, scale and email-disabled flags.
2. Apply the prepared narrow web environment patch: keep `Email__Enabled=false`; supply From, HTTPS base URL, SES region/configuration set, exact SNS topic, feedback enabled and subscription auto-confirmation. No AWS send credential is needed by the web feedback handler.
3. Validate the existing SES stack change set after approval. It must add only one HTTPS subscription to the existing feedback topic; reject identity, IAM, DNS, configuration-set sending, unrelated resource or replacement changes. The [CloudFormation template](../infra/aws/ses.cfn.yaml) defaults `EnableFeedbackSubscription` to false and `FeedbackEndpoint` to empty.
4. Subscribe the exact HTTPS `/webhooks/ses` endpoint. Keep signed envelopes (`RawMessageDelivery=false`). The prepared subscription allows five retries at 60-second intervals and throttles to one delivery per second. This bounds the pilot's failure traffic and allows an idle database to resume. It is not an unlimited feedback-retention guarantee or a production durability policy.
5. Verify confirmation from native subscription attributes and a Running/Ready revision plus custom health. Disable subscription auto-confirmation after successful confirmation. Keep ordinary sending and the configuration set disabled. An exhausted callback/confirmation retry fails the phase; do not proceed or silently drop feedback evidence.

The private package contains the exact eight environment settings, existing scope/identity references, preserved before-state and rollback values. No compiled template or real endpoint belongs in Git. A source merge does not create this subscription.

## Phase B: feedback simulator, at most ten recipient attempts

Requires separate explicit authorization for the finite sending window. Keep public application email disabled.

Use only the existing scoped send-only identity and existing configuration set. Temporarily enable that set for the approved window; use tiny synthetic messages, no attachments or human recipients. Cover success, permanent bounce, complaint and one transient-bounce case where supported. Use fresh simulator labels to avoid preexisting suppression. Reserve every attempted provider submission, including definite failures/retries/unknown acknowledgements; do not refund or blindly repeat it.

Verify actual authenticated callbacks, causal provider receipts and exact labelled-recipient suppression. Confirm permanent bounce and complaint block subsequent application dispatch before another provider call; transient bounce must not create permanent suppression. Do not confuse SES acceptance with inbox delivery or claim an outbox row was updated when a direct simulator probe created no matching row. Correlate real outbox records only if prepared through supported application work. Keep raw receipts, tokens and callback bodies private. Restore configuration-set sending disabled at the end or first failure.

No real mailbox address is required for this phase. Simulator messages are billable and can be sent while SES remains sandboxed.

## Phase C: private full signing pilot, at most twenty recipient attempts

This phase is planned but **not activatable with current source**. Before owner approval of deployment, implement and validate the QUILS-116 disabled-by-default pilot capability with these requirements:

- Public sender and lookup intake remain unavailable. Only an explicit operator-started run can request the initial verification and access its enrolled test envelopes; no anonymous test backdoor, bypass token in URLs or global sending enablement.
- Exact owner-approved recipient allowlist, at most three explicitly enrolled synthetic envelopes, immutable run identity and UTC expiry, and a durable cross-process provider-call budget. Enforce scope in admission and immediately before every transport call. Unknown/old queued work and non-allowlisted addresses cannot obtain credentials or submit. Narrow the existing SES identity's recipient permissions as defense in depth only under separate reviewed approval.
- Reserve twenty real-mail attempts and four live TSA attempts before their requests, including retries, errors and uncertain acknowledgements; preserve counters across restarts and never refund them. Unknown submissions require receipt recovery, not blind retry. A copied stale configuration, midnight rollover, another replica or a late worker must not reopen the budget.
- Bound each outgoing message's complete encoded size to 1 MiB and the combined thirty-message test allowance to 30 MiB. Use a small synthetic PDF and no DOCX conversion, new Office intake, reminders, contact correction or AI in this baseline pilot. Those features have their own later validation.
- Original web, dispatch and recovery processes must use compatible checked code/schema/key ring. Scope any credential references to the existing vault/identity and verify existing access before proposing new grants. Pilot expiry/rollback closes future submissions and prevents repeated wakeups of obsolete pilot work; it must not reactivate earlier unrelated queued email.

After these source gates pass local captured-mail, budget/concurrency/recovery and real browser checks, prepare a fresh exact private deployment diff and owner approval. Then execute within one 60-minute active test window:

| Scenario | Required evidence |
| --- | --- |
| Normal completion | Actual sender verification mailbox link; PDF upload/confirmation; two signers and manual fields; reviewed Send and private sender confirmation |
| Sequential signing | Signer 2 has no invitation/authority before signer 1 publishes; each signer reviews the correct current PDF, consents, adopts, applies fields and explicitly finishes |
| Final publication | Exact accepted bytes/checkpoints, immutable final versions/deadline, platform seal and timestamp, appended and standalone certificates |
| Delivery and retrieval | Sender, both signers and completion-only recipient get the correct attachments/private link; original sender/recipient lookup returns only their retained packet; unauthorized reads fail |
| Replacement and terminal paths | One deliberate unused-link resend if within budget; separate void and decline fixtures; old links/duplicate Finish/Send cannot create extra work or authority |
| Failure and cutoff | Source/session/revision mismatch, suppressed recipient and exhausted budget fail closed; exact counters/outbox receipts survive worker restart; existing retention deadline is unchanged |

One completed envelope plus one void and one decline envelope is the maximum initial set. Twenty is an attempt ceiling, not a promise to send all twenty. Completion seals two PDF outputs; four TSA attempts include any failed/uncertain calls and contingency. Stop at the first unaccounted receipt, missing feedback, budget inconsistency or unexpected recipient. The accelerated local one-hour purge and separate hosted immutable-expiry probes remain valid evidence; do not require another seven-day wait or label them a full hosted purge.

## Costs and approval boundary

Verified Essentials pricing is USD 0.00016 per recipient, with no fixed monthly Essentials fee. The following conservative arithmetic assumes no free credits and uses current regional price-list rates, not an invoice prediction:

| Bounded item | Calculation | USD |
| --- | --- | ---: |
| SES recipient attempts | 30 × 0.00016 | 0.004800000 |
| Conservative outgoing data | 30 × 1,048,576 bytes ÷ 1,000,000,000 × 0.12 | 0.0037748736 |
| SNS HTTP chunk attempts | 12,000 × 0.0000006 | 0.007200000 |
| SNS request units | 2,000 × 0.0000005 | 0.001000000 |
| AWS message/request subtotal (excluding transfer and tax) | Sum of the above | **0.0167748736** |
| FreeTSA | At most four approved calls; no subscription/request fee | **0** |
| New fixed monthly services | No new compute service, plan, IP, add-on, queue or paid support | **0** |

The outgoing-data illustration uses a decimal GB divisor rather than assuming binary GiB billing, and includes the full encoded message bound. The SNS bounds conservatively include all configured event types, signed bodies up to the existing 512-KiB handler bound, 64-KiB billing chunks and the finite retry policy. A new address-verification message or a larger message is not silently added to this package. No paid plan upgrade, dedicated IP, validation add-on, Mail Manager, SMS or live converter request is included.

SNS data transfer, Azure compute, requests, storage, Key Vault, logging, egress, tax and account-wide credits are metered. An exact all-in invoice cannot honestly be quoted before execution. At current regional active rates, the existing web's two-replica maximum for one hour, sixty worst-timeout dispatch executions and two executions of each storage-only recovery job illustrate **USD 0.24525 of compute before free grants**. That is an allocation illustration, not a guaranteed total or an instruction to run sixty jobs. SQL paid overflow stays disabled.

Propose a separate **USD 1 incremental operator allowance**, with no new fixed monthly fee, for the bounded approved experiment; the listed AWS message/request arithmetic above is below two cents and excludes SNS transfer and tax. Validate current account plan, image/configuration, logging cap and revised source limits immediately before approval. Azure budget alerts are not a hard billing cap; the operator stops admission/calls at the approved counts/window and reports observed usage and any cost uncertainty. Do not describe USD 1 as an exact promised invoice. If the owner requires a guaranteed exact total, keep the hosted experiment disabled and use local captured mail.

## Rollback and completion

Disable configuration-set sending first on failure, disable the pilot/dispatch sending path, and verify all new provider submissions have stopped. Preserve protected budgets and uncertain receipts. Restore only the reviewed runtime values, leaving unrelated disclosure/retention/analytics/identity/scale/secrets intact. Remove the newly created subscription only if that rollback was approved; never delete the topic, sender identity, suppression evidence or final protected documents. Preserve the original before-state and inspect drift before restoring it. Do not broaden IAM recipient permissions during rollback without the approved original-policy restoration scope.

Preparation is complete when templates/docs/private patch and deterministic costs are validated, secret-scanned, reviewed through a small PR and merged. Feedback and full-flow execution remain separate approval gates. Publish results only after real mailbox, callback, worker, attachment and final-storage evidence passes; public launch is a later decision.

## Sources

- [SES pricing](https://aws.amazon.com/ses/pricing/) and regional public price-list metadata, checked 2026-10-18.
- [SNS pricing](https://aws.amazon.com/sns/pricing/) and [HTTP delivery policies](https://docs.aws.amazon.com/sns/latest/dg/sns-message-delivery-retries.html).
- [SES sandbox restrictions](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html) and [mailbox simulator](https://docs.aws.amazon.com/ses/latest/dg/send-an-email-from-console.html).
- [Azure Container Apps billing](https://learn.microsoft.com/en-us/azure/container-apps/billing) and [Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices), regional rates checked 2026-10-18.
- [FreeTSA](https://www.freetsa.org/index_en.php).

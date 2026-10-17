# Hosted demo rollout

This is an operator review and validation plan. It does not authorize resource changes or establish that the hosted signing flow is ready. Keep identifiers, domains, addresses, secrets, certificate material and deployment evidence in ignored configuration.

## Observed deployment and remaining gates

Read-only checks on 2026-10-17 found an earlier application image on the web app and both existing jobs. Email remained disabled. The web/dispatch environment did not include the new demo-retention, synthetic-disclosure or timestamp settings. Storage versioning, seven-day blob/container soft deletion and a seven-day document lifecycle rule were enabled. The final container reported no immutability policy or legal hold; version-level support was not demonstrated. A data-plane inventory could not be verified with the operator's current permissions. Do not assume the container is empty or grant access implicitly.

These observations are a dated snapshot, not a continuous health check. Re-check the scoped resources before an approved rollout. Source/CI tests and local synthetic browser flows do not replace hosted provider, identity and storage validation.

| Gate | Required evidence before general demo sending |
| --- | --- |
| Release and schema | Main has passed its checks; migrations and web/dispatch/recovery images match the intended commit |
| Demo policy | New uploads capture the configured interval; review, consent and access use the original fixed deadline |
| Purge | Worker can execute the guarded SQL operation and delete only eligible owned objects; storage-only recovery is scheduled |
| Final storage | Actual version policy is locked until the exact saved upload deadline; bytes, version, ETag and expiry read back correctly |
| Sealing | Persistent demo identity, explicit TSA trust files and shared request coordination work through retries |
| Email | Separate SES production/feedback, suppression and approved recipient/pilot checks pass |
| Office conversion | Supported converter isolation is demonstrated before enabling DOCX; PDF/image validation is separate |

AI field suggestions remain deferred.

## Resource and permission approval package

Review the actual scopes and deployment diff privately with the owner. Existing hosting approval does not automatically approve these additions or broaden the hint-recovery identity.

| Proposed change | Scope and reason |
| --- | --- |
| Temporary inventory access | If required, approve temporary Storage Blob Data Reader access on the final container for the operator, including removal after the scoped audit; do not use account keys |
| Worker SQL execution grant | After migration, the explicit `database grant-demo-purge` command grants only the guarded procedure to `app_worker`; direct evidence-table denials remain |
| Dispatch document access | Container-scoped access needed for checkpoint/seal reads and bounded purge; verify existing grants before adding any |
| Final-version policy permission | Limit the additional immutability-management permission to the final container and sealing identity |
| Version-level final protection | Review migration, its initial policy and exact version expiry. Proceed only after an approved inventory confirms an empty, lease-free container; stop for separate review if existing data is found |
| Lifecycle alignment | Review the existing broad seven-day base/version/snapshot deletion rules against the configured interval and enrolled-policy ownership |
| Storage-only maintenance | Separate scheduled job/identity running `dotnet QuillSign.dll work purge-recover 32`, proposed hourly, one replica, 0.25 CPU/0.5 GiB, 90-second execution timeout and no platform retry; the command itself has a 50-second budget |
| Maintenance permissions | Only required document, marker/hint, persistent key-ring and protection-key access; no SQL connection, email or TSA configuration |
| Runtime configuration/trust files | Approved private settings and read-only trust-file delivery for web and dispatch; retain historical TSA roots |

The maintenance job must use the shared persistent Data Protection application/key ring. Its deployment/image update path must include the new job, so it does not silently retain an older image. Keep the existing hourly `work recover` job SQL/key-ring-free. Review actual role scopes rather than assuming a generic contributor role includes policy management.

Microsoft lists the immutability-management action and **Storage Blob Data Owner** as the least privileged built-in role for `Set Blob Immutability Policy`. The proposed built-in assignment is container-scoped and needs explicit approval. This is not a reason to grant account-wide ownership. [Azure REST permissions](https://learn.microsoft.com/en-us/rest/api/storageservices/set-blob-immutability-policy).

Enabling version-level support on an existing container requires migration and cannot be reversed. Migration requires versioning and an existing retention policy; active leases block it. Review unlocked default-policy handling before migration. Do not lock a seven-day default measured from final-file creation: it can outlast the document's seven-day-from-upload deadline. [Azure migration guidance](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-policy-configure-version-scope).

An unlocked default can be overridden by a version policy; an already locked version cannot have its expiry shortened. The application must confirm the exact deadline on the actual stored version, rather than relying on inheritance or a portal flag. Validate protection with real provider behavior before use. [Version-level policy behavior](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-version-level-worm-policies).

## Private settings

Use environment variables, approved secret references and read-only file mounts. This table describes desired settings; it does not apply them.

| Setting | Rollout choice |
| --- | --- |
| `Demo__PurgeAfterDays` | Owner-selected interval; seven days for the general demo. Set consistently where retention configuration is consumed |
| `ElectronicRecords__Profile` | `synthetic-demo-v1` for synthetic enrolled demo documents only |
| `Seal__TsaUrl` | Selected FreeTSA RFC 3161 endpoint, configured privately |
| `Seal__TsaTrustedRootPaths__0` | Absolute path to an independently verified, read-only TSA root file; retain additional historical roots when rotating |
| `Seal__TimestampCoordination__Enabled` | `true` for participating sealing processes, with the shared keys container |
| `Seal__TimestampCoordination__MinimumIntervalMilliseconds` | At least `1000` |
| `Seal__Provider` | Existing persistent demo fallback unless another certificate provider is approved; never replace missing/corrupt saved identity automatically |
| `Completion__AllowDevelopmentWriteOnce` | Keep disabled in Production; it cannot substitute for real immutable version protection |
| `Email__Enabled` | Keep `false` until separate email/pilot approval and validation |
| `Gotenberg__Enabled` | Keep disabled until hosted conversion and outbound isolation are supported and approved |

Web and dispatch must share compatible TSA trust and persistent protection configuration. The new storage-only job uses the same private storage/key-ring settings but never needs the database, email credentials or signing provider. Do not publish real URIs, file contents, fingerprints or secret values in this document.

FreeTSA's public service permits one request per second per source IP and offers best-effort availability without an SLA. The app's shared coordinator covers participating QuillSign callers, including both completion seals. Keep bounded timeout/failure behavior; do not silently skip a timestamp when the provider is unavailable. No paid dedicated TSA instance is proposed. [FreeTSA usage policy](https://www.freetsa.org/freetsa.html), [platform seal configuration](platform-pdf-seals.md).

The persisted self-signed demo seal does not establish public certificate trust in PDF viewers. Preserve that distinction when reviewing downloaded files. A timestamp is not permission to describe this demo as suitable for real contracts.

## Retention and existing data

The [first-upload snapshot](document-retention.md) fixes access expiry and enrolled purge ownership. Replacements and later setting changes cannot reset it. Changing an environment variable affects new enrollments, not saved policy or disclosure snapshots. Existing unenrolled records require a separate reviewed disposition; do not backfill a convenient new deadline.

The current lifecycle rule is independent of enrollment and uses blob age rather than the saved policy. Do not treat it as the coordinator or leave it inconsistent with a longer configured interval. Review its disablement/replacement for owned document prefixes before enabling adjustable retention; never extend it to keys, markers or unrelated data implicitly.

The observed seven-day storage soft-delete window can preserve recoverable copies after active deletion. SQL backups, logs and party-held copies have separate lifetimes. Record actual operational windows in private configuration and check the accuracy of user-facing disclosures; seven-day access expiry is not a promise that every physical copy disappears at that instant. Changing recovery settings needs a separate explicit decision.

The [coordinator](demo-purge-coordinator.md) removes eligible private SQL state and performs bounded owned-object cleanup. Minimal detached work bindings and authenticated recovery markers remain. Markers persist after clean passes so later writes can be found; scheduled scans are bounded and do not promise immediate or permanent erasure. Preserve the key ring and protection-key versions needed to authenticate them.

## Ordered validation and stop conditions

1. Record the intended main commit, passed checks, scoped inventory and private deployment/configuration diff. Obtain approval for the listed resource/permission/configuration changes before applying them. Preserve existing data and unrelated resources.
2. Apply the approved schema/provisioning changes with the deployment/administrator identities. Grant only the explicit purge procedure execution permission. Do not remove table denials or grant the web runtime general evidence deletion.
3. Apply the approved final-storage configuration and permissions. With clearly synthetic objects, verify exact policy readback, mutation/deletion rejection before expiry and permitted cleanup afterward. A primitive storage probe alone does not prove the complete application purge flow.
4. Deploy the checked image to web and every supported job, configure the approved trust/policy settings and verify revision readiness plus the distinctive `/health` JSON. Health/startup checks must not open SQL; preserve free-offer overflow protection and idle auto-pause.
5. After separate email readiness approval, exercise a synthetic sender/signing flow with an approved reachable test recipient. Check exact upload/preview confirmation, frozen disclosure, deliberate field application, immutable review/Finish, sequential current-copy progression, both final seals, downloads and attachments. Use no real agreement or personal sample document.
6. Verify controlled provider/storage failure and supported recovery without resending ambiguous email or resealing a committed output. Ordinary finite-attempt terminal jobs require explicit operator review; a hint-resume command is not a general dead-letter reset. Inspect supported state before retrying.
7. Let a genuinely enrolled synthetic record reach its saved deadline, then verify denied access, guarded SQL removal, version/protection handling, bounded continuation and late-write storage recovery. If a shorter pilot interval is approved, set it before that pilot's first upload. Never rewrite the policy/audit or backdate a hosted record to manufacture proof.
8. Record the observed limits and obtain approval for general demo sending only after the relevant gates pass. The separate infrastructure/email work retains its SNS feedback and bounded delivery-test approval; this document does not send messages or claim that approval is complete.

Stop enabling new enrollments/sending if protection expiry, trust, permissions, marker recovery or worker lease behavior differs from the verified contract. Keep existing enrolled purge/recovery operational through service failures. Disabling a feature flag, changing the interval or rolling back an image does not undo existing policies, locked versions, sent mail, completed signatures or schema migrations. Review rollback compatibility before switching any component to an older image; never delete keys or shorten protection to make a test pass.

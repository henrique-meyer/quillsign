# Eligible production deletion and recovery

Production deletion is a separate default-disabled source capability. It does
not activate a hosted deployment, choose a legal policy or authorize real data
destruction. Use the existing installation identity, witness namespace and
original frozen production policies. Missing or inconsistent evidence fails
closed. Keep actual configuration, SIDs, endpoints and operator identities
outside tracked files.

## Eligibility and entrypoints

An abandoned draft uses its exact original creation plus its frozen interval.
Expired, declined and voided records use their authenticated terminal anchor and
original frozen interval. Signing/completing records have no automatic cleanup
authority. A completed finite record additionally needs a per-record retained-copy
and archive disposition attestation through the private operator UI. An explicit
indefinite completed policy has no deletion deadline. Neither elapsed access nor
successful email submission supplies disposition authority.

Set `ProductionDeletion__Enabled` explicitly, with the complete enabled
production hold/worker composition and a bounded nonempty
`ProductionDeletion__CompletedCommitmentStatement`. See
[private operator controls](private-operator.md) for the separate
`AuthorizeDeletion` permission and exact review/confirmation. The statement is
operator configuration, not a default policy supplied by the application.

Invoke bounded maintenance through the application CLI:

```text
work prepare-production-deletion <32-character-record-id>
work recover-production-deletion <32-character-record-id>
work recover-production-deletions [opaque-continuation]
```

Preparation runs only after the original eligibility deadline. It saves one
exact deterministic queued cleanup job under an externally acknowledged
operation, then publishes its wakeup. An acknowledged job may be re-hinted after
a lost wakeup acknowledgement without creating another job or resetting attempts.
An unresolved prepare outcome is reconciled from the original exact receipt or
remains pending. The browser can attest a completed prepared job and wake it;
it cannot invent a new job. The ordinary registered worker processes the typed
job. Batch recovery selects at most eight opaque encrypted index hints and
independently authenticates every record's original journal; the index is not
authority. These explicit bounded commands do not install recurring idle SQL
polling. An installation must invoke them through its reviewed maintenance
operation when records become eligible.

## Permanent fence and exact storage effects

Reservation appends an encrypted immutable external deletion fact before the
first work claim mutation or destructive effect. Pending/active holds, unresolved
operations, inconsistent request/control heads and restored SQL block it.
Authenticated R0 and exactly released independent holds are supported. Once
reserved, the barrier permanently blocks new participant/business operations
and hold placement across lease expiry, restart, operator disablement and whole
database restore. It is not cleared by cancellation or missing SQL.

The plan inventories all current versions, historical versions, snapshots and
inactive/deleted observations under the exact record prefixes in `originals`,
`normalized`, `preview` and `final`, plus every authenticated archive placement
prefix. It retains separate factual inactive observations rather than inventing
byte hashes for unreadable deleted entries. New or changed unknown selectors
quarantine cleanup. Current-root demotion and each exact historical/snapshot
delete are separate conditional effects. Before and after provider awaits, the
original live maintenance epoch and external head are checked. Exact bytes,
length, ETag, version and actual current protection are rechecked before delete.
Active legal hold, unexpired protection or unknown protection refuses; cleanup
never clears a hold or shortens retention.

Each effect has an immutable intent before the request and exact outcome after.
The exact create-only recovery hint must be acknowledged before each destructive
continuation, using the immutable first-plan digest even when later plans extend.
A lost acknowledgement permits only read-only exact outcome reconciliation;
it does not replay DELETE or assume absence means success. Storage requests have
no automatic retry, redirect, secondary-host or authentication-challenge replay.
The original witness event/payload budgets stay unchanged; insufficient headroom
refuses before a new destructive phase. Plans are bounded to 4096 objects,
256 MiB aggregate inspected bytes and 8 MiB canonical plan data.

## SQL removal and bounded recovery

After verified active-storage cleanup, the worker records SQL intent, executes
one static ownership-chained procedure in the same caller transaction, records
the exact expected post-state before commit, then acknowledges its exact fresh
readback. It removes the closed owned dependency set in FK order and detaches
only the same technical Work row, preserving its payload/lease. The worker
finishes that exact row through its own expected/acknowledged protocol. Protected
global contact/lookup/pilot state and operator access observations are not
silently swept into a record deletion. A known global direct association that
cannot be proven owned causes refusal, including a future closeout subject row.

An already-live or receipt-only reconciled claim never grants another execution
lease. Recovery of an existing live storage-only epoch remains read-only/pending;
only the invocation that records a fresh epoch may begin its destructive work.
Expired cleanup leases are never extended or reused. After all previous unknown
provider/SQL/claim outcomes reconcile, a new externally recorded owner and
incremented attempt precede any new work mutation. Exact known SQL rollback can
be recorded and retried in a new bounded technical round; an unknown commit
remains closed. These epochs do not change retention, signing, token, session or
provider protection clocks or refund counters.

After an authenticated SQL-commit receipt, a new explicitly recorded StorageOnly
epoch can reconcile planned active storage while SQL is unavailable. It cannot
claim that SQL Work was updated. When SQL returns, the same live epoch separately
claims and acknowledges the exact retained Work before Finish. Missing parent,
missing Work or a storage index hint alone is never proof of commit. Restored
old SQL remains quarantined by the external reservation, even after all original
cleanup leases expire.

## Explicit database permissions

Apply the source migration through the installation's reviewed migration
identity. Provision the documented runtime and worker identities separately.
The following administrator operations are opt-in and never run at startup:

```text
database grant-production-holds
database grant-production-purge
```

The hold command requires exact private expected `Database__RuntimePrincipalSid`
and `Database__WorkerPrincipalSid` selectors in `0x` hexadecimal format.
`Database__ProductionHoldPrincipalMode` defaults to `External` (SQL type E);
`Sql` (type S) must be selected explicitly for a supported SQL Server deployment.
No engine/name-based downgrade is performed. The closed dbo-owned
`app_production_hold_role` accepts only the two fixed identities with matching
SIDs/types and grants SELECT/INSERT for ProductionHoldRequests/Controls while
denying UPDATE/DELETE. The separate `app_production_purge_role` grants only the
worker EXECUTE on the static deletion procedure. Existing runtime grants are
unchanged. No hosted grant, identity provisioning or migration apply occurs
merely by deploying this source.

Native tests use actual effective S database contexts under that exact API;
they are not proof of real SQL-login or Entra authentication. Actual configured
External identity, managed-identity storage, key rotation, backup operations and
hosted installation verification remain QUILS-150 acceptance.

## What cleanup does and does not report

Recorded SQL removal and verified active-data cleanup are distinct from pending
work, restored-SQL quarantine and blocked protection. An old receipt is a
historical statement; offline recorded status does not claim a current provider
inspection or fresh SQL absence. Private status saves an observability receipt
and rechecks the external head before responding.

API deletion can leave soft-deleted versions, provider tombstones, backups,
replicas, diagnostic logs and participant-held copies. Inactive observations and
known provider deletion results remain in the immutable journal. Cleanup does
not erase or shorten the separate witness journal or encrypted opaque recovery
index. Those retained encrypted control facts prevent restore/replay and permit
bounded recovery; their own backup/key/archive responsibility requires explicit
installation policy. This is verified active-namespace cleanup, not universal
physical erasure, legal adequacy or a promise that independent copies vanished.

# Production retention foundation

QUILS-146 defines the policy contract for ordinary, non-demo records. QUILS-151 adds an internal persistence backend and schema; it is not registered with the running application. These foundations do not enable production enrollment, change existing retention, grant deletion authority or implement legal holds. QUILS-152 must integrate admission, disclosure, publication and access. The remaining production lifecycle stories in [the plan](plan.md#production-self-hosting-release-gate) remain required.

The operator explicitly supplies a version, archive responsibility and every interval. Completed records may have deliberately selected indefinite retention (`CompletedDays = 0`). Abandoned drafts and expired, declined and voided requests require finite positive intervals. There is no universal duration or demo default. These options are not yet bound to runtime configuration.

| Record state | Clock | Result |
| --- | --- | --- |
| Unsent abandoned draft | Original record creation | Finite draft interval |
| Still signing | No terminal clock yet | Await terminal state; no deletion deadline |
| Incomplete completion | Requires authoritative disposition/recovery | No automatic deletion deadline |
| Completed | Actual completion | Finite completed interval or explicit indefinite retention |
| Expired | Authoritative effective expiry | Finite expired interval |
| Declined | Actual decline | Finite declined interval |
| Voided | Actual void | Finite voided interval |

The persistence backend verifies the exact record, original creation and terminal event/time under the existing envelope transaction and audit chain. In particular, a late expiry worker does not restart retention from its processing time. Incomplete completion requires recovery or an explicit reviewed disposition; worker failure alone must never make accepted signing evidence deletable. Operator visibility and disposition remain dependent work.

The draft rule is a creation-based maximum lifetime, not a sliding inactivity timer. Saves, replacement uploads and later settings changes cannot restart it. The integration must disclose and enforce that saved deadline before this rule is enabled.

Snapshot values are immutable and independent of later configuration. Stored snapshots use a bounded exact canonical representation and a SHA-256 digest for correlation with trusted provenance. A digest alone does not authenticate the record or authorize access, hold release or deletion. Missing/duplicate/unknown properties, unsupported versions, inconsistent times and unrepresentable deadlines fail closed. Capture UTC whole-second timestamps once at the trusted persistence boundary.

Enrollment occurs only while creating a new production record, in the same transaction as its insert and append-only enrollment evidence. Reads distinguish missing records, demo records and unenrolled historical records; they never silently enroll or migrate a historical document. A retry after an uncertain commit reads and verifies the original saved policy, rather than replacing it with current settings. The backend captures one immutable terminal anchor only through an explicit internal operation and verifies its authoritative transition again on reads and retries. A completed status alone is insufficient: recorded publication evidence must verify.

Exact original timestamps are retained alongside the second-normalized policy clock. Finite terminal durations use the exact original timestamp, so normalization cannot shorten the interval. Storage integration must round a protection deadline up if the provider cannot represent that precision. The backend grants no destructive capability, and normal startup does not call it. Installing the schema alone does not make an instance ready for real contracts.

An eligibility date is not a statement that data has been deleted or may safely be deleted. Future maintenance must also verify active holds, current owned versions, immutable storage protection and destructive authority, and recover partial/uncertain outcomes. Indefinite retention is a policy choice, distinct from case-specific legal holds. No physical-erasure, backup, regulatory-compliance or real-use readiness claim is made by this contract.

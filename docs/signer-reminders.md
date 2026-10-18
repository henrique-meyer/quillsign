# Sequential signer reminders

Optional automatic reminders use the durable work queue and shared invitation
successor delivery. They remain off by default. The public synthetic demo always
freezes an empty reminder policy; no hosted email or cloud schedule is enabled.

## Authority and schedule

Reminders are system actions authorized by the sender's reviewed Send, not a
replayed sender session or an automatic call to the manual resend endpoint.
Freeze a canonical, versioned reminder policy in the Send audit transaction.
QUILS-121 binds the server-derived review to the exact policy hash, writes
the canonical policy/hash in the immutable `sent` audit and verifies it during
saved Send reads. Changed configuration requires a fresh review. Historical
Send records without either new field have an explicitly empty schedule; an
old mutable `ReminderDaysJson` array cannot authorize reminders. A partial,
noncanonical or mismatched new evidence pair fails closed. No scheduled work
is created by that policy slice.
The generic application's existing day offsets are 3 and 7; an empty schedule
disables reminders. A demo envelope always freezes an empty schedule. An
operator must explicitly enable reminders and configure bounded daily global,
sender and recipient limits before the producer can admit any mail. No
invented IP identity or sender-ticket lifetime belongs in system admission.

Offsets are positive whole elapsed UTC days from the current signer's original
invitation admission. This means a later sequential signer gets the same
opportunity to sign as the first; a manual resend does not reset their clock.
The frozen schedule contains at most two strictly increasing offsets, each at
most 30 days. Reject malformed configuration rather than sorting, coercing or
silently omitting it. Do not change existing frozen schedules after a deployment.

Each invitation epoch binds the envelope, signer, original invitation ID and
admission time, normalized recipient, current PDF object/hash, disclosure hash,
frozen policy hash and signing/retention deadlines. One deterministic work ID
per epoch and day offset supplies idempotence. Only create an epoch for the
current unfinished signer. Send creates the first epoch; successful checkpoint
publication creates the next one in the same SQL transaction as its invitation.
Contact correction retires the old epoch, even when an address changes away and
back. The current correction workflow has no reviewed reminder restart policy:
no reminder epoch is created automatically for the corrected address. This does
not prevent its deliberate correction invitation or manual resend.

Do not schedule a due time at or beyond either the signing deadline or the
immutable retention cutoff. Dispatch may occur late after service interruption,
but never after those cutoffs. Distinguish a scheduled due time from actual
provider submission in evidence. An empty or wholly out-of-window schedule
creates no reminder work and no storage hints.

## Durable preparation and dispatch

Use the existing SQL outbox/work and storage-only future hints. Hints contain
only opaque work IDs and UTC due times. Publish only after SQL commit; a hint
created before an uncertain commit is harmless because a worker reads the
authoritative row. Storage recovery must not enumerate SQL while idle, and a
queue's seven-day delay limit must not change the intended SQL due time.
Early or duplicate deliveries use existing work deferral and leasing.

Dispatch takes the envelope and shared admission lock before work/outbox/token locks. Verify the
frozen policy and exact epoch against canonical audit evidence, immutable sent
evidence and the verified current-copy chain. Recheck current signer and email,
absence of accepted Finish, envelope state, current time, suppression, explicit
limits, retention and the owned lease immediately before committing intent.
Reserve counters on the actual UTC submission day; a late queue delivery must
not spend a reservation from the original due day. Do not refund a consumed
reservation because submission or receipt recording is uncertain.

The canonical latest-invitation chain must include original, manual resend,
reminder and contact-correction invitations. Each replacement binds its verified
predecessor. A pending or ambiguous predecessor blocks another submission;
definitely rejected, settled predecessors follow supported bounded retry rules.
Neither original nor manual-resend dispatch may become current again after a
reminder. Implement this shared contract before enabling reminder dispatch.
Do not weaken current resend evidence/index verification to add a template.

At dispatch, mint a fresh document/disclosure-bound single-use link. Atomically
expire older unused invitation links and persist protected token/submission
intent. Preserve used tokens, already redeemed sessions, consent, adopted marks
and field entries. The reminder explains that the new link replaces unused
earlier links. Manual resend retains its own deliberate affirmation and limits.
A corrected recipient requires the correction slice's explicit session/consent
revocation; a reminder cannot perform or reverse a contact correction.

No external mail call occurs inside the SQL transaction. A known pre-submission
rejection clears only its verified intent and expires that unused token. An
unknown provider outcome retains intent and never triggers a blind second
send. Record the shared `invitation_successor_submitted` receipt, bound to the
protected `Reminder` scope, only after a supported provider receipt;
provider acceptance is not proof of inbox delivery. SNS feedback attaches to
the exact outbox row and existing suppression rules. Do not report a scheduled,
queued or ambiguously submitted reminder as delivered.

Finish acceptance, checkpoint progression, correction, void, decline, expiry
and purge make obsolete epochs ineligible. Dispatch must revalidate even if
best-effort cancellation has removed hints. Purge must remove private schedule
payloads through its existing guarded cleanup, and must not erase a same-day
cap reservation while it can still be spent. Re-enabling a feature must not
revive abandoned or ambiguous work automatically.

## Implementation slices and validation

1. Strict versioned policy, canonical hash, bounded UTC schedule and immutable
   epoch identity, with configuration/boundary tests. No mail producer or UI.
2. Canonical invitation successor contract shared with correction and manual
   resend; evidence/index, pending/ambiguous and stale-delivery regressions.
3. Atomic Send/checkpoint policy and epoch preparation, durable hint recovery,
   system cap admission, protected reminder outbox and supported dispatch.
4. Sender review/status presentation with accurate schedule/delivery meanings;
   private metadata and complete local desktop/mobile/keyboard flows.

Each implementation slice gets its own matching Jira story and plan entry
before code. This design does not make any of those slices complete.

Use genuine SQL/Azurite and loopback captured mail, never live email or live
timestamp calls. Cover demo/disabled behavior, invalid JSON and duplicate or
unordered offsets, UTC/offset/midnight and exact-cutoff boundaries, second-signer
timing, deterministic duplicate identity, stale or tampered source/policy/epoch,
suppression and caps, explicit manual replacement, accepted Finish, correction,
terminal states, unknown commits, lease loss, provider ambiguity, retention
cleanup, and storage-hint recovery. A captured fresh link must redeem through
the normal consent/PDF flow while old unused links fail and redeemed sessions
remain usable. Hosted enablement and operator caps require separate approval.

## Supported runtime protocol

QUILS-123 adds a separate `signer-reminder-runtime-v1` approval to the private
Send review. A nonempty policy needs both its exact policy hash and that runtime
version. Old QUILS-121 policy-only reviews must be refreshed; historical sent
records without the runtime version create no work even if they contain a
nonempty policy. The mutable envelope day array remains irrelevant.

The Send transaction and each successful current-copy checkpoint create at most
two `Reminder` work rows plus canonical system schedule evidence. A verified
legacy contact is represented by its original empty-ID/zero-number epoch from
the full contact-history verifier, never an invented baseline revision. Storage
hints contain only the deterministic work ID and due time. The required schema
change only extends the existing work-kind constraint; a checked application
release still needs a separately approved hosted migration and configuration.

At due time, only the latest overdue offset may admit mail, preventing a burst
after downtime. A disabled due job is abandoned rather than revived later.
Pending or ambiguous prior invitations block admission under the existing retry
bound. Actual-day global, sender and address reservations include queued, failed
and uncertain requests. Reservations cannot outlive their retained evidence:
admission is refused when retention ends before that UTC day ends. A schedule
row and its mail row have distinct deterministic IDs. A lost commit response
recovers that same admission and never allocates another reminder for the offset.

Reminder admission has no sender session, IP address or reused sender proof.
The exact current policy, contact, PDF, disclosure and schedule are checked again
before submission. Fresh links expire prior unused links; opened sessions and
signing evidence are preserved. Provider acceptance is displayed separately from
inbox delivery using the existing feedback/status path. Optional operational
limits can prevent a reviewed reminder, so the sender review makes no delivery
promise. There is no background SQL polling while idle.

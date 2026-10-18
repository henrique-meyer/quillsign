# Sequential signer reminders

This is the design for optional automatic reminders. Reminders are not yet
dispatched by the application. The public synthetic demo keeps reminders off,
and this work does not enable hosted email or add a cloud schedule.

## Authority and schedule

Reminders are system actions authorized by the sender's reviewed Send, not a
replayed sender session or an automatic call to the manual resend endpoint.
Freeze a canonical, versioned reminder policy in the Send audit transaction.
The generic application's existing day offsets are 3 and 7; an empty schedule
disables reminders. A demo envelope always freezes an empty schedule. An
operator must explicitly enable reminders and configure bounded daily global,
sender and recipient limits before a future producer can admit any mail. No
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
An explicitly confirmed contact correction creates a new epoch bound to its immutable contact revision, even when an address changes away and back; its earlier
epoch remains evidence and cannot authorize another message to the old address.
The correction's own reviewed policy determines whether it restarts the clock;
do not infer that policy from a mutable signer email.

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

Dispatch takes the envelope lock before work/outbox/token locks. Verify the
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
send. Record `reminder_submitted` only after a supported provider receipt;
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

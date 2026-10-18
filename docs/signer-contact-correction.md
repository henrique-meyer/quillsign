# Unsigned signer contact correction

QUILS-96 records the reusable application's design. This document does not
enable correction, change demo disclosures or authorize a deployment. The
synthetic public demo continues to offer no post-send contact correction.

## Scope and meaning

A verified sender may deliberately correct the email address of the current,
unfinished sequential signing slot. This is a delivery/contact correction for
the same named signer and role, not substitution of a different contracting
party. Name, role, order, field placement, sender-filled values, recipients,
expiry and retention do not change. Changing the intended person requires
voiding the request and preparing a new one.

The correction cannot undo information already read or mail already accepted by
a provider. Confirmation must say that prior access will be revoked, old entries
will not transfer, and the corrected mailbox must open a fresh invitation,
consent, adopt marks and fill its fields again. Provider acceptance must never be
described as inbox delivery or mailbox ownership.

Reject correction after any accepted Finish for that slot, even while its
checkpoint is still processing and its status has not become Signed. Reject
terminal, expired or retention-cutoff envelopes, future signers, unsupported or
unverifiable history, duplicate addresses within the request and suppressed
destinations. A repeated address with a different case is not a correction.

## Findings in the existing source

The following dependencies make an email update alone unsafe:

| Existing contract | Required integration |
| --- | --- |
| `SignerAccess` derives current identity from the mutable signer row and compares session email, document and disclosure | Check an independently persisted contact epoch on every invitation redemption and authenticated read/mutation. An A to B to A correction must not restore an earlier session. |
| `VerifiedSigner` has a random session ID and is serialized into consent/adoption/review/Finish evidence bindings | Preserve legacy serialization and already-signed evidence. Introduce a versioned epoch-aware session identity/proof format; do not silently add a serialized property to historical bindings. |
| `SignerCheckpointState` verifies each signed predecessor using exact accepted fields, email and adoption | Never correct a finished predecessor. The current accepted PDF and predecessor chain stay byte-for-byte unchanged. |
| `fields_finalized` hashes field IDs, signing-slot IDs, placement and sender-filled values | Keep the stable `SignerId` as the signing slot and keep field definitions unchanged. Archive prior slot entries before clearing active entry values and adoption references. |
| `CompletionEvidenceCollector.Metadata` compares the active signer roster to the final pre-Send `signer_*` event | Fold verified append-only corrections over the original roster. Keep the original roster and show the corrected effective party and correction history in the completion evidence. |
| `InvitationResendRules.VerifyIndexAsync` compares historical outbox recipient with current `Signer.Email` | Validate historical recipient against its historical epoch, not against a mutable current address. Keep old receipt and cap reservations valid after correction. |
| Invitation work and Finish work take the envelope lock before acting | Use that same lock to serialize correction with redemption, consent, adoption, fields, review, Finish and dispatch. |
| Lookup and completion membership are derived from current verified effective parties | Only the final effective mailbox receives new completion/lookup authority. Old contact evidence is history, not membership. |

These findings are source inspection, not a claim that correction already works.
There is currently no supported correction route, worker or runtime setting.

## Identity and immutable evidence

Retain the existing `SignerId` and order as the stable signing slot. A new
append-only contact-revision record identifies each corrected mailbox epoch with
a fresh random revision ID, previous revision ID, ordinal, exact prior/new
normalized address, unchanged name/role, sender identity, command ID, server UTC
time, reviewed envelope/signer versions, current-copy and disclosure bindings,
statement version/hash and prior correction hash. The uncorrected generation is
an explicit legacy epoch; absence is accepted only when a verified correction
chain proves that no correction exists.

Capture the full previous active signer state, owned field values/revisions and
adoption/preview/review references in a bounded immutable retirement snapshot
before changing their active projections. Preserve historical consent events,
used preview records and stored mark/review bytes until the original retention
cutoff. Add a canonical hash-chained audit event linking the retirement snapshot,
revision and queued invitation. Do not relabel old consent or adoption as the
new mailbox's actions, or append another event using the old party as actor.

The active signer projection may change its email, reset status to Pending and
clear consent, adoption and unsigned field entries only in the same correction
transaction. Dates, signature marks, checkbox/text/date and Full Name entries
start empty for the new epoch. Field definitions, owned IDs and immutable sent
PDF/disclosure remain unchanged. Historical rows and blobs remain readable only
through existing authorized evidence paths, never by the replacement session.

Persisted revision history needs application SELECT/INSERT but no UPDATE/DELETE.
Runtime projection updates must be fenced by exact versions and latest epoch.
The guarded worker purge procedure must remove new envelope-owned evidence in
foreign-key order at the original immutable deadline. Add migration, SQL role
and purge tests before deployment; deployment/grant changes need owner approval.

## Review, admission and mail delivery

1. Private metadata-only GET shows old/new address, unchanged named signer and
   role, current source, prior-access limitation and loss of unfinished entries.
   It does not reserve work, revoke access or send mail. Normalize/validate the
   proposed address server-side and bind it into a protected review.
2. A purpose-separated review binds verified sender and original ticket expiry,
   envelope and signer versions, latest contact epoch, exact current PDF and
   disclosure, destination, a server-created command ID and fixed statement.
   Bound it to ten minutes, sender authority, signing/retention cutoff and the
   current UTC cap day. A CSRF-protected POST requires affirmative confirmation.
3. Under the common envelope lock, recheck retained sent evidence, entire
   current-copy chain, current slot, no accepted Finish, latest epoch, duplicate
   destination, suppression, feature/email/work flags and explicitly configured
   address/IP/sender/global admission caps. Retain cap evidence until day end;
   refuse when the original purge cutoff would erase it sooner. Never extend
   retention to permit correction.
4. Refuse while a predecessor dispatch is leased, submitting, ambiguous or has an
   unknown receipt. A queued never-started predecessor may be canceled only under
   the common lease/intent fence. Preserve all outbox/work rows, immutable
   admissions and historical receipts. A correction cannot solve uncertain
   delivery by sending a second email blindly.
5. In one transaction append retirement/revision/admission evidence, update the
   active projection, supersede unused reviews, expire unused old tokens and
   fence all prior redeemed sessions/proofs by epoch. Retire old future reminder
   work. Enqueue exactly one protected epoch-bound correction invitation and
   durable work hint. Failure before commit restores the entire old state.
6. Dispatch rechecks current epoch, exact reviewed source/disclosure, remaining
   deadline, suppression, lease and enablement. Issue a token only then. Use the
   existing protected submission-intent/receipt pattern. Unknown acknowledgement
   preserves intent and prohibits blind retry; definite non-submission revokes
   only the exact unused issued token. Never restore the old mailbox as rollback
   after a committed correction. A fresh explicit correction/resend is needed.
7. Idempotent retry with the same command ID returns its exact stored outcome
   only when every original binding matches. A changed address or stale review
   requires new explicit review. Post-commit response loss must not send again.

Epoch checks apply to PDF receipts/downloads, decline, signature preview/adoption,
field apply/clear, review preparation/PDF access, Finish, confirmation and all
queued notification paths, not just the initial invitation. Legacy sessions for
unchanged or previously finished slots retain their exact existing bindings.
New proof serialization uses explicit versions and purposes. Missing, duplicate,
damaged or cross-envelope revision evidence fails closed, without falling back
to the original invitation or email comparison.

## Completion and presentation

Replay the original pre-Send roster through a contiguous verified correction
chain. Verify both directions: every current projected address comes from that
chain and every correction has its retirement/admission evidence. Completion
must reject an untracked row mutation or missing intermediate revision.

Each effective signer must have a fresh link, consent, adoption, fields, accepted
Finish and checkpoint all belonging to its final epoch. The certificate lists
the final signer and a clearly labeled contact-correction trail with server time
and sender authorization. Earlier unfinished consent/marks appear only as
retired evidence; they are not signatures by the corrected mailbox. Preserve
already-signed predecessors and their document hashes and evidence unchanged.

New completion notifications, access links and lookup membership use verified
final effective parties. A retired address must not receive them merely because
it appears in an original snapshot, historical token or audit event. Sender
status distinguishes correction queued, provider accepted, definite failure,
uncertain submission and fresh signer progress. Use clean redirects, protected
one-use HttpOnly notices and private no-store/noindex/no-referrer pages without
analytics. Preserve private-route SEO boundaries.

## Implementation sequence and acceptance gates

| Slice | Required proof before completion |
| --- | --- |
| Revision/evidence contract | Bounded, canonical chain and original-roster fold; repeated address cycles, branching/missing/tampered/cross-envelope history and mutation rejection; no active route or changed legacy bytes. |
| Durable data and authority | Immutable storage constraints, role/purge coverage, all token/session/proof epoch checks, archived unsigned-entry reset and unchanged signed/legacy evidence. No correction admission yet. |
| Admission and delivery | Exact review, transaction/Finish/dispatch races, caps/suppression, idempotence, rollback and unknown-commit/provider recovery; local captured mail only. |
| Completion and private UI | Certificate/membership reconciliation plus desktop/mobile/keyboard old/new mailbox flows, stale tabs/proofs and A to B to A revocation, accurate private status and SEO checks. |
| Hosted activation | Separate reviewed deployment/grants, operator disclosure change and bounded approved mail testing. Keep current demo correction disabled. |

Keep the reusable feature disabled until all admission, authority, completion
and UI slices are integrated. Do not ship an email-changing endpoint in an
intermediate slice. Reuse permissive dependencies; there is no AI placement or
new mail provider in this work.

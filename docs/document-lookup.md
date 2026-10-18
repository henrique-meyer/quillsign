# Completed-document lookup

QUILS-84 adds the backend for finding retained completed documents after verifying a mailbox. QUILS-85 adds an explicit handoff to the existing read-only final-packet reader. QUILS-86 adds scanner-safe browser entry and the private list. QUILS-87 adds the internal durable mail producer. Pre-envelope contact-data cleanup (QUILS-88) and a public email-request form remain required before public lookup delivery. Hosted sending remains disabled.

`DocumentLookup.IssueAsync` is a trusted issuance operation. Its protected transport must be delivered privately to the nominated mailbox, never returned by an anonymous request API, logged or exposed in a query string. The mail producer calls it at supported dispatch, after checking its SQL lease. Browser entry uses explicit scanner-safe POST redemption, CSRF protection and clean redirects.

Issuance generates a random 256-bit secret and saves only its hash, the `Lookup` purpose and technical lifecycle fields in `AuthTokens`. The token has no envelope, party or document binding and stores an empty email. A dedicated protected transport binds the secret to the normalized mailbox, token ID, issuance row revision, issuance time and original expiry. Any write to that row invalidates the original link, including resetting `UsedAt` after consumption. Bare legacy lookup secrets and completion-access links do not redeem here.

Redemption locks the token and consumes it once. After a confirmed commit it returns a separate protected receipt and read-only identity bound to the consumed row revision, mailbox, session nonce and original times. Both the dedicated principal and matching receipt are required. Unknown commit acknowledgements return no receipt; fresh explicit issuance recovers without replaying a consumed link. A session retains its original expiry even if the already-consumed link expires first. Deleting or changing the token invalidates the session.

Each explicit list operation considers a bounded page of completed candidates matching the mailbox as sender, signer or completion recipient. It uses a completion-time ceiling and protected keyset cursor bound to that session. An envelope appears once even when the mailbox has several party roles. The service verifies frozen publication evidence and the actual executed PDF/certificate pair, then rechecks membership, source, session and saved first-upload retention after I/O. Expired or purged documents are not returned; missing/corrupt evidence fails closed and can be retried explicitly when storage recovers. Listing never extends retention, reseals, prepares a download, issues completion-access links or restores edit/signing authority.

Results contain only the document's public ID, title, completion time and effective retention deadline. Other parties' contact details, storage locations, file grants and cryptographic proofs are absent. A returned entry is metadata, not download authority; the explicit download handoff independently authorizes the chosen current publication and exact files.

Technical options use the standard environment-variable convention:

| Setting | Default | Bound |
| --- | --- | --- |
| `DocumentLookup__LinkMinutes` | 15 | 1–60 |
| `DocumentLookup__SessionMinutes` | 30 | 1–60 |
| `DocumentLookup__PageSize` | 5 | 1–10 |

There is no background SQL polling, cloud change, live timestamp request or automatic email in this foundation. It reuses the existing schema and completion verification; no new dependencies or migration are required.

## Opening one retained packet

`LookupPacketAccess.OpenAsync` requires the dedicated lookup principal, its matching private receipt and one canonical document public ID. The selected completed record must belong to that verified mailbox and fit the lookup's original completion-time ceiling. A cursor, another party's claims or a mailbox string provides no authority. Overlapping roles use the frozen sender first, then a matching signer in signing order, then a completion recipient.

The operation verifies the actual final pair before its transaction, then takes the envelope lock followed by the consumed lookup-token lock. It rechecks lookup revision/session, frozen publication/party and saved retention. Issuance and immediate once-only consumption of a fresh exact-party completion token commit together with the handoff audit. The temporary raw link remains inside the backend. A protected final-reader receipt leaves only after confirmed commit and final authorization/retention checks; unknown acknowledgements return no session. An explicit still-authenticated retry creates a fresh bounded reader rather than replaying the unconfirmed transport.

The reader expiry is fixed at the earliest of its configured normal lifetime, the original lookup expiry and current document retention. Opening again cannot refresh the lookup or extend retention. Normal mailed completion links retain their existing independent lifetime. A successfully issued packet reader is a separate narrow identity; its exact publication/file/source and own original expiry are independently rechecked on later reads.

`completion_lookup_opened` records preparation of that read-only session, with technical identifiers tying the lookup to the chosen party/publication and reader. It contains no raw link or protected receipt, and does not assert that the document was viewed, downloaded or retained. No edit, signing, Finish, broad storage or worker authority is restored.

## Browser access

`/find/access` accepts a privately delivered `#token=...` fragment or a manually entered access code. Script immediately removes the fragment from the address bar and keeps it only in memory until the user selects Continue. This first CSRF-protected POST validates the protected transport and stores a private pending cookie, bounded by ten minutes and the original link expiry. A separate Open my documents POST supplies its nonce and consumes the code once. Neither GET nor script automatically redeems a link. Another tab's newer pending link invalidates the earlier confirmation nonce. An uncertain redemption acknowledgement requires a fresh link or returning to an already-open list.

Successful redemption issues only the named lookup authentication ticket and its matching HttpOnly receipt. The private `/find/documents` view lists the original verified snapshot with UTC completion/retention times. Next and Start at first document are CSRF-protected POSTs: their protected session-bound cursor stays in POST bodies and an HttpOnly paging cookie, followed by a clean redirect. Refresh is read-only. Invalid or cross-session cursors require an explicit reset; they never silently broaden the view.

Open document is another explicit CSRF-protected POST. It invokes `LookupPacketAccess`, issues the independently bounded completion-reader cookie/receipt and redirects to `/complete/{publicId}`. Existing download buttons prepare and reverify the exact executed PDF and standalone certificate. Opening or downloading never refreshes original lookup authority, restores editing or extends retention. Missing storage or changed source evidence produces a private recoverable error rather than a substitute file. Expired sessions return to clean access entry with a private one-use notice.

All `/find` responses, including antiforgery and rate-limit failures, use `no-store`, `no-referrer` and `nosniff`. Entry POSTs share the configured sender entry-window limits through an independent IP partition; list reads allow 120 per minute and list actions 30 per minute. These limits supplement the later email-request abuse controls; they do not enable sending or provide a public way to obtain a lookup code.

## Internal durable mail

`DocumentLookupRequests.RequestAsync` accepts a server-chosen request ID, one address and a canonical IP. Disabled email/work gates precede SQL and queue access. A transaction application lock serializes bounded daily admission caps and suppression checks. Unknown mailboxes follow the same path without document-membership queries; callers receive only a neutral/unavailable outcome, never a private link or work ID. Reusing an ID cannot alter an existing request or create another message.

The envelope-null outbox row holds the destination and a dedicated protected payload binding its ID, destination, private IP hash, original time and fixed dispatch deadline. Generic work metadata and storage hints contain only technical identifiers/times. The hint is saved before SQL commit; queue publication follows confirmed commit and can recover independently. No code is minted while the request waits in the queue.

The supported email worker verifies the current lease and protected scope before standalone lookup issuance. It then rechecks current policy, current-day delivery caps, request deadline and exact unused token revision/hash under its submission transaction. Only confirmed submission intent permits provider I/O. The private email contains a fragment link, manual code and absolute UTC expiry, with no attachments, document details or tracking. It reuses the existing demo/retention warnings and makes no new operator privacy-policy claim.

A definite non-submission invalidates the exact unconsumed token and clears only the owned intent before a permitted retry. Unknown provider or commit acknowledgements preserve intent for existing ambiguous recovery; the worker never blindly resends or reuses a consumed issuance. Receipt recording verifies the exact protected intent using ordinal comparisons under locks and preserves concurrent feedback status. Neither retries nor configuration increases extend the original request deadline.

| Setting | Default | Bound |
| --- | --- | --- |
| `DocumentLookupDelivery__DailyAddressRequests` | 3 | 1–global daily cap |
| `DocumentLookupDelivery__DailyIpRequests` | 10 | 1–global daily cap |
| `DocumentLookupDelivery__DailyRequests` | 50 | 1–1,000 |
| `DocumentLookupDelivery__RequestHours` | 24 | 1–24 |

Caps apply separately to requests admitted on the UTC day and submission intents started on that day, including queued requests from an earlier day and uncertain submissions. Definitely unsubmitted retries retain their original admission record. Existing global suppression and lazy provider credentials remain enforced.

This producer has no public request endpoint and does not enable email. Contact cleanup is a separate scope from document purge, as described below.

## Lookup contact retention

New internal mail requests require `Demo__PurgeAfterDays` (1–36,500). It remains unset by default; an absent policy refuses admission before SQL or storage access. The same configured demo interval applies to these contacts from their original request time, independently of a document's first-upload clock. The immutable `LookupContactRetentionSnapshots` row freezes the original UTC second, day count and deletion deadline. A later setting change applies to new enrollments and never extends a saved deadline. No mailbox, IP hash or provider identifier appears in that snapshot or generic cleanup work.

Admission atomically saves the outbox, email work, snapshot and a deterministic purpose-separated `Purge` job. Both hints are written before SQL commit, with queue publication after confirmed commit. Existing storage-only recovery can recover a lost publication without polling SQL while idle. Cleanup retries do not expire at the ordinary email attempt limit. As with document cleanup, the deadline starts a recoverable deletion process; it does not promise immediate physical erasure of backups, logs, or copies already held by a recipient.

Dispatch verifies the exact saved snapshot and active cleanup schedule before issuing or submitting a link. UTC daily counters include admission and uncertain submissions. A one-day policy also closes dispatch at the end of the original request's UTC day, so cleanup cannot discard counters from a later delivery day. Policies of two days or longer preserve the original at-most-24-hour dispatch window. Neither policy changes nor retries extend it.

The distinct `lookup-contact-purge-v1` worker path has no document/blob capability and needs no private payload key after enrollment. The static `RemoveExpiredLookupContacts` SQL procedure verifies actual server UTC time, the exact current cleanup lease, canonical payload, deterministic work ID, immutable policy digest and original envelope-null lookup scope. It waits for a live email/outbox lease to expire. It atomically deletes the outbox recipient, protected payload, provider details and saved snapshot, leaving a terminal technical email-work tombstone to prevent request-ID reuse and unsafe replay. An uncertain submission stays marked ambiguous. A lost cleanup commit acknowledgement can be retried idempotently. This is contact cleanup, not evidence of document erasure.

Global bounce/complaint suppression remains independent: authenticated late feedback still suppresses an address even after the old outbox is gone. Lookup tokens themselves contain no mailbox; cleanup does not revoke an otherwise live link or receipt. Their original expiry, document retention and exact publication checks continue to apply.

After migration, an administrator must explicitly run `database grant-runtime` for the new table permissions and `database grant-lookup-retention` for worker-only procedure execution. Runtime and worker retain direct `UPDATE`/`DELETE` denials on the immutable snapshot; the web identity receives no cleanup procedure execution. These source changes do not apply hosted grants or migrations automatically.

`work resume-lookup-retention <32-character-request-id>` is an explicit trusted recovery/enrollment action. It verifies legacy protected lookup scope and original request time, refuses a live email lease, and schedules the original fixed deadline rather than starting a fresh clock. Existing enrollment can be rescheduled with private payload keys or the setting unavailable. A one-day legacy policy refuses a submission intent recorded on a later UTC day, since its counters could otherwise be erased early; it requires an explicitly suitable configured policy. Enrollment after the deadline does not assert that cleanup had previously been scheduled. Missing/cleaned records gain no new authority. No periodic SQL sweep or new cloud resource is introduced.

# Completed-document lookup

QUILS-84 adds the backend for finding retained completed documents after verifying a mailbox. QUILS-85 adds an explicit handoff to the existing read-only final-packet reader. QUILS-86 adds scanner-safe browser entry and the private list. An anonymous email-request form and mail delivery remain separate work. Hosted sending remains disabled.

`DocumentLookup.IssueAsync` is a trusted issuance operation. Its protected transport must be delivered privately to the nominated mailbox, never returned by an anonymous request API, logged or exposed in a query string. There is no mail producer yet. Browser entry uses explicit scanner-safe POST redemption, CSRF protection and clean redirects.

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

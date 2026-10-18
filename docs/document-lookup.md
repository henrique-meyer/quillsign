# Completed-document lookup foundation

QUILS-84 adds an internal backend for finding retained completed documents after verifying a mailbox. QUILS-85 adds an explicit internal handoff to the existing read-only final-packet reader. Public request/redemption pages, abuse limits and mail delivery are separate work. Hosted sending remains disabled.

`DocumentLookup.IssueAsync` is a trusted issuance operation. Its protected transport must be delivered privately to the nominated mailbox, never returned by an anonymous request API, logged or exposed in a query string. There is no HTTP route or mail producer in this slice. A future browser flow must use explicit scanner-safe POST redemption, CSRF protection and clean redirects.

Issuance generates a random 256-bit secret and saves only its hash, the `Lookup` purpose and technical lifecycle fields in `AuthTokens`. The token has no envelope, party or document binding and stores an empty email. A dedicated protected transport binds the secret to the normalized mailbox, token ID, issuance row revision, issuance time and original expiry. Any write to that row invalidates the original link, including resetting `UsedAt` after consumption. Bare legacy lookup secrets and completion-access links do not redeem here.

Redemption locks the token and consumes it once. After a confirmed commit it returns a separate protected receipt and read-only identity bound to the consumed row revision, mailbox, session nonce and original times. Both the dedicated principal and matching receipt are required. Unknown commit acknowledgements return no receipt; fresh explicit issuance recovers without replaying a consumed link. A session retains its original expiry even if the already-consumed link expires first. Deleting or changing the token invalidates the session.

Each explicit list operation considers a bounded page of completed candidates matching the mailbox as sender, signer or completion recipient. It uses a completion-time ceiling and protected keyset cursor bound to that session. An envelope appears once even when the mailbox has several party roles. The service verifies frozen publication evidence and the actual executed PDF/certificate pair, then rechecks membership, source, session and saved first-upload retention after I/O. Expired or purged documents are not returned; missing/corrupt evidence fails closed and can be retried explicitly when storage recovers. Listing never extends retention, reseals, prepares a download, issues completion-access links or restores edit/signing authority.

Results contain only the document's public ID, title, completion time and effective retention deadline. Other parties' contact details, storage locations, file grants and cryptographic proofs are absent. A returned entry is metadata, not download authority; a future download handoff must independently authorize the chosen current publication and exact files.

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

`completion_lookup_opened` records preparation of that read-only session, with technical identifiers tying the lookup to the chosen party/publication and reader. It contains no raw link or protected receipt, and does not assert that the document was viewed, downloaded or retained. No edit, signing, Finish, broad storage or worker authority is restored. Future public handlers must use explicit CSRF-protected POSTs, bounded abuse controls, private cookies and clean redirects; no new HTTP route exists in this slice.

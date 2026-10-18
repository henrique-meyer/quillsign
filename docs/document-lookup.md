# Completed-document lookup foundation

QUILS-84 adds an internal backend for finding retained completed documents after verifying a mailbox. Public request/redemption pages, abuse limits, mail delivery and the handoff to final downloads are separate work. Hosted sending remains disabled.

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

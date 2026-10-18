# Internal invitation resend

`InvitationResends` provides verified-sender review and admission for a replacement invitation to the current unfinished sequential signer. `InvitationResendDelivery` handles the supported durable mail work. This is an internal foundation: there is no public resend endpoint or sender form, and the existing status page still describes the original invitation. Sender UI and status integration need a separate slice. Hosted mail and resend remain disabled.

The internal caller supplies the original protected sender authentication ticket's expiry, an exact current review, an explicit affirmation of `InvitationResendStatement`, and a server-chosen GUID reused for retries. A future HTTP caller must obtain the ticket expiry from authentication, enforce CSRF and entry-rate limits, and preserve that command identifier; form values cannot grant authority. No raw invitation token is returned by the sender operation.

Review and admission verify sender/envelope membership, the immutable Send evidence, current sequential source and disclosure, envelope revision, absence of accepted Finish, and signing/retention deadlines under the common envelope lock. A stale review, wrong signer, terminal request or expired sender ticket cannot enqueue mail. Admission refuses queued, leased or uncertain prior submission state; it cannot bypass an invitation that might already have been accepted by the provider.

## Replacement and delivery evidence

Admission commits one protected envelope-owned outbox/work pair, a canonical hash-chained audit event, and expiration of older **unused** signer-access tokens. A storage hint is written before SQL commit and published afterward. A lost commit acknowledgement requires explicit saved-state recovery with the same request ID; it does not justify a new provider attempt. Known rollback preserves the old unused links. A committed request may revoke them even if subsequent delivery fails, so admission means queued, never confirmed delivery.

Used tokens, existing redeemed sessions, their original expiries, prior consent, adopted marks, fields, accepted Finish and frozen PDFs remain intact. This operation does not correct contacts, replace a disclosure, extend signing or document retention, or withdraw consent. A replacement link can create another session for the same current signer under the existing signer-access rules.

Each request binds its exact predecessor and current document/disclosure. Original invitation dispatch and older replacement work are fenced by the latest canonical admission, including explicit trusted replay of old work. Dispatch verifies that admission, current eligibility, enabled settings, suppression, caps, exact lease and source again before recording submission intent. The token is generated at dispatch and uses the existing invitation lifetime, capped by signing and verified retention. The committed authorization may outlive the sender's browser ticket, within its fixed dispatch deadline.

The protected intent contains only the issued token's identifier/hash/expiry, never its raw value. Definite non-submission clears only that exact owned intent and expires its unused token before bounded retry. Unknown intent-commit, provider or receipt outcomes retain intent; existing work recovery settles ambiguity without blindly sending again. Receipt processing is outside the definite-transport-failure catch. Provider acceptance is recorded as acceptance, not proof of delivery. Late feedback is preserved, signing progress cannot regress, and a late receipt cannot recreate a purged parent or private rows.

## Explicit configuration and daily bounds

Resend has no enabled-by-default policy or default cap values. Set these only after choosing the intended limits for an operator's deployment:

| Setting | Default / requirement |
| --- | --- |
| `InvitationResend__Enabled` | `false` |
| `InvitationResend__DailyRequests` | Unset; required when enabled, 1–1,000 |
| `InvitationResend__DailyAddressRequests` | Unset; required, 1 through the global limit |
| `InvitationResend__DailyIpRequests` | Unset; required, 1 through the global limit |
| `InvitationResend__DailySenderRequests` | Unset; required, 1 through the global limit |

Both `Email__Enabled` and `Work__Enabled` must also be true. Disabled operations do not open SQL, issue tokens or resolve work signals. Enabling resend without valid explicit caps is rejected. The local tests choose synthetic limits for their own hosts; these are not proposed hosted defaults.

A transaction application lock reserves caps across instances. All admitted requests count, including queued and definitely failed attempts; an idempotent replay spends no additional reservation. Canonical IP normalization prevents alternate IPv4/IPv6 spellings from bypassing an IP cap. Admission audit time anchors the UTC day, so moving an outbox timestamp cannot hide a reservation. Daily reservation reads are bounded to 1,001 records with SQL byte-length checks before loading proof/payload bodies. Missing keys, missing records or malformed protected/canonical evidence fail closed.

Dispatch ends at the earliest of its original midnight UTC boundary and existing signing/retention limits. Tokens may remain usable beyond that dispatch boundary within their original signing/retention limits. Admission is unavailable when document retention would purge the reservation before that UTC day ends. This restriction preserves daily cap accounting without extending retention or retaining new contact counters beyond document purge. A delayed request is not silently carried into a new day; a later request requires fresh sender authorization. Current cap settings also apply to queued dispatch.

## Local verification and operational scope

Tests use real local SQL/Azurite, persistent application keys, captured fake mail and loopback Mailpit SMTP. They cover old-link rejection, existing-session and consent preservation, deliberate scope, concurrent deduplication, shared-instance caps, corrupt/oversized evidence, UTC and retention cutoffs, exact leases, original-work replay, rollback and lost acknowledgements, definite versus uncertain transport, actual Finish races, and captured replacement-link redemption.

No schema migration, runtime grant, new storage service, idle SQL polling, cloud setting, deployment, live email, timestamp request or AI feature is introduced. The existing envelope purge removes these envelope-owned rows and audit records with the document. Network wakeups and storage-only recovery retain their existing contracts. Operators still need their existing mail, suppression/feedback and durable-work configuration before any later public enablement.

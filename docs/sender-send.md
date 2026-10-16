# Reviewed Send and private sender status

QUILS-39 exposes Send from the sender's preparation review and a private, read-only status page in the original verified sender session. It uses the [atomic freeze and invitation backend](send-freeze.md) and the [signer review/Finish flow](signer-review-finish.md). Final sealing, completion delivery and sender status-link email remain later work.

## Deliberate Send

GET review reads one coherent draft revision and never freezes or sends. The page shows the document, sequential signers, sender values, completion recipients, expiry and the configured electronic-record disclosure. Send stays disabled if preparation fails, expiry has passed, work/email is unavailable or actual operator policies are incomplete. Example policy values stay empty; synthetic test policies are not operator defaults.

The bounded, rate-limited Send POST requires antiforgery protection, one current envelope/email-scoped verified sender identity, the reviewed eight-byte rowversion, an exclusions/suitability acknowledgment and separate affirmative intent to send that reviewed request to the listed signers in order. The backend requires both confirmations and the canonical `sender-send-v1` statement explicitly. It rechecks current preparation and source bytes under the envelope lock before freezing anything.

The original normalized PDF remains unchanged. One transaction saves the frozen sender-prefilled PDF/hash, exact disclosure/version/hash, preparation and Send evidence, and the first invitation outbox/work pair. Send evidence binds the reviewed version, canonical statement text/version/hash and affirmative sender confirmation. No client PDF, hash, storage reference or timestamp authorizes Send.

An exact retry recovers the same frozen request and invitation once, including a lost response or uncertain commit. A queued invitation may receive another wake hint; durable work prevents duplicate submission. A different reviewed version cannot claim the earlier Send. Recovery still works read-only when delivery is subsequently disabled. Old sent records without the new review/intent evidence can be read as status but cannot satisfy a new exact Send replay.

Successful HTML requests redirect to `/draft/{publicId}/sent` with a short-lived, HttpOnly, once-only notice. JSON returns a confirmation path/body. No action notice, token or protected proof is added to a URL. Recoverable failures explain that sending could not be confirmed and direct the sender to reload saved state before retrying; submitted confirmations remain checked where a draft can still be displayed. A stale review requires explicit reload.

## Private status

The status URL grants no authority by itself. Every request requires the original live verified sender session and exact envelope/public-ID/email scope. It exposes no signer credential, work ID, protected proof or document storage reference. Reads validate Send evidence and the published checkpoint chain. Failed verification produces a recoverable error without asserting delivery, signing or completion.

Progress distinguishes invitation queued, provider submission, link opened with consent pending, consent recorded, Finish accepted with checkpoint processing pending, and Signed with actual accepted Finish time. Rejection, bounce, complaint and an unconfirmed submission outcome have separate delivery-attention states; they are never described as queued or delivered. Queuing and provider acceptance do not prove inbox delivery. All signers Signed still means final completion pending until finalization exists. A bare Completed status without completion metadata fails verification.

The same session may read retained expired, declined or voided sent requests. That does not revive signing or editing. Sent preparation is frozen, and revisiting preparation review redirects to private status. Refresh is manual; the page introduces no recurring database polling. Values are encoded and responses use `no-store`/`no-referrer`; separate limits bound status reads and Send attempts.

The sender and signers are listed as intended completion recipients; no final packet or sender confirmation email is sent by this slice. Production Send remains unavailable until the operator supplies real disclosure policies and approved delivery configuration.

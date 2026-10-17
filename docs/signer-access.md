# Signer invitation and session foundation (QUILS-26)

`SignerInvitationFactory`, `SignerAccess` and the separate `QuillSign.Signer` authentication scheme provide internal invitation redemption and scoped read authorization. This foundation exposes no token-issuance endpoint, consent/signing page or mail operation. It records email-link possession evidence, not civil identity, authority, consent or adoption of a signature.

## Invitation and redemption

The pure factory generates 32 random bytes encoded as a canonical 43-character base64url token. Its `AuthToken` record contains SHA-256 of the encoded token, envelope/signer IDs, SignerAccess purpose, Signer party type, normalized email/expiry and the exact document object/hash and disclosure hash selected at dispatch. Plaintext remains in memory for dispatch and must not be logged or stored unprotected. Calling the factory alone grants no access. Legacy records without document/disclosure binding cannot redeem and are never silently rebound.

Create at actual dispatch rather than enqueue time. `SignerAccess:InvitationHours` defaults to 24 (supported 1–168); `SessionHours` defaults to 2 (supported 1–24). Both are clamped to envelope expiry. Committed settings contain only these nonsecret defaults, and environment examples are empty.

Redemption validates canonical token shape, locates scope, then takes the common envelope lock before the token lock. It rereads current data and requires a Sent, unexpired, sender-verified envelope with a valid verified current PDF and stored ERSD snapshot. The signer must belong to the envelope, remain unsigned/undeclined, have no earlier unsigned signer and have no accepted Finish. Purpose, party, email, expiry, unused state, token hash and exact current document/disclosure binding must match. Invalid or premature tokens remain unconsumed.

Token consumption and `link_opened` evidence commit together. The event records the persisted signer actor ID/email, authentication method, token ID and frozen PDF/disclosure hashes, with timestamp/IP/user agent through the canonical audit writer. It contains no plaintext token. Audit failure rolls back consumption; concurrent redemption yields one committed identity. Issue the cookie only from the successful committed result. An uncertain response/commit must not be treated as proof of a reusable token; later resend/recovery belongs to the dispatch workflow.

## Session and frozen-document reads

Signer cookies use a separate name and authentication purpose from sender cookies, HttpOnly, SameSite Lax, a root path and non-sliding expiration. Production uses `__Host-QuillSign.Signer` with Secure required. Ticket and claims carry the absolute session end; middleware rejects expired or malformed claim bindings without querying SQL.

Claims bind exactly one authenticated signer identity to envelope/public ID, signer ID, email, frozen object ID, PDF hash and ERSD hash. `GetContextAsync` rechecks eligibility and these current bindings under the envelope lock on each authorized workflow read. It rejects mixed/duplicate/wrong-scheme claims, expired sessions, changed contact/document/disclosure, invalid ERSD, advanced signing order or ended envelopes. Reading does not extend the original session deadline or accept consent.

QUILS-37 resolves that source from the [verified checkpoint chain](signer-checkpoints.md) after earlier signers finish. The original sent PDF remains immutable; missing or inconsistent prior checkpoints fail closed instead of falling back to it. Accepted/completed-signer confirmation and own-checkpoint downloads use a separate narrow accepted-proof contract and never restore editable context or grant general blob reads.

Frozen PDF objects use distinct immutable IDs in the existing private normalized container. Signer copy authorization permits only the bound envelope/object in that container; original, preview, other objects and other envelopes are denied. Sender identity remains required for writes/deletes. **Future handlers must obtain a current `SignerReadContext` before copying and verify actual PDF bytes against its expected hash before successful display/download.** Low-level blob authorization checks protected claim scope; it does not independently query current SQL state or establish content integrity.

## Fixed demo retention during signing

For an enrolled demo request, the shared [upload-retention policy](document-retention.md) adds an independent absolute access limit. Full token or session/party/source/disclosure authorization happens before private policy reads. Missing or inconsistent enrolled policy/provenance fails closed; ordinary and historical unenrolled requests are not silently enrolled.

Newly redeemed sessions, PDF-access receipts, adoption previews and review candidates cannot outlive the fixed cutoff. Existing protected session identities retain their exact original serialization so consent/adoption/Finish evidence remains verifiable; every public use independently checks the verified retention limit. Public mutation boundaries recheck time after audit/work preparation, and buffered document/asset reads recheck context before returning verified bytes. At the exact cutoff, authenticated signer pages, accepted confirmation and own-checkpoint downloads return a private generic 410. Unverifiable retention evidence returns a private generic 503; unknown identities keep their existing behavior. Responses include no document or party metadata and retain no-store/no-referrer headers.

Accepted signing never restores edits. Trusted checkpoint/history workers retain their existing narrow system capabilities after original signer-session expiry and do not impersonate a signer. This change adds no purge, completed-recipient retrieval guard or worker-publication behavior. Downloads already started and copies held by parties cannot be recalled.

## Integration still required

The mail worker must create/persist protected invitation state at actual dispatch, handle retries/resends and update notification status without overwriting a later signer state. Add rate limits and a safe landing/redemption flow before exposing a public invitation endpoint. Keep tokens out of request logs/referrers and redirect to clean URLs after redemption.

The [consent flow](signer-consent.md) uses the saved ERSD and frozen PDF, requires access/retention confirmations and records a separate affirmative act. It supports pre-consent decline. The [capture UI](signature-capture.md) adds explicit adoption, and internal send/freeze queues invitation mail. Deliberate field filling, completion/current-copy downloads, post-consent withdrawal and sender status remain later work. Active access ends when the signer finishes or the envelope ends; completed-copy retrieval needs its own authorized contract.

Tests exercise concurrent redemption/replay, sequential eligibility, wrong/expired scope, changed bindings, ERSD tampering, audit rollback and signer attribution, delayed-dispatch expiry, cookie isolation/non-sliding expiry, and real Azurite frozen-object copy with write/delete denial. No startup or idle SQL polling is introduced.

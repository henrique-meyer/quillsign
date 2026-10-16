# Internal draft freeze and first invitation

QUILS-28 adds `SendDraftWorkflow` and durable first-signer invitation dispatch. No public Send endpoint/button is exposed. Sender confirmation/status UI and signer adoption, field filling, Finish, next-signer progression and completion remain subsequent work. This implementation does not enable email, supply operator policies or change deployed/cloud configuration.

## Freeze transaction

The internal service requires exactly one verified sender identity for the envelope/public ID, its current eight-byte rowversion and an explicit exclusions acknowledgment. It requires enabled work/email configuration and complete actual ERSD policies. Missing policies fail before blob writes; examples remain empty. A later public handler must provide CSRF protection, a clear confirmation and a clean redirect.

Under the common envelope lock it reloads the confirmed PDF, title/message, ordered signers, completion recipients and fields. It reruns preparation checks and validates bounds, party details, caps, pending signer state, expiry and suppression. A signer without a Signature field remains a preparation warning. Every sender-owned field must have a valid value.

It copies the bounded normalized source, verifies its hash through the production sender-prefill renderer, and writes a new normalized object ID containing the sender values. The original/normalized source is preserved. The new object is immutable through the application's write-once object contract; this does not claim that cloud WORM policies have been provisioned.

One SQL transaction persists Sent state/time, exclusions acknowledgment, frozen PDF reference/hash, exact ERSD body/version/hash, `fields_finalized` and `sent` audit evidence, and a paired outbox/work item for the first signer only. The title is canonicalized to the exact disclosure header so decomposed Unicode or surrounding whitespace cannot break later snapshot verification. The field-snapshot hash binds assignments, types, geometry, required flags, labels and values. The sent event explicitly describes invitation dispatch as queued.

The durable hint is stored before SQL commit; queue publication follows commit. A lost publication is recoverable from the hint. Known pre-commit failure rolls back SQL and attempts to remove only the newly created object. If the commit outcome is uncertain, that object is preserved because it may already be referenced. Cleanup failures are deferred with a generic diagnostic. Concurrent/stale sends cannot freeze or queue twice. Existing preparation workflows reject Sent envelopes.

## Dispatch and token lifetime

The protected outbox payload stores signer scope and the last token ID, never a raw invitation token. Before submission, dispatch locks the envelope before the work row, revalidates Sent/frozen/disclosure/current signer/email/order/expiry and checks suppression. It creates the QUILS-26 256-bit token at dispatch, with its configured lifetime clamped to envelope expiry. Only SHA-256 enters `AuthTokens`; the raw value exists in the in-memory email and is not stored even inside the protected payload.

Razor text/HTML `SignerInvite` templates include document title, sender contact, signer name/role, optional message with line breaks, the `/sign/invitation` landing link and exact UTC expiry. HTML values are encoded. Opening the landing records neither consent nor a signature.

Token activation and email submission intent commit together before the provider call. Definite non-submission expires that token and permits a bounded retry with a fresh token. An unknown provider/receipt outcome leaves submission intent intact; lease recovery marks it ambiguous and does not resend automatically. Duplicate wakeups cannot resubmit completed work. A known provider acceptance records `invitation_submitted`, explicitly distinguished from proof of delivery. Notified updates cannot overwrite Viewed/Signed/Declined progress. A later void/decline/expiry prevents token redemption through current-state checks.

This slice queues only the first invitation. A later Finish transaction must atomically advance the sequential workflow and prepare the next signer's work. It does not queue sender confirmation/status links or completion mail yet.

## Validation

SQL/Azurite tests cover exact source/frozen separation and hashes, disclosure binding, canonical title handling, authorization/version/preparation/policy/expiry/suppression/delivery gates, concurrent sends, blob/hint/audit failures and cleanup, uncertain commit recovery, delayed dispatch, stale scope/order/state rejection, definite and ambiguous outcomes, duplicate wakeups and local Mailpit delivery. Tests verify actual invitation redemption and the frozen signer context. A browser flow follows a locally dispatched Mailpit invitation into the stored disclosure, frozen prefilled PDF and consent screen, using a clearly fictional non-agreement fixture on a 390-pixel phone. No live mail or cloud operations are involved.

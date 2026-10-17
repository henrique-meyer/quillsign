# Sender void backend

QUILS-53 adds an internal application operation for a verified sender to stop an unfinished sent request. It has no public endpoint, new button or email producer. Public confirmation controls and supported void notifications remain a dependent slice.

## Authority and confirmation

`SenderVoid.VoidAsync` receives the authenticated original sender principal and that named ticket's original expiry from trusted server code. A future HTTP caller must obtain the expiry from authentication, never from a form, and cannot substitute a signer or completion-reader ticket. The backend checks the exact sender scheme, envelope/public ID/email, recorded sender verification, current eight-byte envelope revision, live ticket and live signing deadline.

The caller must affirm the canonical `SenderVoidStatement` and its current version. An optional plain-text reason is bounded to 512 characters, rejects control characters other than line breaks/tab, and normalizes line endings, surrounding whitespace and Unicode for exact replay. The canonical statement, version and SHA-256 are recorded with the action.

Only `Sent` requests can transition to `Voided`. Draft, declined, expired and completed requests are closed to this operation. A confirmed identical repeat can read the existing void action using its original reviewed revision and normalized reason; a changed or stale confirmation cannot create another event.

## Transaction and preserved evidence

The operation owns a clean standalone unit of work and locks the parent envelope before inspecting or changing state. It verifies the original Send/disclosure bindings, current processed checkpoint chain and any accepted pending Finish. It records actual server UTC time, sender attribution, the reviewed revision, statement/reason, sent/disclosure hashes and current copy/checkpoint identity in one canonical `voided` audit record in the state-transition transaction.

Replay verifies canonical evidence, its own hash and its immediate predecessor link. The operation rechecks ticket/deadline validity before commit and clears its tracker after known rollback or an exception. A lost commit acknowledgement propagates without claiming confirmation; a later explicit saved-state check or identical repeat can verify an existing action without creating a second void.

The parent lock serializes void against Finish, checkpoint publication and final publication. A Finish accepted before void remains recorded; a confirmed void prevents further authoritative signing progression and completion. An already committed completed packet wins. Existing signer mutation and invitation/current-source checks reject a voided request. Workers keep their truthful terminal or uncertain outcomes.

Void changes the envelope state and appends its action evidence. It does not change prior signers, accepted fields/adoptions/Finish records, original sent bytes, checkpoints, prepared seals, final objects, token bindings or retention policy. It does not delete or regenerate files, acquire signing keys, or enqueue unsupported work. Existing private sender status can represent the closed request while preserving earlier progress evidence.

The implementation adds no account, issuer, public lookup/resend, live delivery, cloud resource or operator-policy configuration.

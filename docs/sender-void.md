# Sender void and notifications

QUILS-53 adds the verified sender operation that stops an unfinished sent request. QUILS-54 adds a private confirmation page, verified saved status and supported durable informative notices.

## Authority and confirmation

`SenderVoid.VoidAsync` receives the authenticated original sender principal and that named ticket's original expiry from trusted server code. The HTTP caller obtains the expiry from named sender authentication, never from a form, and cannot substitute a signer or completion-reader ticket. The backend checks the exact sender scheme, envelope/public ID/email, recorded sender verification, current eight-byte envelope revision, live ticket and live signing deadline.

The caller must affirm the canonical `SenderVoidStatement` and its current version. An optional plain-text reason is bounded to 512 characters, rejects control characters other than line breaks/tab, and normalizes line endings, surrounding whitespace and Unicode for exact replay. The canonical statement, version and SHA-256 are recorded with the action.

Only `Sent` requests can transition to `Voided`. Draft, declined, expired and completed requests are closed to this operation. A confirmed identical repeat can read the existing void action using its original reviewed revision and normalized reason; a changed or stale confirmation cannot create another event.

## Transaction and preserved evidence

The operation owns a clean standalone unit of work and locks the parent envelope before inspecting or changing state. It verifies the original Send/disclosure bindings, current processed checkpoint chain and any accepted pending Finish. It records actual server UTC time, sender attribution, the reviewed revision, statement/reason, sent/disclosure hashes and current copy/checkpoint identity in one canonical `voided` audit record in the state-transition transaction.

Replay verifies canonical evidence, its own hash and its immediate predecessor link. The operation rechecks ticket/deadline validity before commit and clears its tracker after known rollback or an exception. A lost commit acknowledgement propagates without claiming confirmation; a later explicit saved-state check or identical repeat can verify an existing action without creating a second void.

The parent lock serializes void against Finish, checkpoint publication and final publication. A Finish accepted before void remains recorded; a confirmed void prevents further authoritative signing progression and completion. An already committed completed packet wins. Existing signer mutation and invitation/current-source checks reject a voided request. Workers keep their truthful terminal or uncertain outcomes.

Void changes the envelope state and appends its action evidence. It does not change prior signers, accepted fields/adoptions/Finish records, original sent bytes, checkpoints, prepared seals, final objects, token bindings or retention policy. It does not delete or regenerate files or acquire signing keys. Private sender status displays the verified action time/reason and earlier progress. An accepted but unpublished Finish is labeled as accepted before void, without claiming processing will continue.

## Private browser confirmation

Live original sender status offers **Review void action**, leading to `/draft/{publicId}/void`. GET reads metadata only. The page shows the frozen title, current signing progress, bounded optional reason and canonical affirmation. POST requires antiforgery and a dedicated limit of at most ten actions per minute per IP; private reads have their own bounded limit.

A stale confirmation preserves the attempted reason, removes the affirmative control and requires an explicit metadata refresh followed by a new affirmation. Refresh never voids or queues work. The confirm form always targets the clean action route, including after refresh. Successful confirmation redirects to clean private status with a short-lived HttpOnly notice; JSON clients receive the confirmation body. An uncertain commit reports that void was not confirmed from that response and points to saved status without claiming unchanged state or delivery.

## Supported informative notifications

When durable work is enabled, the void transaction also creates once-only `envelope-voided` outbox/work pairs, canonical queue evidence and storage hints. Wakeups publish after commit. Destinations include the sender and all frozen signers, grouped by email with stable sender-first priority. Completion-only recipients receive no void notice. Confirmed replay does not implicitly queue missing mail.

Protected static payloads bind the exact canonical action/audit, post-void envelope revision, preserved sent/current-copy source and frozen party roster. Dispatch verifies these bindings and its owned lease without a sender session or signing key, even after the original sender/signing sessions expire. Existing recorded purge deadlines still apply. The escaped HTML and plain-text message gives the actual title, UTC void time, optional reason and conditional demo facts. It contains no access link, token, attachment or new authority.

The dispatcher commits submission intent before the provider call and rechecks the scope and lease after asynchronous work. A definite rejection can clear known unused intent and retry. Unknown provider acceptance or receipt-commit uncertainty keeps intent; lease recovery stops ambiguous submission rather than sending again. Disabled email, suppression, bounded retries and storage-only hint recovery remain enforced. Queueing and provider acceptance do not confirm inbox delivery or receipt.

For an existing void, a trusted operator can run this explicit finite command with the internal envelope ID:

```powershell
dotnet run --project src/QuillSign -- work resume-void-notifications <32-character-envelope-id>
```

Resume verifies the retained canonical scope, creates only missing supported pairs and preserves terminal, ambiguous and live-leased work. It performs no idle SQL discovery, public resend, replacement issuance or PDF regeneration. Ordinary pages never invoke resume. Use existing `work once` and `work recover` for finite processing and storage-hint recovery.

The implementation adds no account, issuer, public lookup/resend, live delivery, cloud resource or operator-policy configuration.

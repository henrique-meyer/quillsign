# Immutable final publication

`CompletionPublication.PublishAsync` consumes the existing [completion candidate](completion-candidates.md) and both verified [completion seals](completion-seals.md). It publishes their exact bytes, then atomically records Completed, actual server completion time, final references/hashes, retention deadline and canonical audit evidence. It never renders or seals a replacement. Original, sent and accepted signer PDFs and actual Finish times remain unchanged.

This is an internal workflow prerequisite. It adds no public endpoint, completion worker producer, download authorization or email delivery. Those integrations remain separate planned work. Registration performs no storage, database, key or network I/O.

## Durable ownership and recovery

Before either final upload, an immutable SQL intent reserves two distinct object IDs and binds the candidate, both winning seal revisions/audit proofs, frozen source envelope and explicit retention selection. A unique envelope constraint and the common envelope lock select one intent. Conditional concurrent/retry uploads reuse these targets. Lost acknowledgements recover by exact length/hash readback; there is no final-object delete or overwrite API.

The completion transaction rechecks the frozen source and exact candidate/stage revisions, both verified final receipts and protection coverage at the actual completion decision. It commits the envelope transition, immutable publication result and completion audit event together. Cancellation, a known rollback or an uncertain commit preserves retained/possibly referenced objects. A retry checks authoritative publication state and either returns the committed winner or resumes the same intent. Missing or corrupt committed files fail closed without regeneration.

SQL grants SELECT/INSERT and denies UPDATE/DELETE on intent/result records; EF also rejects tracked mutation. Private JSON is bounded in SQL before loading. Final capabilities are internal, single-object/operation/hash/reference scoped, expire after two minutes and grant no listing, ordinary document access or deletion.

## Explicit retention and truthful protection

Set `Retention__CompletedDays` for ordinary requests: a positive supported day count, or 0 for indefinite retention. Stored demo requests require a positive `Demo__PurgeAfterDays`. Choices are intentionally unset in the example configuration; publication fails closed until an operator supplies them. Retention starts at actual completion. This does not implement a purge scheduler or alter an existing hosting lifecycle policy; operators must align those separately. Keep the source, accepted evidence, candidate and private seal inputs available for the same verification window.

Hosted publication requires an existing private final container with version-level immutability support. The adapter verifies the actual final blob version, ETag, full length/hash and either sufficient locked time-based protection or a legal hold. A finite policy cannot establish indefinite protection. Legal-hold evidence records the hold observed at publication; privileged operator release remains outside application authority. The adapter cannot create hosted containers or set, lock, extend or release policies/holds.

Azure exposes actual per-blob policy and hold facts through [Get Blob Properties](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-properties); new versions may inherit an existing [default version-level policy](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-policy-configure-version-scope). Container presence alone is insufficient. Existing policy coverage needs enough margin to span upload and the eventual completion decision; insufficient coverage preserves the intent/files and leaves the request uncompleted.

Local Azurite may use `Completion__AllowDevelopmentWriteOnce=true` only in Development for a stored demo request. This is conditional application write-once behavior, explicitly recorded as `DevelopmentWriteOnce`; it is not physical WORM storage. The exception cannot authorize hosted or ordinary-request publication.

## Completed-copy verification

`ReadAsync` verifies immutable publication recipes, canonical preparation/completion proofs, exact before/after envelope bindings and the original anchored signing evidence. A narrowly internal published-source context accounts only for the authorized completion columns and resulting row version. It does not restore sender/signer sessions or editing authority. Candidate and seal verification still independently checks accepted evidence, source geometry, actual CMS and RFC 3161 facts using stored public certificate material, without a current private key.

The completion prefix remains bounded and hash-verified. Later download/delivery audit events may grow beyond the original certificate's event/page budget without changing that historical snapshot or preventing final access. These reads do not claim to verify the later tail. Source, candidate, stage, publication or completion-proof changes fail closed, including changes during final I/O.

Final reads pin the recorded blob version and ETag, verify every byte/hash and compare the pair with the exact winning private seals. Before the recorded finite protection deadline, weakened storage protection is rejected. After that deadline, a still-existing exact version remains readable and cryptographically verifiable; no extended retention promise is implied. A recorded indefinite legal hold must still be present.

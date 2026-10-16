# Durable completion worker

Publishing the last signer checkpoint now prepares one supported `Sealing` work item in the same SQL transaction. The versioned payload binds the exact current Finish, checkpoint hash, disclosure hash and signing order. Its stable envelope/version-derived ID prevents duplicate completion jobs. Intermediate checkpoints retain sequential invitation behavior.

The storage hint is durable before the checkpoint/job transaction commits. The queue notification follows commit; storage-only recovery can republish a lost notification. A verified replay of an already processed last checkpoint can repair missing supported completion work. Empty queues still return without opening SQL, and unrelated worker deliveries do not resolve completion storage or sealing providers.

## Pipeline and ownership

The finite handler verifies its exact lease/payload and the authoritative all-signed current checkpoint, then resumes [candidate preparation](completion-candidates.md), [both seal stages](completion-seals.md) and [immutable final publication](final-publication.md). A scoped internal worker guard rechecks the same lease under the common envelope lock at each durable candidate, seal, intent and final-publication boundary. An expired/replaced worker cannot commit new completion records. Lease-bounded cancellation supplements these checks.

Already committed stages and final target IDs survive reconstruction. If publication committed but the work acknowledgement was lost, a later lease verifies and reuses the existing completed pair without another private-key acquisition or timestamp request. Historical on-time accepted evidence remains verifiable after original signer sessions expire. User sessions and edits are never restored.

The guarantee is one authoritative completion result and one embedded platform seal per final file. A crash before a stage becomes durably recoverable or concurrent attempts can require redundant TSA requests; this is not an exactly-once remote-request promise.

## Configuration and recovery

Use the existing finite `work once` command and storage-only `work recover` mechanism. New sealing requires explicit supported provider/TSA configuration; final publication requires explicit retention and truthful existing storage protection as described in the publication guide. Registration has no provider, storage or database I/O. Missing dependencies produce bounded retries with fixed redacted failure codes; invalid source/evidence produces a failed work item. Neither outcome fabricates Completed.

`CompletionJobs.ResumeAsync` is an explicit internal recovery operation for a known, verified all-signed Sent request. It creates/reuses the same scoped job and republishes its hint/notification. There is no recurring SQL discovery or public resume route. It does not silently reset terminal work or replace another lease; failed work requires operator review.

Completed records become visible in the existing private sender status page. The signer's existing confirmation remains a readonly accepted checkpoint, with its actual Finish/Date Signed and own-copy download. Authorized final-pair download UI and completion-email delivery remain separate planned work. `Completed` records final publication, not successful delivery to every party.

Local verification uses synthetic NO AGREEMENT requests, generated loopback TSA certificates and explicit Development demo application write-once storage. It makes no live cloud/TSA/email call and selects no real operator retention or disclosure policy.

# Immutable completion candidates

QUILS-44 adds internal `CompletionCandidates.PrepareAsync` and `ReadAsync`. Explicit preparation freezes one authoritative QUILS-43 evidence snapshot and one unsigned executed PDF per envelope. The PDF includes the exact last checkpoint's visible document pages and the completion appendix produced by QUILS-42. This service has no public route, supported job producer, seal/TSA call, Completed transition or email operation.

## Durable ownership and retries

The candidate row binds its envelope, last accepted/published Finish and sequential copy version; exact source object/hash/geometry; unsigned packet object/hash/length/page counts; evidence JSON/hash and recorded snapshot time; historical audit sequence/anchor; frozen database-row binding; renderer/snapshot versions; and a canonical recipe digest. SQL enforces one candidate per envelope and a same-envelope Finish foreign key. The runtime role receives SELECT/INSERT with explicit UPDATE/DELETE denials, and the operator-invoked runtime verifier checks those restrictions. EF also rejects tracked updates and deletes; privileged retention will need its own explicit path.

Preparation collects verified evidence, renders outside the SQL transaction, conditionally uploads a new object and reads its exact bytes back. It then takes the common envelope lock, rechecks the full optimistic source state, and atomically records the candidate and `completion_prepared` system audit event. A concurrent winner keeps its earlier snapshot and exact bytes. A committed candidate is never rerendered or replaced after a storage failure.

An upload with a lost acknowledgement can continue only after exact length/hash verification. After a possible SQL commit, the service rereads authoritative state and verifies the saved object; uncertain objects are never deleted. If recovery itself is unavailable or cancelled, a later explicit retry reuses the durable row. A crash before the candidate commit has frozen no snapshot and can leave a private unreachable object for privileged envelope retention.

Known pre-commit rollback or a losing attempt cleans up only an object whose ownership was established by successful upload or exact-byte recovery and whose lack of a candidate reference is rechecked under the envelope lock. Cleanup uses a separate ten-second cancellation budget. Failed cleanup leaves private bytes for retention; it does not enqueue an unsupported purge job or delete a guessed object.

## Reading the same historical evidence

The collector retains its full audit-anchor-sensitive optimistic binding for new preparation. A separate frozen-row binding excludes only the audit anchor, allowing verified appended operational events without invalidating the candidate because of its own preparation event. It still includes the original frozen rows and their row versions. Restoring a changed row's visible values does not restore its previous binding.

Saved reads collect current authoritative evidence again, verify the complete canonical chain, and compare the same historical prefix and original snapshot time against the saved typed evidence digest. Current source, party, accepted field/adoption/mark and Finish bindings must match. The exact canonical preparation event must still be present in that verified chain. Candidate storage reads are bounded and checked against the committed length/hash, followed by another locked source/anchor/candidate/preparation-event recheck. No historical session or edit authority is restored.

The evidence snapshot is complete through its recorded anchor. Later preparation, sealing, publication and delivery events are external to the certificate's pre-seal chronology. The returned prepared-packet DTO contains the saved unsigned packet and its source/evidence/page bindings; its separate `AppendixBytes` is empty on saved reads because the appendix is already inside the packet and standalone certificate rendering does not require a second appendix copy.

## Storage and limits

Candidate objects use a separate `completion-candidates` path beneath their envelope in the existing private normalized-document container. A new internal object kind avoids aliases through ordinary normalized-document references. Only an in-process capability for the exact envelope/object/kind and single read, write or delete operation grants access. Capabilities expire after two minutes and reject altered identities. Public sender/signer sessions cannot obtain candidate authority.

PDFs remain bounded to 64 MiB and 200 total pages, including at most 64 certificate pages. Evidence retains existing renderer limits and has a 32 MiB UTF-8 serialized ceiling, with SQL text-size checks before materialization; source geometry is bounded separately. Counts, hashes, versions and same-envelope references fail closed. Original, sent and accepted checkpoint bytes stay unchanged.

Final sealing/publication must use this committed candidate's exact packet and snapshot, verify its eligibility at publication and durably recover both sealed outputs. Final attachments, download authority, delivery and the Completed state remain dependent work.

# Resumable completion seals

QUILS-45 adds internal `CompletionSealOutputs.PrepareAsync` and `ReadAsync` on top of the committed [completion candidate](completion-candidates.md). These operations prepare and verify private sealed outputs. They have no public route, completion work producer, Completed transition, final publication or email behavior.

## Two immutable stages

The first stage consumes the candidate's exact unsigned executed packet and applies the [platform seal](platform-pdf-seals.md). The second renders the standalone completion certificate from that same historical snapshot and the first stage's verified executed-file hash/seal/timestamp facts. It seals the standalone form using the first file's exact platform certificate fingerprint. A changed/unavailable configured identity fails before another timestamp request; it never silently chooses a replacement.

Each successful stage has one immutable SQL row per envelope/candidate/kind. The row binds the candidate recipe and shared evidence hash; source object/hash/length; sealed object/hash/length/page count; versioned metadata and recipe; and a canonical system audit event. The standalone stage also binds the executed-file hash. Its exact unsigned source is retained privately, so recovery verifies the original source bytes instead of rerendering them. The runtime role receives SELECT/INSERT with explicit UPDATE/DELETE denials; EF also rejects tracked updates/deletes. Same-envelope foreign keys and unique indexes protect ownership.

The candidate, original upload, immutable sent PDF and accepted checkpoints remain unchanged. The certificate chronology remains complete through the original pre-seal snapshot; later preparation/seal/publication/delivery events are recorded externally. Neither output contains its own recursively calculated final hash.

## Verification and recovery

Successful reads revalidate the authoritative candidate and historical audit prefix, the actual stored source/sealed bytes and their complete length/hashes, and the canonical stage evidence. They independently verify the full-file CMS signature, signer certificate binding and RFC 3161 signature/imprint/trust/time facts using the existing production verifier. Stored public leaf DER must match the certificate fingerprint; no private key or current provider access is needed to read an already successful output. Historical verification uses the retained configured TSA trust roots and actual timestamp time, with certificate downloads disabled.

Page geometry is checked against the exact unsigned source. After I/O, locked checks verify frozen signing/candidate state, output row versions/recipes and stage evidence. The standalone stage also rechecks its exact executed predecessor and audit proof. Verified appended operational events are allowed; source changes, altered predecessor evidence or changed/deleted stage records fail closed.

Retries reuse a successful first stage after second-stage failure. Concurrent attempts select one committed winner per stage, and later work uses that winner's exact bytes and certificate identity. Missing/corrupt successful files are errors, never permission to regenerate or reseal them.

Upload acknowledgements are recovered by exact-byte readback. Each stage row and audit event commit atomically after source/predecessor rechecks. Lost SQL acknowledgements recover by authoritative reread; cancellation or an unresolved possible commit retains potential references for a later retry. Only proven unreferenced losing/rolled-back attempts are deleted under the envelope lock, with a separate ten-second cleanup budget. Uncertain or failed-cleanup objects remain private for privileged retention.

A crash before sealed bytes and their authoritative row become durably recoverable can require another timestamp request. Concurrent attempts can also make redundant requests. The contract is one embedded platform seal per published file and reuse of committed successful outputs; it is not an exactly-once remote TSA request guarantee.

## Storage and operational boundaries

Executed seals, unsigned standalone sources and standalone seals use distinct `completion-seals` subpaths/kinds within the existing private normalized-document container. Exact in-process capabilities grant a single object and operation for at most two minutes. Public sender/signer sessions and ordinary normalized references cannot access or alias them. PDF reads/writes are bounded to 64 MiB and 200 pages; certificate pages retain the renderer's 64-page bound. Public certificate material is bounded to 64 KiB and versioned metadata to 128 KiB UTF-8, with SQL size checks before loading it.

Seal services register idempotently and perform no registration/startup database, storage, key or network I/O. There is no default TSA. New sealing requires explicit valid private provider/TSA configuration; generated local tests use a loopback TSA and synthetic certificates only.

The service currently verifies all-signed Sent envelopes, including historical on-time accepted work after session/deadline expiry. Final publication must explicitly bind both sealed files and account for its own final fields/Completed transition, then provide narrow completed-copy read authority and delivery. It must not revive editing or pretend its own operational writes are unchanged source row versions.

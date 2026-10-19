# Restricted completion timestamp boundary

QUILS-134 supplies source-only composition for the restricted operator pilot. Application and worker startup do not call `AddPilotTimestampBoundaryFoundation`. This change does not enable the pilot, email, timestamps, cloud services or deployment.

The scoped `PilotTimestampBoundary` reads a nominated owned sealing lease and its exact completion payload. It uses an indexed enrollment lookup independent of current run configuration. An enrolled envelope cannot become ordinary work when its run is disabled, expires, changes, loses protected secrets or has corrupt evidence. The existing pilot work authority verifies admission, the fixed roster, accepted Finish/checkpoint chain and current source. An absent or rejected pilot scope resolves no completion pipeline or certificate provider.

The boundary mints immutable server-only work and artifact contexts. Each artifact binds the envelope, candidate, Finish, copy version, candidate recipe and owned source digest. Certificate artifacts also bind the persisted executed seal and recipe. Caller byte arrays are copied before asynchronous checks. The PDF engine verifies its own source copy against this context before certificate acquisition, then checks again after acquisition. The singleton PDF and timestamp engines receive these contexts per call; neither captures a scoped database or ledger.

Immediately before a bound HTTP request:

1. Acquire the existing shared timestamp coordinator and retain its lease through response processing and disposal. Pilot configuration must retain a minimum interval of one second.
2. Recheck the owned work/run/source/artifact and reserve a nonrefunded attempt in the independent ledger transaction. Its request digest is SHA-256 of the complete encoded RFC 3161 request, including its nonce. The run permits at most four timestamp attempts.
3. Recheck coordinator ownership, consume the one-use exact-request permit, and recheck current authority before HTTP. An existing receipt, mismatched digest or unknown commit acknowledgement permits no call. A new worker lease can make another bounded attempt; it cannot refund a prior attempt.
4. Use the configured fixed endpoint with no redirects, cookies or proxy, an exact HTTP/1.1 request and connection close. There is no application retry. Bound timeouts end at the earlier work/run deadline. A response received after authority expires cannot produce a seal.

The explicitly composed singleton policy marker blocks unbound seal/probe requests before certificate access. Ordinary uncomposed sealing retains its existing behavior. Timestamp token verification and saved-output reads make no request and reserve no attempt. The original accepted source and normal completion publication checks remain authoritative.

Local tests use actual pilot admission, normal synthetic sender verification and both signers' consent, adoption, field application, Finish and published checkpoints. Email delivery is an in-memory fake; timestamps come from a synthetic loopback authority. Tests cover the two exact completion artifacts, actual POST digests, coordinator lifetime, consumed receipt and concurrent replay, budget exhaustion, disabled/corrupt/changed authority, source/candidate/lease changes, expiry during certificate acquisition/coordinator/preflight/HTTP, and a database interceptor that loses acknowledgement after the real reservation commit. No external provider is called.

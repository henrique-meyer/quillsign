# Restricted operator lookup

This source component is not registered by application or worker startup. Public email and public lookup intake remain disabled. It adds no recipient field or public endpoint.

An explicit capability-authenticated operator request selects the existing pilot manifest's Sender and its sole enrolled Completion scenario. The normal completion verifier reads the exact published PDF pair before admission. A second request for that run recovers the original request; it cannot create another lookup message. A lost commit acknowledgement is reconciled by that same immutable identity.

Append-only operational mappings bind the original protected lookup request, retention snapshot, completion publication and each issued token/worker attempt. They contain identifiers and digests rather than mailbox copies. They have no envelope, outbox or token foreign keys, so document/contact purge can proceed. Existing manifest-secret cleanup and lookup contact retention remain responsible for personal data.

Lookup work, outbox and outgoing MIME keep `EnvelopeId = null`; lookup tokens remain System tokens without envelope, party or mailbox columns. A distinct typed sender obtains its accounting subject from authenticated mapping evidence and charges the existing application/byte budgets. It preserves the captured prepared MIME bytes, commits a nonrefunded reservation before lazy credentials, and rechecks source, configuration, suppression and deadlines afterward. The envelope-only pilot sender remains unchanged.

A nullable immutable lookup request marker on tokens and an optional protected run marker on mail payloads prevent known pilot evidence from falling into ordinary lookup when mappings are missing. Null markers are omitted from ordinary serialization. No address alone grants pilot authority.

The normal explicit mailbox-link confirmation and one-use redemption remain required. Pilot sessions list only the bound retained publication, have no next-page cursor, and can create only a read-only final reader for that publication. Both temporary reader token and reader session are bounded by the original lookup session. When the optional lookup gate is composed, ordinary sessions exclude enrolled pilot envelopes. The separate overall pilot reader guard must also be composed for later configuration/capability revocation of a handed-off reader.

Lock order is completion parent, global lookup admission, owned work, outbox and token. The budget reservation happens only after the submission-intent transaction commits. Unknown commit/provider outcomes preserve intent; an already-consumed reservation is never translated into evidence that no earlier provider call occurred.

## Composition and rollout

The private operator page owns CSRF, HTTP rate limiting and capability submission. It calls `EmailPilotLookupAdmission.RequestAsync(capability, serverIp, cancellationToken)` with no caller-supplied mailbox or envelope. The result reports only request identity, recovery and wakeup state.

Compose `EmailPilotLookupAccess` in the normal scoped lookup backend, `LookupLinkDelivery` and optional email-dispatch pre-routing, plus a lazy `Func<EmailPilotLookupSender>` for this typed path. All closures must resolve the same scoped database. Reuse the existing run/cohort ledger, seven-day contact-retention configuration, completion publication verifier and dedicated raw SES adapter. Compose the global pilot completion reader guard as well. Missing composition never enables public intake.

The appended migration adds two operational tables and the nullable token marker. Runtime access is deliberately SELECT/INSERT only for the mapping tables, with UPDATE/DELETE denied and token-marker updates denied. It adds no cleanup authority, grant at startup, hosted migration or cloud operation. Any rollout must separately apply checked schema and its exact approved runtime grants.

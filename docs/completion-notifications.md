# Completion notifications

QUILS-52 connects immutable final publication to the existing finite email worker. When durable work is enabled, publication creates a supported `completion-ready` outbox/work pair for each distinct frozen email destination in its own transaction. A sender who also signs receives one message. The stable primary link identity is the sender first, then the first signer in signing order, then a recipient. Each link grants only readonly access to the exact completed packet.

The publication transaction also records canonical queued evidence and durable storage hints. Wakeups are published after commit. Retries and explicit recovery preserve existing leases and terminal outcomes; ordinary pages and file GETs never enqueue mail. For an already completed packet, an operator can run the finite command below with its internal envelope ID:

```powershell
dotnet run --project src/QuillSign -- work resume-completion-notifications <32-character-envelope-id>
```

This command verifies the actual retained pair before restoring missing supported work. It does not discover envelopes through idle SQL polling, reset failed or ambiguous submissions, expose an issuer endpoint, or regenerate PDFs. Existing `work once` and storage-hint recovery process the resulting work.

## Dispatch and attachments

Dispatch verifies both exact stored final versions, hashes, seals, frozen source and party membership without acquiring private signing keys. It checks the parent envelope before the work lease, checks canonical queue evidence, and obtains a fresh party-bound completion link in the submission transaction. Queue delays therefore do not consume the link lifetime. Link and reader lifetimes remain bounded by actual retention and are independent of the old signing deadline.

The message contains `QuillSign-executed.pdf` and `QuillSign-certificate.pdf`, copied from the verified published bytes. HTML escapes the title and other model values; plain text and HTML provide a scanner-safe fragment link to the explicit Continue/Open records flow. Recorded completion, retention and demo facts are used without inventing operator policy.

If the verified pair exceeds the configured decoded or estimated encoded attachment limit, the message explicitly states that files are not attached and instructs the recipient to save both through the private link. Every link-only message includes this warning, including the sender's. Missing, corrupt, stale or unavailable records never trigger size fallback. Transport bounds are described in [email-attachments.md](email-attachments.md).

## Submission and recovery

Protected queue payloads bind the publication, recipe, revision, exact file references and frozen primary party. Raw link codes and PDF bytes are never stored in outbox payloads. Only the token record reference is added for an attempted submission; raw transport remains in memory. Audit records contain scope/file hashes and truthful queue, attempt and provider-acceptance facts, without link codes or protected payloads.

Submission intent is committed before calling the provider. A definite non-submission can clear that intent and retry with a fresh link; old unused hashes retain their original expiry. An unknown result after the provider call retains intent and follows existing ambiguous-submission recovery, which forbids automatic resend or replacement issuance. Successful provider acceptance does not establish inbox delivery, receipt or saving. Disabled email and suppression remain enforced.

Email is still disabled by default. This workflow does not enable live sending, configure cloud resources, choose legal retention/disclosure policy, or give completion readers signing or sender authority.

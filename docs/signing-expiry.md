# Signing request expiry maintenance

QUILS-57 adds a trusted finite `SigningExpiry` operation and `work expire` command. It records the terminal Expired state for a Sent request whose configured UTC signing deadline has elapsed. Existing signer and invitation checks continue rejecting new activity at the deadline even before maintenance records the terminal transition.

## Transition and recovery

Each operation takes the common envelope lock and verifies sent/current-copy metadata, sequential signer order, accepted Finish evidence and the bounded audit chain. It records the original deadline, server-observed expiration time, pre-transition row revision and a frozen-source/roster digest in one canonical System audit event. The status update, unused signer-token expiry and audit append commit together. Original sent bytes, saved fields/marks, accepted times and published checkpoints remain unchanged. Queued invitations cannot pass their existing eligibility check after expiry; this operation sends no message or notification.

Concurrent/repeated expiry calls verify and reuse the single saved event. Other terminal outcomes and drafts are skipped. Broken source/audit evidence cannot manufacture a confirmed expiry. Failed audit writes roll back; an unknown commit acknowledgement reports no new confirmed success. A fresh explicit operation reads authoritative saved state without duplicating the event.

An accepted, unpublished Finish defers expiry. The checkpoint worker can publish the exact on-time accepted review after the signing deadline; Signed and Date Signed remain the actual accepted Finish time. It verifies that acceptance and review were bounded by the deadline. Late processing does not create a next signer invitation. Once that intermediate checkpoint is published, maintenance can expire the remaining request. If all signers accepted on time, the final checkpoint/completion path remains eligible for sealing/publication after the deadline; maintenance skips the all-signed request. No old session or edit authority is restored.

## Finite operator command

Apply the migration, configure the existing database connection, then run:

```text
dotnet run --project src/QuillSign -- work expire
dotnet run --project src/QuillSign -- work expire 64
dotnet run --project src/QuillSign -- work expire 64 <continuation>
```

One invocation examines at most 1–64 due records (default 32) within the existing 240-second command deadline. A filtered `(ExpiresAt, Id)` index supports due discovery. A nonempty `NextCursor` means another explicit call can continue after the last examined key. The cursor is technical continuation input, not an access capability. Preserve it verbatim. A new pass without a cursor revisits skipped or failed records; pending accepted work must be recovered through the supported checkpoint/completion workflow first.

The JSON output gives counts and optional continuation only. `Failed` records include unverifiable evidence or an uncertain write result and require inspection/retry; they do not stop later records in the same bounded pass. Partial results return exit code 1. An invalid command shape or batch count returns usage; an invalid continuation fails without echoing its value. SQL outages and cancellation stop processing without claiming unfinished work succeeded. Rollback/committed states remain safe for a later explicit retry.

The command works with durable work disabled and performs no queue, storage, email, private-key or timestamp operation. It opens SQL only during the explicit invocation. This slice creates no background timer, recurring SQL discovery, delayed job, automatic expiry notification, reminder delivery, retention purge or cloud resource. Automatic scheduling and notices remain separate work; there is no claim that this command runs itself at the deadline. Operator retention/disclosure settings are unchanged.

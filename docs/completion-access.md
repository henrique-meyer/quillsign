# Completed-record retrieval

Completed-record access covers the frozen sender, signers and completion recipients. QUILS-49 provides party-bound authentication and exact-file reads; QUILS-50 adds the private browser entry and downloads. Completion-mail issuance, attachments, delivery and lookup/resend remain later supported slices.

## Opening and saving records

Open a supported completion link with a fragment access code (`/complete/access#token=<code>`), or enter its code manually at `/complete/access`. The browser removes the fragment from history promptly. Select Continue to prepare the link, then Open records to use it once. Preparing a link does not consume it or log you in. If another tab prepares a different link, the original confirmation fails instead of silently opening that other link.

The completed-record page shows the request's completion time and the current session/retention limits. Select Download executed PDF or Download certificate of completion to prepare and save the exact published files. The executed PDF includes all saved signer entries and the certificate; the separate certificate provides a standalone copy of the evidence. Save both before access or server retention ends.

Access is readonly and does not restore signing or editing. A used or expired link cannot create another session. If opening access could not be confirmed, the link may already be consumed; return to records if you already opened them, or ask the sender for another copy. Missing or unverifiable storage shows a private retry message and never regenerates or replaces the packet. Refresh manually to retry.

Completed retrieval has its own `CompletionAccess` token purpose and `QuillSign.CompletionReader` identity. It cannot authorize sender edits, signer fields, Finish, worker operations or direct blob access. The existing sender/signer download flow continues to require its original live sessions; this backend can operate after those sessions and the signing deadline expire, while the completed record remains retained.

## Scope and stored evidence

Before issuing or redeeming a link, the backend verifies the existing published PDF pair, including its original source, frozen signing evidence, exact stored versions/hashes and CMS/RFC 3161 seals. It derives party identities from verified frozen rows under the common envelope lock; callers cannot choose an arbitrary email address.

`AuthTokens` gains nullable publication ID, publication-recipe SHA-256 and party-scope SHA-256 fields. The party scope includes the publication revision as well as the exact party type, ID, name, address and signing order where applicable. Completion tokens require these bindings and leave the older signer-document fields empty. Existing token purposes retain their previous bindings. SQL purpose/scope/hash constraints and a publication foreign key enforce the record shape; EF rejects changes to completion-token bindings after insertion.

Only the SHA-256 of a cryptographically random 256-bit link token is stored. Canonical issuance and redemption audit records bind the token record, party, publication, expiry and consumed session facts. Raw tokens and protected session receipts are absent from those audit payloads. Issuance and redemption demonstrate possession of a scoped link; they do not establish inbox delivery, government identity or a new signing act.

## Transactions and sessions

- `IssueAsync` owns a clean unit of work and returns raw transport only after a confirmed commit. Internal `PrepareAsync` and `PrepareLockedAsync` support a later trusted delivery transaction: verify outside the transaction, then recheck under the envelope lock and protect the raw payload before that caller commits. The preparation context is bounded to two minutes and retention.
- `RedeemAsync` locates scope, locks the envelope before the token, verifies canonical issuance and current publication/party state, then conditionally consumes the token once. It appends redemption evidence and returns a protected session receipt only after a confirmed commit. Concurrent losers and consumed links return no new session.
- A dedicated-scheme principal must match its bounded Data Protection receipt. Authentication rechecks the consumed token revision, session nonce and original lifetime, canonical evidence, frozen party/publication and retention. A link's expiry controls redemption; an already established session retains its own original bounded expiry.
- `ReadAsync` verifies the actual immutable pair and rechecks authority after I/O before returning either exact file. Authentication and reads do not append audit events, prepare packets, regenerate PDFs or acquire a new seal. Changed completed-source conflicts produce controlled integrity failures; active-draft conflict behavior is unchanged.

Rollback returns no transport/session and does not leave pending entities to be accidentally saved on a standalone retry. An unknown issuance commit may leave an unused hash that expires. An unknown committed redemption leaves the link consumed and returns no session; it is not silently replayed into a replacement session. A later explicit fresh issuance is the recovery path. Caller-owned preparation leaves commit, rollback and change-tracker ownership with that caller. None of these paths enqueue unsupported delivery or delete retained files.

## Technical lifetime configuration

`CompletionAccess:LinkHours` defaults to 24 and permits 1–168 hours. `CompletionAccess:SessionHours` defaults to 1 and permits 1–24 hours. Both are shortened by the completed record's current retention boundary. These settings control authentication lifetimes; they do not select a legal retention policy or change operator disclosure settings.

The HTTP flow uses its dedicated named authentication ticket and separate private bounded receipt cookie, with the original backend expiry and no sliding renewal. Explicit antiforgery-protected, rate-limited POSTs redeem links or prepare downloads. Ordinary page/file GETs never consume tokens, prepare grants or mutate domain state. File grants bind the reader audience, full authenticated cookie, receipt, party, publication/revision, exact kind/hash/version and fresh nonce. Authorization is checked again after I/O and under the final parent lock. Existing sender/signer downloads remain separate audiences. Cookie clearing is a normal-browser convenience; an authenticated copy of a grant can repeat readonly reads until its original two-minute/session/retention limit. Preparing or serving a download does not prove receipt or saving.

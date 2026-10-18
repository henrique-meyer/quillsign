# Verified invitation succession

QUILS-114 supplies a shared integrity reader for original invitations, existing
manual resends and future canonical successors. It creates no successor mail.
Supported preparation and delivery follow in QUILS-118; actual reminder and
contact-correction producers remain separately gated work.

An invitation belongs to a specific signer slot, immutable contact revision,
recipient, PDF object/hash and electronic-record disclosure hash. A successor
also identifies its exact predecessor, reason, admission time, bounded dispatch
deadline and reason-specific authorization digest. Its outbox payload is
purpose-separated and protected. Canonical audit evidence verifies the actor,
reason, time, scope and hash; this integrity format alone is not authorization
to send mail or alter contact details.

`InvitationLineage` runs inside the caller's envelope transaction. It consumes
only `VerifiedSignerContacts` from the complete persisted contact-history
verifier, and resolves each historical recipient against that entry's exact
contact epoch. A retired recipient is not compared with mutable current email.
The original invitation is bound to reviewed Send or the signed predecessor's
published checkpoint. Entries must form one chronological, nonforking chain
with settled predecessors and unchanged PDF/disclosure bindings. Correction
successors bind the verified contact revision and its exact digest. Missing,
orphaned, oversized, altered or uncertain evidence cannot become a successful
fallback to the original invitation.

Existing original and manual-resend formats have an explicit unchanged-contact
bridge. Zero contact fields are omitted from original invitation serialization;
existing ciphertext can still be read. New original invitations for a corrected
later signer bind the verified current contact revision. Newly issued tokens
carry that exact immutable revision using QUILS-115's nullable token binding.
Original and legacy resend dispatch cannot overtake a canonical successor.
The legacy manual-resend producer cannot authorize a corrected contact; its
reviewed canonical producer must handle that integration separately.

Sender status reports the latest canonical invitation independently of signing
progress. A retired invitation stays retired even when its address is reused.
An old opening is not reported as activity in a corrected contact epoch, and
queued or provider-accepted mail is not described as inbox delivery.

Reads and audit/payload sizes are bounded. No idle SQL polling or new recurring
job is introduced. The QUILS-115 migration and permission package must be applied
through an approved rollout before deploying code that uses its new token
column or enabling contact-aware features. This source change does not deploy
that migration, change cloud resources, enable public email or activate the
synthetic demo's deferred reminders/contact-correction settings.

QUILS-118 provides the internal delivery path and correction preparation API.
`InvitationSuccessorJobs.RetirePredecessorLockedAsync` runs before a correction
is persisted, inside the caller's envelope transaction. It permits settled
predecessors and can retire queued or leased work only when there is no
submission intent, provider receipt or ambiguity. Its audit explicitly means
never submitted, rather than a recall. The caller must roll back the entire
transaction if admission fails. `PrepareCorrectionAsync` then verifies the
saved revision, retirement, projection and audit, creates deterministic
revision-bound work, and puts a durable recovery hint before commit.
`PublishAsync` runs after commit; a lost queue response does not discard the
hint. A retry reuses the exact saved admission.

Delivery requires exactly one enabled `IInvitationSuccessorPolicy` for its
reason. The policy verifies persisted feature authority and cap reservation
under the caller's envelope lock; it must neither commit nor call transport.
Acquire any shared cap lock before inserting revision or reservation evidence.
No reason-specific policy is registered by this slice, so a protected payload
alone cannot activate delivery. Feature integrations own those policies and
their bounded admission rules.

The worker revalidates current contact, source, disclosure, canonical latest
predecessor, deadline, retention, suppression and lease before committing a
fresh token and protected submission intent. Same-contact replacements retire
unused links while preserving redeemed sessions. Correction separately retires
prior contact authority. Transport runs outside SQL. A definite rejection may
clear its exact intent and retry; uncertain commit, provider or receipt results
retain evidence and cannot blindly resend. Provider receipts do not claim inbox
delivery, and already received bounce/complaint state is preserved. Mail copy
distinguishes reminders, replacement links and corrected contacts; opening any
of these remains separate from consent or signing.

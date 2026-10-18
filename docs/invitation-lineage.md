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

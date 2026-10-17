# Fixed document retention

`Demo__PurgeAfterDays` is an optional positive integer from 1 through 36500. It remains unset in examples. Configure actual deployment values privately; the selected demo policy is seven days from the first successful document upload.

For a stored demo envelope, the first successful upload freezes one immutable `DocumentRetentionSnapshot` in the upload transaction. It records the policy version, selected days, UTC start and exact deletion deadline, and the first original/normalized object identities and hashes. The first upload audit binds the complete snapshot. A failed upload starts no interval; a committed upload whose acknowledgement is lost retains its original snapshot and readable objects.

Replacements preserve the first snapshot even if configuration changes or becomes unset. Replacement at or after its deadline is rejected. Concurrent first uploads use the common envelope lock and reviewed row version, so only the winning upload can establish the snapshot. Runtime SQL permissions permit snapshot reads/inserts and deny updates/deletes; EF also rejects tracked mutations. A later privileged purge path must deliberately remove these records.

Ordinary envelopes and unconfigured demo envelopes are not enrolled. Existing uploaded demo documents without a snapshot require an explicit migration decision before replacement after the setting is enabled. The application does not infer an earlier upload time, silently backfill them or reset their age. Reading a document does not create a snapshot.

This foundation does **not** schedule deletion, expire every read/signing capability, or change hosted storage. Legacy `Envelope.PurgeAfter` and completion-based retention remain separate until the dependent alignment slice. Completion publication for newly enrolled snapshots fails closed rather than adding a fresh interval at completion. Finish final-protection/deadline alignment, purge orchestration, disclosure text, and hosted validation before enabling this setting in the public demo. Existing completed ordinary/legacy records retain their established behavior.

Deletion must account for immutable blob versions, soft delete, backups and service logs. A logical deadline must not be described as immediate irreversible erasure of every recovery copy. No Azure/AWS resource or policy is created or changed by this code.

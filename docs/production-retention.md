# Frozen production retention

Set `Records__Mode=Production` only with every `Records__Production__*` value and complete, truthful `ElectronicRecords__*` operator policies. The synthetic demo profile is rejected. Version and archive responsibility are operator text; the project supplies no production policy or recommended legal interval. The configuration example leaves those values empty. `Demo` remains the default.

An ordinary new production request atomically saves its immutable policy, exact original creation time and enrollment audit evidence before requesting email verification. Normal verification remains necessary. Changing settings affects future records; it cannot reclassify an existing demo, enroll an old record or change an existing production clock. The restricted demo pilot retains its separate admission rules.

| State | Retention clock |
| --- | --- |
| Unsent draft | Original creation plus the frozen abandoned-draft interval; document replacement does not restart it |
| Signing pending or completion incomplete | No automatic retention deadline; session and signing deadlines still apply |
| Expired | Effective signing expiry plus the frozen expired interval, even if maintenance executes later |
| Declined | Actual authenticated decline plus the frozen declined interval |
| Voided | Actual authenticated void plus the frozen voided interval |
| Completed | Actual immutable publication plus the frozen completed interval; explicit `0` means indefinite preservation |

All finite values are positive whole days, measured as elapsed durations. Exact original timestamps are retained alongside normalized audit/policy clocks. Operator text and the saved policy reference appear in the electronic-record disclosure reviewed at Send and later accepted by the signers. Send rejects a stale policy review. Historical disclosure and publication formats remain verifiable without rewriting their bytes.

Terminal status alone is insufficient. The actual transition atomically captures one anchor bound to its authoritative evidence. Reads verify the saved enrollment and terminal prefix under the common record lock; missing, orphaned or conflicting provenance fails closed. Later operational access events neither renew a deadline nor invalidate the original bounded signing snapshot. Readers do not manufacture anchors or repair missing enrollment.

Final publication binds its recipe to the authenticated production policy, verifies the exact sealed bytes and actual immutable protection, and rejects development write-once protection for production. Finite protection must cover the exact actual completion interval; an adapter may preserve longer, never shorter. Explicit indefinite preservation is separate from a case-specific legal hold. The application does not provision or shorten locked cloud protection through these settings.

Sender, signer, completed-record lookup, final-download and notification paths check the saved access deadline after their own authorization. A stale pre-transition record cannot hide a terminal deadline. Narrow final-read capabilities also expire during an in-flight read at a finite access cutoff. Preserved bytes, including indefinite preservation, do not renew an expired session or invitation or grant broader access.

A retention deadline alone grants no deletion or hold authority. The connected hold/operator controls and separately enabled [production deletion](production-deletion.md) enforce the additional evidence boundaries. Complete hosted/self-hosted acceptance remains required in QUILS-150. A retention eligibility date is neither proof of physical erasure nor a guarantee of enforceability. Cloud rollout, grants and actual destructive operations require a separate reviewed deployment.

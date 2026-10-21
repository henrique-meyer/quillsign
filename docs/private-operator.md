# Private production record controls

The source includes a private operator workflow at `/operator/retention`. It is
disabled by default. Participant magic links, participant cookies, email
addresses and identity-provider roles do not grant operator permission. This is
source functionality, not a hosted deployment or a claim of production readiness.
Production deletion/recovery and complete installation acceptance remain separate
requirements in the [implementation plan](plan.md).

## Explicit configuration

Keep all actual identity, storage and policy values in private configuration.
The committed example contains empty values only. Enabling the workflow requires
both `ProductionOperator__Enabled` and `ProductionHolds__Enabled`, a complete saved
production-policy configuration under `Records`, ordinary production disclosures,
Azure managed-identity storage and an enabled worker. It registers the coordinator
and completed participant/worker admission adapters together; a UI cannot enable
holds while leaving ordinary record mutations outside the admission boundary.

`ProductionOperator__Issuer` is the exact HTTPS OIDC issuer.
`ClientId` and `ClientSecret` identify the operator's confidential client. Register
the exact HTTPS callback path `/operator/retention/signin-oidc` at that provider.
The actual middleware validates the signed issuer, audience, lifetime and nonce;
authorization-code requests use PKCE and correlation/state. No automatic public
signup or participant challenge is added.

Each `ProductionOperator__Grants` entry explicitly supplies `Subject`, plus the
separate booleans `Status`, `PlaceHold`, `ReleaseHold` and `ReadEvidence`. The
issuer and subject must match exactly. Status does not imply sensitive-read or
hold permission. Configure status together with the desired action permission
so an operator can select and review the record before acting. A dedicated
Secure HttpOnly cookie has an absolute maximum lifetime of five minutes, with
no sliding renewal. After a restart loads changed effective configuration, removing a grant denies subsequent requests. Configuration is captured at host startup; this does not promise live configuration reload.

`ProductionHolds__InstallationId` is a stable, nonempty lowercase GUID in `N`
format chosen for this installation. Preserve it across restarts, restores and
operator disablement. `WitnessContainerUri` names the exact existing private
version-enabled immutable witness container, with a canonical HTTPS URI and no
trailing slash. The namespace digest is derived from the versioned installation
ID and that exact URI. `InstallationDigest` may stay empty for derivation; a
supplied mismatch is fatal. A cosmetic URI variation must not select another
namespace. Never change this pair to bypass missing or retained evidence.

`ServiceUri` must match the configured ordinary primary Azure blob service.
`AllowIndefiniteWitnessLegalHold` must be explicitly true when enabling witness
appends: those independent journal objects are created under legal hold without
an invented expiry. The adapter creates no container, identity or cloud grant,
and does not automatically clear witness holds. The managed identity, immutable
container and actual operator policies require their own reviewed installation
setup. The source performs no deployment during configuration.

## Exact-record actions

Operators select one exact record identifier with a CSRF-protected POST. Status
shows its saved policy/deadline, pending state, independent holds and historical
archive receipts. A separate explicit inspection reads actual exact-version
archive bytes and protection; a stored receipt alone is not a current protection
claim or deletion authority.

Placement and release have distinct review/confirmation posts. Confirmations
bind the exact purpose, command, record, hold, operator session, reviewed witness
head and an expiry of at most two minutes. Changed state, another session,
expired privilege and replay cannot create a replacement command. Each hold
continues blocking until its own exact release reconciles. An uncertain outcome
stays pending; inspect its recorded state instead of repeating provider effects.

Sensitive-read permission exports a bounded JSON **evidence inventory**: table
and object hashes, historical preservation receipts and private hold
reasons/references. It is not a raw document or complete-archive download, a
provider capability, a fresh protection inspection, or authority to delete.
Status and exports first save a bounded encrypted append-only private access
receipt. Audit failure denies the response. This receipt is observability only;
it is separate from participant audit/PDF evidence and is not an external
whole-database rollback witness. Existing hold command journals remain the
authoritative mutation record.

The route uses no-store, noindex and no-referrer responses, fixed clean URLs,
request bounds, CSRF and a private rate limit. GET does not read record metadata
or perform a command. Reasons, operator subjects, provider selectors and record
identifiers are not added to public discovery metadata or participant pages.

## Disablement and existing records

Disabling the operator does not remove the known record/worker admission gates.
An explicitly configured original witness location remains a read-only source;
production mutations and provider writes remain closed. Missing or inconsistent
evidence never becomes an empty-witness proof.

New genuine demo requests carry a closed original-demo creation fact inside their
existing protected initial verification payload. It binds the original record,
public ID, sender, creation time and demo classification. The disabled admission
adapter can authenticate that never-production origin without simulating an
external absence. It does not extend any token, session or retention deadline.
Production payload bytes and production enrollment rules remain unchanged, and
enabled production still performs its original external downgrade/restore check.

Legacy demos without that fact need the same explicitly configured witness
reader or fail generically. There is no automatic migration, retroactive origin
proof, production adoption or historical rollout in this change. Review that
limitation before changing an existing installation's image/configuration.

The new private-access-receipt migration is source only. Its runtime permissions
are narrowly scoped SELECT/INSERT, with application and SQL UPDATE/DELETE refusal.
No hosted migration, operator identity or production legal policy is supplied.

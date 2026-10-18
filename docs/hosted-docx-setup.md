# Hosted DOCX conversion setup proposal

The DOCX package gate, Gotenberg conversion client, upload persistence and sender preview are implemented. Local synthetic conversion has passed. Hosted conversion stays disabled while its isolated transport is prepared and tested. This proposal covers a bounded infrastructure pilot; it does not claim that the hosted sender flow works.

## Proposed Azure package

Create one `Microsoft.App/sandboxGroups` resource inside the existing project resource group. Give the existing web managed identity **Container Apps SandboxGroup Data Owner** on that group only. Give the signed-in operator the same group-scoped role temporarily for the pilot, then remove that operator assignment. Reuse the existing project identities and deployment region.

Use the documented `2026-07-01` ARM shape. Its optional environment link is unnecessary for the pilot. Older preview examples show CPU, count and timeout properties that the current ARM schema does not expose; those examples must not be treated as validated group-level spending controls. The operator plan must enforce its own workload limits. [ARM resource reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.app/sandboxgroups), [group-scoped access example](https://sandboxes.azure.com/docs/sandboxes/quickstart/setup-bicep).

The proposed workload is one active sandbox at a time, with 1 vCPU and 2 GiB RAM, using the existing pinned Gotenberg image. The pilot performs at most two synthetic conversions. Image import, sandbox execution and cleanup are separately bounded and recorded. This approval does not enable public conversion or email delivery.

## Conversion and isolation

The proposed transport uses authenticated file upload, a fixed conversion command against Gotenberg's loopback listener, and authenticated PDF download. It publishes no converter port. Each conversion starts with fresh state, fixed generated paths and a known synthetic source digest. The sandbox receives document bytes without application, database, storage, email or signing credentials.

Set default-deny egress with **Full** traffic inspection when creating the sandbox, before supplying a document. Read the policy back and require the exact expected settings. Verify actual outbound denial and its policy evidence; a timeout against an unreachable address alone is insufficient. Preserve the existing Gotenberg route restrictions and DOCX package validation. [Sandbox egress controls](https://learn.microsoft.com/en-us/azure/container-apps/sandboxes-egress-policies).

Keep the existing input/output byte limits, cancellation and PDF normalization. Check the original digest, returned media and bounded bytes, normalized PDF digest, both expected pages and visual output. The application adapter remains a later source change: the existing HTTPS-origin converter cannot be enabled by pointing it at an unauthenticated sandbox port.

## Deadlines, recovery and cleanup

The operator must enforce a 180-second execution deadline independently of auto-suspend. Azure auto-suspend measures inactivity; API activity can extend that interval. Stopping can retain a snapshot, so a stopped sandbox is not proof of deletion. [Sandbox lifecycle](https://learn.microsoft.com/en-us/azure/container-apps/sandboxes-overview).

Disable automatic retries for resource-creating writes. Record the run label and returned identifiers privately. After an uncertain acknowledgement, reconcile the exact owned inventory instead of creating a replacement blindly. Require an initially empty pilot inventory and stop if unrelated resources appear.

Delete the exact pilot sandboxes and any snapshots produced from them, and verify their absence. Remove the temporary operator role after cleanup. Delete the pilot disk image unless an explicitly approved follow-on needs it. If cleanup cannot be verified, preserve the private identifiers, stop further conversions and report the recovery action. Retain no document-bearing volumes or snapshots as an idle fallback.

## Cost and approval

The initial request is a **USD 1 usage budget for the two-conversion pilot**, including cleanup and measurement. It is an operator budget, not an Azure hard billing cap. It does not approve a permanently active converter, a paid support plan or general public sending.

As a reference calculation, 44 monthly conversions using 1 vCPU/2 GiB for 60–180 seconds each consume approximately USD 0.08–0.24 in active compute before shared free grants, using the rates checked during preparation. Count the complete allocated runtime, including startup and cleanup. These are estimates for the stated workload, not a guarantee about arbitrary traffic. [Container Apps pricing](https://azure.microsoft.com/en-us/pricing/details/container-apps/), [retail pricing API](https://prices.azure.com/api/retail/prices).

Image and snapshot storage must be accounted for separately. Microsoft currently describes that storage billing as coming soon at Premium Blob ZRS rates. A Docker image's local size is not a measurement of its converted, billable disk image. Measure the hosted image and retained inventory before offering a recurring total or promising a sub-dollar monthly bill. [Sandbox cost model](https://sandboxes.azure.com/docs/sandboxes/cost).

## Release gates

1. Review the private Bicep/parameter preview, group-scoped assignments, exact pilot operations and cleanup plan; obtain owner approval before deployment.
2. Validate provider availability, effective access, actual egress denial, two real synthetic conversions, normalized output and final cleanup.
3. Record measured lifecycle/storage costs and any service limitations. The inspected Python operator SDK is MIT licensed and marked community preview; it is not an application dependency or proof of provider behavior.
4. Prepare and validate the supported application transport in a separate source slice. Exercise sender upload, conversion failure/recovery, PDF preview/download and explicit confirmation before requesting normal hosted enablement.

No hosted conversion, new resource or permission grant is performed merely by merging this document. Keep [document conversion](document-conversion.md) and [hosted rollout](hosted-demo-rollout.md) evidence distinct from this proposal.

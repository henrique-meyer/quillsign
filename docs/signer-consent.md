# Signer disclosure, PDF review and decline

QUILS-27 adds the public signer consent flow on the QUILS-26 invitation/session foundation. Internal send/freeze and invitation dispatch are described in the send/freeze guide. After consent, the [capture UI](signature-capture.md) supports explicit signature/initials adoption; field filling and Finish remain subsequent work. No public token-issuance endpoint exists.

## Entry and private reads

`GET /sign/invitation?token=...` checks canonical token shape without database access or consumption. An explicit antiforgery-protected POST redeems once, issues the committed signer cookie and redirects to `/sign/{publicId}`. Invitation requests share the configured per-IP sender request limits. The app suppresses request-URL diagnostic logging; operators must also exclude invitation query strings from ingress/access logs.

Every private handler revalidates current sequential signer eligibility, the non-sliding session, Sent state and the frozen PDF/verified stored disclosure bindings. Private responses use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Sender credentials do not authorize signer pages.

The disclosure is the encoded, exact stored text, with a UTF-8 text download. Current operator settings never replace a sent disclosure. The read-only local PDF.js preview supports paging, fit/100%/200% zoom and selectable text. Download/open links provide a PDF viewer alternative.

PDF preparation stages the entire object within a hard 64 MiB bound, checks its length and SHA-256, and validates supported PDF structure/page limits. No bytes are returned on failure. Validation output is discarded: downloads contain the exact stored frozen bytes. Reads recheck scope after preparation. The structural parser is serialized to bound concurrent parsing work; the frozen PDF must already have passed the send-time policy.

## Consent evidence

Successful initial server preparation produces a protected ten-minute receipt bound to the complete signer identity, original session expiry, PDF hash and disclosure hash. It attests that the server prepared verified bytes. It cannot prove human reading, successful client rendering, understanding or legal sufficiency.

The signer separately selects preview or downloaded-PDF access and confirms both ability to view/retain the record and agreement to electronic records for this request. The two checkboxes start unchecked. With JavaScript, preview access becomes selectable after a rendered-page event; the download alternative works without JavaScript and relies on the signer's truthful report.

Consent POST rechecks PDF availability/integrity before attempting acceptance. Under the shared envelope lock, the service revalidates scope and receipt, records `ConsentAt`, IP and bounded user agent, and appends one signer-attributed `consent_given` event atomically. Evidence includes disclosure version/hash, frozen PDF hash, receipt ID, selected access method and explicit confirmations. Concurrent/repeated successful posts record once. Expired/foreign/missing receipts, missing confirmations, changed bindings and failed server PDF access cannot create consent. Reloading generates fresh access evidence when the ten-minute receipt expires.

After consent the clean page displays the recorded time and continues read-only review. Consent does not create a signature or alter document fields/PDF bytes.

## Decline and notification recovery

Before consent/signing, Decline accepts an optional reason of up to 512 characters. One envelope-locked transaction marks the signer and envelope Declined, records signer-attributed audit evidence and persists a protected `signer-declined` email outbox item with paired work. With durable work enabled, the hint is stored before commit and queue publication occurs afterward. Normal hint recovery handles a lost publication. Current-state validation ends all active signing access.

The clean decline confirmation displays the stored disclosure, states that delivery may be delayed/unavailable, and signs out the declining session. It distinguishes closing this request from the disclosure's broader withdrawal procedure. Paper/contact instructions come from the stored disclosure.

Disabling work/email must not prevent decline. A notification is still retained. If work was disabled, an operator may explicitly publish that **specific** queued notification after delivery configuration has been separately approved:

```text
dotnet QuillSign.dll work publish-notification <32-character-item-id>
```

This command does not enable delivery or change configuration. It accepts only an existing queued decline notification without submission intent and its queued work item. It stores a recovery hint and publishes a wakeup. It never scans SQL on an idle timer. Ordinary `work recover` remains a blob-hint recovery operation and does not discover items created while work was disabled.

Decline mail uses the existing work lease/submission-intent protocol. Definite provider rejection can retry; ambiguous acceptance is not resent automatically. Duplicate wakeups cannot resubmit a completed item. Suppression and disabled delivery remain enforced. Notifications contain no magic link or new auth token.

## Validation

Tests exercise actual Razor routes, non-consuming invitation GET, CSRF, private scopes/cache headers, exact downloads, per-IP limiting, unavailable/malformed/hash-mismatched/oversized storage, storage loss between page load and consent, receipt/confirmation failures, concurrent consent and transaction rollback. Decline checks cover protected payloads, disabled-work preservation, explicit item recovery, commit-before-publication, notification retries, duplicate delivery prevention and actual local Mailpit delivery. Browser checks use clearly fictional non-agreement fixtures on desktop and a 390-pixel phone, including paging/zoom, keyboard controls, PDF download, consent, decline and unavailable access. No live email or cloud resources are involved.

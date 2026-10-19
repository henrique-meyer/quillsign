# Restricted SES refusal evidence

The restricted pilot records a definite SES 4xx refusal as a bounded work/outbox reason:
`provider-rejected-<HTTP status>-<category>`.

Categories distinguish unverified identity, authorization, account or configuration
pause, missing configuration or resource, unverified MAIL FROM, throttling, message
rejection, invalid request and other refusal. An unknown SDK error code produces
`other`; the original code is never copied. Recognized identity/pause wording is
classified in memory without retaining the provider message.

The exception message and public failure responses remain generic. Operational
evidence contains no raw SDK message, request identifier, address, message body,
token or credential. CLI logging providers remain disabled. Ordinary transports
keep their existing generic `provider-rejected` contract.

A category helps diagnose a failure; it does not grant retry authority or identify
which address failed verification. The existing handler decides retryability and
persists the safe reason. A rejected pilot attempt remains consumed. Unknown
outcomes, cancellation and server errors retain their existing ambiguity handling;
they are not converted to definite rejection. No SDK retries, ledger resets, new
runs or live diagnostic submissions are enabled by this change. Historical generic
rejections cannot be retrospectively classified.

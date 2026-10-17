# Uploaded PDF verification backend

QUILS-55 adds `UploadedPdfVerification.VerifyAsync`, a bounded readonly service for the planned public verification flow. This slice has no public upload endpoint or browser page.

The service streams the supplied upload through SHA-256 with a strict byte limit, PDF-header check, optional exact declared length and operation deadline. It keeps only a small read buffer. It does not persist, normalize or rewrite the upload. Oversized input consumes at most the configured limit plus one detection byte; unrecognized bytes never enter a PDF parser or open private stored files.

Two filtered, nonunique indexes support lookup by the executed and standalone-certificate hashes. Only a unique, still-retained Completed artifact can proceed. A match across multiple envelopes or both artifact kinds is unrecognized. Expired signing sessions and signing deadlines do not invalidate a still-retained completed packet; an elapsed recorded purge deadline prevents recognition.

For a recognized artifact, the service reuses immutable final-publication verification. That verifies the canonical publication, frozen signing/audit evidence, exact stored pair, full-file CMS seal and RFC 3161 timestamp evidence using public certificates and configured timestamp trust roots. The uploaded digest and byte count must match that verified artifact. The service then rechecks the parent scope and matching index ranges before returning success. Ordinary growing operational audit tails remain compatible with the immutable completed packet.

The result contains only a status, supplied SHA-256 and verified artifact kind. Seal/timestamp integrity flags are affirmative only for verified results. Other statuses distinguish rejected input, an unrecognized artifact, evidence that could not be verified and temporary unavailability. A false flag does not by itself establish an invalid signature. Unrecognized files may come from another instance, have expired server retention, be altered or simply be unrelated.

No party identity, envelope/public ID, title, stored file, capability, session, raw audit evidence or private storage reference is returned. Successful integrity verification does not establish a person's identity, legal validity, AdES/QES status, independent trust in the platform signing certificate or long-term revocation validity. There is no general verification claim for arbitrary third-party PDFs.

The backend performs no document writes/deletes, packet regeneration, private-key acquisition, new TSA request, embedded-URL fetch, OCSP/CRL download, email/work enqueueing, token issuance or audit mutation. Existing offline certificate validation disables certificate downloads and revocation network checks. Public timestamp trust material must remain available; private signing material is not needed for verification.

`AddUploadedPdfVerification` registers the service lazily for hosts with the existing completed-publication verification services. Optional `PdfVerification:MaximumBytes` is bounded to 16 bytes through 64 MiB, defaulting to 64 MiB; `PdfVerification:TimeoutSeconds` is bounded to 1–120 seconds, defaulting to 60. These are technical processing limits, not retention or disclosure policy. HTTP request bounds, antiforgery, rate limits and visible result wording belong to the later public browser slice.

# Electronic-signature requirements and acceptance checklist

Legal research reviewed: **2026-10-15**. Scope: ordinary electronic signatures under US ESIGN/state electronic-transactions law and the EU eIDAS framework. Other countries, individual US state variations, EU national formalities, and sector-specific rules require separate review.

This is an engineering requirements guide, not legal advice or a compliance certification. The signing controls below are **QuillSign acceptance targets**, not a statement that the current application implements them. See the [implementation plan](plan.md) for delivery status. Operators should obtain legal review of their transaction, disclosure text, and evidence package before relying on the service.

## 1. What makes an electronic signature legally usable?

There is no universal certificate or checklist that makes every electronically signed document enforceable. Three questions must be answered separately:

1. **Does this qualify as an electronic signature?** A person deliberately adopts a signing act associated with a particular record.
2. **Is the transaction legally effective?** Applicable law permits the method, the parties agree where required, and contract formation, authority, capacity, delivery, and any special formalities are satisfied.
3. **Can it be proved later?** Reliable evidence identifies the act, the record, the circumstances, and subsequent changes; entitled parties can retain and reproduce the record.

US law prevents rejection solely because a record or signature is electronic; it preserves other substantive requirements. EU eIDAS similarly protects electronic signatures from rejection solely because of their form or lack of qualified status, while preserving contract and form rules. Neither provision promises that every contract is valid or every signature is authentic. Sources: [ESIGN §§7001(a)–(b), 7006(5)][esign]; [eIDAS Arts. 2(3), 3(10), 25][eidas].

A typed name, drawn mark, uploaded signature image, or deliberate signing process can be an ordinary electronic signature. A signature image alone does not establish intent, identity, authority, or which version was signed. A cryptographic PDF signature is a technical integrity mechanism; it does not by itself establish all those legal elements.

### Requirement labels

| Label | Meaning |
| --- | --- |
| Legal element | Required by the cited framework within its scope. The law may allow several ways to satisfy it. |
| Conditional legal duty | Applies when a specified condition is met, such as replacing a legally required consumer paper disclosure. |
| QuillSign control | A required product acceptance target supporting the legal element or evidence. It is not necessarily a technology mandated by law. |
| Operator duty | A decision or obligation the software cannot settle, such as applicable law, authority, or a statutory retention period. |

## 2. Decide whether the transaction belongs in this workflow

Before sending, the operator must determine the applicable jurisdictions, transaction type, participants, required signature level, and any witness, notarial, filing, delivery, language, or accessibility rules. Ordinary contract issues still apply, including agreement to the terms, capacity, authority to bind an organization, lawful purpose, and any applicable consideration requirement. An authenticated mailbox does not answer those questions. Sources: [ESIGN §7001(b)(1)][esign]; [UETA §3(d)][ueta]; [eIDAS Art. 2(3)][eidas].

### US exclusions and special cases

ESIGN §7003 excludes the following from its general §7001 rule, subject to any applicable regulatory exception:

- Wills, codicils, and testamentary trusts.
- Adoption, divorce, and other family-law matters governed by state law.
- UCC-governed records except the specified §§1-107 and 1-206 and Articles 2 and 2A.
- Court orders, court notices, and official court documents required in court proceedings.
- Notices terminating utility services.
- Default, acceleration, repossession, foreclosure, eviction, or cure notices under credit secured by, or rental agreements for, an individual's primary residence.
- Cancellation or termination notices for health insurance or benefits or life-insurance benefits, excluding annuities.
- Product recalls or material-failure notices involving health or safety risks.
- Documents required to accompany transportation or handling of hazardous materials, pesticides, or other toxic or dangerous materials.

An exclusion from ESIGN is **not a universal ban on electronic execution**: another applicable statute, court rule, or specialist process may permit it. QuillSign v1 must treat these as unsupported ordinary-workflow uses and require a sender acknowledgment of the exclusions. The acknowledgment is a screening control, not a legal determination. Source: [ESIGN §7003][esign].

Notarization is not categorically prohibited electronically: [ESIGN §7001(g)][esign] and [UETA §11][ueta] recognize electronic notarial acts subject to the other applicable requirements. QuillSign v1 does not supply a notary, witness service, remote-notarization procedure, or governmental filing acceptance.

FDA-regulated records under [21 CFR Part 11][part11], transferable records with authoritative-copy/control requirements under [ESIGN §7021][esign] or [UETA §16][ueta], and regulated financial disclosures need separate systems or review. QuillSign v1 does not claim Part 11 compliance, electronic-note control, or satisfaction of a regulator's prescribed delivery method. ESIGN preserves agency filing standards and specified consumer receipt requirements: §§7004(a), 7001(c)(2)(B).

### State and national variations

UETA is a model act; the enacted law in the relevant state controls. Its core provisions concern electronic agreement (§5), recognition (§7), retainable disclosures (§8), attribution (§9), errors (§10), retention (§12), and evidence (§13). [Florida's enactment, §668.50][florida], illustrates these rules; it is not a substitute for checking another state's statute. New York has its own [Electronic Signatures and Records Act, §304][new-york].

In the EU, check the member state's rules and the receiving authority's requirements. QuillSign's ordinary-signature workflow is unsuitable wherever a stronger signature or another formality is required. It must not advertise blanket suitability for every employment, property, public-sector, or cross-border transaction. Sources: [eIDAS Arts. 2(3), 25–27][eidas]; [Commission eSignature FAQ][eu-faq].

## 3. Core US legal elements and QuillSign controls

| ID | Element and legal basis | QuillSign acceptance target |
| --- | --- | --- |
| L1 | Voluntary electronic participation. ESIGN §7001(b)(2); UETA §5(b). | Present a readable Electronic Record and Signature Disclosure (ERSD), require an unchecked affirmative agreement for each signer, and offer Decline. Do not infer consent from opening an invitation. Record the disclosure version, exact text/hash, actor, time, and affirmative action. A mandatory checkbox is QuillSign's chosen evidence mechanism. |
| L2 | Intent to sign the record. ESIGN §7006(5); UETA §2(8). | Explain the signing effect when a signer adopts a typed/drawn/uploaded mark and at the final submission. Require a deliberate signing action for each signature field and an explicit Finish action after review. Prefilling a name, viewing a document, or AI suggesting a field must never count as signing. Preserve the statement shown and the actions taken. |
| L3 | The act is attributable to the person. UETA §9; Florida §668.50(9). | Bind each invitation/session to the envelope, signer, and purpose. Use high-entropy, expiring, single-use links with hashed token storage; record the authentication method and result. Reject replay, wrong-party access, and unauthorized delegation. An optional email OTP adds a mailbox recheck, not independent identity proof. |
| L4 | The signing act is attached to or logically associated with the record. ESIGN §7006(5). | Freeze and hash the signing document and sender-prefilled values before invitations. Bind accepted fields, consent, signing acts, and checkpoints to that version and signer. Show earlier sequential signers' accepted values. Reject stale submissions and changes to frozen terms; changed terms require a new signing process rather than silently carrying signatures forward. |
| L5 | Accurate, retainable, reproducible records where writing/retention rules apply. ESIGN §7001(d)–(e); UETA §§8, 12. | Give entitled parties downloadable, readable PDFs without print/save restrictions. Preserve the accepted content, final values, disclosure, and relevant evidence; verify that the final PDF matches the signing records. Retention/access must last for the applicable period, using the operator's archive where appropriate. |
| L6 | Other disclosure, delivery, error, and form rules remain applicable. ESIGN §7001(c)(2), (f)–(g); UETA §§8, 10–11. | Let signers review all pages and values, correct their own fields before Finish, and decline. Preserve errors/corrections and void events. Do not claim this replaces a legally required delivery acknowledgment, notarial act, or a substantive right to correct an error after signing. |

Legal sources: [ESIGN][esign], [UETA model text][ueta], and [Florida's enacted UETA][florida].

**Attribution limits:** email verification proves access to the invited mailbox or link at that time, subject to forwarding and account compromise. A full name is usually self-asserted. IP addresses, user agents, and timestamps corroborate events; none alone proves legal identity, actual reading, informed understanding, or organizational authority. Higher-risk uses may require independent identity verification and authority checks outside v1. The evidence package must describe the actual procedure without calling it verified legal identity.

## 4. Conditional US consumer electronic-record disclosure

ESIGN §7001(c) applies when law requires transaction information to be provided or made available **in writing to a consumer**, and an electronic record is used to satisfy that requirement. A consumer here obtains products or services primarily for personal, family, or household use (§7006(1)). This is not an unconditional requirement for every business signature, and consent to electronic delivery is separate from assent to contract terms. QuillSign nevertheless targets a versioned ERSD for every signer. Source: [ESIGN §§7001(c), 7006(1)][esign].

### Before consent

The operator's clear and conspicuous disclosure must state:

1. Any right or option to receive the record on paper or in nonelectronic form.
2. The right to withdraw electronic-record consent, including disclosed conditions, consequences, and any fees.
3. The scope: this transaction only or specifically identified categories of future records. QuillSign v1 targets this envelope only.
4. How to withdraw and update electronic contact details, using a real, functioning contact/procedure.
5. How to request a paper copy after consent and any applicable copy fee.
6. Hardware and software needed both to **access and retain** the records, including the PDF format, supported browser/viewer, download/storage or printing capability, and email access where delivery uses email.

The disclosure must match the operator's actual service. Do not promise free paper copies, immediate withdrawal, or contact updates if no one will provide them. Source: [ESIGN §7001(c)(1)(B)–(C)][esign].

### Consent and demonstrated access

Obtain affirmative consent, or its electronic confirmation, in a way that reasonably demonstrates access to the electronic form actually used. QuillSign must present a representative PDF in the signing environment and a functioning download/retention path before collecting the access confirmation. Preserve which PDF/form was used, successful access evidence, the user's affirmative confirmation, and the disclosure version. Test failed rendering, mobile browsers, assistive access, and download failures; offer an alternative rather than recording successful access when the PDF cannot be accessed.

A generic checkbox or a browser page that merely contains a PDF placeholder is not automatically sufficient. Whether the chosen demonstration satisfies the statute requires review for the actual format and delivery flow. Source: [ESIGN §7001(c)(1)(C)(ii)][esign].

### After consent

- Process withdrawal within a reasonable period and stop relying on it for subsequent covered electronic records. A decline before signing ends this envelope's workflow; it is not the complete definition of withdrawal. Withdrawal does not automatically rescind a previously signed contract or invalidate earlier properly provided records.
- If changed access/retention requirements create a material risk of losing access to subsequent covered records, disclose the revised requirements and qualifying fee-free withdrawal rights, then repeat the access/consent procedure.
- Preserve the content, timing, specified delivery method, and receipt verification required by the underlying law. An email provider accepting a message is not proof the person received or read it.

Sources: [ESIGN §7001(c)(1)(D), (2), (4)][esign]. Section 7001(c)(3) also says a consumer contract is not invalid **solely** because electronic consent/access confirmation was not obtained as required by (1)(C)(ii); that does not remove applicable disclosure obligations. Record failures honestly rather than declaring every defect automatically voids the signature.

## 5. EU eIDAS signature levels

The framework is Regulation (EU) No 910/2014 as amended, including Regulation (EU) 2024/1183. The consolidated text reviewed is dated 18 October 2024. Ordinary electronic signatures are often called **simple electronic signatures (SES)**; that shorthand is not a compliance certification.

| Level | Requirements | Legal effect and QuillSign scope |
| --- | --- | --- |
| Ordinary / simple | Electronic signing data attached to or logically associated with the signed data and used by the natural-person signatory to sign: Arts. 3(9)–(10). | Art. 25(1) protects against rejection solely for electronic form or lack of qualified status. V1 targets this level; national transaction/form rules still apply. |
| Advanced (AdES) | All four Art. 26 requirements: unique link to the signatory; ability to identify them; creation data usable under their sole control with high confidence; and linkage making subsequent data changes detectable. | V1 makes no AdES claim. Mailbox access plus a server's completion seal does not by itself establish all four conditions for each signer. |
| Qualified (QES) | An advanced signature created using a qualified signature creation device and based on a qualified certificate: Art. 3(12), Arts. 28–32 and Annexes I–II. Qualification involves the applicable qualified trust-service framework. | Art. 25(2) gives handwritten-signature equivalence across the EU. V1 does not provide signer QES, a qualified device, or a qualified signer certificate. |

Sources: [eIDAS][eidas]; [Commission eSignature FAQ][eu-faq]. Ordinary and advanced signatures can have legal effect under applicable law; QES has the explicit EU-wide handwritten-equivalence rule. Even QES does not supply missing capacity, authority, witnesses, notarization, or other transaction formalities.

An application-controlled PDF signing certificate is a **platform completion seal** in this product's terminology. Do not imply it is an eIDAS qualified electronic seal, a qualified timestamp, or each person's certificate-backed signature. Public-sector advanced-signature format recognition also has specific rules; [Implementing Regulation (EU) 2026/248][eu-formats] does not make an ordinary QuillSign signature advanced or qualified.

## 6. Integrity, timestamps, and evidence

These are QuillSign product controls supporting accuracy and attribution. US ordinary-signature law does not universally mandate SHA-256, a digital certificate, IP capture, WORM storage, a timestamp authority, or a completion certificate. Choose and test these controls without describing them as statutory prerequisites for every signature.

### Document and cryptographic integrity

- Preserve the original, any normalized PDF, the frozen sent PDF, and each signer's checkpoint with explicit hashes and version relationships. Conversion and sender prefill happen before freezing; the sender confirms the signing copy.
- Complete sequential signing before producing the final PDF. Apply one platform seal with an RFC 3161 timestamp at completion; v1 does not apply a separate cryptographic signature for every signer.
- Validate document byte integrity, certificate trust, certificate status, and timestamp trust as separate results. A self-signed certificate may verify mathematically while lacking an independently trusted identity. Report unknown/untrusted results clearly.
- A trusted timestamp supports that the timestamped hash existed by the asserted time. It does not prove the human signed at exactly that time or identify that human. Server event times and TSA times must remain distinguishable.
- Protect accepted records from overwrite and unauthorized modification; use the planned immutable final storage and access controls. A hash chain alone can be rewritten by a sufficiently privileged attacker unless its root is independently protected.
- Do not claim PAdES baseline B-T conformance merely because a PDF contains CMS and an RFC 3161 token. Validate the complete claimed profile with an independent validator. V1 does not claim PAdES B-LT/B-LTA or indefinite validation after certificate expiry/revocation.

Technical sources: [RFC 3161][rfc3161]; [ETSI EN 319 142-1 V1.2.1, §§4–6][pades]. These specify timestamp/signature mechanisms and profiles, not a universal legal-validity test.

### Audit trail and certificate of completion

The evidence package must be exportable by authorized parties and understandable without a live QuillSign service. Include:

- Envelope/document identifiers, document versions, page count, hashes, and final status.
- Sender and signer names, their party roles/order, verified mailbox information, and the exact authentication procedures/results used.
- Consent/disclosure text or a durable referenced copy, version/hash, affirmative consent and withdrawal events, and demonstrated-access evidence.
- Signature adoption, field ownership and accepted values, document-view events, final signing submissions, declines, corrections, voids, and sequential checkpoints.
- Ordered UTC event times; clearly labeled local-time displays where available. Record observed IP/user-agent evidence under the privacy policy, without claiming that it establishes identity.
- Delivery attempts, definite failures, ambiguous provider outcomes, and downloads; distinguish an invitation open, provider delivery report, and actual signing.
- Audit-chain linkage and the independently protected root covered by the final evidence seal; platform certificate and timestamp validation metadata.

Append completion-certificate pages to the executed PDF and provide a standalone certificate. Avoid circular hashes: a PDF cannot contain its own final whole-file hash. Record the sealed PDF's final hash in the separate certificate/export manifest, and identify any pre-seal hash embedded in the packet explicitly. Similarly, state which audit events the embedded audit root covers; later delivery/download events cannot retroactively be included in an already sealed root.

A completion certificate is an evidence summary, **not** a government approval, a qualified signer certificate, or a substitute for underlying records. Admissibility and evidentiary weight remain subject to the forum's rules. Sources for electronic evidence/attribution: [UETA §§9, 13][ueta]; [Florida §668.50(9), (13)][florida]; [eIDAS Art. 25(1)][eidas].

## 7. Delivery, retention, and access

QuillSign's completion target is to send the fully executed PDF and standalone completion certificate as attachments to the sender, every signer, and designated recipients, with a secure download link as backup. Each party must be able to save and print its own readable copy independently of an expiring session or the service remaining online.

If provider size limits prevent attachments, use the planned secure-link fallback and warn the sender. A link-only fallback is **not automatically equivalent** to successful retainable delivery: provide a working save path, disclose availability/expiry, monitor failures, and arrange another retainable delivery method when needed. Do not mark delivery successful merely because it was queued or submitted to a provider. Authorized resends and contact corrections must be audited.

ESIGN and UETA do not set one universal minimum number of retention days. The applicable transaction law, regulator, contract, dispute/hold obligations, and privacy law determine the actual period and access needs. Configure server retention accordingly and identify who maintains the authoritative archive. Emailing a copy does not discharge every operator retention duty. Sources: [ESIGN §7001(d)–(e)][esign]; [UETA §§8, 12][ueta]; [Florida §668.50(8), (12)][florida].

The demo must disclose periodic purging and must not be presented as a statutory archive. Provide authorized export/retrieval before purge. Preserve records needed under a valid legal hold; coordinate holds with deletion and immutable-storage expiry. Test retrieval after restart/key rotation and export readability after service access ends. A deleted server record must not remain advertised as retrievable.

## 8. Privacy and operational duties

Where GDPR applies, names, addresses, IPs, signatures, and audit evidence require a lawful processing basis, an appropriate privacy notice, proportionate collection, security, and justified retention. Consent to electronic signing is not automatically GDPR consent. Identify controller/processor roles, required processor arrangements, subprocessors, and international-transfer safeguards. Self-hosting does not automatically remove those obligations.

Restrict documents and evidence to authorized parties. Explain the evidence collected and who receives the completion packet. Handle data-subject requests while respecting applicable retention/legal-claim exceptions; do not promise unconditional immediate erasure. Sources: [GDPR Arts. 3, 5–6, 13–14, 17(3), 28, 32, Chapter V][gdpr].

QuillSign controls also include secure transport, scoped sessions, antiforgery, token protection, rate limits, suppression, upload validation, and access isolation. These support trustworthy operation; they do not substitute for legal review or make an unsupported transaction suitable. Keep signing accessible, including keyboard operation and typed signatures; evaluate any applicable accessibility law separately.

## 9. Release acceptance checklist

Every checkbox is intentionally unchecked. Completing this documentation does not complete the signing implementation or certify a deployment. Record evidence and the tested version for each implemented item; review legal applicability per transaction.

- [ ] **Scope:** Publish supported ordinary-signature uses and exclusions; the sender acknowledges the screening statement. The operator has reviewed jurisdiction, authority, capacity, required signature level, and special formalities.
- [ ] **Agreement:** Each signer affirmatively accepts a versioned ERSD with a Decline path; opening an invitation does not create consent or a signature.
- [ ] **Consumer duties:** Where ESIGN §7001(c) applies, all pre-consent statements, actual-format access demonstration, withdrawal/contact/paper procedures, and material-requirement-change handling pass review.
- [ ] **Intent:** Adoption and Finish show clear signing statements; signature fields need deliberate action; all pages/values can be reviewed and corrected before submission.
- [ ] **Attribution:** Scoped, expiring, single-use credentials reject replay and other-party access; audit exports accurately describe mailbox verification and its limits.
- [ ] **Record association:** Every acceptance binds the correct frozen version, party, and fields. Stale submissions, competing changes, and attempts to edit frozen terms are rejected.
- [ ] **Sequential integrity:** Earlier accepted values and per-signer checkpoints are preserved; declines/voids stop the workflow; only all required acceptances produce completion.
- [ ] **Final packet:** Independent comparison confirms the final PDF contains the accepted terms/values; executed and standalone certificate PDFs are reproducible, readable, and printable.
- [ ] **Evidence:** Disclosure, authentication, signing, document hashes, and audit exports can be correlated; certificate/root/hash boundaries avoid self-reference and include no unsupported identity assertions.
- [ ] **Seal verification:** Valid, changed, truncated, untrusted, expired/revoked-certificate, and failed-TSA cases produce accurate results. Any PAdES claim has independent profile validation.
- [ ] **Delivery:** All intended parties receive the packet or a working retainable alternative. Oversize, bounced, suppressed, delayed, and ambiguous deliveries are visible and recoverable.
- [ ] **Retention:** Required periods, archive responsibility, expiry notices, export, legal holds, purge, and post-restart/key-rotation retrieval are documented and exercised.
- [ ] **Privacy/accessibility:** Notices, access isolation, data minimization, retention exceptions, processor/transfer duties, keyboard signing, and readable disclosures have been reviewed.
- [ ] **Claims:** Product text accurately states ordinary EU signature scope, one platform completion seal, authentication limits, demo purge, and unsupported regulated/QES uses. No blanket enforceability guarantee.
- [ ] **Legal review:** The operator's disclosure wording, transaction scope, retention/delivery procedure, and evidence package have received review appropriate to the intended use and jurisdictions.

## 10. Sources and maintenance

Use the cited provisions rather than vendor marketing claims. Review this guide when laws, supported jurisdictions, authentication, disclosures, delivery formats, retention, or cryptographic profiles change. The US source below is the 2024 Code edition; check subsequent amendments and the current enacted state law for actual use. The eIDAS consolidation is a documentation aid; the underlying Official Journal acts are authoritative. This guide does not survey every implementing act or every jurisdiction.

| Source | Provisions used |
| --- | --- |
| [US ESIGN, 15 USC Chapter 96][esign] | §§7001–7004, 7006, 7021 |
| [ULC 1999 UETA final text with comments, CMU mirror][ueta] | §§2–3, 5, 7–13, 16; model text, not a state's enactment |
| [Florida Statutes §668.50, 2025 edition][florida] | Enacted example: agreement, recognition, retention, attribution, errors, evidence |
| [New York State Technology Law §304][new-york] | State-specific electronic-signature recognition |
| [eIDAS consolidated regulation][eidas] | Arts. 2–3, 25–32; Annexes I–II |
| [Commission eSignature FAQ][eu-faq] | Signature levels, legal effects, validation distinctions |
| [Implementing Regulation (EU) 2026/248][eu-formats] | Public-sector advanced-signature/seal format recognition |
| [GDPR, Regulation (EU) 2016/679][gdpr] | Territorial scope, principles, lawful basis, notices, erasure exceptions, processors, security, transfers |
| [21 CFR Part 11][part11] | Specialized FDA electronic-record/signature regime; unsupported by v1 |
| [RFC 3161][rfc3161] | Timestamp protocol and trust assumptions |
| [ETSI EN 319 142-1 V1.2.1 (2024-01)][pades] | PDF signature syntax and baseline profile requirements |

[esign]: https://www.govinfo.gov/content/pkg/USCODE-2024-title15/html/USCODE-2024-title15-chap96.htm
[ueta]: https://euro.ecom.cmu.edu/program/law/08-732/Transactions/ueta.pdf
[florida]: https://www.flsenate.gov/Laws/Statutes/2025/0668.50
[new-york]: https://www.nysenate.gov/legislation/laws/STT/304
[eidas]: https://eur-lex.europa.eu/eli/reg/2014/910/2024-10-18/eng
[eu-faq]: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/880312429/eSignature%2BFAQ
[eu-formats]: https://eur-lex.europa.eu/eli/reg_impl/2026/248/oj/eng
[gdpr]: https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng
[part11]: https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11
[rfc3161]: https://www.rfc-editor.org/rfc/rfc3161
[pades]: https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf

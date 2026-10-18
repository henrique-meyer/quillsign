# Optional homepage analytics

Google Analytics is disabled by default. Configure `Analytics__Enabled=true` and
`Analytics__MeasurementId` with your web stream's `G-` measurement ID to load it
on the clean homepage (`GET /` with no query string). Missing or malformed
configuration disables both the integration and its external CSP permissions.
Keep deployment values in environment configuration or ignored local settings.
For Bicep, set `analyticsEnabled` and `analyticsMeasurementId` in the ignored web
or hosting parameter file. These parameters affect only the web container.

When enabled, analytics loads on eligible visits without a banner, settings
button or status message. Browser Do Not Track and Global Privacy Control keep
collection disabled. Previously saved declines are also honored until their
preference cookie expires or the visitor clears it in browser settings; no new
preference cookies are written. Blocked visits remove existing host-only
Analytics cookies. Analytics cookies last up to 180 days. JavaScript is required
to load analytics; signing works independently of it.

Only the homepage is eligible. Queries, fragments, POST responses, errors and all
other routes are excluded, including verification, lookup, sender and signer
pages, private document readers and downloads. Page metadata is fixed to the
public homepage URL and `QuillSign` title, with an empty referrer. Automatic page
views and advertising signals are disabled. In the Analytics web stream, keep
**Enhanced measurement off** and do not add advertising destinations or remote
tag rules that collect additional content. An operator must review such changes
before expanding collection.

Measurement sends usage data to Google, including IP and browser/device
information. Operators remain responsible for their privacy obligations. Never put
participant details, document content or access codes into analytics events.

To verify a deployment, first check the running release and `/health`. Open a
clean homepage in a browser without privacy blocking or a saved decline. Confirm
that no analytics controls appear and the stream receives the homepage `page_view` using browser
network tools or Tag Assistant and the property's Realtime report. Separately
verify saved declines, privacy signals and private-route exclusions.
Ad blockers, saved declines and browser privacy signals can prevent a visit
from appearing. Account/stream creation alone does not install the tag, and a
synthetic test visit does not identify a particular human visitor.

References: [Google tag configuration](https://developers.google.com/tag-platform/gtagjs/reference),
[privacy controls](https://developers.google.com/tag-platform/security/guides/privacy),
[CSP guidance](https://developers.google.com/tag-platform/security/guides/csp),
[collection verification](https://support.google.com/analytics/answer/9333790).

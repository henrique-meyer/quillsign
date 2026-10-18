# Optional homepage analytics

Google Analytics is disabled by default. Configure `Analytics__Enabled=true` and
`Analytics__MeasurementId` with your web stream's `G-` measurement ID to offer it
on the clean homepage (`GET /` with no query string). Missing or malformed
configuration disables both the integration and its external CSP permissions.
Keep deployment values in environment configuration or ignored local settings.
For Bicep, set `analyticsEnabled` and `analyticsMeasurementId` in the ignored web
or hosting parameter file. These parameters affect only the web container.

Visitors explicitly choose **Allow analytics** or **Decline analytics**. Google
is not contacted until acceptance; signing works independently of that choice.
The **Analytics settings** control reopens the choice. Declining after acceptance
disables collection, removes the host-only Analytics cookies and reloads the
page to unload the tag. The preference lasts up to 180 days. Browser Do Not Track
and Global Privacy Control keep collection disabled even after acceptance.
JavaScript is required to show the choice and load analytics.

Only the homepage is eligible. Queries, fragments, POST responses, errors and all
other routes are excluded, including verification, lookup, sender and signer
pages, private document readers and downloads. Page metadata is fixed to the
public homepage URL and `QuillSign` title, with an empty referrer. Automatic page
views and advertising signals are disabled. In the Analytics web stream, keep
**Enhanced measurement off** and do not add advertising destinations or remote
tag rules that collect additional content. An operator must review such changes
before expanding collection.

Opted-in measurement still sends usage data to Google, including IP and browser/
device information. The page explains this and links Google's privacy policy;
this feature does not replace an operator's own privacy obligations. Never put
participant details, document content or access codes into analytics events.

To verify a deployment, first check the running release and `/health`. Open a
clean homepage in a browser without a stored choice: no Google tag should load.
Accept, then confirm the stream receives the homepage `page_view` using browser
network tools or Tag Assistant and the property's Realtime report. Separately
verify decline, withdrawal, privacy signals and private-route exclusions.
Ad blockers, rejected consent and browser privacy signals can prevent a visit
from appearing. Account/stream creation alone does not install the tag, and a
synthetic test visit does not identify a particular human visitor.

References: [Google tag configuration](https://developers.google.com/tag-platform/gtagjs/reference),
[privacy controls](https://developers.google.com/tag-platform/security/guides/privacy),
[CSP guidance](https://developers.google.com/tag-platform/security/guides/csp),
[collection verification](https://support.google.com/analytics/answer/9333790).

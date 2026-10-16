# Manual field placement

The verified sender opens **Place document fields** from signer setup after confirming the current PDF. The editor keeps the envelope in Draft. It does not send invitations, capture consent/signatures, stamp values into the PDF, run AI, or seal a document.

Fields support add, move, resize, duplicate, delete, page changes, assignment, labels and required flags. A named functional color legend identifies owners; names and accessible labels also identify ownership without relying on color. The sender bucket accepts only Text, Checkbox and Date. Signature, Initials, FullName and DateSigned require a signer. Assigned fields accept no values here. Full names and signing dates will be populated during signing.

Select a field in the document list to edit it with keyboard-accessible controls. Position and size controls use percentages, and **Apply changes** updates the working field list. Unapplied property edits stay visible through validation errors; apply or explicitly discard them before changing field selection. Exports include any unapplied control values, and leaving the page warns about them. Sender dates use `YYYY-MM-DD`; checkboxes store `true` or `false`; text is limited to 4,000 characters. Empty sender values may be prepared later. Validation that every sender field is filled and every signer is ready belongs to the future send step. Changing a PDF clears its fields and preview confirmation.

## Coordinate contract

Each field stores page number (one-based), X, Y, Width and Height as decimal fractions of the **visible, rotated CropBox**. The origin is its top-left corner. X/Y are nonnegative, width/height positive, and the whole rectangle must fit inside the unit square. SQL persists eight decimal places; the service truncates validated values to that precision without enlarging a rectangle beyond the page.

The overlay uses percentage CSS positions over PDF.js's actual viewport, so changing zoom or screen width does not alter stored geometry. Drag deltas are divided by the overlay's current CSS width/height, independent of device pixel ratio and canvas resolution. Resize uses the same viewport. Page loading temporarily hides the overlay and disables adding fields, preventing edits against the wrong page. The preview preserves page rotation, effective crop and UserUnit.

`FieldGeometry.ToPdfRectangle` maps a visible rectangle back to raw PDF user space before `/Rotate` and `/UserUnit`. For a CropBox with bottom-left `(L,B)` and dimensions `(W,H)`, the mapping is:

| Rotation | PDF X | PDF Y | PDF width | PDF height |
| --- | --- | --- | --- | --- |
| 0° | L + xW | B + (1 − y − h)H | wW | hH |
| 90° | L + yW | B + xH | hW | wH |
| 180° | L + (1 − x − w)W | B + yH | wW | hH |
| 270° | L + (1 − y − h)W | B + (1 − x − w)H | hW | wH |

UserUnit affects physical size, not raw content coordinates. A future PDFsharp stamper must apply its own drawing coordinate transform consistently; this helper does not draw or claim final-output validation. Tests cover Letter, A4, landscape, crop offsets, all rotations and non-default UserUnit. Rendered stamped golden files remain a gate for the stamping story.

## Save and conflict behavior

The browser debounces changes and allows only one PATCH request in flight. Each request replaces the field list for that document using its stable field IDs, PDF blob identity and shared envelope rowversion. A response advances the client revision; edits made while that request was in flight remain dirty until a subsequent save succeeds. The UI reports **All field changes saved** only after the latest working list is confirmed.

`PATCH /api/envelopes/{publicId}/fields` requires the sender cookie and an antiforgery token in `X-CSRF-TOKEN`. The service requires verified sender ownership, Draft status and current preview confirmation. It checks types, page bounds, values, signer ownership, unique IDs, field limits, and foreign field IDs. The request limit is 2 MiB, with 200 fields by default. Non-JSON requests return 415. Failed authorization, antiforgery, malformed requests and stale revisions cannot modify fields.

Upload, confirmation, signer edits and field saves share a SQL envelope lock and version. The field rows, version advance and hash-chained `fields_saved` audit entry commit together. Audit data includes the document identity and field list. Rollback leaves the prior draft intact. The final `sender_prefilled` stamping event belongs to the send transaction, not draft editing.

A conflict or unconfirmed save pauses autosave and leaves the working list in memory. **Export field edits** downloads that list as JSON before reloading. The export is a recovery aid; automatic import/reconciliation is not implemented. Reloading can discard unsaved edits, so the browser warns before leaving a dirty editor. There is no periodic database polling while idle.

## Browser dependency

Build-time restoration uses the exact interact.js 1.10.28 archive and pinned integrity hashes in `Build/BrowserAssets.targets`. The full upstream MIT notice accompanies the script at `wwwroot/vendor/interact/LICENSE` in build/publish output. The ignored cache and build output preserve the notice verbatim without placing upstream contact details in Git. The repository contains only restoration/verification metadata and original application code. The first build requires the npm registry; later builds reuse and verify cached bytes. No package lifecycle scripts execute. PDF.js remains the existing pinned local distribution.

# Synthetic conversion pair

`synthetic-conversion.docx` is the generated two-page **NO AGREEMENT** document from `GotenbergDocxConverterTests.Docx`. `synthetic-conversion.pdf` is the unmodified PDF response captured from the pinned local Gotenberg sidecar (LibreOffice 26.8.1.1). Neither file contains an agreement or personal data.

The capture validated the exact DOCX through `DocxPackageValidation`, sent those bytes through the actual isolated Gotenberg conversion route, and validated its response through the client/PDF validator. The source and provider-response hashes are pinned in `DocxDocumentWorkflowTests`; the persistence test replays that exact response for the same source through actual SQL Server/Azurite upload, retention, audit and sender confirmation. The PDF client normalization runs in the test. This is a paired component integration test, not a combined live SQL/converter or hosted test.

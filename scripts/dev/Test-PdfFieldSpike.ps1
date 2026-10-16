#requires -Version 7.0
[CmdletBinding()]
param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (!$OutputDirectory) { $OutputDirectory = Join-Path $taskRoot 'artifacts/pdf-fields' }
$taskOutput = [IO.Path]::GetFullPath($OutputDirectory)
Push-Location $taskRoot
try {
    if ($taskOutput.Equals($taskRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The repository root cannot be used for generated fixtures.'
    }
    if ($taskOutput.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        git check-ignore --quiet $taskOutput
        if ($LASTEXITCODE -ne 0) { throw 'Generated fixtures must stay in an ignored directory or outside the repository.' }
    }
    python scripts/dev/vendor_pdfjs.py --verify
    if ($LASTEXITCODE -ne 0) { throw 'Pinned PDF.js/font verification failed.' }
    dotnet restore tools/PdfFieldSpike/PdfFieldSpike.csproj --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Pinned spike restore failed.' }
    dotnet run --project tools/PdfFieldSpike/PdfFieldSpike.csproj -c Release --no-restore -- $taskOutput
    if ($LASTEXITCODE -ne 0) { throw 'PDF field feasibility checks failed.' }
    $taskReport = Get-Content -LiteralPath (Join-Path $taskOutput 'report.json') -Raw | ConvertFrom-Json
    if ($taskReport.cases.Count -ne 9 -or $taskReport.productionCases.Count -ne 9 -or $taskReport.rejected.Count -ne 25 -or !$taskReport.naiveTransformDetected -or !$taskReport.canonicalAccent) {
        throw 'The feasibility report is incomplete.'
    }
} finally { Pop-Location }
exit 0

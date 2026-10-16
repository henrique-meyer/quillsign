param([string]$OpenSsl)

$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $OpenSsl) {
    $opensslCommand = Get-Command openssl -ErrorAction SilentlyContinue
    if ($opensslCommand) { $OpenSsl = $opensslCommand.Source }
    elseif ($IsWindows -and (Test-Path -LiteralPath "$env:ProgramFiles/Git/usr/bin/openssl.exe")) {
        $OpenSsl = "$env:ProgramFiles/Git/usr/bin/openssl.exe"
    }
    else { throw 'OpenSSL is required for independent CMS/timestamp verification. Supply -OpenSsl with its executable path.' }
}

Push-Location $taskRoot
try {
    dotnet run --project tools/PdfSealSpike/PdfSealSpike.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'PDF seal harness failed' }
    $fixturePath = 'artifacts/pdf-seal-spike'
    & $OpenSsl cms -verify -binary -inform DER -in "$fixturePath/signature.der" `
        -content "$fixturePath/signed-bytes.bin" -noverify -out "$fixturePath/verified-content.bin"
    if ($LASTEXITCODE -ne 0) { throw 'Independent OpenSSL CMS verification failed' }
    & $OpenSsl ts -verify -token_in -in "$fixturePath/timestamp.der" `
        -data "$fixturePath/signature-value.bin" -CAfile "$fixturePath/tsa.crt"
    if ($LASTEXITCODE -ne 0) { throw 'Independent OpenSSL timestamp verification failed' }

    $rejectionOutput = & $OpenSsl cms -verify -binary -inform DER -in "$fixturePath/signature.der" `
        -content "$fixturePath/altered-signed-bytes.bin" -noverify -out "$fixturePath/rejected-content.bin" 2>&1
    if ($LASTEXITCODE -eq 0) { throw 'OpenSSL accepted changed document bytes' }
    $rejectionOutput = & $OpenSsl ts -verify -token_in -in "$fixturePath/timestamp.der" `
        -data "$fixturePath/altered-signed-bytes.bin" -CAfile "$fixturePath/tsa.crt" 2>&1
    if ($LASTEXITCODE -eq 0) { throw 'OpenSSL accepted an unrelated timestamp imprint' }
    Write-Output 'PASS: OpenSSL independently verifies CMS/timestamp and rejects altered content/imprints.'
}
finally { Pop-Location }

# The final native check intentionally fails; report overall success explicitly for CI's wrapper.
exit 0

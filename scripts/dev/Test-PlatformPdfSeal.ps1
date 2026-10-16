param([string]$OpenSsl)
$ErrorActionPreference='Stop'
$sealTaskRoot=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if(-not $OpenSsl) {
    $sealCommand=Get-Command openssl -ErrorAction SilentlyContinue
    if($sealCommand) { $OpenSsl=$sealCommand.Source }
    elseif($IsWindows -and (Test-Path -LiteralPath "$env:ProgramFiles/Git/usr/bin/openssl.exe")) { $OpenSsl="$env:ProgramFiles/Git/usr/bin/openssl.exe" }
    else { throw 'OpenSSL is required for independent production seal verification.' }
}
$previousArtifacts=[Environment]::GetEnvironmentVariable('QUILLSIGN_SEAL_ARTIFACTS')
Push-Location $sealTaskRoot
try {
    $sealEvidence=Join-Path $sealTaskRoot 'artifacts/platform-seal'
    $env:QUILLSIGN_SEAL_ARTIFACTS=$sealEvidence
    dotnet test tests/QuillSign.Tests/QuillSign.Tests.csproj -c Release --nologo --filter FullyQualifiedName~PlatformPdfSealTests
    if($LASTEXITCODE -ne 0) { throw 'Production seal tests failed.' }
    & $OpenSsl cms -verify -binary -inform DER -in "$sealEvidence/signature.der" -content "$sealEvidence/signed-bytes.bin" -noverify -out "$sealEvidence/verified-content.bin"
    if($LASTEXITCODE -ne 0) { throw 'OpenSSL rejected the production detached CMS signature.' }
    & $OpenSsl ts -verify -token_in -in "$sealEvidence/timestamp.der" -data "$sealEvidence/signature-value.bin" -CAfile "$sealEvidence/tsa-root.crt"
    if($LASTEXITCODE -ne 0) { throw 'OpenSSL rejected the production signature timestamp.' }
    $altered=[IO.File]::ReadAllBytes((Join-Path $sealEvidence 'signed-bytes.bin')); $altered[0]=$altered[0] -bxor 1
    [IO.File]::WriteAllBytes((Join-Path $sealEvidence 'altered-signed-bytes.bin'),$altered)
    $negative=& $OpenSsl cms -verify -binary -inform DER -in "$sealEvidence/signature.der" -content "$sealEvidence/altered-signed-bytes.bin" -noverify -out "$sealEvidence/rejected-content.bin" 2>&1
    if($LASTEXITCODE -eq 0) { throw 'OpenSSL accepted altered production signed bytes.' }
    $negative=& $OpenSsl ts -verify -token_in -in "$sealEvidence/timestamp.der" -data "$sealEvidence/altered-signed-bytes.bin" -CAfile "$sealEvidence/tsa-root.crt" 2>&1
    if($LASTEXITCODE -eq 0) { throw 'OpenSSL accepted an unrelated production timestamp imprint.' }
    Write-Output 'PASS: Production PDF seals verify independently and reject changed content/imprints. Certificates and timestamps are synthetic local fixtures.'
}
finally { [Environment]::SetEnvironmentVariable('QUILLSIGN_SEAL_ARTIFACTS',$previousArtifacts); Pop-Location }
exit 0

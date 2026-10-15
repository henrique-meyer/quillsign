#requires -Version 7.0
[CmdletBinding()]
param([ValidateSet('Migrate', 'Test')][string]$Action = 'Migrate')

$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '../..')
$previousConnection = [Environment]::GetEnvironmentVariable('ConnectionStrings__Database')
$previousTestConnection = [Environment]::GetEnvironmentVariable('QUILLSIGN_TEST_DATABASE')
$previousTestStorage = [Environment]::GetEnvironmentVariable('QUILLSIGN_TEST_STORAGE')
$previousTestSmtpPort = [Environment]::GetEnvironmentVariable('QUILLSIGN_TEST_SMTP_PORT')
$previousTestMailPort = [Environment]::GetEnvironmentVariable('QUILLSIGN_TEST_MAIL_PORT')
try {
    # Let Compose parse .env and honor process precedence, without printing resolved secrets.
    $resolved = docker compose config --format json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Compose configuration could not be resolved.' }
    $connection = [System.Data.Common.DbConnectionStringBuilder]::new()
    $connection['Server'] = '127.0.0.1,' + $resolved.services.sql.ports[0].published
    $connection['Initial Catalog'] = 'QuillSignDev'
    $connection['User ID'] = 'sa'
    $connection['Password'] = $resolved.services.sql.environment.MSSQL_SA_PASSWORD
    $connection['Encrypt'] = 'True'
    $connection['TrustServerCertificate'] = 'True' # Local SQL container's self-signed certificate only.
    if ($Action -eq 'Migrate') {
        $env:ConnectionStrings__Database = $connection.ConnectionString
        dotnet tool restore
        if ($LASTEXITCODE -ne 0) { throw 'EF tool restore failed.' }
        dotnet ef database update --project src/QuillSign/QuillSign.csproj
    } else {
        $env:QUILLSIGN_TEST_DATABASE = $connection.ConnectionString
        # Azure's connection format is not ADO.NET's (which would quote the base64 key).
        $hostBlob = 'BlobEndpoint=http://127.0.0.1:' + $resolved.services.azurite.ports[0].published + '/quillsigndev'
        $env:QUILLSIGN_TEST_STORAGE = [regex]::Replace(
            $resolved.services.app.environment.Storage__ConnectionString, 'BlobEndpoint=[^;]+', $hostBlob)
        $env:QUILLSIGN_TEST_SMTP_PORT = $resolved.services.mailpit.ports[0].published
        $env:QUILLSIGN_TEST_MAIL_PORT = $resolved.services.mailpit.ports[1].published
        dotnet test tests/QuillSign.Tests/QuillSign.Tests.csproj -c Release --nologo
    }
    if ($LASTEXITCODE -ne 0) { throw "Local database action failed: $Action" }
} finally {
    [Environment]::SetEnvironmentVariable('ConnectionStrings__Database', $previousConnection)
    [Environment]::SetEnvironmentVariable('QUILLSIGN_TEST_DATABASE', $previousTestConnection)
    [Environment]::SetEnvironmentVariable('QUILLSIGN_TEST_STORAGE', $previousTestStorage)
    [Environment]::SetEnvironmentVariable('QUILLSIGN_TEST_SMTP_PORT', $previousTestSmtpPort)
    [Environment]::SetEnvironmentVariable('QUILLSIGN_TEST_MAIL_PORT', $previousTestMailPort)
    Pop-Location
}

#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Migrate', 'Test', 'WorkOnce', 'RecoverWork', 'ListenWork', 'VerifyWork', 'RunApp')][string]$Action = 'Migrate',
    [ValidateRange(1, 65535)][int]$AppPort,
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '../..')
$previousConnection = [Environment]::GetEnvironmentVariable('ConnectionStrings__Database')
$previousTestConnection = [Environment]::GetEnvironmentVariable('QUILLSIGN_TEST_DATABASE')
$previousTestStorage = [Environment]::GetEnvironmentVariable('QUILLSIGN_TEST_STORAGE')
$previousTestSmtpPort = [Environment]::GetEnvironmentVariable('QUILLSIGN_TEST_SMTP_PORT')
$previousTestMailPort = [Environment]::GetEnvironmentVariable('QUILLSIGN_TEST_MAIL_PORT')
$workPrevious = @{}
$limitNames = 'Sender__SessionHours','Sender__DailyRequests','Sender__RequestsPerWindow','Sender__WindowMinutes','Documents__MaximumBytes','Documents__MaximumPages'
foreach ($name in $limitNames) { $workPrevious[$name] = [Environment]::GetEnvironmentVariable($name) }
foreach ($name in 'ASPNETCORE_ENVIRONMENT','Storage__Provider','Storage__ConnectionString','Work__Enabled','Work__QueueName','Work__HintContainer',
    'Email__Enabled','Email__Provider','Email__FromEmail','Email__BaseUrl','Email__Smtp__Host','Email__Smtp__Port','Email__Smtp__UseStartTls') {
    $workPrevious[$name] = [Environment]::GetEnvironmentVariable($name)
}
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
        $hostQueue = 'QueueEndpoint=http://127.0.0.1:' + $resolved.services.azurite.ports[1].published + '/quillsigndev'
        $env:QUILLSIGN_TEST_STORAGE = [regex]::Replace($env:QUILLSIGN_TEST_STORAGE, 'QueueEndpoint=[^;]+', $hostQueue)
        $env:QUILLSIGN_TEST_SMTP_PORT = $resolved.services.mailpit.ports[0].published
        $env:QUILLSIGN_TEST_MAIL_PORT = $resolved.services.mailpit.ports[1].published
        if ($Action -eq 'Test') {
            dotnet test tests/QuillSign.Tests/QuillSign.Tests.csproj -c Release --nologo
        } else {
            $env:ConnectionStrings__Database = $connection.ConnectionString
            $env:ASPNETCORE_ENVIRONMENT = 'Development'
            $env:Storage__Provider = 'Azurite'
            $env:Storage__ConnectionString = $env:QUILLSIGN_TEST_STORAGE
            $env:Work__Enabled = 'true'
            $env:Work__QueueName = $resolved.services.app.environment.Work__QueueName
            $env:Work__HintContainer = $resolved.services.app.environment.Work__HintContainer
            foreach ($name in $limitNames) { [Environment]::SetEnvironmentVariable($name, [string]$resolved.services.app.environment.$name) }
            $env:Email__Enabled = 'true'
            $env:Email__Provider = 'Smtp'
            $env:Email__FromEmail = 'noreply@example.invalid'
            $port = if ($AppPort) { $AppPort } else { $resolved.services.app.ports[0].published }
            $env:Email__BaseUrl = 'http://localhost:' + $port
            $env:Email__Smtp__Host = '127.0.0.1'
            $env:Email__Smtp__Port = $env:QUILLSIGN_TEST_SMTP_PORT
            $env:Email__Smtp__UseStartTls = 'false'
            [string[]]$buildArguments = if ($NoBuild) { @('--no-build') } else { @() }
            if ($Action -eq 'RunApp') {
                dotnet run --project src/QuillSign/QuillSign.csproj -c Release -p:UseAppHost=false @buildArguments -- --urls $env:Email__BaseUrl
            } else {
                $command = @{ WorkOnce = 'once'; RecoverWork = 'recover'; ListenWork = 'listen'; VerifyWork = 'verify' }[$Action]
                dotnet run --project src/QuillSign/QuillSign.csproj -c Release -p:UseAppHost=false @buildArguments -- work $command
            }
        }
    }
    if ($LASTEXITCODE -ne 0) { throw "Local database action failed: $Action" }
} finally {
    [Environment]::SetEnvironmentVariable('ConnectionStrings__Database', $previousConnection)
    [Environment]::SetEnvironmentVariable('QUILLSIGN_TEST_DATABASE', $previousTestConnection)
    [Environment]::SetEnvironmentVariable('QUILLSIGN_TEST_STORAGE', $previousTestStorage)
    [Environment]::SetEnvironmentVariable('QUILLSIGN_TEST_SMTP_PORT', $previousTestSmtpPort)
    [Environment]::SetEnvironmentVariable('QUILLSIGN_TEST_MAIL_PORT', $previousTestMailPort)
    foreach ($name in $workPrevious.Keys) { [Environment]::SetEnvironmentVariable($name, $workPrevious[$name]) }
    Pop-Location
}

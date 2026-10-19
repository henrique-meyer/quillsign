#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$ServerName,
    [Parameter(Mandatory)][string]$DatabaseName,
    [Parameter(Mandatory)][guid]$RuntimeClientId,
    [Parameter(Mandatory)][guid]$MigrationClientId,
    [guid]$WorkerClientId,
    [ValidateSet('provision-identities', 'provision-worker', 'migrate', 'grant-runtime', 'grant-demo-purge', 'grant-lookup-retention', 'grant-email-pilot-retention')]
    [string[]]$Operations = @('provision-identities', 'migrate', 'grant-runtime')
)
$ErrorActionPreference = 'Stop'
if ($RuntimeClientId -eq [guid]::Empty -or $MigrationClientId -eq [guid]::Empty -or $RuntimeClientId -eq $MigrationClientId) {
    throw 'Use distinct runtime and migration client IDs.'
}
Push-Location (Join-Path $PSScriptRoot '../..')
$previous = @{}
foreach ($name in 'ConnectionStrings__Database', 'Database__RuntimeClientId', 'Database__MigrationClientId', 'Database__WorkerClientId') {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name)
}
$ruleName = 'SqlAdmin-' + [guid]::NewGuid().ToString('N')
$attempted = $false
try {
    $address = [System.Net.IPAddress]::Parse((Invoke-RestMethod 'https://api.ipify.org').Trim())
    if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -eq '0.0.0.0') {
        throw 'An exact operator IPv4 address is required.'
    }
    $attempted = $true
    az deployment group create -g $ResourceGroup --name $ruleName --template-file infra/sql-administrator-access.bicep `
        --parameters "serverName=$ServerName" "firewallRuleName=$ruleName" "operatorIp=$address" -o none
    if ($LASTEXITCODE -ne 0) { throw 'Temporary SQL administrative access could not be configured.' }
    $connection = [System.Data.Common.DbConnectionStringBuilder]::new()
    $connection['Server'] = "tcp:$ServerName.database.windows.net,1433"
    $connection['Initial Catalog'] = $DatabaseName
    $connection['Authentication'] = 'Active Directory Default'
    $connection['Encrypt'] = 'True'
    $connection['TrustServerCertificate'] = 'False'
    $connection['Connect Timeout'] = 90
    $connection['Pooling'] = 'False'
    $env:ConnectionStrings__Database = $connection.ConnectionString
    $env:Database__RuntimeClientId = $RuntimeClientId.ToString()
    $env:Database__MigrationClientId = $MigrationClientId.ToString()
    $env:Database__WorkerClientId = $WorkerClientId.ToString()
    foreach ($operation in $Operations) {
        dotnet run --project src/QuillSign/QuillSign.csproj -c Release --no-build -- database $operation
        if ($LASTEXITCODE -ne 0) { throw "Administrative SQL operation failed: $operation" }
    }
} finally {
    foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name]) }
    if ($attempted) {
        # Remove only the unique rule created by this invocation, including partial failures.
        az sql server firewall-rule delete -g $ResourceGroup -s $ServerName -n $ruleName -o none
        if ($LASTEXITCODE -ne 0) { Write-Error 'Temporary SQL access cleanup failed; remove this invocation''s rule before continuing.' }
    }
    Pop-Location
}

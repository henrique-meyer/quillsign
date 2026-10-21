#requires -Version 7.0
[CmdletBinding()]
# Default: QUILLSIGN_ENV_FILE when set (e.g. a private file outside the checkout), else the ignored repo .env.
param([string]$Path = $(if ($env:QUILLSIGN_ENV_FILE) { $env:QUILLSIGN_ENV_FILE } else { Join-Path $PSScriptRoot '../../.env' }))

$ErrorActionPreference = 'Stop'
$envPath = [IO.Path]::GetFullPath($Path)
$content = if (Test-Path -LiteralPath $envPath) { [IO.File]::ReadAllText($envPath) } else { '' }

foreach ($name in @('MSSQL_SA_PASSWORD', 'AZURITE_ACCOUNT_KEY')) {
    # Compose gives process variables precedence over .env. Preserve both sources.
    if ([Environment]::GetEnvironmentVariable($name)) { continue }
    $pattern = '(?m)^' + $name + '=(.*)\r?$'
    $entry = [regex]::Match($content, $pattern)
    if ($entry.Success -and $entry.Groups[1].Value.Trim() -notin @('', '""', "''")) { continue }

    $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(64)
    $value = [Convert]::ToBase64String($bytes)
    if ($name -eq 'MSSQL_SA_PASSWORD') {
        $value = 'Qs9!' + $value.Replace('+', 'A').Replace('/', 'B').TrimEnd('=')
    }
    $line = $name + '=' + $value
    if ($entry.Success) {
        $content = [regex]::Replace($content, $pattern, $line)
    } else {
        if ($content -and -not $content.EndsWith("`n")) { $content += "`n" }
        $content += $line + "`n"
    }
}

[IO.File]::WriteAllText($envPath, $content, [Text.UTF8Encoding]::new($false))
Write-Host 'Local configuration is ready. Values were saved only in the ignored environment file.'

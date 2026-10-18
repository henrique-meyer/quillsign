#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ConfigurationPath,
    [Parameter(Mandatory)][string] $JournalPath,
    [switch] $Execute,
    [string] $AwsCliPath = 'aws'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

function Assert-PrivatePath([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($full)
    if (!(Test-Path -LiteralPath $parent -PathType Container)) { throw 'Private file parent must already exist.' }
    $root = & git -C $parent rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -eq 0) {
        & git -C $root ls-files --error-unmatch -- $full 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { throw 'Private configuration and journal must never be tracked.' }
        & git -C $root check-ignore --quiet --no-index -- $full
        if ($LASTEXITCODE -ne 0) { throw 'Configuration and journal must be outside Git or explicitly ignored.' }
    }
    return $full
}

function Invoke-Aws([string[]] $Arguments) {
    # Explicit endpoints prevent inherited endpoint overrides redirecting this operator request.
    $service = if ($Arguments[0] -eq 'sts') { 'sts' } else { 'email' }
    $endpoint = 'https://' + $service + '.' + $config.region + '.amazonaws.com'
    $output = & $AwsCliPath @Arguments --region $config.region --endpoint-url $endpoint --output json --no-cli-pager 2>&1
    $code = $LASTEXITCODE
    $text = [string]::Join("`n", @($output | ForEach-Object { $_.ToString() })).Trim()
    if ($code -ne 0) {
        if ($Arguments[0] -eq 'sesv2' -and $Arguments[1] -eq 'get-email-identity' -and
            $text -match '\(NotFoundException\)\s+when\s+calling\s+the\s+GetEmailIdentity\s+operation(?:\s+\(reached max retries: 0\))?:') { return $null }
        throw ('An AWS request failed (' + $Arguments[0] + ' ' + $Arguments[1] + '). No creation request will be automatically retried.')
    }
    try { return ConvertFrom-Json -InputObject $text -AsHashtable -ErrorAction Stop }
    catch { throw 'AWS response was not valid JSON. Reconcile any recorded creation intent read-only.' }
}

function Read-Identity([string] $Address) {
    $identity = Invoke-Aws -Arguments @('sesv2', 'get-email-identity', '--email-identity', $Address)
    if ($null -ne $identity) {
        $project = @($identity.Tags | Where-Object { $_.Key -ceq 'Project' })
        if ($identity.IdentityType -cne 'EMAIL_ADDRESS' -or $project.Count -ne 1 -or
            $project[0].Value -cne $config.projectTag -or $identity.VerifiedForSendingStatus -isnot [bool]) {
            throw 'Existing identity is outside the approved tagged email-address scope.'
        }
    }
    return $identity
}

function Assert-SendingOff {
    $account = Invoke-Aws -Arguments @('sesv2', 'get-account')
    if ($account.ProductionAccessEnabled -isnot [bool]) { throw 'SES sandbox status is unavailable.' }
    $set = Invoke-Aws -Arguments @('sesv2', 'get-configuration-set', '--configuration-set-name', $config.configurationSet)
    $project = @($set.Tags | Where-Object { $_.Key -ceq 'Project' })
    if ($set.SendingOptions.SendingEnabled -ne $false -or $set.SendingOptions.SendingEnabled -isnot [bool] -or
        $project.Count -ne 1 -or $project[0].Value -cne $config.projectTag) {
        throw 'The approved tagged configuration set must remain sending-disabled.'
    }
    return !$account.ProductionAccessEnabled
}

function Append-Journal([hashtable] $Record) {
    $Record.sequence = $script:recordCount
    $Record.at = [DateTimeOffset]::UtcNow.ToString('O')
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Record | ConvertTo-Json -Depth 8 -Compress) + "`n")
    $journal.Seek(0, [IO.SeekOrigin]::End) | Out-Null
    $journal.Write($bytes, 0, $bytes.Length)
    $journal.Flush($true) # The intent is durable before invoking the provider.
    $script:recordCount++
}

$configurationFile = Assert-PrivatePath $ConfigurationPath
$journalFile = Assert-PrivatePath $JournalPath
if ($configurationFile -ceq $journalFile) { throw 'Configuration and journal must be different files.' }
if ((Get-Item -LiteralPath $configurationFile).Length -gt 16384) { throw 'Configuration exceeds its bound.' }
$configurationJson = Get-Content -LiteralPath $configurationFile -Raw
$document = [Text.Json.JsonDocument]::Parse($configurationJson)
try {
    $properties = @($document.RootElement.EnumerateObject())
    if (@($properties.Name | Select-Object -Unique).Count -ne $properties.Count) { throw 'Duplicate configuration keys are invalid.' }
} finally { $document.Dispose() }
$config = $configurationJson | ConvertFrom-Json -AsHashtable
$expected = @('version','accountId','region','projectTag','configurationSet','addresses','maximumManagedVerificationMessages')
if (@($config.Keys).Count -ne $expected.Count -or @($config.Keys | Where-Object { $_ -cnotin $expected }).Count -ne 0 -or
    $config.version -cne 'ses-test-recipients-v1' -or $config.accountId -notmatch '^\d{12}$' -or
    $config.region -notmatch '^[a-z]{2}-[a-z]+-\d$' -or $config.region -like 'cn-*' -or
    $config.projectTag -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' -or
    $config.configurationSet -notmatch '^[A-Za-z0-9_-]{1,64}$' -or
    $config.maximumManagedVerificationMessages -ne 4 -or $config.addresses -isnot [array] -or $config.addresses.Count -ne 4) {
    throw 'Expected an exact bounded four-address configuration.'
}
$addresses = @($config.addresses)
foreach ($address in $addresses) {
    if ($address -isnot [string] -or $address.Length -gt 254 -or $address -cne $address.ToLowerInvariant() -or
        $address -notmatch '^[a-z0-9][a-z0-9.!#$%&''*+/=?^_`{|}~-]*@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$' -or
        $address.Contains('..')) { throw 'Each mailbox must be an exact normalized email address, never a domain.' }
}
if (@($addresses | Select-Object -Unique).Count -ne 4) { throw 'Four distinct mailbox addresses are required.' }
[string[]] $addresses = $addresses
[Array]::Sort($addresses, [StringComparer]::Ordinal)
$canonical = [ordered]@{ version=$config.version; accountId=$config.accountId; region=$config.region; projectTag=$config.projectTag;
    configurationSet=$config.configurationSet; addresses=$addresses; maximumManagedVerificationMessages=4 } | ConvertTo-Json -Compress
$scope = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant()
$oldAttempts = $env:AWS_MAX_ATTEMPTS
$oldMode = $env:AWS_RETRY_MODE
$journal = $null
try {
    $env:AWS_MAX_ATTEMPTS = '1'
    $env:AWS_RETRY_MODE = 'standard'
    $journal = [IO.FileStream]::new($journalFile, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    if ($journal.Length -gt 65536) { throw 'Journal exceeds its bound; preserve it and stop.' }
    $reader = [IO.StreamReader]::new($journal, [Text.Encoding]::UTF8, $false, 1024, $true)
    try { $saved = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $records = @()
    if ($saved.Length -gt 0) {
        if (!$saved.EndsWith("`n")) { throw 'Journal ends in a partial record; preserve it and stop.' }
        foreach ($line in $saved.TrimEnd("`n").Split("`n")) { $records += ConvertFrom-Json -InputObject $line -AsHashtable }
    }
    $script:recordCount = $records.Count
    $intents = @{}
    for ($n = 0; $n -lt $records.Count; $n++) {
        $record = $records[$n]
        if ($record.sequence -ne $n) { throw 'Journal sequence is invalid.' }
        if ($n -eq 0) {
            if ($record.type -cne 'scope' -or $record.scope -cne $scope) { throw 'Journal belongs to another immutable scope.' }
        } elseif ($record.type -ceq 'intent') {
            if ($record.address -cnotin $addresses -or $intents.ContainsKey($record.address)) { throw 'Journal contains a repeated or unknown intent.' }
            $intents[$record.address] = $true
        } elseif ($record.type -ceq 'result') {
            if (!$intents.ContainsKey($record.address) -or $record.outcome -cnotin @('acknowledged','uncertain')) { throw 'Journal result is invalid.' }
        } else { throw 'Unknown journal record.' }
    }
    if ($records.Count -eq 0) { Append-Journal @{type='scope';scope=$scope} }
    $caller = Invoke-Aws -Arguments @('sts', 'get-caller-identity')
    if ($caller.Account -cne $config.accountId) { throw 'AWS account does not match the approved scope.' }
    $sandbox = Assert-SendingOff
    $states = @{}
    foreach ($address in $addresses) { $states[$address] = Read-Identity $address }
    foreach ($address in $intents.Keys) {
        if ($null -eq $states[$address]) { throw 'An earlier creation intent is unresolved or its identity was removed. Never recreate it.' }
    }
    $createdThisRun = 0
    if ($Execute -and $sandbox) {
        foreach ($address in $addresses) {
            if ($null -ne $states[$address]) { continue }
            # Resample eligibility and the exact identity before spending its one durable attempt.
            if (!(Assert-SendingOff)) { break }
            $states[$address] = Read-Identity $address
            if ($null -ne $states[$address]) { continue }
            if ($intents.ContainsKey($address) -or $intents.Count -ge 4) { throw 'Creation budget is unavailable.' }
            Append-Journal @{type='intent';address=$address}
            $intents[$address] = $true
            try {
                $tag = 'Key=Project,Value=' + $config.projectTag
                $answer = Invoke-Aws -Arguments @('sesv2','create-email-identity','--email-identity',$address,'--tags',$tag)
                if ($answer.IdentityType -cne 'EMAIL_ADDRESS') { throw 'Unexpected identity creation acknowledgement.' }
            } catch {
                Append-Journal @{type='result';address=$address;outcome='uncertain'}
                # A read can reconcile an acknowledged resource, but never authorize another create.
                $states[$address] = Read-Identity $address
                throw 'A creation attempt failed or its acknowledgement is uncertain. Preserve the journal; inspect status without re-requesting a verification message.'
            }
            Append-Journal @{type='result';address=$address;outcome='acknowledged'}
            $createdThisRun++
            $states[$address] = Read-Identity $address
            if ($null -eq $states[$address]) { throw 'The creation acknowledgement needs read-only reconciliation. Never recreate the identity.' }
        }
    }
    [pscustomobject]@{
        mode = $(if ($Execute) { 'bounded-execute' } else { 'read-only' })
        sandbox = $sandbox
        creationIntentsEver = $intents.Count
        creationsAcknowledgedThisRun = $createdThisRun
        verified = @($addresses | Where-Object { $null -ne $states[$_] -and $states[$_].VerifiedForSendingStatus }).Count
        pending = @($addresses | Where-Object { $null -ne $states[$_] -and !$states[$_].VerifiedForSendingStatus }).Count
        absent = @($addresses | Where-Object { $null -eq $states[$_] }).Count
        configurationSetSending = $false
    } | ConvertTo-Json -Compress
} finally {
    if ($null -ne $journal) { $journal.Dispose() }
    $env:AWS_MAX_ATTEMPTS = $oldAttempts
    $env:AWS_RETRY_MODE = $oldMode
}

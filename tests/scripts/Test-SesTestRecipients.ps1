#requires -Version 7.2
$ErrorActionPreference = 'Stop'
$helper = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../scripts/cloud/Initialize-SesTestRecipients.ps1'))
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('ses-recipient-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$previousEnvironment = @{}
foreach ($name in @('QUILLSIGN_FAKE_SES_STATE','QUILLSIGN_FAKE_SES_JOURNAL','AWS_MAX_ATTEMPTS','AWS_RETRY_MODE')) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
}
$fake = Join-Path $fixture 'aws.ps1'
@'
$arguments = @($args)
$statePath = $env:QUILLSIGN_FAKE_SES_STATE
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable
$operation = $arguments[1]
if ($env:AWS_MAX_ATTEMPTS -ne '1' -or $env:AWS_RETRY_MODE -ne 'standard') { throw 'Retries were not disabled.' }
if ($arguments -cnotcontains '--endpoint-url' -or $arguments -cnotcontains '--no-cli-pager') { throw 'Missing explicit endpoint/pager guard.' }
$state.calls += ,@($arguments)
function Save { $state | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $statePath }
$global:LASTEXITCODE = 0
if ($operation -eq 'get-caller-identity') { Save; @{Account=$state.account}|ConvertTo-Json -Compress; return }
if ($operation -eq 'get-account') { Save; @{ProductionAccessEnabled=$state.production}|ConvertTo-Json -Compress; return }
if ($operation -eq 'get-configuration-set') { Save; @{SendingOptions=@{SendingEnabled=$state.sending};Tags=@(@{Key='Project';Value='test-project'})}|ConvertTo-Json -Depth 4 -Compress; return }
$address = $arguments[[array]::IndexOf($arguments, '--email-identity') + 1]
if ($operation -eq 'get-email-identity') {
    Save
    if ($state.readError) { $global:LASTEXITCODE=254; 'An error occurred (AccessDeniedException) when calling the GetEmailIdentity operation: denied'; return }
    if (!$state.identities.ContainsKey($address)) { $global:LASTEXITCODE=254; 'aws: [ERROR]: An error occurred (NotFoundException) when calling the GetEmailIdentity operation (reached max retries: 0): missing'; return }
    $state.identities[$address]|ConvertTo-Json -Depth 4 -Compress; return
}
if ($operation -ne 'create-email-identity') { throw 'Unexpected operation.' }
$tags = $arguments[[array]::IndexOf($arguments, '--tags') + 1]
if ($tags -cne 'Key=Project,Value=test-project') { throw 'Incorrect create tags.' }
# Inspect the on-disk journal at the provider boundary, not just the final result.
$journal = Get-Content -LiteralPath $env:QUILLSIGN_FAKE_SES_JOURNAL | ForEach-Object { $_ | ConvertFrom-Json }
if (@($journal|Where-Object {$_.type -eq 'intent' -and $_.address -ceq $address}).Count -ne 1) { throw 'Missing durable intent before provider call.' }
$state.creates += $address
if ($state.failure -eq 'before') { Save; $global:LASTEXITCODE=255; 'Connection closed before acknowledgement'; return }
$state.identities[$address] = @{IdentityType='EMAIL_ADDRESS';VerifiedForSendingStatus=$false;Tags=@(@{Key='Project';Value='test-project'})}
Save
if ($state.failure -eq 'after') { $global:LASTEXITCODE=255; 'Connection closed after acceptance'; return }
@{IdentityType='EMAIL_ADDRESS';VerifiedForSendingStatus=$false}|ConvertTo-Json -Compress
'@ | Set-Content -LiteralPath $fake

function Assert([bool] $Condition, [string] $Message) { if (!$Condition) { throw $Message } }
function New-Fixture([string] $Name) {
    $directory = Join-Path $fixture $Name
    New-Item -ItemType Directory -Path $directory | Out-Null
    $script:configPath = Join-Path $directory 'config.json'
    $script:journalPath = Join-Path $directory 'journal.jsonl'
    $env:QUILLSIGN_FAKE_SES_STATE = Join-Path $directory 'state.json'
    $env:QUILLSIGN_FAKE_SES_JOURNAL = $script:journalPath
    $script:configuration = @{version='ses-test-recipients-v1';accountId='000000000000';region='us-east-2';projectTag='test-project';
        configurationSet='test-set';addresses=@('a@example.test','b@example.test','c@example.test','d@example.test');maximumManagedVerificationMessages=4}
    $script:configuration | ConvertTo-Json | Set-Content -LiteralPath $script:configPath
    @{account='000000000000';production=$false;sending=$false;readError=$false;failure='';calls=@();creates=@();identities=@{}} |
        ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $env:QUILLSIGN_FAKE_SES_STATE
}
function State { Get-Content -LiteralPath $env:QUILLSIGN_FAKE_SES_STATE -Raw | ConvertFrom-Json -AsHashtable }
function Save-State([hashtable] $State) { $State|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $env:QUILLSIGN_FAKE_SES_STATE }
function Run([bool] $Execute=$true) {
    $output = & $helper -ConfigurationPath $script:configPath -JournalPath $script:journalPath -AwsCliPath $fake -Execute:$Execute
    Assert ($LASTEXITCODE -eq 0) 'Successful inspection must not leave an expected native lookup failure as its exit status.'
    return $output | ConvertFrom-Json
}
function Reject([scriptblock] $Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    Assert $failed 'Expected fail-closed rejection.'
}

try {
    New-Fixture 'dry-run'
    $env:AWS_MAX_ATTEMPTS='9'; $env:AWS_RETRY_MODE='adaptive'
    $result=Run $false
    Assert ($result.absent -eq 4 -and (State).creates.Count -eq 0) 'Dry run must not request mail.'
    Assert ($env:AWS_MAX_ATTEMPTS -eq '9' -and $env:AWS_RETRY_MODE -eq 'adaptive') 'Caller retry configuration must be restored.'
    $result=Run
    Assert ($result.creationIntentsEver -eq 4 -and $result.pending -eq 4 -and (State).creates.Count -eq 4) 'Exactly four requests expected.'
    $result=Run
    Assert ($result.creationsAcknowledgedThisRun -eq 0 -and (State).creates.Count -eq 4) 'Restart must never resend verification.'
    $state=State; $state.identities['a@example.test'].VerifiedForSendingStatus=$true; Save-State $state
    Assert ((Run $false).verified -eq 1 -and (State).creates.Count -eq 4) 'Read-only verification must not resend.'

    New-Fixture 'lost-ack'
    $state=State; $state.failure='after'; Save-State $state
    Reject { Run }
    Assert ((State).creates.Count -eq 1) 'Unknown acknowledgement stops subsequent creation.'
    $state=State; $state.failure=''; Save-State $state
    $result=Run
    Assert ((State).creates.Count -eq 4 -and $result.creationIntentsEver -eq 4) 'Resume must read-reconcile accepted identity, then create only unattempted ones.'

    New-Fixture 'unknown-missing'
    $state=State; $state.failure='before'; Save-State $state
    Reject { Run }; Reject { Run }
    Assert ((State).creates.Count -eq 1) 'Unresolved intent must never be retried.'

    New-Fixture 'account'
    $state=State; $state.account='111111111111'; Save-State $state
    Reject { Run }; Assert ((State).creates.Count -eq 0) 'Wrong account must block all mutation.'

    New-Fixture 'production'
    $state=State; $state.production=$true; Save-State $state
    Assert (!(Run).sandbox -and (State).creates.Count -eq 0) 'Production access makes bootstrap unnecessary.'

    New-Fixture 'sending'
    $state=State; $state.sending=$true; Save-State $state
    Reject { Run }; Assert ((State).creates.Count -eq 0) 'Enabled configuration set must block.'

    New-Fixture 'denied-read'
    $state=State; $state.readError=$true; Save-State $state
    Reject { Run }; Assert ((State).creates.Count -eq 0) 'Denied lookup is not an absent identity.'

    New-Fixture 'foreign-tag'
    $state=State; $state.identities['d@example.test']=@{IdentityType='EMAIL_ADDRESS';VerifiedForSendingStatus=$false;Tags=@(@{Key='Project';Value='unrelated'})}; Save-State $state
    Reject { Run }; Assert ((State).creates.Count -eq 0) 'All identities must be checked before first mutation.'

    New-Fixture 'changed-scope'
    Run $false|Out-Null
    $script:configuration.addresses[0]='changed@example.test'; $script:configuration|ConvertTo-Json|Set-Content -LiteralPath $script:configPath
    Reject { Run }; Assert ((State).creates.Count -eq 0) 'Scope cannot change behind a saved journal.'

    New-Fixture 'duplicate'
    $script:configuration.addresses[1]=$script:configuration.addresses[0]; $script:configuration|ConvertTo-Json|Set-Content -LiteralPath $script:configPath
    Reject { Run }; Assert ((State).calls.Count -eq 0) 'Duplicate address must fail before any AWS call.'

    New-Fixture 'truncated-journal'
    Run $false|Out-Null; [IO.File]::AppendAllText($script:journalPath, '{"type":"intent"')
    Reject { Run }; Assert ((State).creates.Count -eq 0) 'Truncated journal must fail closed.'

    New-Fixture 'concurrent-owner'
    Run $false|Out-Null
    $lock=[IO.FileStream]::new($script:journalPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { Reject { Run } } finally { $lock.Dispose() }
    Assert ((State).creates.Count -eq 0) 'Concurrent process cannot bypass journal ownership.'

    New-Fixture 'tracked-path'
    $directory=[IO.Path]::GetDirectoryName($script:configPath)
    & git -C $directory init --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Fixture Git initialization failed.' }
    Reject { Run }; Assert ((State).calls.Count -eq 0) 'Unignored private input must fail before AWS.'
    "config.json`njournal.jsonl`n"|Set-Content -LiteralPath (Join-Path $directory '.gitignore')
    Assert ((Run $false).absent -eq 4) 'Explicitly ignored private paths must work.'
    Write-Output 'SES recipient bootstrap: 16 bounded fake-provider scenarios passed; no AWS connection or email.'
} finally {
    foreach ($name in $previousEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name]) }
    # This uniquely generated fixture root is the only recursive cleanup target.
    $resolvedFixture = [IO.Path]::GetFullPath($fixture)
    if ([IO.Path]::GetDirectoryName($resolvedFixture) -cne [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)) { throw 'Unexpected fixture cleanup target.' }
    Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
$global:LASTEXITCODE = 0

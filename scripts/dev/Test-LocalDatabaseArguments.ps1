#requires -Version 7.0
# Pure regression: invoke the real script with function-only native shims.
# No Docker, dotnet, SQL, storage or provider process is executed.
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'Use-LocalDatabase.ps1'
if (Get-Variable -Name QuillSignArgumentProbe -Scope Global -ErrorAction SilentlyContinue) { throw 'Argument probe already active.' }
$global:QuillSignArgumentProbe = @{ Checks = 0; Calls = [Collections.Generic.List[object]]::new(); FailAt = 0; Compose = $null }
$global:QuillSignArgumentProbe.Compose = @{
    services = @{
        sql = @{ ports = @(@{ published = 11433 }); environment = @{ MSSQL_SA_PASSWORD = 'synthetic-local-only' } }
        azurite = @{ ports = @(@{ published = 11000 }, @{ published = 11001 }) }
        mailpit = @{ ports = @(@{ published = 11025 }, @{ published = 18025 }) }
        app = @{
            ports = @(@{ published = 18080 })
            environment = @{
                Storage__ConnectionString = 'BlobEndpoint=http://azurite:10000/quillsigndev;QueueEndpoint=http://azurite:10001/quillsigndev'
                Work__QueueName = 'synthetic-work'; Work__HintContainer = 'synthetic-hints'
                Sender__SessionHours = 1; Sender__DailyRequests = 1; Sender__RequestsPerWindow = 1
                Sender__WindowMinutes = 1; Documents__MaximumBytes = 1024; Documents__MaximumPages = 1
            }
        }
    }
} | ConvertTo-Json -Depth 8 -Compress
function Assert-Argument([bool]$condition, [string]$message) {
    if (!$condition) { throw "Local database argument regression: $message" }
    $global:QuillSignArgumentProbe.Checks++
}
function docker {
    Assert-Argument (($args -join '|') -ceq 'compose|config|--format|json') 'unexpected Docker action'
    $global:LASTEXITCODE = 0
    $global:QuillSignArgumentProbe.Compose
}
function dotnet {
    $global:QuillSignArgumentProbe.Calls.Add([string[]]$args)
    $global:LASTEXITCODE = if ($global:QuillSignArgumentProbe.FailAt -eq $global:QuillSignArgumentProbe.Calls.Count) { 37 } else { 0 }
}
function Same-Arguments($actual, [string[]]$expected) {
    Assert-Argument (($actual -join '|') -ceq ($expected -join '|')) ('exact argument sequence: ' + ($actual -join '|'))
}
$names = @('ConnectionStrings__Database','QUILLSIGN_TEST_DATABASE','QUILLSIGN_TEST_STORAGE','QUILLSIGN_TEST_SMTP_PORT','QUILLSIGN_TEST_MAIL_PORT',
    'Sender__SessionHours','Sender__DailyRequests','Sender__RequestsPerWindow','Sender__WindowMinutes','Documents__MaximumBytes','Documents__MaximumPages',
    'ASPNETCORE_ENVIRONMENT','Storage__Provider','Storage__ConnectionString','Work__Enabled','Work__QueueName','Work__HintContainer',
    'Email__Enabled','Email__Provider','Email__FromEmail','Email__BaseUrl','Email__Smtp__Host','Email__Smtp__Port','Email__Smtp__UseStartTls')
$original = @{}
$before = @{}
# Present synthetic sentinels make restoration observable on both Windows and Unix.
foreach ($name in $names) {
    $original[$name] = [Environment]::GetEnvironmentVariable($name)
    $before[$name] = 'synthetic-argument-probe'
    [Environment]::SetEnvironmentVariable($name, $before[$name])
}
$previousExitCode = $global:LASTEXITCODE
function Invoke-Case([string]$action, [bool]$noBuild, [int]$failAt = 0) {
    $global:QuillSignArgumentProbe.Calls.Clear(); $global:QuillSignArgumentProbe.FailAt = $failAt
    Assert-Argument ((Get-Command docker).CommandType -eq 'Function' -and (Get-Command dotnet).CommandType -eq 'Function') 'native shims required'
    $failed = $false
    try { & $target -Action $action -NoBuild:$noBuild }
    catch {
        if ($_.Exception.Message -notin @('EF tool restore failed.', "Local database action failed: $action")) { throw }
        $failed = $true
    }
    Assert-Argument ($failed -eq ($failAt -gt 0)) 'failure must propagate'
    foreach ($name in $names) { Assert-Argument ([Environment]::GetEnvironmentVariable($name) -ceq $before[$name]) ('environment must be restored: ' + $name) }
}
try {
    Invoke-Case 'Migrate' $false
    Assert-Argument ($global:QuillSignArgumentProbe.Calls.Count -eq 2) 'default migration call count'
    Same-Arguments $global:QuillSignArgumentProbe.Calls[0] @('tool','restore')
    Same-Arguments $global:QuillSignArgumentProbe.Calls[1] @('ef','database','update','--project','src/QuillSign/QuillSign.csproj')
    Invoke-Case 'Migrate' $true
    Assert-Argument ($global:QuillSignArgumentProbe.Calls.Count -eq 2) 'migration reuses build without fallback'
    Same-Arguments $global:QuillSignArgumentProbe.Calls[0] @('tool','restore')
    Same-Arguments $global:QuillSignArgumentProbe.Calls[1] @('ef','database','update','--project','src/QuillSign/QuillSign.csproj','--configuration','Release','--no-build')
    # Functions consume the -- terminator and split -p:value. Assert the original
    # native command tokens separately instead of mistaking shim binding for argv.
    $parseErrors = $null; $tokens = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$parseErrors)
    Assert-Argument ($parseErrors.Count -eq 0) 'target parses'
    $workCommands = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'dotnet' -and $node.Extent.Text -match '-- work \$command$'
    }, $true))
    Assert-Argument ($workCommands.Count -eq 1) 'one existing native work command'
    Assert-Argument ($workCommands[0].Extent.Text -ceq 'dotnet run --project src/QuillSign/QuillSign.csproj -c Release -p:UseAppHost=false @buildArguments -- work $command') 'native work separator and build arguments retained'
    foreach ($pair in @(@('RecoverWork','recover'), @('WorkOnce','once'), @('VerifyWork','verify'), @('WorkOnce','once'))) {
        Invoke-Case $pair[0] $true
        Assert-Argument ($global:QuillSignArgumentProbe.Calls.Count -eq 1) 'one finite work invocation'
        Same-Arguments $global:QuillSignArgumentProbe.Calls[0] @('run','--project','src/QuillSign/QuillSign.csproj','-c','Release','-p:','UseAppHost=false','--no-build','work',$pair[1])
    }
    Invoke-Case 'Migrate' $true 1
    Assert-Argument ($global:QuillSignArgumentProbe.Calls.Count -eq 1) 'failed tool restore stops'
    Invoke-Case 'Migrate' $true 2
    Assert-Argument ($global:QuillSignArgumentProbe.Calls.Count -eq 2) 'failed no-build migration never rebuilds'
    Invoke-Case 'WorkOnce' $true 1
    Assert-Argument ($global:QuillSignArgumentProbe.Calls.Count -eq 1) 'failed work never replays'

    $workflow = Get-Content (Join-Path $PSScriptRoot '../../.github/workflows/ci.yml') -Raw
    $section = [regex]::Match($workflow, '(?ms)^  local-stack:\r?\n(?<body>.*?)(?=^  [A-Za-z][A-Za-z-]*:|\z)').Groups['body'].Value
    Assert-Argument ($section -match '(?m)^    timeout-minutes: 60\s*$') 'unchanged job bound'
    Assert-Argument ($section -match '(?m)^        run: ./scripts/dev/Use-LocalDatabase.ps1 -Action Test\s*$') 'full test still builds'
    $finite = [regex]::Matches($section, '(?m)^\s+\./scripts/dev/Use-LocalDatabase\.ps1 -Action (Migrate|RecoverWork|WorkOnce|VerifyWork)([^\r\n]*)\r?$')
    Assert-Argument ($finite.Count -eq 5) 'all five finite commands retained'
    $order = @('Migrate','RecoverWork','WorkOnce','VerifyWork','WorkOnce')
    for ($i = 0; $i -lt 5; $i++) {
        Assert-Argument ($finite[$i].Groups[1].Value -ceq $order[$i] -and $finite[$i].Groups[2].Value.Trim() -ceq '-NoBuild') 'finite order and reuse'
    }
    Assert-Argument ($section.IndexOf('Test-LocalDatabaseArguments.ps1') -lt $section.IndexOf('docker compose up')) 'pure proof before services'
    Assert-Argument ($section -match '(?s)Remove test stack and its volumes\s+if: always\(\)\s+run: docker compose down --volumes --remove-orphans') 'unconditional cleanup retained'
    Write-Output "Passed $($global:QuillSignArgumentProbe.Checks) local database argument checks; no native tools executed."
} finally {
    foreach ($name in $names) {
        $value = if ($null -eq $original[$name]) { [NullString]::Value } else { $original[$name] }
        [Environment]::SetEnvironmentVariable($name, $value)
    }
    $global:LASTEXITCODE = $previousExitCode
    Remove-Variable -Name QuillSignArgumentProbe -Scope Global
}

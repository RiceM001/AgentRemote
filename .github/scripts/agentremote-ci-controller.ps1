param(
    [ValidateSet('SelfCheck', 'Start', 'WaitReady', 'WaitFinal', 'Stop')]
    [string]$Mode = 'SelfCheck',
    [int]$TimeoutSeconds = 300,
    [double]$PollSeconds = 2,
    [int]$ShutdownSeconds = 30,
    [switch]$Preflight,
    [int]$StartupAckSeconds = 30
)
$ErrorActionPreference = 'Stop'

function Assert-Identity($actual, $expected) {
    $mode = if ($expected.preflight -eq $true) { '--preflight --wait-controller' } else { '--apply' }
    $command = '^"?' + [regex]::Escape($expected.executable) + '"?\s+-B\s+"?' +
        [regex]::Escape($expected.script) + '"?\s+' + [regex]::Escape($mode) + '\s*$'
    if ($actual.pid -ne $expected.pid -or $actual.ticks -ne $expected.ticks -or
        $actual.executable -ine $expected.executable -or $actual.command -notmatch $command) {
        throw 'CI process identity mismatch; refusing to control it.'
    }
}

function Get-Phase($ready, $final, $alive, $now, $deadline) {
    if ($now -ge $deadline) { return 'timeout' }
    if ($null -ne $final -and $final.passed -ne $true) { return 'failed' }
    if (-not $alive) { return 'exited' }
    if ($null -ne $ready) { return 'ready' }
    return 'waiting'
}

if ($Mode -eq 'SelfCheck') {
    $expected = @{ pid = 123; ticks = 456; executable = 'C:\Python\python.exe'; script = 'C:\repo\node.py' }
    $valid = @{ pid = 123; ticks = 456; executable = 'C:\Python\python.exe'; command = '"C:\Python\python.exe" -B "C:\repo\node.py" --apply' }
    Assert-Identity $valid $expected
    $preflightIdentity = $expected.Clone(); $preflightIdentity.preflight = $true
    $preflightActual = $valid.Clone(); $preflightActual.command = $valid.command.Replace('--apply', '--preflight --wait-controller')
    Assert-Identity $preflightActual $preflightIdentity
    $rejected = $false
    try { Assert-Identity $valid $preflightIdentity } catch { $rejected = $true }
    if (-not $rejected) { throw 'Different execution mode accepted' }
    foreach ($field in @('pid', 'ticks', 'executable', 'command')) {
        $bad = $valid.Clone()
        $bad[$field] = if ($field -in @('pid', 'ticks')) { 999 } else { 'foreign' }
        $rejected = $false
        try { Assert-Identity $bad $expected } catch { $rejected = $true }
        if (-not $rejected) { throw "Accepted foreign process $field" }
    }
    if ((Get-Phase @{} $null $true 20 10) -ne 'timeout') { throw 'Late ready accepted' }
    if ((Get-Phase @{} @{passed=$false} $true 1 10) -ne 'failed') { throw 'Early failure ignored' }
    if ((Get-Phase $null $null $false 1 10) -ne 'exited') { throw 'Exited node accepted' }
    if ((Get-Phase @{} $null $false 1 10) -ne 'exited') { throw 'Stale ready from an exited node accepted' }
    if ((Get-Phase @{} $null $true 1 10) -ne 'ready') { throw 'Ready node rejected' }
    if ((Get-Phase $null $null $true 1 10) -ne 'waiting') { throw 'Missing ready accepted' }
    $multiplePython = @([pscustomobject]@{Source='C:\Python312\python.exe'}, [pscustomobject]@{Source='C:\Python311\python.exe'})
    $firstPython = ($multiplePython | Select-Object -First 1).Source
    if ($firstPython -isnot [string] -or $firstPython -ne 'C:\Python312\python.exe') { throw 'Multiple Python matches did not resolve to one first executable' }
    '{"self_check":"passed","processes_started":false,"network_used":false}'
    exit 0
}

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or $PSVersionTable.Platform -ne 'Win32NT') {
    throw 'Refuse CI process control outside GitHub-hosted Windows.'
}
if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 3300 -or $PollSeconds -le 0 -or $PollSeconds -gt 10 -or $ShutdownSeconds -lt 1 -or $StartupAckSeconds -lt 1 -or $StartupAckSeconds -gt 120) {
    throw 'Invalid controller timeout configuration.'
}
$scriptPath = [IO.Path]::GetFullPath((Join-Path $env:GITHUB_WORKSPACE '.github/scripts/agentremote-ci-node.py'))
$outputPath = Join-Path $env:GITHUB_WORKSPACE 'ci-output'
$identityPath = Join-Path $outputPath 'controller-private.json'
$readyPath = Join-Path $outputPath 'ready.json'
$finalPath = Join-Path $outputPath 'final.json'

function Read-Json($path) {
    if (Test-Path -LiteralPath $path -PathType Leaf) { return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
    return $null
}

function Owned-Process($identity) {
    if ([bool]$identity.preflight -ne [bool]$Preflight) { throw 'Controller execution mode mismatch.' }
    if ($identity.script -ine $scriptPath -or (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash -ine $identity.script_sha256) {
        throw 'CI script identity changed; refusing process control.'
    }
    $process = Get-Process -Id ([int]$identity.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    $null = $process.Handle
    $cim = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$identity.pid)
    if ($null -eq $cim) { $process.Dispose(); return $null }
    try {
        Assert-Identity @{pid=$process.Id; ticks=$process.StartTime.ToUniversalTime().Ticks;
            executable=$process.Path; command=$cim.CommandLine} $identity
    } catch { $process.Dispose(); throw }
    return $process
}

if ($Mode -eq 'Start') {
    if (Test-Path -LiteralPath $identityPath) { throw 'A CI controller identity already exists.' }
    if (Test-Path -LiteralPath (Join-Path $outputPath 'started.json')) { throw 'Stale interpreter startup marker.' }
    $null = New-Item -ItemType Directory -Path $outputPath -Force
    $pythonExe = (Get-Command python -CommandType Application | Select-Object -First 1).Source
    if ($pythonExe -isnot [string] -or -not [IO.Path]::IsPathRooted($pythonExe) -or
        [IO.Path]::GetExtension($pythonExe) -ine '.exe' -or -not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
        throw 'Expected one existing absolute Python executable.'
    }
    $nodeMode = if ($Preflight) { '--preflight --wait-controller' } else { '--apply' }
    if ($Preflight -and (Test-Path -LiteralPath (Join-Path $outputPath 'preflight-release'))) { throw 'Stale preflight release marker.' }
    $process = Start-Process -FilePath $pythonExe -ArgumentList @('-B', ('"' + $scriptPath + '"'), $nodeMode) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $outputPath 'node-private.stdout.log') `
        -RedirectStandardError (Join-Path $outputPath 'node-private.stderr.log')
    $null = $process.Handle
    $identity = @{pid=$process.Id; ticks=$process.StartTime.ToUniversalTime().Ticks; executable=$process.Path;
        script=$scriptPath; script_sha256=(Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash; preflight=[bool]$Preflight}
    $identity | ConvertTo-Json | Set-Content -LiteralPath $identityPath -Encoding utf8
    $owned = Owned-Process $identity
    if ($null -eq $owned) { throw 'CI child exited at startup.' }
    $owned.Dispose()
    $startupDeadline = [DateTimeOffset]::UtcNow.AddSeconds($StartupAckSeconds)
    while (-not (Test-Path -LiteralPath (Join-Path $outputPath 'started.json'))) {
        if ($process.WaitForExit([int]($PollSeconds * 1000))) {
            if (-not (Test-Path -LiteralPath $finalPath)) {
                @{schema=1; passed=$false; stage='host_interpreter'; error_type='InterpreterExitedBeforeAck';
                  exit_code=$process.ExitCode; powershell_version=@($PSVersionTable.PSVersion.Major,$PSVersionTable.PSVersion.Minor,$PSVersionTable.PSVersion.Patch)} |
                    ConvertTo-Json | Set-Content -LiteralPath $finalPath -Encoding utf8
            }
            throw 'Interpreter exited before safe startup acknowledgement.'
        }
        if ([DateTimeOffset]::UtcNow -ge $startupDeadline) {
            if (-not (Test-Path -LiteralPath $finalPath)) {
                @{schema=1; passed=$false; stage='host_interpreter'; error_type='InterpreterStartupTimeout'} |
                    ConvertTo-Json | Set-Content -LiteralPath $finalPath -Encoding utf8
            }
            throw 'Interpreter startup acknowledgement timed out.'
        }
    }
    $started = Read-Json (Join-Path $outputPath 'started.json')
    if ($started.schema -ne 1 -or $started.runtime_version.host.Count -ne 3 -or
        @($started.runtime_version.host | Where-Object { ($_ -isnot [int] -and $_ -isnot [long]) -or $_ -lt 0 }).Count) {
        throw 'Invalid interpreter startup acknowledgement.'
    }
    $process.Dispose()
    '{"ci_child_started":true}'
    exit 0
}

$identity = Read-Json $identityPath
if ($null -eq $identity) {
    if ($Mode -eq 'Stop') { exit 0 }
    throw 'Missing CI process identity.'
}
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
while ($true) {
    $process = Owned-Process $identity
    $alive = $null -ne $process
    $ready = Read-Json $readyPath
    $final = Read-Json $finalPath
    if ($Preflight -and $Mode -eq 'WaitFinal' -and $alive) {
        $null = New-Item -ItemType File -Path (Join-Path $outputPath 'preflight-release') -Force
    }
    if ($Mode -eq 'Stop') {
        if (-not $alive) { break }
        $scope = if ($null -ne $ready) { $ready } else { Read-Json (Join-Path $outputPath 'boot-private.json') }
        if ($null -ne $scope -and $scope.run_nonce -match '^[0-9a-f]{32}$') {
            $work = [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP ('agentremote-file-ci-' + $scope.run_nonce)))
            if ([IO.Path]::GetFullPath($scope.fixture_root) -ine (Join-Path $work 'fixtures')) { throw 'CI fixture scope mismatch.' }
            $stopPath = Join-Path $work 'profile/WinRemotePersistent/stop'
            if (Test-Path -LiteralPath (Split-Path -Parent $stopPath)) { $null = New-Item -ItemType File -Path $stopPath -Force }
        }
        if (-not $process.WaitForExit($ShutdownSeconds * 1000)) {
            $process.Kill()
            if (-not $process.WaitForExit($ShutdownSeconds * 1000)) { throw 'CI controller did not stop.' }
        }
        $process.Dispose()
        break
    }
    if ($alive) { $process.Dispose() }
    $phase = Get-Phase $ready $final $alive ([DateTimeOffset]::UtcNow) $deadline
    if ($Mode -eq 'WaitReady' -and $phase -eq 'ready') {
        '{"ready_artifact_can_upload":true}'
        break
    }
    if ($Mode -eq 'WaitFinal' -and $phase -ne 'timeout' -and $null -ne $final -and -not $alive) {
        if ($final.passed -ne $true) { throw 'CI file validation failed; see sanitized final artifact.' }
        '{"ci_file_controller_completed":true}'
        break
    }
    if ($phase -in @('timeout', 'failed', 'exited')) {
        if ($null -eq $final) {
            @{schema=1; passed=$false; error_type=('CIController_' + $phase);
              startup_acknowledged=(Test-Path -LiteralPath (Join-Path $outputPath 'started.json'))} | ConvertTo-Json | Set-Content -LiteralPath $finalPath -Encoding utf8
        }
        throw ('CI controller state: ' + $phase)
    }
    Start-Sleep -Milliseconds ([int]($PollSeconds * 1000))
}

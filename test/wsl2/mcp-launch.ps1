<#
.SYNOPSIS
Checks, from Windows, that an MCP client can run whyreach inside a WSL2
distro (docs/wsl2-lab.md, step 5): wsl.exe starts it, it answers
initialize, tools/list and one read-only tool call, which must report a
WSL2 platform, and it exits as soon as its input closes, leaving nothing
running in the distro. With -Cold, it stops the distro first, so wsl.exe
has to boot it, as when a client starts whyreach after WSL stopped the
idle distro; it skips that with Docker Desktop's integration, which keeps
the distro running.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File \\wsl.localhost\Ubuntu-24.04\home\you\whyreach\test\wsl2\mcp-launch.ps1 -Distro Ubuntu-24.04 -Whyreach /home/you/whyreach/bin/whyreach -Cold
#>
param(
    [Parameter(Mandatory = $true)][string]$Distro,
    [Parameter(Mandatory = $true)][string]$Whyreach,
    [switch]$Cold
)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false) # no byte-order mark
$ok = $true

# The output goes to the results: no user names from home paths.
function Hide-Home([string]$s) { $s -replace '/home/[^/\s]+', '/home/<user>' }

# A command's output lines from inside the distro, its errors dropped:
# Windows PowerShell 5.1 would turn them into terminating errors under
# ErrorActionPreference Stop. It starts a stopped distro.
function Invoke-InDistro([string[]]$argv) {
    $ErrorActionPreference = 'Continue'
    @(& wsl.exe -d $Distro --exec $argv 2>$null)
}

# whyreach servers already running in the distro (another MCP client's):
# afterwards there must be no more than these. -1 when they can't be
# counted.
function Count-Servers {
    $out = @(Invoke-InDistro @('pgrep', '-fc', 'whyreach mcp serve'))
    $n = 0
    if ($out.Count -gt 0 -and [int]::TryParse("$($out[0])".Trim(), [ref]$n)) { return $n }
    return -1
}
$noCount = 'FAIL: cannot count whyreach servers in the distro: pgrep comes with procps (docs/wsl2-lab.md, step 2)'

if ($Cold) {
    # Docker Desktop keeps a wsl.exe session open in each distro it
    # integrates with (its proxy), so the distro doesn't go idle while
    # Docker Desktop runs, and stopping it would cut the integration off.
    $engine = "$(@(Invoke-InDistro @('docker', 'version', '--format', '{{.Server.Platform.Name}}')) | Select-Object -First 1)".Trim()
    if ($engine -like '*Desktop*') {
        "cold start skipped: $Distro has Docker Desktop's integration ($engine), which keeps the distro running; stopping it would cut the integration off"
        'SKIP'
        exit 0
    }
    # Counting starts the distro, so a cold start counts nothing first: a
    # stopped distro runs no whyreach server.
    & wsl.exe --terminate $Distro | Out-Null
    $before = 0
    "cold start: $Distro stopped first, so wsl.exe boots it"
}
else {
    $before = Count-Servers
    "warm start: $Distro running"
    if ($before -lt 0) { $ok = $false; $noCount }
}

# Windows PowerShell 5.1 gives the child's input a writer in the console's
# input encoding, which writes a UTF-8 byte-order mark first when the code
# page is 65001 (Windows' "Use Unicode UTF-8" setting). A BOM before the
# first JSON-RPC line would break it, so the console's input encoding is
# set to UTF-8 without one while the process starts, and every line goes
# to the pipe as raw bytes.
$savedInput = $null
try {
    $savedInput = [Console]::InputEncoding
    [Console]::InputEncoding = $utf8
}
catch { $savedInput = $null }

# What an MCP client does: start the command with pipes, no shell.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'wsl.exe'
$psi.Arguments = "-d `"$Distro`" --exec $Whyreach mcp serve --log-level info"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.StandardOutputEncoding = $utf8
$psi.StandardErrorEncoding = $utf8
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$proc = [System.Diagnostics.Process]::Start($psi)
if ($null -ne $savedInput) { try { [Console]::InputEncoding = $savedInput } catch {} }
$stdin = $proc.StandardInput.BaseStream
$stderr = $proc.StandardError.ReadToEndAsync()
"command: wsl.exe $(Hide-Home $psi.Arguments)"

function Send-Line([string]$json) {
    $bytes = $utf8.GetBytes($json + "`n")
    $stdin.Write($bytes, 0, $bytes.Length)
    $stdin.Flush()
}

# The answer to request $id, skipping anything else the server sends first
# (a notification). Throws on a timeout, on a line that isn't JSON (which
# would break any MCP client), and when the server closes its output.
function Receive-Answer([int]$id, [int]$timeoutMs) {
    $wait = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $left = $timeoutMs - [int]$wait.ElapsedMilliseconds
        if ($left -le 0) { throw "no answer to request $id within $($timeoutMs / 1000) s" }
        $task = $proc.StandardOutput.ReadLineAsync()
        if (-not $task.Wait($left)) { throw "no answer to request $id within $($timeoutMs / 1000) s" }
        $line = $task.Result
        if ($null -eq $line) { throw 'the server closed its output' }
        try { $msg = $line | ConvertFrom-Json }
        catch { throw "a line on the server's output isn't JSON-RPC: $(Hide-Home $line)" }
        if ($null -ne $msg -and $null -eq $msg.method -and $msg.id -eq $id) { return $msg }
    }
}

try {
    Send-Line '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"wsl-launch-check","version":"1"}}}'
    $init = Receive-Answer 1 30000
    "initialize: $($init.result.serverInfo.name) $($init.result.serverInfo.version), protocol $($init.result.protocolVersion), $($clock.ElapsedMilliseconds) ms after the start"
    if ($init.result.serverInfo.name -ne 'whyreach') { $ok = $false; 'FAIL: the server is not whyreach' }

    Send-Line '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    Send-Line '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    $list = Receive-Answer 2 20000
    $names = @($list.result.tools | ForEach-Object { $_.name })
    "tools: $($names -join ', ')"
    if ($names.Count -ne 4) { $ok = $false; 'FAIL: want 4 tools' }

    # Read-only: what whyreach sees of the platform from here. Docker may
    # not answer yet, as right after a cold start (dockerd starts with the
    # distro), and the platform is then "other": ask again every 2 s, for
    # up to 20 s after the first answer. whyreach asks Docker afresh on
    # every call.
    $id = 3
    $retry = $null
    while ($true) {
        Send-Line ('{"jsonrpc":"2.0","id":' + $id + ',"method":"tools/call","params":{"name":"inspect_environment","arguments":{"scope":"host"}}}')
        $insp = Receive-Answer $id 30000
        if ($null -ne $insp.error) { throw "inspect_environment: $($insp.error.message)" }
        if ($insp.result.isError) { throw "inspect_environment: $(@($insp.result.content | ForEach-Object { $_.text }) -join ' ')" }
        $platform = $insp.result.structuredContent.host.platform
        "inspect_environment, $($clock.ElapsedMilliseconds) ms after the start: platform $platform"
        "  $(Hide-Home $insp.result.structuredContent.summary)"
        if ($null -eq $retry) { $retry = [System.Diagnostics.Stopwatch]::StartNew() }
        if ($platform -ne 'other' -or $retry.Elapsed.TotalSeconds -ge 20) { break }
        Start-Sleep -Seconds 2
        $id++
    }
    if ($platform -notin @('wsl2-engine', 'wsl2-desktop')) {
        $ok = $false
        "FAIL: want platform wsl2-engine or wsl2-desktop, got '$platform'"
        if ($platform -eq 'other') { '  whyreach found no Docker API in 20 s: Docker must run in this setup (docs/wsl2-lab.md, step 1 and Troubleshooting)' }
    }
    elseif ($id -gt 3) { "note: Docker answered only after $($id - 3) more tries" }
}
catch {
    $ok = $false
    "FAIL: $_"
}

# The client goes away: all the server sees is its input ending.
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$stdin.Close()
if ($proc.WaitForExit(5000)) {
    "exit $($proc.ExitCode), $($sw.ElapsedMilliseconds) ms after its input closed"
    if ($proc.ExitCode -ne 0) { $ok = $false; 'FAIL: want exit 0' }
}
else {
    $ok = $false
    'FAIL: still running 5 s after its input closed'
    $proc.Kill()
}
Start-Sleep -Milliseconds 500
$after = Count-Servers
if ($after -lt 0) { $ok = $false; $noCount }
elseif ($after -gt [Math]::Max($before, 0)) { $ok = $false; "FAIL: $($after - [Math]::Max($before, 0)) whyreach server(s) still running in the distro" }
else { "nothing left running in the distro ($before other whyreach server(s) before, $after after)" }

'stderr, last lines (without their times):'
$stderr.Result -split "`n" | Where-Object { $_ } | Select-Object -Last 5 | ForEach-Object { Hide-Home ($_ -replace '"time":"[^"]*",', '') }
if ($ok) { 'PASS' } else { 'FAIL'; exit 1 }

<#
.SYNOPSIS
Checks, from Windows, that an MCP client can run whyreach inside a WSL2
distro (docs/wsl2-lab.md, step 5): wsl.exe starts it, it answers
initialize, tools/list and one read-only tool call, which must report a
WSL2 platform, and it exits as soon as its input closes, leaving nothing
running in the distro. With -Cold, it stops the distro first, so wsl.exe
has to boot it, as when a client starts whyreach after WSL stopped the
idle distro.

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

# whyreach servers already running in the distro (another MCP client's):
# afterwards there must be no more than these.
function Count-Servers {
    $n = & wsl.exe -d $Distro --exec pgrep -fc 'whyreach mcp serve'
    if ($n) { return [int]($n | Select-Object -First 1) } else { return 0 }
}

# Counting starts the distro, so a cold start counts nothing first: a
# stopped distro runs no whyreach server.
if ($Cold) {
    & wsl.exe --terminate $Distro | Out-Null
    $before = 0
    "cold start: $Distro stopped first, so wsl.exe boots it"
}
else {
    $before = Count-Servers
    "warm start: $Distro running"
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
$ok = $true
"command: wsl.exe $($psi.Arguments)"

function Send-Line([string]$json) {
    $bytes = $utf8.GetBytes($json + "`n")
    $stdin.Write($bytes, 0, $bytes.Length)
    $stdin.Flush()
}

function Receive-Line([int]$timeoutMs) {
    $task = $proc.StandardOutput.ReadLineAsync()
    if (-not $task.Wait($timeoutMs)) { throw "no answer within $($timeoutMs / 1000) s" }
    if ($null -eq $task.Result) { throw "the server closed its output" }
    return $task.Result
}

try {
    Send-Line '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"wsl-launch-check","version":"1"}}}'
    $init = Receive-Line 20000 | ConvertFrom-Json
    "initialize: $($init.result.serverInfo.name) $($init.result.serverInfo.version), protocol $($init.result.protocolVersion), $($clock.ElapsedMilliseconds) ms after the start"
    if ($init.result.serverInfo.name -ne 'whyreach') { $ok = $false; 'FAIL: the server is not whyreach' }

    Send-Line '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    Send-Line '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    $list = Receive-Line 20000 | ConvertFrom-Json
    $names = @($list.result.tools | ForEach-Object { $_.name })
    "tools: $($names -join ', ')"
    if ($names.Count -ne 4) { $ok = $false; 'FAIL: want 4 tools' }

    # Read-only: what whyreach sees of the platform from here.
    Send-Line '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_environment","arguments":{"scope":"host"}}}'
    $insp = Receive-Line 30000 | ConvertFrom-Json
    $platform = $insp.result.structuredContent.host.platform
    "inspect_environment: platform $platform"
    "  $($insp.result.structuredContent.summary)"
    if ($platform -notin @('wsl2-engine', 'wsl2-desktop')) { $ok = $false; 'FAIL: want platform wsl2-engine or wsl2-desktop' }
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
if ($after -gt $before) { $ok = $false; "FAIL: $($after - $before) whyreach server(s) still running in the distro" }
else { "nothing left running in the distro ($before other whyreach server(s) before, $after after)" }

'stderr, last lines:'
$stderr.Result -split "`n" | Where-Object { $_ } | Select-Object -Last 5
if ($ok) { 'PASS' } else { 'FAIL'; exit 1 }

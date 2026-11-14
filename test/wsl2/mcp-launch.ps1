<#
.SYNOPSIS
Checks, from Windows, that an MCP client can run whyreach inside a WSL2
distro (docs/wsl2-lab.md, step 5): wsl.exe starts it, it answers
initialize, tools/list and one read-only tool call, and it exits as soon
as its input closes, leaving nothing running in the distro.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\mcp-launch.ps1 -Distro Ubuntu-24.04 -Whyreach /home/you/whyreach/bin/whyreach
#>
param(
    [Parameter(Mandatory = $true)][string]$Distro,
    [Parameter(Mandatory = $true)][string]$Whyreach
)
$ErrorActionPreference = 'Stop'

function Send-Line($proc, [string]$json) {
    $proc.StandardInput.WriteLine($json)
    $proc.StandardInput.Flush()
}

function Receive-Line($proc, [int]$timeoutMs) {
    $task = $proc.StandardOutput.ReadLineAsync()
    if (-not $task.Wait($timeoutMs)) { throw "no answer within $($timeoutMs / 1000) s" }
    if ($null -eq $task.Result) { throw "the server closed its output" }
    return $task.Result
}

# What an MCP client does: start the command with pipes, no shell.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'wsl.exe'
$psi.Arguments = "-d `"$Distro`" --exec $Whyreach mcp serve --log-level info"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
$proc = [System.Diagnostics.Process]::Start($psi)
$stderr = $proc.StandardError.ReadToEndAsync()
$ok = $true
"command: wsl.exe $($psi.Arguments)"

try {
    Send-Line $proc '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"wsl-launch-check","version":"1"}}}'
    $init = Receive-Line $proc 20000 | ConvertFrom-Json
    "initialize: $($init.result.serverInfo.name) $($init.result.serverInfo.version), protocol $($init.result.protocolVersion)"
    if ($init.result.serverInfo.name -ne 'whyreach') { $ok = $false; 'FAIL: the server is not whyreach' }

    Send-Line $proc '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    Send-Line $proc '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    $list = Receive-Line $proc 20000 | ConvertFrom-Json
    $names = @($list.result.tools | ForEach-Object { $_.name })
    "tools: $($names -join ', ')"
    if ($names.Count -ne 4) { $ok = $false; 'FAIL: want 4 tools' }

    # Read-only: what whyreach sees of the platform from here.
    Send-Line $proc '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_environment","arguments":{"scope":"host"}}}'
    $insp = Receive-Line $proc 30000 | ConvertFrom-Json
    "inspect_environment: platform $($insp.result.structuredContent.host.platform)"
    "  $($insp.result.structuredContent.summary)"
}
catch {
    $ok = $false
    "FAIL: $_"
}

# The client goes away: all the server sees is its input ending.
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$proc.StandardInput.Close()
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
$left = & wsl.exe -d $Distro --exec pgrep -f 'whyreach mcp serve'
if ($left) { $ok = $false; "FAIL: still running in the distro (PIDs $($left -join ' '))" }
else { 'nothing left running in the distro' }

'stderr, last lines:'
$stderr.Result -split "`n" | Where-Object { $_ } | Select-Object -Last 5
if ($ok) { 'PASS' } else { 'FAIL'; exit 1 }

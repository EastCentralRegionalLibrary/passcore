<#
.SYNOPSIS
    Restarts the Passcore backend with a different configuration, for the AD
    smoke test's group-membership legs.

.DESCRIPTION
    The workflow runs one Passcore instance, but each group-membership leg needs
    different RestrictedAdGroups/AllowedAdGroups values. Configuration is read
    once at startup, so a leg means a restart.

    Per-leg values arrive as command-line arguments rather than as environment
    variables or as edits to appsettings.ADTest.json, for two independent
    reasons:

      * Win32_Process.Create does not pass the caller's environment to the new
        process, so environment variables would simply not arrive.
      * .NET configuration binds arrays by index and merges per key, so an
        override cannot SHRINK an array -- a leg that wants one group name
        cannot remove the three the base file ships. Command-line arguments sit
        last in the configuration chain and win outright, and the workflow's
        "Clear the shipped group lists from the published configuration" step
        has already emptied the base arrays so there is nothing left to merge
        against.

    Command-line configuration uses ':' as its separator. '__' is
    environment-variable syntax only and does nothing here.

.PARAMETER LegName
    Human-readable label for the leg, used in log output.

.PARAMETER ExtraArgs
    Additional command-line arguments appended to the launch line, one array
    element per argument, e.g.
    '--ClientSettings:PasswordProviderOptions:AllowedAdGroups:0=AllowedGroup'.

    Passed as an array rather than one pre-joined string so that each element
    can be quoted individually when the cmd.exe command line is built. Group
    names contain spaces -- "Domain Users" is exactly the case Leg C exercises --
    and an unquoted element would arrive as two arguments and bind the wrong
    value.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $LegName,
    [string[]] $ExtraArgs = @()
)

$ErrorActionPreference = 'Stop'

Write-Host "=== Restarting Passcore for leg: $LegName ==="
if ($ExtraArgs.Count -eq 0) {
    Write-Host "  no extra configuration arguments (baseline configuration)"
}
foreach ($argument in $ExtraArgs) { Write-Host "  configuration argument: $argument" }

# --- Stop the previous instance -------------------------------------------
# The recorded pid is cmd.exe's; the app is its child, so the tree has to go.
if (Test-Path backend.pid) {
    $previousPid = (Get-Content backend.pid).Trim()
    Write-Host "Stopping previous Passcore tree rooted at PID $previousPid..."

    # Run through cmd.exe with stderr folded into stdout THERE, so nothing
    # taskkill writes ever reaches PowerShell's error stream.
    #
    # taskkill's exit code is advisory here and must not fail the step. It is
    # non-zero when the pid is already gone, and it is also non-zero on a PARTIAL
    # kill -- "The operation attempted is not supported" for one member of the
    # tree while the rest terminate -- which has been observed on the runner and
    # failed a leg whose restart had actually worked. Neither is the question the
    # caller cares about.
    #
    # The real invariants are checked below and they are unforgiving: port 5000
    # must be free before relaunching, and the new instance must answer. A leg
    # cannot silently run against the previous configuration whatever taskkill
    # reports.
    $taskkillOutput = cmd /c "taskkill /F /T /PID $previousPid 2>&1"
    $taskkillExit = $LASTEXITCODE
    $taskkillOutput | ForEach-Object { Write-Host "  $_" }
    Write-Host "taskkill exit code: $taskkillExit (advisory; the port check below is the gate)"

    $global:LASTEXITCODE = 0
    $Error.Clear()
}

# --- Confirm port 5000 is actually free ------------------------------------
# A relaunch while the old instance still holds the port would bind nothing and
# every assertion in the leg would then be answered by the OLD configuration --
# the exact silent-wrong-answer this gate exists to prevent.
$portDeadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $portDeadline) {
    if (-not (Get-NetTCPConnection -State Listen -LocalPort 5000 -ErrorAction SilentlyContinue)) {
        break
    }
    Start-Sleep -Seconds 1
}

if (Get-NetTCPConnection -State Listen -LocalPort 5000 -ErrorAction SilentlyContinue) {
    Get-NetTCPConnection -State Listen -LocalPort 5000 |
        Select-Object LocalAddress, LocalPort, OwningProcess |
            Format-Table | Out-String | Write-Host
    throw "Port 5000 is still held 30s after stopping the previous instance; refusing to relaunch."
}

Write-Host "Port 5000 is free."

# --- Relaunch --------------------------------------------------------------
$publishDir = (Resolve-Path ".\passcore_output").Path
$exe = Join-Path $publishDir "Unosquare.PassCore.Web.exe"

# Appended, not truncated, so one log accumulates every leg in order and the
# end-of-job dump still shows the whole run.
$stdout = Join-Path $env:GITHUB_WORKSPACE "passcore.log"
$stderr = Join-Path $env:GITHUB_WORKSPACE "passcore-error.log"

# Each argument quoted individually, so a group name containing a space stays
# one argument instead of becoming two.
$quotedArgs = ($ExtraArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '

$commandLine = 'cmd.exe /c ""{0}" --environment ADTest --urls http://localhost:5000 {1} >> "{2}" 2>> "{3}""' -f `
    $exe, $quotedArgs, $stdout, $stderr
Write-Host "Launching: $commandLine"

$result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine      = $commandLine
    CurrentDirectory = $publishDir
}

if ($result.ReturnValue -ne 0) {
    throw "Win32_Process.Create failed with return value $($result.ReturnValue)."
}

$result.ProcessId | Out-File -FilePath backend.pid -Encoding ascii
Write-Host "Started Passcore host shell with PID $($result.ProcessId)"

# --- Readiness -------------------------------------------------------------
$passcorePid = [int]$result.ProcessId
$deadline = (Get-Date).AddSeconds(90)
$ready = $false

do {
    if (-not (Get-Process -Id $passcorePid -ErrorAction SilentlyContinue)) {
        Write-Host "Passcore host shell $passcorePid is gone; the app exited during startup."
        break
    }

    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5000/api/password" `
            -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
            Write-Host "Passcore is ready for leg '$LegName'."
            $ready = $true
            break
        }
    }
    catch {
        Start-Sleep -Seconds 2
    }
} while ((Get-Date) -lt $deadline)

if (-not $ready) {
    Write-Host "=== Passcore Standard Output ==="
    if (Test-Path $stdout) { Get-Content $stdout -Tail 60 }
    Write-Host "=== Passcore Error Output ==="
    if (Test-Path $stderr) { Get-Content $stderr -Tail 60 }
    throw "Passcore failed to become ready for leg '$LegName' within 90 seconds."
}

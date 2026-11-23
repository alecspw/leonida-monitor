<#
.SYNOPSIS
    Runs the Leonida PR Security Monitor as a scheduled task.

.DESCRIPTION
    This script runs the monitor.py script and can be scheduled via Windows Task Scheduler.
    It handles logging, error recovery, and state persistence.

.EXAMPLE
    .\run_monitor.ps1 -IntervalMinutes 15 -SincePR 8500

.PARAMETER IntervalMinutes
    How often to run the check (default: 15 minutes)

.PARAMETER SincePR
    Only check PRs after this number (default: 0)

.PARAMETER Once
    Run once and exit (for testing)
#>

param(
    [int]$IntervalMinutes = 15,
    [int]$SincePR = 8500,
    [switch]$Once
)

$ErrorActionPreference = "Stop"

# Setup paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$MonitorScript = Join-Path $ScriptDir "monitor.py"
$LogDir = Join-Path $ScriptDir "logs"
$StateFile = Join-Path $ScriptDir "monitor_state.json"

# Create log directory
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path (Join-Path $LogDir "monitor_$(Get-Date -Format 'yyyy-MM-dd').log") -Value $logMessage
}

function Check-RateLimit {
    try {
        $result = gh api rate_limit --jq '.rate.remaining'
        return [int]$result
    } catch {
        Write-Log "Failed to check rate limit: $_" "WARN"
        return 5000
    }
}

function Run-Monitor {
    param($SincePR)
    Write-Log "Starting security monitor check..."

    $remaining = Check-RateLimit
    Write-Log "GitHub API remaining: $remaining"

    if ($remaining -lt 100) {
        Write-Log "Rate limit too low ($remaining), skipping this run" "WARN"
        return
    }

    $args = @("--once", "--limit", "100", "--since-pr", $SincePR)
    $process = Start-Process -FilePath "python" -ArgumentList ($MonitorScript + " " + ($args -join " ")) `
        -WorkingDirectory $ScriptDir `
        -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -ne 0) {
        Write-Log "Monitor exited with code $($process.ExitCode)" "ERROR"
    } else {
        Write-Log "Monitor completed successfully"
    }
}

# Main loop
Write-Log "Leonida PR Security Monitor started"
Write-Log "Interval: $IntervalMinutes minutes, Since PR: $SincePR"

if ($Once) {
    Run-Monitor -SincePR $SincePR
} else {
    while ($true) {
        Run-Monitor -SincePR $SincePR
        Write-Log "Sleeping for $IntervalMinutes minutes..."
        Start-Sleep -Minutes $IntervalMinutes
    }
}
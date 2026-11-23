<#
.SYNOPSIS
    Creates a Windows Scheduled Task for continuous Leonida PR monitoring.

.DESCRIPTION
    Registers a scheduled task that runs the monitor every 15 minutes.
    Run as Administrator.

.EXAMPLE
    .\setup_scheduled_task.ps1 -TaskName "LeonidaPRMonitor" -IntervalMinutes 15
#>

param(
    [string]$TaskName = "LeonidaPRMonitor",
    [int]$IntervalMinutes = 15,
    [string]$PythonPath = (Get-Command python).Source,
    [string]$ScriptDir = (Split-Path -Parent $MyInvocation.MyCommand.Definition),
    [string]$RunScript = "run_monitor.ps1"
)

# Check for admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

$ScriptPath = Join-Path $ScriptDir $RunScript
if (-not (Test-Path $ScriptPath)) {
    Write-Error "Run script not found: $ScriptPath"
    exit 1
}

# Create action
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -IntervalMinutes $IntervalMinutes"

# Create trigger (repeating every N minutes)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

# Settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -Hidden `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

# Principal (run as current user with highest privileges)
$principal = New-ScheduledTaskPrincipal -UserId (Get-CimInstance Win32_ComputerSystem).UserName `
    -LogonType Interactive `
    -RunLevel Highest

# Register task
try {
    Register-ScheduledTask -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Continuous security monitoring of ItsNotRexed/Leonida PRs using leonida-reviews methodology" `
        -Force

    Write-Host "Task '$TaskName' registered successfully!" -ForegroundColor Green
    Write-Host "Runs every $IntervalMinutes minutes as $(Get-CimInstance Win32_ComputerSystem).UserName"
} catch {
    Write-Error "Failed to register task: $_"
    exit 1
}

# Show task info
Get-ScheduledTask -TaskName $TaskName | Format-List TaskName, State, NextRunTime, LastRunTime
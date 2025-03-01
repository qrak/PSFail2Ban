[CmdletBinding()]
param(
    [string]$TaskName = "PSFail2Ban-Hourly",
    [int]$RepeatMinutes = 60
)

# Check if running as administrator and self-elevate if needed
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Verbose "Script requires elevation. Attempting to restart as administrator..."
    $arguments = "-NoExit -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    
    # Add parameters to the arguments
    if ($TaskName -ne "PSFail2Ban-Hourly") { $arguments += " -TaskName `"$TaskName`"" }
    if ($RepeatMinutes -ne 60) { $arguments += " -RepeatMinutes $RepeatMinutes" }
    
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    Exit
}

$ErrorActionPreference = 'Stop'

# Path to the script that updates the firewall rules
$scriptPath = Join-Path $PSScriptRoot "Update-FirewallRule.ps1"

# Ensure script exists
if (-not (Test-Path $scriptPath)) {
    throw "Script $scriptPath not found!"
}

# Create action to run PowerShell with the script
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" `
    -WorkingDirectory $PSScriptRoot

# Create trigger to run the task repeatedly
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $RepeatMinutes)

# Set the task settings
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

# Setup the task principal to run with highest privileges
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Register the scheduled task
try {
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    
    if ($existingTask) {
        # Update existing task
        Set-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal
        Write-Host "Updated scheduled task '$TaskName'"
    } else {
        # Create new task
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal
        Write-Host "Created scheduled task '$TaskName'"
    }
    
    # Start the task immediately
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Started the task. Windows Firewall will be updated with blocked IPs shortly."
    Write-Host "The task will run every $RepeatMinutes minutes."
} catch {
    Write-Error "Failed to set up scheduled task: $_"
}

# Check for required files
$requiredFiles = @('whitelist.txt', 'blacklist.txt')
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $PSScriptRoot $file
    if (-not (Test-Path $filePath)) {
        # Create empty file
        New-Item -Path $filePath -ItemType File -Force | Out-Null
        Write-Host "Created empty $file file"
    }
}

Write-Host "`nPSFail2Ban installation complete!"
Write-Host "To uninstall, run: Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"

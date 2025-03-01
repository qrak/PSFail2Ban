[CmdletBinding()]
param(
    [int]$LastHours = 6,
    [Switch]$ShowUsernames = $false,
    [bool]$UserWhitelistEnabled = $false,
    [string[]]$AllowedUsers = @()
)

# Check if running as administrator and self-elevate if needed
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Verbose "Script requires elevation. Attempting to restart as administrator..."
    $arguments = "-NoExit -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    
    # Add parameters to the arguments
    if ($LastHours -ne 6) { $arguments += " -LastHours $LastHours" }
    if ($ShowUsernames) { $arguments += " -ShowUsernames" }
    if ($UserWhitelistEnabled) { $arguments += " -UserWhitelistEnabled `$true" }
    if ($AllowedUsers.Count -gt 0) { 
        $usersList = $AllowedUsers -join "','"
        $arguments += " -AllowedUsers @('$usersList')" 
    }
    
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    Exit
}

$ErrorActionPreference = 'Stop'

# If not passed from the main script, check locally for user whitelist
if (-not $UserWhitelistEnabled) {
    $usersWhitelistFile = Join-Path $PSScriptRoot 'userswhitelist.txt'
    $UserWhitelistEnabled = Test-Path -Path $usersWhitelistFile
    if ($UserWhitelistEnabled) {
        $AllowedUsers = Get-Content -Path $usersWhitelistFile -Encoding Ascii | 
        Where-Object { $_ -and (!$_.StartsWith('#')) }
    }
}

#
# Returns the number of failed logons attempts for each source IP address.
#

$filters = @{LogName = "Security"; ID = 4625 } 
if ($LastHours -gt 0) {
    $filters.StartTime = (Get-Date).AddHours($LastHours * -1)
}

$results = @{}

try {
    # Check if the Security log exists and has entries
    $logExists = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    
    if ($logExists) {
        $events = Get-WinEvent -FilterHashTable $filters -ErrorAction SilentlyContinue
        
        if ($events) {
            $events | ForEach-Object {
                try {
                    # Check if Properties has enough elements
                    if ($_.Properties.Count -ge 20) {
                        $sourceIp = $_.Properties[19].Value.ToString()
                        $username = $_.Properties[5].Value.ToString()
                        
                        # Skip entries with no IP or non-IP format
                        if ($sourceIp -eq '-' -or !($sourceIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')) { 
                            return 
                        }
                        
                        # When userswhitelist.txt exists, immediately flag IPs trying unauthorized usernames
                        if ($UserWhitelistEnabled -and $username -and $username -notin $AllowedUsers) {
                            if (-not $results.ContainsKey($sourceIp)) {
                                # Using 999 as a threshold value to ensure IP is blocked (requires > 3 attempts)
                                $results[$sourceIp] = 999
                            }
                        }
                        else {
                            # Normal counting logic
                            if (-not $results.ContainsKey($sourceIp)) {
                                $results[$sourceIp] = 0
                            }
                            $results[$sourceIp]++
                        }
                    }
                }
                catch {
                    Write-Verbose "Error processing event: $_"
                }
            }
        }
        else {
            Write-Verbose "No failed logon events found in the last $LastHours hours."
        }
    }
    else {
        Write-Warning "Security event log not found or not accessible."
    }
}
catch {
    Write-Warning "Error accessing event logs: $_"
}

# Return the results
$results.GetEnumerator() | 
Where-Object { $_.Value -gt 3 } |
ForEach-Object {
    [PSCustomObject]@{
        Name  = $_.Key
        Count = $_.Value
    }
} |
Sort-Object -Property 'Count' -Descending

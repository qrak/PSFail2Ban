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
# Returns the number of failed credential validations for each source workstation.
#

$filters = @{LogName = "Security"; ID = 4776 } 
if ($LastHours -gt 0) {
    $filters.StartTime = (Get-Date).AddHours($LastHours * -1)
}

$results = @{}

# Common failure codes for credential validation
$failureCodes = @(
    "0xC0000064", # Account does not exist
    "0xC0000070", # Account locked out  
    "0xC0000071", # Password expired
    "0xC0000072", # Account disabled
    "0xC000006A", # Wrong password
    "0xC000006D", # Logon failure
    "0xC000006F", # Outside authorized hours
    "0xC0000193", # Account expired
    "0xC0000224", # Password must change
    "0xC0000234"  # Account locked out
)

# Function to validate if a string is a valid IPv4 address
function Test-IPv4Address {
    param([string]$IPAddress)
    
    if ($IPAddress -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        return $Matches[1] -le 255 -and $Matches[2] -le 255 -and $Matches[3] -le 255 -and $Matches[4] -le 255
    }
    return $false
}

try {
    # Check if the Security log exists and has entries
    $logExists = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    
    if ($logExists) {
        $events = Get-WinEvent -FilterHashTable $filters -ErrorAction SilentlyContinue
        
        if ($events) {
            $events | ForEach-Object {
                try {
                    # Extract data from event
                    if ($_.Properties.Count -ge 4) {
                        $status = $_.Properties[3].Value.ToString()
                        $username = $_.Properties[1].Value.ToString()
                        $workstation = $_.Properties[2].Value.ToString()
                        
                        # Skip if not a failure or workstation is empty
                        if ($status -notin $failureCodes -or [string]::IsNullOrEmpty($workstation)) { return }
                        
                        # Skip if workstation appears to be an application name and not an IP
                        if ($workstation -match '\.exe$') { return }
                        
                        # Check if workstation is already an IP address
                        if (-not (Test-IPv4Address -IPAddress $workstation)) {
                            # Try to resolve hostname to IP with timeout
                            try {
                                $resolveTimeout = New-TimeSpan -Seconds 2
                                $resolveTask = [System.Net.Dns]::GetHostAddressesAsync($workstation)
                                
                                if ([System.Threading.Tasks.Task]::WaitAny(@($resolveTask), $resolveTimeout) -eq 0) {
                                    $ip = $resolveTask.Result | 
                                          Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
                                          Select-Object -First 1 -ExpandProperty IPAddressToString
                                    
                                    if ($ip -and (Test-IPv4Address -IPAddress $ip)) {
                                        $workstation = $ip
                                    } else {
                                        return # Skip if can't be resolved to valid IP
                                    }
                                } else {
                                    return # Skip if resolution times out
                                }
                            } catch {
                                Write-Verbose "Failed to resolve $workstation to IP: $_"
                                return # Skip if resolution fails
                            }
                        }
                        
                        # Check against user whitelist
                        if ($UserWhitelistEnabled -and $username -and $username -notin $AllowedUsers) {
                            if (-not $results.ContainsKey($workstation)) {
                                # Using 999 as a threshold value to ensure IP is blocked (requires > 3 attempts)
                                $results[$workstation] = 999
                            }
                        } else {
                            # Normal counting logic
                            if (-not $results.ContainsKey($workstation)) {
                                $results[$workstation] = 0
                            }
                            $results[$workstation]++
                        }
                    }
                } catch {
                    Write-Verbose "Error processing event: $_"
                }
            }
        } else {
            Write-Verbose "No credential validation events found in the last $LastHours hours."
        }
    } else {
        Write-Warning "Security event log not found or not accessible."
    }
} catch {
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

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
# Returns the number of failed credential validations for each source workstation/IP.
#

$filters = @{LogName = "Security"; ID = 4776 } 
if ($LastHours -gt 0) {
    $filters.StartTime = (Get-Date).AddHours($LastHours * -1)
}

# Also look for RDP logon failures to correlate
$rdpFilters = @{LogName = "Security"; ID = 4625 }
if ($LastHours -gt 0) {
    $rdpFilters.StartTime = (Get-Date).AddHours($LastHours * -1)
}

$results = @{}

# Common failure codes for credential validation
$failureCodes = @(
    "0xc0000064", # Account does not exist (lowercase hex format)
    "0xC0000064", # Account does not exist (uppercase hex format)
    "0xc0000070", # Account locked out  
    "0xC0000070", # Account locked out
    "0xc0000071", # Password expired
    "0xC0000071", # Password expired  
    "0xc0000072", # Account disabled
    "0xC0000072", # Account disabled
    "0xc000006a", # Wrong password
    "0xC000006A", # Wrong password
    "0xc000006d", # Logon failure
    "0xC000006D", # Logon failure
    "0xc000006f", # Outside authorized hours
    "0xC000006F", # Outside authorized hours
    "0xc0000193", # Account expired
    "0xC0000193", # Account expired
    "0xc0000224", # Password must change
    "0xC0000224", # Password must change
    "0xc0000234", # Account locked out
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

Write-Verbose "Getting all events before starting correlation..."

# Create a cache for RDP connections that maps timestamps and users to source IPs
$rdpSourceCache = @{}

# First, collect RDP logon failures for correlation
try {
    Write-Verbose "Collecting RDP events (ID 4625) for correlation lookup..."
    $rdpEvents = Get-WinEvent -FilterHashTable $rdpFilters -ErrorAction SilentlyContinue
    
    if ($rdpEvents) {
        Write-Verbose "Found $($rdpEvents.Count) RDP events for correlation"
        
        foreach ($event in $rdpEvents) {
            try {
                # Extract source IP and target username from the RDP logon failure
                if ($event.Properties.Count -ge 20) {
                    $username = $event.Properties[5].Value.ToString()
                    $sourceIp = $event.Properties[19].Value.ToString()
                    $logonType = $event.Properties[10].Value
                    
                    Write-Verbose "Event ID 4625: Username=$username, IP=$sourceIp, LogonType=$logonType"
                    
                    # Only include entries that have valid IPs
                    if (Test-IPv4Address -IPAddress $sourceIp) {
                        # Store by time window (3 minute range) - FIX: replace <= with -le
                        for ($i = -1; $i -le 1; $i++) {
                            $timeKey = $event.TimeCreated.AddMinutes($i).ToString('yyyy-MM-dd HH:mm')
                            
                            if (-not $rdpSourceCache.ContainsKey($timeKey)) {
                                $rdpSourceCache[$timeKey] = @{}
                            }
                            
                            if (-not $rdpSourceCache[$timeKey].ContainsKey($username)) {
                                $rdpSourceCache[$timeKey][$username] = $sourceIp
                                Write-Verbose "Added to correlation cache: Time=$timeKey, User=$username, IP=$sourceIp"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Error processing RDP event: $_"
            }
        }
    }
    else {
        Write-Verbose "No RDP events found for correlation"
    }
}
catch {
    Write-Verbose "Error collecting RDP events: $_"
}

try {
    Write-Verbose "Collecting credential validation events (ID 4776)..."
    
    # Check if the Security log exists and has entries
    $logExists = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    
    if ($logExists) {
        $events = Get-WinEvent -FilterHashTable $filters -ErrorAction SilentlyContinue
        
        if ($events) {
            Write-Verbose "Found $($events.Count) credential validation events to process"
            $failedCount = 0
            $mstscCount = 0
            
            foreach ($event in $events) {
                try {
                    # Extract data from event
                    if ($event.Properties.Count -ge 4) {
                        $status = $event.Properties[3].Value.ToString()
                        $username = $event.Properties[1].Value.ToString()
                        $workstation = $event.Properties[2].Value.ToString()
                        $timestamp = $event.TimeCreated
                        
                        Write-Verbose "Processing event: Status=$status, Username=$username, Workstation=$workstation"
                        
                        # Check failure status with case-insensitive comparison
                        $isFailure = $false
                        foreach ($code in $failureCodes) {
                            if ($status -eq $code) {
                                $isFailure = $true
                                $failedCount++
                                Write-Verbose "Failure detected: $status matches $code"
                                break
                            }
                        }
                        
                        # Skip if not a failure
                        if (-not $isFailure) { 
                            Write-Verbose "Skipping - not a failure status code: $status"
                            continue
                        }
                        
                        Write-Verbose "Failed login detected for $username from $workstation with status $status"
                        
                        # Check if workstation is mstsc.exe
                        if ($workstation -eq "mstsc.exe") {
                            $mstscCount++
                            Write-Verbose "MSTSC.EXE connection found ($mstscCount total)"
                        }
                        
                        # Handle different types of workstation values
                        $sourceIp = $null
                        
                        # Check if workstation is already an IP address
                        if (Test-IPv4Address -IPAddress $workstation) {
                            $sourceIp = $workstation
                            Write-Verbose "Workstation is already an IP: $sourceIp"
                        }
                        # Handle Remote Desktop connections (mstsc.exe)
                        elseif ($workstation -eq "mstsc.exe" -or $workstation -match '\.exe$') {
                            Write-Verbose "Found application in workstation field: $workstation - looking for correlation"
                            
                            # Try to find matching RDP connection in our cache
                            # Look across a wider range for better matching - FIX: replace <= with -le
                            $timeWindows = @()
                            for ($min = -5; $min -le 5; $min++) {
                                $timeWindows += $timestamp.AddMinutes($min).ToString('yyyy-MM-dd HH:mm')
                            }
                            
                            $found = $false
                            foreach ($timeKey in $timeWindows) {
                                if ($rdpSourceCache.ContainsKey($timeKey) -and 
                                    $rdpSourceCache[$timeKey].ContainsKey($username)) {
                                    $sourceIp = $rdpSourceCache[$timeKey][$username]
                                    Write-Verbose "Found correlated RDP source IP: $sourceIp for user $username at time $timeKey"
                                    $found = $true
                                    break
                                }
                            }
                            
                            # If we couldn't find a correlated IP, set to a default IP
                            if (-not $found) {
                                # Use the most recent source IP for this username from any failed RDP attempt
                                $recentIpForUser = $null
                                $recentIpTimestamp = $null
                                
                                foreach ($timeKey in $rdpSourceCache.Keys) {
                                    if ($rdpSourceCache[$timeKey].ContainsKey($username)) {
                                        try {
                                            $keyTime = [DateTime]::ParseExact($timeKey, 'yyyy-MM-dd HH:mm', $null)
                                            if ($null -eq $recentIpTimestamp -or $keyTime -gt $recentIpTimestamp) {
                                                $recentIpTimestamp = $keyTime
                                                $recentIpForUser = $rdpSourceCache[$timeKey][$username]
                                            }
                                        }
                                        catch {
                                            Write-Verbose "Error parsing date: $timeKey"
                                        }
                                    }
                                }
                                
                                if ($recentIpForUser) {
                                    $sourceIp = $recentIpForUser
                                    # FIX: Use curly braces around variables before colons
                                    Write-Verbose "Using most recent IP for user ${username}: ${sourceIp}"
                                }
                                else {
                                    Write-Verbose "WARNING: Could not determine source IP for $workstation credential failure"
                                    # For security, we can use a configurable setting here
                                    # For now, just use a default IP that can be identified later
                                    $sourceIp = "192.168.1.254"
                                    # FIX: Use curly braces around variables before colons
                                    Write-Verbose "Using fallback IP address: ${sourceIp}"
                                }
                            }
                        }
                        # Try to resolve hostname to IP
                        else {
                            try {
                                Write-Verbose "Attempting to resolve hostname: $workstation to IP"
                                $resolveTimeout = New-TimeSpan -Seconds 2
                                $resolveTask = [System.Net.Dns]::GetHostAddressesAsync($workstation)
                                
                                if ([System.Threading.Tasks.Task]::WaitAny(@($resolveTask), $resolveTimeout) -eq 0) {
                                    $ip = $resolveTask.Result | 
                                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
                                    Select-Object -First 1 -ExpandProperty IPAddressToString
                                    
                                    if ($ip -and (Test-IPv4Address -IPAddress $ip)) {
                                        $sourceIp = $ip
                                        Write-Verbose "Successfully resolved $workstation to $sourceIp"
                                    }
                                    else {
                                        Write-Verbose "Failed to resolve to valid IP"
                                        continue # Skip if can't be resolved to valid IP
                                    }
                                }
                                else {
                                    Write-Verbose "DNS resolution timed out"
                                    continue # Skip if resolution times out
                                }
                            }
                            catch {
                                Write-Verbose "Failed to resolve $workstation to IP: $_"
                                continue # Skip if resolution fails
                            }
                        }
                        
                        # Now process the source IP if we have one
                        if ($sourceIp) {
                            # Check against user whitelist
                            if ($UserWhitelistEnabled -and $username -and $username -notin $AllowedUsers) {
                                if (-not $results.ContainsKey($sourceIp)) {
                                    # Using 999 as a threshold value to ensure IP is blocked
                                    $results[$sourceIp] = 999
                                    Write-Verbose "Flagging IP $sourceIp for unauthorized user $username"
                                }
                            }
                            else {
                                # Normal counting logic
                                if (-not $results.ContainsKey($sourceIp)) {
                                    $results[$sourceIp] = 0
                                }
                                $results[$sourceIp]++
                                Write-Verbose "Incrementing failure count for IP $sourceIp to $($results[$sourceIp])"
                            }
                        }
                        else {
                            Write-Verbose "No source IP could be determined, skipping event"
                        }
                    }
                }
                catch {
                    Write-Verbose "Error processing event: $_"
                }
            }
            
            Write-Verbose "Total failed credential validations: $failedCount"
            Write-Verbose "Total mstsc.exe connections: $mstscCount" 
        }
        else {
            Write-Verbose "No credential validation events found in the last $LastHours hours."
        }
    }
    else {
        Write-Warning "Security event log not found or not accessible."
    }
}
catch {
    Write-Warning "Error accessing event logs: $_"
}

# Output summary before returning results
Write-Verbose "Processing complete. Found $(($results.Keys | Measure-Object).Count) unique IPs with failed credential attempts."
foreach ($ip in $results.Keys) {
    Write-Verbose "IP: $ip - Failed attempts: $($results[$ip])"
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

[CmdletBinding()]
param(
    [int]$LastHours = 6
)

# Check if running as administrator and self-elevate if needed
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Verbose "Script requires elevation. Attempting to restart as administrator..."
    $arguments = "-NoExit -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    
    # Add parameters to the arguments
    if ($LastHours -ne 6) { $arguments += " -LastHours $LastHours" }
    
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    Exit
}

$ErrorActionPreference = 'Stop'

# Centralize all configuration files
$blacklistFile = Join-Path $PSScriptRoot 'blacklist.txt'
$whitelistFile = Join-Path $PSScriptRoot 'whitelist.txt'
$usersWhitelistFile = Join-Path $PSScriptRoot 'userswhitelist.txt'

# Load user whitelist if it exists
$userWhitelistEnabled = Test-Path -Path $usersWhitelistFile
$allowedUsers = @()
if ($userWhitelistEnabled) {
    $allowedUsers = Get-Content -Path $usersWhitelistFile -Encoding Ascii | 
    Where-Object { $_ -and (!$_.StartsWith('#')) }
    Write-Verbose "User whitelist enabled with $(($allowedUsers | Measure-Object).Count) allowed users"
}



function Get-FailedIps {
    # Get IP addresses with more than 3 failed logon attempts
    $ExtraParams = @{}
    if ($LastHours -gt 0) {
        $ExtraParams = @{LastHours = $LastHours }
    }

    # Add user whitelist parameters if enabled
    if ($userWhitelistEnabled) {
        $ExtraParams['UserWhitelistEnabled'] = $true
        $ExtraParams['AllowedUsers'] = $allowedUsers
    }

    $getFailedLogons = Join-Path $PSScriptRoot 'Get-FailedLogons.ps1'
    $failedIps = @()
    
    # Get IPs from failed logons (Event ID 4625)
    try {
        & $getFailedLogons @ExtraParams |
        ForEach-Object {
            $failedIps += $_.Name
        }
        Write-Verbose "Found $($failedIps.Count) IPs from failed logons"
    }
    catch {
        Write-Warning "Error getting failed logons: $_"
    }
    
    # Return unique IPs
    $failedIps | Select-Object -Unique
}



function Get-BlockedIps {
    # Get blacklisted IPs (already blocked)
    try {
        $ips = Get-Content -Path $blacklistFile -Encoding Ascii -ErrorAction SilentlyContinue
        Write-Verbose "Found $(($ips | Measure-Object).Count) IPs in blacklist"
        return $ips
    }
    catch {
        Write-Warning "Error reading blacklist: $_"
        return @()
    }
}



function Get-AllowedIps {
    # Get whitelisted IPs
    try {
        $ips = Get-Content -Path $whitelistFile -Encoding Ascii -ErrorAction SilentlyContinue
        Write-Verbose "Found $(($ips | Measure-Object).Count) whitelisted IPs"
        return $ips
    }
    catch {
        Write-Warning "Error reading whitelist: $_"
        return @()
    }
}



#
# Main
#

$failedIps = Get-FailedIps
$blockedIps = Get-BlockedIps
$allIps = [array]$failedIps + [array]$blockedIps | Select-Object -Unique | Sort-Object

# Update blacklist
$allIps | Out-File -FilePath $blacklistFile -Encoding ascii

# Remove allowed IPs
$allowedIps = Get-AllowedIps
$allIps = $allIps | Where-Object { $_ -notin $allowedIps }

Write-Verbose "Total IPs to block: $(($allIps | Measure-Object).Count)"

# Update firewall
$ruleName = 'PSFail2Ban-Block-Failed-Logons'
$ruleDisplayName = 'PSFail2Ban: Blocks IP addresses from failed logons'

try {
    if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
        # Update rule - handle empty IP list case
        if ($allIps.Count -gt 0) {
            Set-NetFirewallRule -Name $ruleName -RemoteAddress $allIps
            Write-Verbose "Updated firewall rule with $($allIps.Count) blocked IPs"
        }
        else {
            # If no IPs to block, use a placeholder that won't block anything
            Set-NetFirewallRule -Name $ruleName -RemoteAddress "255.255.255.255"
            Write-Verbose "No IPs to block, set placeholder IP in firewall rule"
        }
    }
    else {
        # Create rule - handle empty IP list case
        if ($allIps.Count -gt 0) {
            New-NetFirewallRule -Name $ruleName -DisplayName $ruleDisplayName -Direction Inbound -Action Block -RemoteAddress $allIps
            Write-Verbose "Created new firewall rule blocking $($allIps.Count) IPs"
        }
        else {
            # If no IPs to block, use a placeholder that won't block anything
            New-NetFirewallRule -Name $ruleName -DisplayName $ruleDisplayName -Direction Inbound -Action Block -RemoteAddress "255.255.255.255" 
            Write-Verbose "Created new firewall rule with placeholder IP"
        }
    }
}
catch {
    Write-Error "Failed to update firewall rule: $_"
}

# PSFail2Ban

Powershell script to block IP addresses after multiple failed logon attempts.

## Requirements

* Windows 10/11 or Windows Server 2016/2019/2022
* PowerShell 5.1 or higher
* Administrative privileges

## How to install

Download all scripts in any folder and run (with administrative privileges):

```powershell
Install-ScheduledTask.ps1
```

This will create a scheduled task to run `Update-FirewallRule.ps1` (see below) every hour.

## How it works

The main script is `Update-FirewallRule.ps1`. It monitors Windows Security logs for suspicious activity and adds blocking rules in Windows Firewall for offending IP addresses. The script checks for:

1. Event ID 4625: Failed logon attempts
2. Event ID 4776: Failed credential validation attempts

IPs with 3 or more failed attempts of either type will be blocked.

All blocked IPs are saved in a `blacklist.txt`. You can modify this file if needed. Addresses in this file will ALWAYS be blocked by the firewall rule even if they didn't show up in Security events.

In the same way, you could keep a `whitelist.txt`. Addresses in this file will NEVER be blocked by the firewall rule.

By default the script will check only the last 6 hours in Security log. You can use the `-LastHours` parameter to change this number.

## User Whitelist Feature

You can create a file named `userswhitelist.txt` containing authorized usernames (one per line) to enable a stricter security mode. When this file exists, any IP attempting to log in with a username not in the whitelist will be immediately blocked, regardless of the number of attempts.

Example `userswhitelist.txt` content:
```
Administrator
YourUsername
AnotherAuthorizedUser
```

Lines starting with # are treated as comments and are ignored.

## Other tools

If you want a quick summary of failed logins, you can run either:

```powershell
Get-FailedLogons.ps1         # For Event ID 4625 (logon failures)
Get-FailedCredentials.ps1    # For Event ID 4776 (credential validation failures)
```

Both scripts will show the number of failed attempts for each source IP address.

You can run them with the `-ShowUsernames` parameter to group results by usernames instead of IP addresses.

By default the scripts will check only the last 6 hours in Security log. You can use the `-LastHours` parameter to change this number.
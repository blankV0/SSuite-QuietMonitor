<#
.SYNOPSIS
    EventParser.ps1 - Parses Windows Security and System event logs for threat indicators.
.DESCRIPTION
    Queries the last 24 hours of Windows Event Logs for the following critical Event IDs:
      4625  - Failed logon attempt (Security log)
      4672  - Special privileges assigned to new logon (Security log)
      7045  - A new service was installed (System log)
      1102  - Audit log was cleared (Security log)

    Repeated failures (brute-force threshold), privilege escalations, new service
    installs, and log clearing are all flagged with appropriate severity.

    ThreatLocker Note: This module is read-only. No system modifications are made.
    Sign with: Set-AuthenticodeSignature .\Modules\EventParser.ps1 -Certificate $cert
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] - List of finding objects.
#>

function Invoke-EventParser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $since         = (Get-Date).AddHours(-24)
    $bruteForceThreshold = 5   # Flag if same account fails this many times

    try {
        # Helper: safe Get-WinEvent wrapper
        function Get-EventsSafe {
            param([hashtable]$FilterHashtable)
            try {
                $events = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue
                if ($null -eq $events) { return @() }
                return @($events)
            } catch [System.Exception] {
                if ($_.Exception.Message -match 'No events were found') { return @() }
                Write-Warning "EventParser: Get-WinEvent failed - $($_.Exception.Message)"
                return @()
            }
        }

        # -----------------------------------------------------------------------
        # Event ID 4625 - Failed Logon
        # -----------------------------------------------------------------------
        $failedLogons = Get-EventsSafe -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $since
        }

        if ($failedLogons.Count -gt 0) {
            # Group by target account to detect brute force
            $byAccount = @{}
            foreach ($ev in $failedLogons) {
                try {
                    $xml      = [xml]$ev.ToXml()
                    $ns       = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
                    $account  = $xml.SelectSingleNode('//e:Data[@Name="TargetUserName"]', $ns).'#text'
                    $srcIp    = $xml.SelectSingleNode('//e:Data[@Name="IpAddress"]', $ns).'#text'
                    $logonType= $xml.SelectSingleNode('//e:Data[@Name="LogonType"]', $ns).'#text'
                    if (-not $account) { $account = 'Unknown' }
                    if (-not $byAccount.ContainsKey($account)) {
                        $byAccount[$account] = [System.Collections.Generic.List[PSCustomObject]]::new()
                    }
                    $byAccount[$account].Add([PSCustomObject]@{ Time = $ev.TimeCreated; SrcIp = $srcIp; LogonType = $logonType })
                } catch {}
            }

            foreach ($account in $byAccount.Keys) {
                $count    = $byAccount[$account].Count
                $severity = if ($count -ge $bruteForceThreshold) { 'Red' } else { 'Yellow' }
                $ips      = ($byAccount[$account] | Select-Object -ExpandProperty SrcIp -Unique) -join ', '
                $details  = "Failed logon attempts for '$account': $count in last 24h. Source IPs: $ips"

                $findings.Add([PSCustomObject]@{
                    Module      = 'EventParser'
                    Severity    = $severity
                    Category    = 'Event: Failed Logon (4625)'
                    Title       = "Failed Logon - $account"
                    Path        = ''
                    Detail          = $details
                    MitreId     = 'T1110'
                    MitreName   = 'Brute Force'
                    ActionTaken = ''
                })
            }
        }

        # -----------------------------------------------------------------------
        # Event ID 4672 - Special Privileges Assigned (Privilege Escalation)
        # -----------------------------------------------------------------------
        $privEvents = Get-EventsSafe -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4672
            StartTime = $since
        }

        if ($privEvents.Count -gt 0) {
            # Group by account, exclude known system accounts
            $systemAccounts = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', 'DWM-1', 'DWM-2', 'UMFD-0', 'UMFD-1')
            $privByAccount  = @{}
            foreach ($ev in $privEvents) {
                try {
                    $xml     = [xml]$ev.ToXml()
                    $ns      = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
                    $account = $xml.SelectSingleNode('//e:Data[@Name="SubjectUserName"]', $ns).'#text'
                    if ($account -and $systemAccounts -notcontains $account -and $account -notmatch '^\$') {
                        if (-not $privByAccount.ContainsKey($account)) { $privByAccount[$account] = 0 }
                        $privByAccount[$account]++
                    }
                } catch {}
            }

            foreach ($account in $privByAccount.Keys) {
                $count = $privByAccount[$account]
                $findings.Add([PSCustomObject]@{
                    Module      = 'EventParser'
                    Severity    = 'Yellow'
                    Category    = 'Event: Privilege Escalation (4672)'
                    Title       = "Privilege Escalation - $account"
                    Path        = ''
                    Detail          = "Special privileges assigned to '$account' $count time(s) in last 24h."
                    MitreId     = 'T1078'
                    MitreName   = 'Valid Accounts'
                    ActionTaken = ''
                })
            }
        }

        # -----------------------------------------------------------------------
        # Event ID 7045 - New Service Installed
        # -----------------------------------------------------------------------
        $svcInstalls = Get-EventsSafe -FilterHashtable @{
            LogName   = 'System'
            Id        = 7045
            StartTime = $since
        }

        foreach ($ev in $svcInstalls) {
            $serviceName = 'Unknown'
            $serviceFile = 'Unknown'
            $serviceType = 'Unknown'
            $startType   = 'Unknown'
            try {
                $xml         = [xml]$ev.ToXml()
                $ns          = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
                $serviceName = $xml.SelectSingleNode('//e:Data[@Name="ServiceName"]', $ns).'#text'
                $serviceFile = $xml.SelectSingleNode('//e:Data[@Name="ImagePath"]', $ns).'#text'
                $serviceType = $xml.SelectSingleNode('//e:Data[@Name="ServiceType"]', $ns).'#text'
                $startType   = $xml.SelectSingleNode('//e:Data[@Name="StartType"]', $ns).'#text'
            } catch {}

            $isWhitelisted = $Whitelist.Services -contains $serviceName
            $severity      = if ($isWhitelisted) { 'Yellow' } else { 'Red' }

            $findings.Add([PSCustomObject]@{
                Module      = 'EventParser'
                Severity    = $severity
                Category    = 'Event: New Service Install (7045)'
                Title       = "New Service - $serviceName"
                Path        = $serviceFile
                Detail          = "New service installed in last 24h. Name: '$serviceName'. Path: $serviceFile. Type: $serviceType. StartType: $startType"
                MitreId     = 'T1543'
                MitreName   = 'Create or Modify System Process'
                ActionTaken = ''
            })
        }

        # -----------------------------------------------------------------------
        # Event ID 1102 - Audit Log Cleared
        # -----------------------------------------------------------------------
        $logClears = Get-EventsSafe -FilterHashtable @{
            LogName   = 'Security'
            Id        = 1102
            StartTime = $since
        }

        foreach ($ev in $logClears) {
            $clearedBy = 'Unknown'
            try {
                $xml       = [xml]$ev.ToXml()
                $ns        = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
                $clearedBy = $xml.SelectSingleNode('//e:Data[@Name="SubjectUserName"]', $ns).'#text'
            } catch {}

            $findings.Add([PSCustomObject]@{
                Module      = 'EventParser'
                Severity    = 'Red'
                Category    = 'Event: Audit Log Cleared (1102)'
                Title       = 'Security Audit Log Cleared'
                Path        = ''
                Detail          = "Security audit log was CLEARED at $($ev.TimeCreated) by '$clearedBy'. This is a critical anti-forensics indicator."
                MitreId     = 'T1070.001'
                MitreName   = 'Indicator Removal: Clear Windows Event Logs'
                ActionTaken = ''
            })
        }

        # Green summary if nothing found
        $flaggedCount = @($findings | Where-Object { $_.Severity -in 'Yellow','Red' }).Count
        if ($flaggedCount -eq 0) {
            $findings.Add([PSCustomObject]@{
                Module      = 'EventParser'
                Severity    = 'Green'
                Category    = 'Event Log'
                Title       = 'Event Parser'
                Path        = ''
                Detail          = "No threat indicators found in last 24h. Checked: 4625 ($($failedLogons.Count)), 4672 ($($privEvents.Count)), 7045 ($($svcInstalls.Count)), 1102 ($($logClears.Count))"
                MitreId     = ''
                MitreName   = ''
                ActionTaken = ''
            })
        }

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: EventParser] [ACTION: Scan] " +
            "[DETAILS: 4625=$($failedLogons.Count), 4672=$($privEvents.Count), 7045=$($svcInstalls.Count), 1102=$($logClears.Count); Flagged=$flaggedCount]"
        ) -Encoding UTF8

    } catch {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: EventParser] [STATUS: ERROR] [DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8
        throw
    }

    return $findings
}

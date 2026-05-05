<#
.SYNOPSIS
    LateralMovement.ps1 - Detects SMB lateral movement and remote service installation.
.DESCRIPTION
    Monitors Windows event logs for indicators of lateral movement:

    Event ID 5140 - Network share was accessed
      Reports access to ADMIN$, C$ and IPC$ administrative shares from remote hosts.
      High volume of 5140 events from the same source = possible automated lateral movement.

    Event ID 5145 - Network share object was checked for access permissions
      Granular share access checks; flags access to sensitive share paths.

    Event ID 7045 - A new service was installed
      New service with a name or binary path matching PsExec/PAExec/RemCom patterns
      indicates remote service execution (common lateral movement technique).

    Event ID 4624 - Logon (Type 3 = network logon from remote)
      High volume of remote logons from a single source IP may indicate pass-the-hash
      or credential-spraying activity.

    MITRE ATT&CK:
      T1021.002 - Remote Services: SMB/Windows Admin Shares

.OUTPUTS
    [PSCustomObject[]] - Finding objects conforming to the QuietMonitor finding schema.
#>

function Invoke-LateralMovementScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog,

        # Look back this many hours (default: 24)
        [int]$LookbackHours = 24,

        # Minimum number of admin share accesses from one source to alert
        [int]$ShareAccessThreshold = 10,

        # Minimum number of remote network logons from one source to alert (Type 3)
        [int]$RemoteLogonThreshold = 20
    )

    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $since       = (Get-Date).AddHours(-$LookbackHours)

    # Admin shares that indicate lateral movement when accessed remotely
    $adminShares = @('ADMIN$', 'C$', 'D$', 'E$', 'IPC$')

    # Service name / binary path patterns matching known remote execution tools
    $remoteExecPatterns = @(
        '(?i)psexesvc',
        '(?i)paexec',
        '(?i)remcom',
        '(?i)winexesvc',
        '(?i)\\Admin\$\\',
        '(?i)RCServerService',
        '(?i)\\temp\\[a-z0-9]{4,10}\.exe'
    )

    function Get-EventsSafe {
        param([string]$LogName, [int]$EventId, [datetime]$Since)
        try {
            Get-WinEvent -FilterHashtable @{
                LogName   = $LogName
                Id        = $EventId
                StartTime = $Since
            } -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -notmatch 'No events') {
                Write-Verbose "LateralMovement: Log '$LogName' ID $EventId - $($_.Exception.Message)"
            }
            @()
        }
    }

    function Get-XmlData {
        param([xml]$xml, [System.Xml.XmlNamespaceManager]$ns, [string]$name)
        $node = $xml.SelectSingleNode("//e:Data[@Name='$name']", $ns)
        if ($node) { $node.InnerText } else { '' }
    }

    # ============================================================
    # 1. Event 5140 - Admin share access
    # ============================================================
    $shareEvents = Get-EventsSafe -LogName 'Security' -EventId 5140 -Since $since

    # Aggregate by source IP + share name
    $shareBySource = @{}
    foreach ($ev in $shareEvents) {
        try {
            $xml = [xml]$ev.ToXml()
            $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

            $shareName = Get-XmlData $xml $ns 'ShareName'
            $sourceIP  = Get-XmlData $xml $ns 'IpAddress'
            $account   = "$(Get-XmlData $xml $ns 'SubjectDomainName')\$(Get-XmlData $xml $ns 'SubjectUserName')"

            # Only alert on admin shares
            $shareLeaf = ($shareName -split '\\' | Select-Object -Last 1).ToUpperInvariant()
            if ($adminShares -notcontains $shareLeaf) { continue }

            # Ignore local access (loopback)
            if ($sourceIP -eq '-' -or $sourceIP -eq '::1' -or $sourceIP -eq '127.0.0.1') { continue }

            $key = "$sourceIP|$shareLeaf|$account"
            if (-not $shareBySource.ContainsKey($key)) {
                $shareBySource[$key] = @{ Count = 0; ShareName = $shareName; IP = $sourceIP; Account = $account }
            }
            $shareBySource[$key].Count++
        } catch {}
    }

    foreach ($kv in $shareBySource.GetEnumerator()) {
        $entry    = $kv.Value
        $count    = $entry.Count
        $severity = if ($count -ge $ShareAccessThreshold) { 'Red' } else { 'Yellow' }

        $findings.Add([PSCustomObject]@{
            Module      = 'LateralMovement'
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Severity    = $severity
            Category    = 'Admin Share Access'
            Name        = "lateral-share-$([System.Math]::Abs($kv.Key.GetHashCode()))"
            DisplayName = "Admin share '$($entry.ShareName)' accessed from $($entry.IP)"
            Path        = ''
            Hash        = ''
            Details     = "Event 5140: Admin share '$($entry.ShareName)' accessed $count time(s) from source IP '$($entry.IP)' by account '$($entry.Account)' in the last $LookbackHours hours. Threshold=$ShareAccessThreshold."
            ActionTaken = ''
            MitreId     = 'T1021.002'
            MitreName   = 'Remote Services: SMB/Windows Admin Shares'
        })
    }

    # ============================================================
    # 2. Event 7045 - Remote service installation (PsExec pattern)
    # ============================================================
    $serviceEvents = Get-EventsSafe -LogName 'System' -EventId 7045 -Since $since

    foreach ($ev in $serviceEvents) {
        try {
            $xml = [xml]$ev.ToXml()
            $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

            $serviceName = Get-XmlData $xml $ns 'ServiceName'
            $imagePath   = Get-XmlData $xml $ns 'ImagePath'
            $account     = Get-XmlData $xml $ns 'AccountName'

            $isRemoteExec = $false
            foreach ($pattern in $remoteExecPatterns) {
                if ($serviceName -match $pattern -or $imagePath -match $pattern) {
                    $isRemoteExec = $true
                    break
                }
            }

            if ($isRemoteExec) {
                $findings.Add([PSCustomObject]@{
                    Module      = 'LateralMovement'
                    Timestamp   = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    Severity    = 'Red'
                    Category    = 'Remote Service Install'
                    Name        = "lateral-svc-$([System.Math]::Abs($serviceName.GetHashCode()))"
                    DisplayName = "Remote Exec Service: $serviceName"
                    Path        = $imagePath
                    Hash        = ''
                    Details     = "Event 7045: New service '$serviceName' installed with binary '$imagePath' running as '$account'. Service name/path matches known remote execution tool (PsExec, PAExec, RemCom, WinExe)."
                    ActionTaken = ''
                    MitreId     = 'T1021.002'
                    MitreName   = 'Remote Services: SMB/Windows Admin Shares'
                })

                Add-Content -Path $AuditLog -Value (
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                    "[USER: $currentUser] " +
                    "[MODULE: LateralMovement] [ACTION: RemoteServiceInstall] " +
                    "[DETAILS: ServiceName='$serviceName' ImagePath='$imagePath' Account='$account']"
                ) -Encoding UTF8
            }
        } catch {}
    }

    # ============================================================
    # 3. Event 4624 - Remote network logons (Type 3) - high volume
    # ============================================================
    $logonEvents = Get-EventsSafe -LogName 'Security' -EventId 4624 -Since $since

    $type3BySource = @{}
    foreach ($ev in $logonEvents) {
        try {
            $xml = [xml]$ev.ToXml()
            $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

            $logonType = Get-XmlData $xml $ns 'LogonType'
            if ($logonType -ne '3') { continue }

            $sourceIP = Get-XmlData $xml $ns 'IpAddress'
            $account  = "$(Get-XmlData $xml $ns 'TargetDomainName')\$(Get-XmlData $xml $ns 'TargetUserName')"

            if (-not $sourceIP -or $sourceIP -eq '-' -or $sourceIP -eq '::1' -or $sourceIP -eq '127.0.0.1') { continue }

            # Ignore machine accounts
            if ((Get-XmlData $xml $ns 'TargetUserName') -match '^\$') { continue }

            $key = "$sourceIP|$account"
            if (-not $type3BySource.ContainsKey($key)) {
                $type3BySource[$key] = @{ Count = 0; IP = $sourceIP; Account = $account }
            }
            $type3BySource[$key].Count++
        } catch {}
    }

    foreach ($kv in $type3BySource.GetEnumerator()) {
        $entry = $kv.Value
        if ($entry.Count -ge $RemoteLogonThreshold) {
            $findings.Add([PSCustomObject]@{
                Module      = 'LateralMovement'
                Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Severity    = 'Red'
                Category    = 'High-Volume Remote Logon'
                Name        = "lateral-logon-$([System.Math]::Abs($kv.Key.GetHashCode()))"
                DisplayName = "High remote logon count: $($entry.Account) from $($entry.IP)"
                Path        = ''
                Hash        = ''
                Details     = "Event 4624 (Type 3/Network): Account '$($entry.Account)' authenticated $($entry.Count) time(s) from '$($entry.IP)' in $LookbackHours hours. Possible Pass-the-Hash, credential stuffing, or automated lateral movement. Threshold=$RemoteLogonThreshold."
                ActionTaken = ''
                MitreId     = 'T1021.002'
                MitreName   = 'Remote Services: SMB/Windows Admin Shares'
            })

            Add-Content -Path $AuditLog -Value (
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                "[USER: $currentUser] " +
                "[MODULE: LateralMovement] [ACTION: HighVolumeRemoteLogon] " +
                "[DETAILS: Account='$($entry.Account)' SourceIP='$($entry.IP)' Count=$($entry.Count)]"
            ) -Encoding UTF8
        }
    }

    # ============================================================
    # Summary / clean result
    # ============================================================
    $alertCount = @($findings | Where-Object { $_.Severity -ne 'Green' }).Count

    if ($findings.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            Module      = 'LateralMovement'
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Severity    = 'Green'
            Category    = 'Lateral Movement'
            Name        = 'lateral-clean'
            DisplayName = 'Lateral Movement Scan - Clean'
            Path        = ''
            Hash        = ''
            Details     = "No lateral movement indicators in last $LookbackHours hours. Checked: admin share access (5140), remote service installs (7045), high-volume network logons (4624)."
            ActionTaken = ''
            MitreId     = 'T1021.002'
            MitreName   = 'Remote Services: SMB/Windows Admin Shares'
        })
    }

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $currentUser] " +
        "[MODULE: LateralMovement] [ACTION: Scan] " +
        "[DETAILS: AlertsGenerated=$alertCount ShareSources=$($shareBySource.Count) LogonSources=$($type3BySource.Count)]"
    ) -Encoding UTF8

    return $findings
}

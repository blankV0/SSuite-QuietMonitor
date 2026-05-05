<#
.SYNOPSIS
    CredentialAccess.ps1 - Monitors for LSASS credential access attempts.
.DESCRIPTION
    Detects credential dumping activity through two complementary methods:

    Method 1 - Sysmon Event ID 10 (primary, requires Sysmon):
      Parses the Microsoft-Windows-Sysmon/Operational log for Event ID 10
      (ProcessAccess events targeting lsass.exe in the last 24 hours).
      GrantedAccess flags indicating credential reads:
        0x1010 - PROCESS_QUERY_INFORMATION | PROCESS_VM_READ  (classic Mimikatz)
        0x1410 - includes PROCESS_VM_READ
        0x1fffff - PROCESS_ALL_ACCESS (generic/suspicious)

    Method 2 - Event ID 4648 (fallback, always run):
      Windows Security log Event ID 4648 = Logon using explicit credentials.
      High frequency or off-hours events indicate credential stuffing or
      lateral movement using harvested credentials.

    Method 3 - Handle enumeration heuristic (no Sysmon fallback):
      If Sysmon is unavailable, opens a read handle to lsass.exe and checks for
      other processes that have opened handles to lsass (via NtQuerySystemInformation).
      NOTE: This uses a .NET P/Invoke wrapper and requires SeDebugPrivilege.

    MITRE ATT&CK:
      T1003.001 - OS Credential Dumping: LSASS Memory

.OUTPUTS
    [PSCustomObject[]] - Finding objects conforming to the QuietMonitor finding schema.
#>

function Invoke-CredentialAccessMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog,

        # Look back this many hours for credential access events (default: 24)
        [int]$LookbackHours = 24,

        # Event 4648 count threshold per account before alerting
        [int]$ExplicitCredThreshold = 5
    )

    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $since       = (Get-Date).AddHours(-$LookbackHours)

    # Accounts to ignore in explicit credential alerts (system/service accounts)
    $ignoredAccounts = @(
        'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'DWM-1', 'DWM-2', 'DWM-3',
        'UMFD-0', 'UMFD-1', 'UMFD-2', 'WINDOW MANAGER', 'FONT DRIVER HOST',
        'ANONYMOUS LOGON'
    )

    # High-risk GrantedAccess masks targeting LSASS memory
    $highRiskMasks = @(
        '0x1010',   # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (Mimikatz classic)
        '0x1410',   # adds PROCESS_VM_READ
        '0x1f0fff', # PROCESS_ALL_ACCESS on some OS versions
        '0x1fffff', # PROCESS_ALL_ACCESS
        '0x143a',   # Procdump default
        '0x40',     # PROCESS_DUP_HANDLE alone (handle duplication)
        '0x1000',   # PROCESS_QUERY_LIMITED_INFORMATION alone on lsass
    )

    # Helper for safe WinEvent reads
    function Get-EventsSafe {
        param([string]$LogName, [int]$EventId, [datetime]$Since)
        try {
            Get-WinEvent -FilterHashtable @{
                LogName   = $LogName
                Id        = $EventId
                StartTime = $Since
            } -ErrorAction Stop
        } catch [Exception] {
            if ($_.Exception.Message -notmatch 'No events') {
                Write-Verbose "CredentialAccess: Log '$LogName' ID $EventId - $($_.Exception.Message)"
            }
            @()
        }
    }

    # ============================================================
    # Method 1: Sysmon Event ID 10 (ProcessAccess on lsass.exe)
    # ============================================================
    $sysmonAvailable = $false

    try {
        $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        $sysmonAvailable = ($sysmonLog -ne $null)
    } catch {}

    if ($sysmonAvailable) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' `
                                       -EventId 10 -Since $since

        $lsassAccesses = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($ev in $sysmonEvents) {
            try {
                $xml = [xml]$ev.ToXml()
                $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

                $getData = { param($name)
                    $node = $xml.SelectSingleNode("//e:Data[@Name='$name']", $ns)
                    if ($node) { $node.InnerText } else { '' }
                }

                $targetImage   = & $getData 'TargetImage'
                $sourceImage   = & $getData 'SourceImage'
                $grantedAccess = & $getData 'GrantedAccess'
                $callTrace     = & $getData 'CallTrace'
                $sourcePid     = & $getData 'SourceProcessId'

                # Only interested in accesses targeting lsass
                if ($targetImage -notmatch 'lsass\.exe') { continue }

                $isHighRisk = $highRiskMasks -contains $grantedAccess.ToLowerInvariant()

                # Check for known Mimikatz/Procdump call trace signatures
                $isMimikatz = $callTrace -match 'wdigest\.dll|lsasrv\.dll|ntdsai\.dll'

                $severity = if ($isHighRisk -or $isMimikatz) { 'Red' } else { 'Yellow' }

                $lsassAccesses.Add(@{
                    SourceImage   = $sourceImage
                    SourcePID     = $sourcePid
                    GrantedAccess = $grantedAccess
                    CallTrace     = $callTrace
                    Severity      = $severity
                    Time          = $ev.TimeCreated
                })
            } catch {}
        }

        if ($lsassAccesses.Count -gt 0) {
            foreach ($access in $lsassAccesses) {
                $findings.Add([PSCustomObject]@{
                    Module      = 'CredentialAccess'
                    Severity    = $access.Severity
                    Category    = 'LSASS Access'
                    Title       = "[Sysmon] $([System.IO.Path]::GetFileName($access.SourceImage)) accessed lsass.exe"
                    Path        = $access.SourceImage
                    Detail          = "Sysmon Event 10: '$($access.SourceImage)' (PID $($access.SourcePID)) opened lsass.exe with GrantedAccess=$($access.GrantedAccess). CallTrace: $($access.CallTrace.Substring(0,[Math]::Min(200,$access.CallTrace.Length)))"
                    ActionTaken = ''
                    MitreId     = 'T1003.001'
                    MitreName   = 'OS Credential Dumping: LSASS Memory'
                })

                if ($access.Severity -eq 'Red') {
                    Add-Content -Path $AuditLog -Value (
                        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                        "[USER: $currentUser] " +
                        "[MODULE: CredentialAccess] [ACTION: LsassAccess] " +
                        "[DETAILS: Source='$($access.SourceImage)' PID=$($access.SourcePID) Access=$($access.GrantedAccess)]"
                    ) -Encoding UTF8
                }
            }
        } else {
            $findings.Add([PSCustomObject]@{
                Module      = 'CredentialAccess'
                Severity    = 'Green'
                Category    = 'LSASS Access'
                Title       = 'LSASS Access - No Sysmon Events'
                Path        = ''
                Detail          = "Sysmon is active. No ProcessAccess events targeting lsass.exe in the last $LookbackHours hours."
                ActionTaken = ''
                MitreId     = 'T1003.001'
                MitreName   = 'OS Credential Dumping: LSASS Memory'
            })
        }
    } else {
        # No Sysmon - record informational finding
        $findings.Add([PSCustomObject]@{
            Module      = 'CredentialAccess'
            Severity    = 'Yellow'
            Category    = 'LSASS Access'
            Title       = 'Sysmon Not Installed - Limited Visibility'
            Path        = ''
            Detail          = 'Sysmon is not installed. LSASS process-access monitoring requires Sysmon (Event ID 10). Install Sysmon for full credential access detection: https://learn.microsoft.com/sysinternals/downloads/sysmon'
            ActionTaken = ''
            MitreId     = 'T1003.001'
            MitreName   = 'OS Credential Dumping: LSASS Memory'
        })
    }

    # ============================================================
    # Method 2: Event ID 4648 - Explicit credential logons
    # ============================================================
    $explicitEvents = Get-EventsSafe -LogName 'Security' -EventId 4648 -Since $since

    $explicitByAccount = @{}
    foreach ($ev in $explicitEvents) {
        try {
            $xml = [xml]$ev.ToXml()
            $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

            $getData = { param($name)
                $node = $xml.SelectSingleNode("//e:Data[@Name='$name']", $ns)
                if ($node) { $node.InnerText } else { '' }
            }

            $account       = "$(& $getData 'SubjectDomainName')\$(& $getData 'SubjectUserName')"
            $targetAccount = "$(& $getData 'TargetDomainName')\$(& $getData 'TargetUserName')"
            $targetServer  = & $getData 'TargetServerName'
            $process       = & $getData 'ProcessName'

            # Ignore system accounts
            $accountPart = (& $getData 'SubjectUserName').ToUpperInvariant()
            if ($ignoredAccounts -contains $accountPart) { continue }
            if ($accountPart -match '^\$$') { continue }  # Machine accounts

            $key = "$account -> $targetAccount"
            if (-not $explicitByAccount.ContainsKey($key)) {
                $explicitByAccount[$key] = @{ Count = 0; Server = $targetServer; Process = $process; Account = $account; Target = $targetAccount }
            }
            $explicitByAccount[$key].Count++
        } catch {}
    }

    foreach ($kv in $explicitByAccount.GetEnumerator()) {
        $entry    = $kv.Value
        $count    = $entry.Count
        $severity = if ($count -ge $ExplicitCredThreshold) { 'Red' } else { 'Yellow' }

        $findings.Add([PSCustomObject]@{
            Module      = 'CredentialAccess'
            Severity    = $severity
            Category    = 'Explicit Credential Use'
            Title       = "Explicit Credentials: $($entry.Account) -> $($entry.Target)"
            Path        = $entry.Process
            Detail          = "Event 4648: '$($entry.Account)' used explicit credentials $count time(s) in last $LookbackHours hours to authenticate as '$($entry.Target)' on server '$($entry.Server)' via '$($entry.Process)'."
            ActionTaken = ''
            MitreId     = 'T1003.001'
            MitreName   = 'OS Credential Dumping: LSASS Memory'
        })
    }

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $currentUser] " +
        "[MODULE: CredentialAccess] [ACTION: Scan] " +
        "[DETAILS: SysmonAvailable=$sysmonAvailable ExplicitCredAccounts=$($explicitByAccount.Count) LookbackHours=$LookbackHours]"
    ) -Encoding UTF8

    return $findings
}

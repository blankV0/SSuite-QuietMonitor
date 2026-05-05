#Requires -RunAsAdministrator
# =============================================================
# PrivilegeAbuse.ps1 — Filesystem-level access monitoring for
# C:\QuietMonitor\ sensitive files. Uses Windows Security event
# log (4656/4663 Audit Object Access) to detect any process
# other than QuietMonitorSvc reading/writing config.json,
# whitelist.enc, manifest.json, or audit.log.
# RMM agent cross-reference: flags known RMM tools accessing
# QuietMonitor files as "Possible unauthorized RMM access".
# MITRE: T1083 (File Discovery), T1005 (Data from Local System)
# =============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:PA_BASE_DIR  = 'C:\QuietMonitor'
$script:PA_SVC_NAME  = 'QuietMonitorSvc'
$script:PA_TAMPER    = 'C:\QuietMonitor\Logs\tamper.log'

# Files that should only be touched by QuietMonitor itself
$script:PA_PROTECTED_FILES = @(
    'C:\QuietMonitor\Config\whitelist.json',
    'C:\QuietMonitor\Config\whitelist.enc',
    'C:\QuietMonitor\Config\whitelist.sig',
    'C:\QuietMonitor\Config\settings.json',
    'C:\QuietMonitor\integrity\manifest.json',
    'C:\QuietMonitor\Logs\audit.log',
    'C:\QuietMonitor\Logs\tamper.log',
    'C:\QuietMonitor\Config\fingerprint.json'
)

# Known RMM tools — used for cross-referencing unauthorised file access
$script:PA_RMM_PROCESS_NAMES = @(
    'NinjaRMMAgent','ninjarmmservice','LTSvc','LTService','ScreenConnect.ClientService',
    'AgentMon','AteraAgent','CagService','TeamViewer_Service','TeamViewer','AnyDesk',
    'SRService','SRAgent','LogMeIn','LMIGuardianSvc','ZohoMeetingController','ZohoURS',
    'PCMonitorSrv','Windows_Agent','HuntressAgent','bomgar-scc','AuvikCollector',
    'action1_agent','superops_agent','DesktopCentral','ManageEngine','winvnc4','tvnserver',
    'vncserver','NaveriskAgent','PCMonitorService','WRSkyClient','itsm_agent',
    'AcronisManagedMachineService','ScreenConnect','LTAgent','N_able','ncentral'
)

function script:New-PAFinding {
    param([string]$Sev, [string]$Name, [string]$Display, [string]$Path, [string]$Details, [string]$Mitre, [string]$MitreName)
    [PSCustomObject]@{
        Severity=$Sev; Module='PrivilegeAbuse'; Category='UnauthorizedAccess'
        Title=$Display; Detail=$Details; Path=$Path
        MitreId=$Mitre; MitreName=$MitreName; ActionTaken='Alert'
    }
}

function script:Write-PATamper {
    param([string]$Message, [string]$AuditLog)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [TAMPER-CRITICAL] [PrivilegeAbuse] $Message"
    try { Add-Content -LiteralPath $script:PA_TAMPER -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    if ($AuditLog) { try { Add-Content -LiteralPath $AuditLog -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {} }
    Write-Host "  [!!!] PRIVILEGE ABUSE: $Message" -ForegroundColor Red
}

# ── Enable audit policy ───────────────────────────────────────
function Enable-QuietMonitorAuditing {
    <#
    .SYNOPSIS
        Enables Windows "Audit Object Access" policy (Success + Failure)
        via auditpol.exe — required for Security event log 4656/4663.
        Also configures SACL (System ACL) on protected QuietMonitor files
        so that all access generates Security log events.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'])

    # Enable Audit Object Access via auditpol
    try {
        $result = & auditpol.exe /set /subcategory:"Object Access" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host '  [PrivilegeAbuse] Audit Object Access policy enabled.' -ForegroundColor Green
        } else {
            Write-Host "  [PrivilegeAbuse] auditpol returned $LASTEXITCODE : $result" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [PrivilegeAbuse] Could not set audit policy: $_" -ForegroundColor Yellow
    }

    # Apply SACL to protected files (generates 4663 events on all access)
    foreach ($filePath in $script:PA_PROTECTED_FILES) {
        if (-not (Test-Path $filePath)) { continue }
        try {
            $acl   = Get-Acl -LiteralPath $filePath -Audit
            $everyone = [System.Security.Principal.NTAccount]::new('Everyone')
            $rights   = [System.Security.AccessControl.FileSystemRights]::FullControl
            $audit    = [System.Security.AccessControl.FileSystemAuditRule]::new(
                $everyone, $rights,
                [System.Security.AccessControl.InheritanceFlags]::None,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AuditFlags]::Success -bor
                [System.Security.AccessControl.AuditFlags]::Failure)
            $acl.AddAuditRule($audit)
            Set-Acl -LiteralPath $filePath -AclObject $acl -ErrorAction Stop
        } catch {
            # SACL changes may fail on non-object-access enabled systems; non-fatal
        }
    }

    if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [PrivilegeAbuse] [ACTION: EnableAuditing] [DETAILS: Audit Object Access enabled; SACL applied to $($script:PA_PROTECTED_FILES.Count) files]" -Encoding UTF8 -ErrorAction SilentlyContinue }
}

# ── Read Security event log for access events ─────────────────
function Get-QuietMonitorAccessEvents {
    <#
    .SYNOPSIS
        Queries Security event log for events 4663 (File Access) and
        4656 (Handle Request) referencing QuietMonitor protected files.
        Looks back 24 hours by default.
    #>
    [CmdletBinding()]
    param(
        [int]$HoursBack = 24,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $events  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cutoff  = (Get-Date).AddHours(-$HoursBack)

    # Build XPath filter for 4656 and 4663 in Security log
    $filter = @{
        LogName   = 'Security'
        Id        = @(4656, 4663)
        StartTime = $cutoff
    }

    try {
        $raw = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue

        foreach ($evt in $raw) {
            $xml  = [xml]$evt.ToXml()
            $data = $xml.Event.EventData.Data

            $objName = ($data | Where-Object { $_.Name -eq 'ObjectName' }).'#text'
            if (-not $objName) { continue }

            # Only care about our protected files
            $isProtected = $script:PA_PROTECTED_FILES | Where-Object {
                $objName -ieq $_ -or $objName.StartsWith($script:PA_BASE_DIR, [System.StringComparison]::OrdinalIgnoreCase)
            }
            if (-not $isProtected) { continue }

            $procName  = ($data | Where-Object { $_.Name -eq 'ProcessName' }).'#text'
            $procId    = ($data | Where-Object { $_.Name -eq 'ProcessId' }).'#text'
            $subjUser  = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            $access    = ($data | Where-Object { $_.Name -eq 'AccessMask' }).'#text'

            $events.Add([PSCustomObject]@{
                TimeCreated = $evt.TimeCreated
                EventId     = $evt.Id
                ObjectName  = $objName
                ProcessName = $procName
                ProcessId   = $procId
                User        = $subjUser
                AccessMask  = $access
            })
        }
    } catch {
        # Security log not accessible or auditing not enabled — gracefully skip
    }

    return $events.ToArray()
}

# ── Main privilege abuse detection ────────────────────────────
function Invoke-PrivilegeAbuseCheck {
    <#
    .SYNOPSIS
        1. Reads Security log for file access events on QuietMonitor files
        2. Cross-references accessor process against known RMM agent list
        3. Flags any non-QuietMonitor process accessing protected files
        4. Generates "External Access Attempts" findings for weekly report
    #>
    [CmdletBinding()]
    param(
        [object]$Whitelist,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Collect current running processes for context enrichment
    $runningProcs = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Id -notin $runningProcs.Keys) {
            $runningProcs[$_.Id] = [PSCustomObject]@{
                Name    = $_.Name
                Path    = try { $_.MainModule.FileName } catch { '' }
                CPU     = $_.CPU
                Parent  = try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).ParentProcessId } catch { 0 }
            }
        }
    }

    # Check currently running processes accessing QuietMonitor directories
    # (real-time check via file system handles — approximated by process open files)
    $allProcs = Get-Process -ErrorAction SilentlyContinue
    foreach ($proc in $allProcs) {
        $procNameClean = [System.IO.Path]::GetFileNameWithoutExtension($proc.Name)

        # Check if process name matches known RMM tool list
        $isRMM = $script:PA_RMM_PROCESS_NAMES | Where-Object {
            $procNameClean -ilike "*$_*" -or $_ -ilike "*$procNameClean*"
        }

        # Check if process has open handles to QuietMonitor directory
        # (using /proc equivalent: check if any module is from QM dir)
        $binPath = try { $proc.MainModule.FileName } catch { '' }
        $isQMProcess = $binPath -like "*\QuietMonitor\*" -or $proc.Name -like '*QuietMonitor*'

        if ($isRMM -and -not $isQMProcess) {
            $rmmName = $isRMM | Select-Object -First 1
            $msg = "Known RMM tool running: $($proc.Name) (PID: $($proc.Id)) — $rmmName — Possible unauthorized RMM access to security configuration"
            script:Write-PATamper $msg $AuditLog

            $parentPid  = try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).ParentProcessId } catch { 0 }
            $parentName = if ($parentPid -and $runningProcs.ContainsKey($parentPid)) { $runningProcs[$parentPid].Name } else { 'Unknown' }
            $cmdLine    = try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).CommandLine } catch { '' }

            $findings.Add((script:New-PAFinding 'Red' 'RMMAccessDetected'
                "Possible unauthorized RMM access: $($proc.Name)"
                $binPath
                "RMM Tool: $rmmName  Process: $($proc.Name) PID:$($proc.Id)  Parent: $parentName (PID:$parentPid)  User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)  CmdLine: $cmdLine  — A remote operator with $rmmName credentials may have full control of this machine"
                'T1219' 'Remote Access Software'))
        }
    }

    # Query Security event log for file access events
    $accessEvents = Get-QuietMonitorAccessEvents -HoursBack 24 -AuditLog $AuditLog

    foreach ($evt in $accessEvents) {
        $procNameClean = if ($evt.ProcessName) { [System.IO.Path]::GetFileNameWithoutExtension($evt.ProcessName) } else { 'Unknown' }

        # Skip QuietMonitor's own service
        if ($procNameClean -ilike '*QuietMonitor*' -or $procNameClean -ilike '*powershell*') { continue }

        $isRMM = $script:PA_RMM_PROCESS_NAMES | Where-Object { $procNameClean -ilike "*$_*" }

        if ($isRMM) {
            $msg = "RMM tool accessed QuietMonitor file: $procNameClean → $($evt.ObjectName) at $($evt.TimeCreated)"
            script:Write-PATamper $msg $AuditLog
            $findings.Add((script:New-PAFinding 'Red' 'RMMFileAccess'
                "RMM tool accessed security file: $(Split-Path $evt.ObjectName -Leaf)"
                $evt.ObjectName
                "Process: $procNameClean (PID: $($evt.ProcessId))  User: $($evt.User)  Time: $($evt.TimeCreated)  Access: $($evt.AccessMask)  — Flagged as: Possible unauthorized RMM access to security configuration"
                'T1219' 'Remote Access Software'))
        } else {
            $findings.Add((script:New-PAFinding 'Yellow' 'UnauthorizedFileAccess'
                "Unexpected process accessed QuietMonitor file: $procNameClean"
                $evt.ObjectName
                "Process: $procNameClean (PID: $($evt.ProcessId))  User: $($evt.User)  Time: $($evt.TimeCreated)  Access: $($evt.AccessMask)"
                'T1083' 'File and Directory Discovery'))
        }
    }

    if ($findings.Count -eq 0 -and $AuditLog) {
        Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [PrivilegeAbuse] [ACTION: Scan] [DETAILS: No unauthorised access to QuietMonitor files detected (last 24h)]" -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    return $findings.ToArray()
}

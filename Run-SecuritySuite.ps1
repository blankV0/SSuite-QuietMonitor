<#
.SYNOPSIS
    Run-SecuritySuite.ps1 - QuietMonitor Security Suite main orchestrator.
.DESCRIPTION
    Orchestrates all detection and response modules for Windows 10/11 endpoint security.
    Dot-sources each module from the .\Modules\ directory, executes detection scans,
    handles response actions with explicit confirmation prompts, sends alerts, and
    generates a color-coded HTML report.

    Execution modes:
      -ScanOnly       Run detection only. No quarantine, no removal, no alerts.
      -AutoQuarantine After confirmation, auto-quarantine all Red-severity findings
                      that have a valid file path.
      -FullReport     Always generate the HTML report, even if no findings are flagged.
                      Default behavior generates a report whenever findings exist.

    Directory layout created/used at runtime:
      C:\QuietMonitor\Logs\audit.log       - Full tamper-evident audit trail
      C:\QuietMonitor\Reports\             - HTML reports + software inventory CSVs
      C:\QuietMonitor\Quarantine\          - AES-256 encrypted quarantine files

    ThreatLocker Zero Trust Compatibility:
      ALL scripts in this suite must be signed with a trusted code-signing certificate
      before deployment in a ThreatLocker-managed environment.
      Use: Get-ChildItem .\*.ps1, .\Modules\*.ps1 | ForEach-Object {
               Set-AuthenticodeSignature $_.FullName -Certificate $cert }
      Add the SHA256 thumbprint of your signing certificate to ThreatLocker allowlist.
      Network modules (Alert.ps1) require outbound policy rules for SMTP/webhook.

    Requirements:
      - Windows PowerShell 5.1 or PowerShell 7+ on Windows 10/11
      - Must be run as Administrator (required for service, event log, and ACL operations)
      - No external dependencies - only built-in cmdlets and .NET BCL
.PARAMETER ScanOnly
    Detection modules only. Disables quarantine, removal, and email/webhook alerts.
.PARAMETER AutoQuarantine
    Automatically quarantine files flagged as Red severity. Still requires "YES" prompt.
.PARAMETER FullReport
    Generate the HTML report even when all findings are Green (clean scan).
.EXAMPLE
    # Standard interactive scan with report
    .\Run-SecuritySuite.ps1 -FullReport

    # Scan only (no actions, no alerts)
    .\Run-SecuritySuite.ps1 -ScanOnly

    # Auto-quarantine red findings (prompts for confirmation)
    .\Run-SecuritySuite.ps1 -AutoQuarantine -FullReport
.NOTES
    Author : QuietMonitor Security Suite
    Version: 1.0.0
    Sign with: Set-AuthenticodeSignature .\Run-SecuritySuite.ps1 -Certificate $cert
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$ScanOnly,
    [switch]$AutoQuarantine,
    [switch]$FullReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # Allow modules to fail gracefully; log and continue

#region -- Path constants -----------------------------------------------------
$ScriptRoot       = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesPath      = Join-Path $ScriptRoot 'Modules'
$ConfigPath       = Join-Path $ScriptRoot 'Config'
$QuietMonitorBase = 'C:\QuietMonitor'
$LogPath          = Join-Path $QuietMonitorBase 'Logs'
$ReportPath       = Join-Path $QuietMonitorBase 'Reports'
$QuarantinePath   = Join-Path $QuietMonitorBase 'Quarantine'
$AuditLog         = Join-Path $LogPath 'audit.log'
#endregion

#region -- Bootstrap directories ----------------------------------------------
foreach ($dir in @($QuietMonitorBase, $LogPath, $ReportPath, $QuarantinePath)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Restrict audit log directory to Administrators + SYSTEM only
try {
    $acl = Get-Acl -Path $LogPath
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($principal in @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.SetAccessRule($rule)
    }
    Set-Acl -Path $LogPath -AclObject $acl -ErrorAction SilentlyContinue
} catch { <# ACL hardening is best-effort #> }
#endregion

#region -- Audit log helper ---------------------------------------------------
function Write-AuditLog {
    param(
        [string]$Action,
        [string]$Module  = 'Orchestrator',
        [string]$Details = '',
        [string]$Status  = 'INFO'
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $line = "[$ts] [USER: $user] [STATUS: $Status] [MODULE: $Module] [ACTION: $Action] [DETAILS: $Details]"
    Add-Content -Path $AuditLog -Value $line -Encoding UTF8
}
#endregion

#region -- Rotate audit log if too large --------------------------------------
try {
    $settings = Get-Content (Join-Path $ConfigPath 'settings.json') -Raw -Encoding UTF8 |
                    ConvertFrom-Json -ErrorAction Stop
    $maxSizeMB = if ($settings.Logging.MaxLogSizeMB) { [int]$settings.Logging.MaxLogSizeMB } else { 50 }
    if ((Test-Path $AuditLog) -and ((Get-Item $AuditLog).Length / 1MB) -gt $maxSizeMB) {
        $archive = $AuditLog -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Move-Item $AuditLog $archive -Force
        Write-Host "  [i] Audit log rotated to: $archive" -ForegroundColor Gray
    }
} catch { <# Non-fatal #> }
#endregion

#region -- Load config --------------------------------------------------------
$WhitelistFile = Join-Path $ConfigPath 'whitelist.json'
$SettingsFile  = Join-Path $ConfigPath 'settings.json'

foreach ($cf in @($WhitelistFile, $SettingsFile)) {
    if (-not (Test-Path $cf)) {
        Write-Error "Required config file not found: $cf"
        Write-Error "Ensure Config\whitelist.json and Config\settings.json exist."
        exit 1
    }
}

try {
    $Whitelist = Get-Content $WhitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $Settings  = Get-Content $SettingsFile  -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse config files: $($_.Exception.Message)"
    exit 1
}
#endregion

#region -- Load modules -------------------------------------------------------
$moduleNames = @(
    'ServiceAudit', 'PortScan', 'TaskAudit', 'StartupAudit',
    'SoftwareInventory', 'UserAudit', 'EventParser', 'ProcessAudit',
    'IOCScanner', 'LOLBINDetection', 'MemoryInjection', 'PersistenceHunter',
    'NetworkAnomaly', 'CredentialAccess', 'LateralMovement', 'ForensicCapture',
    'WeeklyReport', 'Baseline', 'VulnCheck', 'ThreatIntel', 'UBA', 'RansomwareGuard', 'SelfProtect',
    'WhitelistProtection', 'IntegrityEngine', 'AuditChain', 'RuntimeProtect',
    'ProcessIntegrity', 'RemoteAnchor', 'PrivilegeAbuse', 'RMMDetect',
    'Quarantine', 'ServiceQuarantine', 'RemoveItem', 'Alert', 'Report'
)

$loadErrors = 0
foreach ($mod in $moduleNames) {
    $modFile = Join-Path $ModulesPath "$mod.ps1"
    if (Test-Path $modFile) {
        try {
            . $modFile
        } catch {
            Write-Warning "Failed to load module '$mod': $($_.Exception.Message)"
            $loadErrors++
        }
    } else {
        Write-Warning "Module file not found: $modFile"
        $loadErrors++
    }
}

if ($loadErrors -gt 0) {
    Write-Warning "$loadErrors module(s) failed to load. Continuing with available modules."
}
#endregion

#region -- Banner -------------------------------------------------------------
$modeLabel = if ($ScanOnly) { 'SCAN ONLY' } elseif ($AutoQuarantine) { 'AUTO QUARANTINE' } else { 'INTERACTIVE' }
Write-Host ""
Write-Host "  +===================================================+" -ForegroundColor Cyan
Write-Host "  |        QuietMonitor Security Suite v2.0           |" -ForegroundColor Cyan
Write-Host "  +===================================================+" -ForegroundColor Cyan
Write-Host "  Host     : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  User     : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor White
Write-Host "  Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "  Mode     : $modeLabel" -ForegroundColor Yellow
Write-Host "  Audit log: $AuditLog" -ForegroundColor Gray
Write-Host ""

Write-AuditLog -Action 'SuiteStart' -Details "Mode=$modeLabel Host=$env:COMPUTERNAME"
$suiteStartTime = Get-Date
#endregion

#region -- Detection phase ----------------------------------------------------
$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

$detectionModules = [ordered]@{
    'ServiceAudit'      = 'Invoke-ServiceAudit'
    'PortScan'          = 'Invoke-PortScan'
    'TaskAudit'         = 'Invoke-TaskAudit'
    'StartupAudit'      = 'Invoke-StartupAudit'
    'SoftwareInventory' = 'Invoke-SoftwareInventory'
    'UserAudit'         = 'Invoke-UserAudit'
    'EventParser'       = 'Invoke-EventParser'
    'ProcessAudit'      = 'Invoke-ProcessAudit'
    'IOCScanner'        = 'Invoke-IOCScanner'
    'LOLBINDetection'   = 'Invoke-LOLBINDetection'
    'MemoryInjection'   = 'Invoke-MemoryInjectionScan'
    'PersistenceHunter' = 'Invoke-PersistenceHunter'
    'NetworkAnomaly'    = 'Invoke-NetworkAnomalyDetection'
    'CredentialAccess'  = 'Invoke-CredentialAccessMonitor'
    'LateralMovement'   = 'Invoke-LateralMovementScan'
    'Baseline'          = 'Invoke-BaselineDrift'
    'VulnCheck'         = 'Invoke-VulnCheck'
    'ThreatIntel'       = 'Invoke-ThreatIntelCheck'
    'UBA'               = 'Invoke-UBAAnalysis'
    'RansomwareGuard'      = 'Invoke-RansomwareGuardScan'
    'SelfProtect'          = 'Invoke-SelfIntegrityCheck'
    'WhitelistProtection'  = 'Invoke-WhitelistIntegrityCheck'
    'IntegrityEngine'      = 'Invoke-IntegrityCheck'
    'AuditChain'           = 'Invoke-AuditChainVerify'
    'RuntimeProtect'       = 'Invoke-RuntimeProtectionCheck'
    'ProcessIntegrity'     = 'Invoke-ProcessIntegrityCheck'
    'RemoteAnchor'         = 'Invoke-RemoteAnchorSync'
    'PrivilegeAbuse'       = 'Invoke-PrivilegeAbuseCheck'
    'RMMDetect'            = 'Invoke-RMMDetection'
    # ServiceQuarantine provides workflow helpers; no top-level detection function to run
}

Write-Host "--- Detection Phase ---------------------------------" -ForegroundColor DarkGray
foreach ($entry in $detectionModules.GetEnumerator()) {
    $modName  = $entry.Key
    $funcName = $entry.Value

    Write-Host "  [*] $modName..." -ForegroundColor Yellow -NoNewline

    # Check function is loaded
    if (-not (Get-Command $funcName -ErrorAction SilentlyContinue)) {
        Write-Host " SKIPPED (not loaded)" -ForegroundColor DarkGray
        Write-AuditLog -Action 'ModuleSkipped' -Module $modName -Details "Function $funcName not loaded" -Status 'WARN'
        continue
    }

    $startTime = Get-Date
    try {
        $moduleFindings = & $funcName -Whitelist $Whitelist -AuditLog $AuditLog
        $elapsed        = [int]((Get-Date) - $startTime).TotalMilliseconds

        if ($moduleFindings) {
            foreach ($f in $moduleFindings) { $allFindings.Add($f) }
        }

        $redCnt    = @($moduleFindings | Where-Object { $_.Severity -eq 'Red'    }).Count
        $yellowCnt = @($moduleFindings | Where-Object { $_.Severity -eq 'Yellow' }).Count
        $greenCnt  = @($moduleFindings | Where-Object { $_.Severity -eq 'Green'  }).Count

        $statusColor = if ($redCnt -gt 0) { 'Red' } elseif ($yellowCnt -gt 0) { 'Yellow' } else { 'Green' }
        $statusText  = " done ($($elapsed)ms) | RED:$redCnt YELLOW:$yellowCnt CLEAN:$greenCnt"
        Write-Host $statusText -ForegroundColor $statusColor

    } catch {
        Write-Host " ERROR" -ForegroundColor Red
        Write-Warning "    $modName failed: $($_.Exception.Message)"
        Write-AuditLog -Action 'ModuleError' -Module $modName -Details $_.Exception.Message -Status 'ERROR'
    }
}
Write-Host ""
#endregion

#region -- Normalize finding schema ------------------------------------------
# Ensure all expected properties exist on every finding so downstream code is safe
$schemaProps = @('Severity','Module','Category','Title','Detail','Path','MitreId','MitreName','ActionTaken')
foreach ($f in $allFindings) {
    foreach ($prop in $schemaProps) {
        if (-not ($f.PSObject.Properties[$prop])) {
            Add-Member -InputObject $f -NotePropertyName $prop -NotePropertyValue '' -Force
        }
    }
}
#endregion

#region -- Smart path exclusions: downgrade known-safe paths to Yellow -------
# Read quarantine settings; fall back to built-in defaults when absent
$quarSettings = if ($Settings.PSObject.Properties['quarantine']) { $Settings.quarantine } else { $null }

$interactiveMode = $true
if ($quarSettings -and $quarSettings.PSObject.Properties['interactiveMode']) {
    $interactiveMode = [bool]$quarSettings.interactiveMode
}

$knownSafePaths = @(
    'C:\Program Files\BraveSoftware\',
    'C:\Program Files\Microsoft VS Code\',
    'C:\Program Files (x86)\Microsoft\EdgeWebView\',
    'C:\Program Files (x86)\Lenovo\',
    'C:\Windows\System32\DriverStore\',
    'C:\Program Files\Adobe\',
    'C:\Program Files\Proton\',
    'C:\Program Files\WindowsApps\'
)
if ($quarSettings -and $quarSettings.PSObject.Properties['knownSafePaths'] -and $quarSettings.knownSafePaths) {
    $knownSafePaths = [string[]]$quarSettings.knownSafePaths
}

# Also read WhitelistedPaths from whitelist.json for per-path suppression
$whitelistedPaths = @()
try {
    $wlObj = Get-Content $WhitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($wlObj.PSObject.Properties['WhitelistedPaths'] -and $wlObj.WhitelistedPaths) {
        $whitelistedPaths = [string[]]$wlObj.WhitelistedPaths
    }
} catch {}

$downgradeCount = 0
foreach ($f in $allFindings) {
    if ($f.Severity -ne 'Red') { continue }
    $fPath = if ($f.PSObject.Properties['Path']) { [string]$f.Path } else { '' }
    if (-not $fPath) { continue }

    # Downgrade if path matches a known-safe prefix
    foreach ($safePath in $knownSafePaths) {
        if ($fPath -like "$safePath*") {
            $f.Severity = 'Yellow'
            $downgradeCount++
            break
        }
    }
    if ($f.Severity -eq 'Red') {
        # Also downgrade if path is individually whitelisted
        foreach ($wlPath in $whitelistedPaths) {
            if ($fPath -ieq $wlPath) {
                $f.Severity = 'Yellow'
                $downgradeCount++
                break
            }
        }
    }
}
if ($downgradeCount -gt 0) {
    Write-Host "  [i] $downgradeCount finding(s) downgraded to YELLOW (matched known-safe/whitelisted paths)." -ForegroundColor DarkGray
}
#endregion

#region -- Risk Score & Scan Summary -----------------------------------------
$redTotal    = @($allFindings | Where-Object { $_.Severity -eq 'Red'    }).Count
$yellowTotal = @($allFindings | Where-Object { $_.Severity -eq 'Yellow' }).Count
$greenTotal  = @($allFindings | Where-Object { $_.Severity -eq 'Green'  }).Count

$riskScore = if (Get-Command 'Get-RiskScore' -ErrorAction SilentlyContinue) { Get-RiskScore -Findings $allFindings } else { 0 }
$riskInfo  = if (Get-Command 'Get-RiskLevel' -ErrorAction SilentlyContinue) { Get-RiskLevel -Score $riskScore } else { [PSCustomObject]@{Level='N/A';Color='';ConsoleColor='Gray'} }

$newSW   = @($allFindings | Where-Object {$_.Module -eq 'Baseline' -and $_.Category -match 'Software' -and $_.Title -match 'NEW'} | ForEach-Object { $_.Title })
$newSvc  = @($allFindings | Where-Object {$_.Module -eq 'Baseline' -and $_.Category -match 'Service'  -and $_.Title -match 'NEW'} | ForEach-Object { $_.Title })
$newUsr  = @($allFindings | Where-Object {$_.Module -eq 'Baseline' -and $_.Category -match 'User'     -and $_.Title -match 'NEW'} | ForEach-Object { $_.Title })
$vulnCnt  = @($allFindings | Where-Object {$_.Module -eq 'VulnCheck'}).Count
$patchCnt = @($allFindings | Where-Object {$_.Module -eq 'VulnCheck' -and $_.Category -match 'Patch'}).Count
$quarCnt  = @($allFindings | Where-Object {$_.ActionTaken -match 'Quarantine'}).Count
$mitreTechniques = @($allFindings | Where-Object {$_.MitreId -and $_.MitreId.Trim()} | Select-Object -ExpandProperty MitreId -Unique)

$summary = [PSCustomObject]@{
    timestamp         = (Get-Date -Format 'o')
    hostname          = $env:COMPUTERNAME
    riskScore         = $riskScore
    riskLevel         = $riskInfo.Level
    findings          = [PSCustomObject]@{ red=$redTotal; yellow=$yellowTotal; green=$greenTotal; total=$allFindings.Count }
    mitreTechniques   = $mitreTechniques
    newSoftware       = $newSW
    newServices       = $newSvc
    newUsers          = $newUsr
    quarantineActions = $quarCnt
    cvesFound         = $vulnCnt
    patchesMissing    = $patchCnt
}
$summaryFile = Join-Path $ReportPath "scan_$(Get-Date -Format 'yyyyMMdd_HHmmss')_summary.json"
try { $summary | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryFile -Encoding UTF8 } catch {}

Write-Host "  Risk Score : $riskScore/100 [$($riskInfo.Level)]" -ForegroundColor $riskInfo.ConsoleColor
Write-Host "  Findings   : RED=$redTotal  YELLOW=$yellowTotal  GREEN=$greenTotal" -ForegroundColor White
Write-Host ""
#endregion

#region -- Response phase -----------------------------------------------------
if (-not $ScanOnly) {
    $redFindings = @($allFindings | Where-Object { $_.Severity -eq 'Red' })

    if ($redFindings.Count -gt 0) {
        Write-Host "--- Response Phase ----------------------------------" -ForegroundColor DarkGray
        Write-Host "  [!] $($redFindings.Count) RED threat(s) detected:" -ForegroundColor Red
        foreach ($f in $redFindings) {
            Write-Host "      [$($f.Module)] $($f.Title)" -ForegroundColor Red
            Write-Host "        $($f.Detail)" -ForegroundColor DarkRed
            if ($f.Path) {
                Write-Host "        Path: $($f.Path)" -ForegroundColor DarkGray
            }
        }
        Write-Host ""

        if ($AutoQuarantine) {
            # ── Bulk auto-quarantine flow (existing) ──────────────────────────
            $quarantineCandidates = @($redFindings | Where-Object { $_.Path -and (Test-Path $_.Path -PathType Leaf -ErrorAction SilentlyContinue) })

            if ($quarantineCandidates.Count -eq 0) {
                Write-Host "  [i] No Red findings have quarantinable file paths." -ForegroundColor Gray
            } else {
                Write-Host "  [!] AutoQuarantine: $($quarantineCandidates.Count) file(s) eligible for quarantine." -ForegroundColor Red
                Write-Host "  [!] This will MOVE the files to: $QuarantinePath" -ForegroundColor Yellow
                Write-Host ""
                $confirm = Read-Host "  Are you sure? Type YES to proceed"

                if ($confirm -eq 'YES') {
                    foreach ($finding in $quarantineCandidates) {
                        try {
                            $result = Invoke-QuarantineFile `
                                -FilePath       $finding.Path `
                                -Reason         $finding.Detail `
                                -QuarantinePath $QuarantinePath `
                                -Password       $Settings.Quarantine.Password `
                                -AuditLog       $AuditLog `
                                -Confirmed      # Caller already obtained YES above

                            if ($result) { $finding.ActionTaken = "Quarantined: $QuarantinePath" }
                        } catch {
                            Write-Warning "    Quarantine failed for $($finding.Path): $($_.Exception.Message)"
                            Write-AuditLog -Action 'QuarantineError' -Module 'Orchestrator' -Details $_.Exception.Message -Status 'ERROR'
                        }
                    }
                } else {
                    Write-Host "  Quarantine aborted by user." -ForegroundColor Yellow
                    Write-AuditLog -Action 'QuarantineAborted' -Details 'User declined YES prompt'
                }
            }

        } elseif ($interactiveMode -and (Get-Command 'Invoke-ServiceQuarantineWorkflow' -ErrorAction SilentlyContinue)) {
            # ── Interactive per-finding quarantine workflow ────────────────────
            # System processes that should never be quarantined
            $systemProcNames = @(
                'svchost.exe','lsass.exe','csrss.exe','wininit.exe',
                'services.exe','winlogon.exe','explorer.exe',
                'powershell.exe','cmd.exe'
            )
            # Chromium/Electron apps that generate MemoryInjection false positives
            $chromiumProcNames = @('brave.exe','msedgewebview2.exe','code.exe')

            # Build eligible findings list
            $eligibleFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($f in $allFindings) {
                if ($f.Severity -ne 'Red') { continue }
                $fPath = if ($f.PSObject.Properties['Path']) { [string]$f.Path } else { '' }
                if (-not $fPath -or -not (Test-Path $fPath -PathType Leaf -ErrorAction SilentlyContinue)) { continue }

                $fBaseName = [System.IO.Path]::GetFileName($fPath).ToLowerInvariant()

                # Skip Windows system processes
                if ($systemProcNames -icontains $fBaseName) { continue }

                # Skip MemoryInjection false positives for Chromium/Electron
                $fModule = if ($f.PSObject.Properties['Module']) { $f.Module } else { '' }
                if ($fModule -eq 'MemoryInjection' -and ($chromiumProcNames -icontains $fBaseName)) { continue }

                $eligibleFindings.Add($f)
            }

            if ($eligibleFindings.Count -eq 0) {
                Write-Host "  [i] No actionable Red findings require interactive review." -ForegroundColor Gray
            } else {
                Write-Host "  [i] $($eligibleFindings.Count) finding(s) available for interactive review." -ForegroundColor Yellow
                Write-Host ""

                $skipAll        = $false
                $pendingFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
                $pendingFile    = 'C:\QuietMonitor\Logs\pending_quarantine.json'

                for ($fi = 0; $fi -lt $eligibleFindings.Count; $fi++) {
                    if ($skipAll) {
                        $pendingFindings.Add($eligibleFindings[$fi])
                        continue
                    }

                    Write-Host "  ── Finding $($fi + 1) of $($eligibleFindings.Count) ──────────────────────" -ForegroundColor DarkGray

                    $wfResult = Invoke-ServiceQuarantineWorkflow `
                        -Finding        $eligibleFindings[$fi] `
                        -Password       $Settings.Quarantine.Password `
                        -AuditLog       $AuditLog `
                        -QuarantinePath $QuarantinePath `
                        -WhitelistFile  $WhitelistFile

                    if ($wfResult -eq 'SkipAll') {
                        $skipAll = $true
                        $pendingFindings.Add($eligibleFindings[$fi])   # include the skipped finding itself
                        # remaining added by the $skipAll guard above on next iterations
                    }
                }

                # Persist or clear pending findings
                if ($pendingFindings.Count -gt 0) {
                    try {
                        $pendingFindings.ToArray() | ConvertTo-Json -Depth 5 |
                            Set-Content -Path $pendingFile -Encoding UTF8 -Force
                        Write-Host ""
                        Write-Host "  [i] $($pendingFindings.Count) finding(s) saved to pending review." -ForegroundColor DarkGray
                        Write-Host "      Review them from the QuietMonitor menu: [3] Quarantine Manager -> [R]" -ForegroundColor DarkGray
                    } catch {
                        Write-Warning "  Could not save pending quarantine file: $($_.Exception.Message)"
                    }
                } else {
                    if (Test-Path 'C:\QuietMonitor\Logs\pending_quarantine.json') {
                        try { Remove-Item 'C:\QuietMonitor\Logs\pending_quarantine.json' -Force -ErrorAction SilentlyContinue } catch {}
                    }
                }
            }

        } else {
            Write-Host "  [i] Use -AutoQuarantine flag to quarantine Red findings." -ForegroundColor Gray
            Write-Host "  [i] To quarantine manually, run:" -ForegroundColor Gray
            Write-Host "      . .\Modules\Quarantine.ps1" -ForegroundColor DarkGray
            Write-Host "      Invoke-QuarantineFile -FilePath '<path>' -Reason '<reason>' ..." -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # -- Alerts ----------------------------------------------------------------
    $alertFindings = @($allFindings | Where-Object { $_.Severity -in 'Red', 'Yellow' })
    if ($alertFindings.Count -gt 0) {
        Write-Host "--- Alerting ----------------------------------------" -ForegroundColor DarkGray
        Write-Host "  [*] Sending alerts ($($alertFindings.Count) finding(s))..." -ForegroundColor Yellow
        if (Get-Command 'Send-SecurityAlert' -ErrorAction SilentlyContinue) {
            try {
                Send-SecurityAlert -Findings $alertFindings -Settings $Settings -AuditLog $AuditLog
            } catch {
                Write-Warning "  Alert module error: $($_.Exception.Message)"
                Write-AuditLog -Action 'AlertError' -Details $_.Exception.Message -Status 'ERROR'
            }
        } else {
            Write-Warning "  Alert module not loaded - skipping."
        }
        Write-Host ""
    }
}
#endregion

#region -- Report phase -------------------------------------------------------
$shouldReport = $FullReport -or ($allFindings | Where-Object { $_.Severity -in 'Red','Yellow' }).Count -gt 0

if ($shouldReport) {
    Write-Host "--- Report ------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [*] Generating HTML report..." -ForegroundColor Yellow

    if (Get-Command 'New-SecurityReport' -ErrorAction SilentlyContinue) {
        try {
            $reportFile = New-SecurityReport -Findings $allFindings -ReportPath $ReportPath -AuditLog $AuditLog
            Write-Host "  [+] Report saved: $reportFile" -ForegroundColor Green
        } catch {
            Write-Warning "  Report generation failed: $($_.Exception.Message)"
            Write-AuditLog -Action 'ReportError' -Details $_.Exception.Message -Status 'ERROR'
        }
    } else {
        Write-Warning "  Report module not loaded - skipping."
    }
    Write-Host ""
}
#endregion

#region -- Summary ------------------------------------------------------------
$redTotal    = @($allFindings | Where-Object { $_.Severity -eq 'Red'    }).Count
$yellowTotal = @($allFindings | Where-Object { $_.Severity -eq 'Yellow' }).Count
$greenTotal  = @($allFindings | Where-Object { $_.Severity -eq 'Green'  }).Count

Write-Host "--- Scan Summary ------------------------------------" -ForegroundColor DarkGray
Write-Host "  Threats (RED)     : $redTotal"    -ForegroundColor $(if ($redTotal -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Suspicious (YELLOW): $yellowTotal" -ForegroundColor $(if ($yellowTotal -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Clean (GREEN)     : $greenTotal"   -ForegroundColor Green
Write-Host "  Total findings    : $($allFindings.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  Audit log : $AuditLog" -ForegroundColor Gray
Write-Host "  Reports   : $ReportPath" -ForegroundColor Gray
if ($shouldReport -and (Get-Variable 'reportFile' -ErrorAction SilentlyContinue)) {
    Write-Host "  Report    : $reportFile" -ForegroundColor Gray
}
Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-AuditLog -Action 'SuiteComplete' -Details "RED=$redTotal YELLOW=$yellowTotal GREEN=$greenTotal TOTAL=$($allFindings.Count)"
#endregion

#region -- JSON export for WebUI ----------------------------------------------
$scanEndTime     = Get-Date
$scanDurationSec = [int]($scanEndTime - $suiteStartTime).TotalSeconds
$latestScanPath  = Join-Path $ReportPath 'latest_scan.json'
$scanHistoryPath = Join-Path $ReportPath 'scan_history.json'

$latestScan = [PSCustomObject]@{
    timestamp     = $scanEndTime.ToString('yyyy-MM-ddTHH:mm:ss')
    riskScore     = $riskScore
    riskLevel     = $riskInfo.Level
    scanDuration  = $scanDurationSec
    serviceStatus = 'RUNNING'
    summary       = [PSCustomObject]@{
        red    = $redTotal
        yellow = $yellowTotal
        green  = $greenTotal
        total  = $allFindings.Count
    }
    findings = @($allFindings | ForEach-Object {
        [PSCustomObject]@{
            severity    = $_.Severity
            module      = $_.Module
            category    = $_.Category
            title       = $_.Title
            detail      = $_.Detail
            path        = $_.Path
            mitreId     = $_.MitreId
            mitreName   = $_.MitreName
            actionTaken = $_.ActionTaken
        }
    })
}

try {
    $latestScan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $latestScanPath -Encoding UTF8
    Write-Host "  [+] JSON export   : $latestScanPath" -ForegroundColor Cyan
} catch {
    Write-Warning "  JSON export failed: $($_.Exception.Message)"
}

$historySummary = [PSCustomObject]@{
    timestamp = $latestScan.timestamp
    riskScore = $riskScore
    red       = $redTotal
    yellow    = $yellowTotal
    green     = $greenTotal
}
try {
    $history = @()
    if (Test-Path $scanHistoryPath) {
        $history = @(Get-Content $scanHistoryPath -Raw | ConvertFrom-Json)
    }
    $history += $historySummary
    if ($history.Count -gt 30) { $history = $history[-30..-1] }
    $history | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $scanHistoryPath -Encoding UTF8
    Write-Host "  [+] Scan history  : $scanHistoryPath" -ForegroundColor Cyan
} catch {
    Write-Warning "  Scan history update failed: $($_.Exception.Message)"
}
Write-AuditLog -Action 'JSONExport' -Details "latest_scan.json written. History entries: $($history.Count)"
#endregion

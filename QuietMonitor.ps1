<#
.SYNOPSIS
    QuietMonitor.ps1 - Interactive entry point for the QuietMonitor Security Suite.
.DESCRIPTION
    Single-file interactive console menu for all QuietMonitor operations.
    Auto-elevates to Administrator if not already running elevated.

    Menu options:
      [1] Run full security scan (all modules, generate HTML report)
      [2] Open last HTML report in browser
      [3] Quarantine Manager (list / restore / delete files)
      [4] Live audit log tail
      [5] Whitelist editor (add/remove entries per module)
      [6] Settings editor (SMTP, scan interval, webhook)
      [7] Service management (install / start / stop / uninstall)
      [8] Quick scan (no report file generated)
      [9] Export forensic IR package (ZIP)
      [0] Exit
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# Auto-elevate
# ============================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argStr = "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argStr
    exit
}

# ============================================================
# Paths
# ============================================================
$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$baseDir     = 'C:\QuietMonitor'
$modulesDir  = Join-Path $scriptDir 'Modules'
$configDir   = Join-Path $scriptDir 'Config'
$logsDir     = Join-Path $baseDir 'Logs'
$reportsDir  = Join-Path $baseDir 'Reports'
$quarantineDir = Join-Path $baseDir 'Quarantine'
$toolsDir    = Join-Path $baseDir 'Tools'
$auditLog    = Join-Path $logsDir 'audit.log'
$serviceStdoutLog = Join-Path $logsDir 'service_stdout.log'
$serviceStderrLog = Join-Path $logsDir 'service_stderr.log'
$nssmPath    = Join-Path $toolsDir 'nssm.exe'
$whitelistFile = Join-Path $configDir 'whitelist.json'
$settingsFile  = Join-Path $configDir 'settings.json'
$quarManifest  = Join-Path $quarantineDir 'quarantine_manifest.json'
$baselineDir   = Join-Path $baseDir 'Baseline'
$scanSummaryPattern = Join-Path $reportsDir 'scan_*_summary.json'
$tamperLog     = Join-Path $logsDir 'tamper.log'
$suiteScript   = Join-Path $scriptDir 'Run-SecuritySuite.ps1'
$installScript = Join-Path $scriptDir 'Install-QuietMonitor.ps1'
$ServiceName   = 'QuietMonitorSvc'

foreach ($dir in $logsDir, $reportsDir, $quarantineDir) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# ============================================================
# UI Helpers
# ============================================================
function Write-Header {
    param([string]$title = '')
    Clear-Host
    Write-Host ('=' * 60) -ForegroundColor DarkCyan
    Write-Host "  QuietMonitor Security Suite" -ForegroundColor Cyan
    if ($title) { Write-Host "  $title" -ForegroundColor White }
    Write-Host ('=' * 60) -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Status ([string]$msg, [string]$color = 'White') {
    Write-Host "  $msg" -ForegroundColor $color
}

function Read-MenuChoice ([string]$prompt = "Choice") {
    Write-Host ""
    Write-Host "  $prompt" -NoNewline -ForegroundColor Yellow
    Write-Host " > " -NoNewline
    return (Read-Host).Trim()
}

function Pause-ForKey ([string]$msg = "Press ENTER to return to menu") {
    Write-Host ""
    Write-Host "  $msg" -ForegroundColor DarkGray
    $null = Read-Host
}

function Invoke-NssmCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$IgnoreExitCode
    )

    if (-not (Test-Path $nssmPath)) {
        throw "nssm.exe missing: place file at '$nssmPath'."
    }

    $output = & $nssmPath @Arguments 2>&1
    if (-not $IgnoreExitCode -and $LASTEXITCODE -ne 0) {
        throw "NSSM command failed (exit $LASTEXITCODE): nssm $($Arguments -join ' ')`n$output"
    }
    return $output
}

function Get-NssmServiceUiStatus {
    if (-not (Test-Path $nssmPath)) {
        return [PSCustomObject]@{ Label = 'NOT INSTALLED'; Color = 'DarkGray' }
    }

    try {
        $statusRaw = (Invoke-NssmCommand -Arguments @('status', $ServiceName) -IgnoreExitCode | Out-String).Trim().ToUpperInvariant()
    } catch {
        return [PSCustomObject]@{ Label = 'NOT INSTALLED'; Color = 'DarkGray' }
    }

    if ($statusRaw -match 'SERVICE_RUNNING') {
        return [PSCustomObject]@{ Label = 'RUNNING'; Color = 'Green' }
    }
    if ($statusRaw -match 'SERVICE_STOPPED') {
        return [PSCustomObject]@{ Label = 'STOPPED'; Color = 'Yellow' }
    }

    return [PSCustomObject]@{ Label = 'NOT INSTALLED'; Color = 'DarkGray' }
}

# ============================================================
# Helper: Get latest HTML report
# ============================================================
function Get-LatestReport {
    if (-not (Test-Path $reportsDir)) { return $null }
    return Get-ChildItem $reportsDir -Filter '*.html' -File |
           Sort-Object LastWriteTime -Descending |
           Select-Object -First 1
}

# ============================================================
# Helper: Load/Save JSON config safely
# ============================================================
function Get-JsonConfig ([string]$path, [hashtable]$defaults) {
    if (Test-Path $path) {
        try { return Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch {}
    }
    return [PSCustomObject]$defaults
}

# ============================================================
# Option 1: Full scan
# ============================================================
function Invoke-FullScan {
    Write-Header "Full Security Scan"
    if (-not (Test-Path $suiteScript)) {
        Write-Status "ERROR: Run-SecuritySuite.ps1 not found at $suiteScript" 'Red'
        Pause-ForKey; return
    }
    Write-Status "Launching full scan with HTML report generation..." 'Cyan'
    Write-Status "This may take several minutes. Press Ctrl+C to abort." 'DarkGray'
    Write-Host ""
    & $suiteScript -FullReport
    Write-Host ""
    $latest = Get-LatestReport
    if ($latest) {
        Write-Status "Report saved: $($latest.FullName)" 'Green'
    }
    Pause-ForKey
}

# ============================================================
# Option 2: Open last report
# ============================================================
function Open-LastReport {
    Write-Header "Open Last Report"
    $latest = Get-LatestReport
    if (-not $latest) {
        Write-Status "No HTML reports found in $reportsDir" 'Yellow'
        Write-Status "Run option [1] to generate one first." 'DarkGray'
    } else {
        Write-Status "Opening: $($latest.FullName)" 'Cyan'
        Start-Process $latest.FullName
    }
    Pause-ForKey
}

# ============================================================
# Option 3: Quarantine Manager
# ============================================================
function Show-QuarantineManager {
    Write-Header "Quarantine Manager"

    if (-not (Test-Path $quarManifest)) {
        Write-Status "No quarantine manifest found. Quarantine is empty." 'DarkGray'
        Pause-ForKey; return
    }

    try {
        $manifest = Get-Content $quarManifest -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Status "Failed to parse quarantine manifest: $_" 'Red'
        Pause-ForKey; return
    }

    $entries = @($manifest | Where-Object { -not $_.Removed })
    if ($entries.Count -eq 0) {
        Write-Status "Quarantine is empty (all files removed or none quarantined)." 'DarkGray'
        Pause-ForKey; return
    }

    Write-Status "Quarantined files ($($entries.Count)):" 'White'
    Write-Host ""

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $e = $entries[$i]
        $sev = if ($e.Severity) { $e.Severity } else { '?' }
        $color = switch ($sev) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'White' } }
        Write-Host "  [$($i+1)] " -NoNewline -ForegroundColor DarkCyan
        Write-Host "$($e.OriginalPath)" -NoNewline -ForegroundColor $color
        Write-Host " | $($e.Timestamp) | SHA256: $($e.SHA256.Substring(0,12))..." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  [R] Restore a file    [D] Delete permanently    [B] Back" -ForegroundColor DarkCyan
    $sub = Read-MenuChoice "Action"

    switch ($sub.ToUpperInvariant()) {
        'R' {
            $idxStr = Read-MenuChoice "Enter number of file to restore (1-$($entries.Count))"
            if ($idxStr -match '^\d+$') {
                $idx = [int]$idxStr - 1
                if ($idx -ge 0 -and $idx -lt $entries.Count) {
                    $entry = $entries[$idx]
                    # Dot-source Quarantine.ps1 to access Invoke-QuarantineRestore
                    $quarScript = Join-Path $modulesDir 'Quarantine.ps1'
                    if (Test-Path $quarScript) {
                        . $quarScript
                        # Read quarantine password from settings
                        $qCfg = $null
                        if (Test-Path $settingsFile) {
                            try { $qCfg = Get-Content $settingsFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
                        }
                        $qPwd = if ($qCfg -and $qCfg.Quarantine -and $qCfg.Quarantine.Password) { $qCfg.Quarantine.Password } else { '' }
                        $restoreDir = Read-MenuChoice "Enter restore directory path (blank = Temp folder)"
                        if (-not $restoreDir) { $restoreDir = [System.IO.Path]::GetTempPath() }
                        try {
                            Invoke-QuarantineRestore -ManifestEntry $entry -Password $qPwd -RestorePath $restoreDir -AuditLog $auditLog
                            Write-Status "Restored to: $restoreDir" 'Green'
                        } catch {
                            Write-Status "Restore failed: $_" 'Red'
                        }
                    } else {
                        Write-Status "Quarantine.ps1 not found." 'Red'
                    }
                }
            }
            Pause-ForKey
        }
        'D' {
            $idxStr = Read-MenuChoice "Enter number of file to permanently delete (1-$($entries.Count))"
            if ($idxStr -match '^\d+$') {
                $idx = [int]$idxStr - 1
                if ($idx -ge 0 -and $idx -lt $entries.Count) {
                    $entry = $entries[$idx]
                    $confirm = Read-MenuChoice "Type YES to permanently delete '$($entry.OriginalPath)'"
                    if ($confirm -eq 'YES') {
                        Remove-Item $entry.EncryptedFile -Force -ErrorAction SilentlyContinue
                        # Mark removed in manifest
                        $raw = Get-Content $quarManifest -Raw -Encoding UTF8 | ConvertFrom-Json
                        foreach ($item in $raw) {
                            if ($item.EncryptedFile -eq $entry.EncryptedFile) { $item.Removed = $true }
                        }
                        $raw | ConvertTo-Json -Depth 10 | Set-Content $quarManifest -Encoding UTF8
                        Write-Status "Permanently deleted." 'Red'
                    } else {
                        Write-Status "Cancelled." 'DarkGray'
                    }
                    Pause-ForKey
                }
            }
        }
    }
}

# ============================================================
# Option 4: Audit log tail
# ============================================================
function Show-AuditLogTail {
    Write-Header "Live Audit Log"
    Write-Host "  [1] audit.log" -ForegroundColor White
    Write-Host "  [2] service_stdout.log" -ForegroundColor White
    Write-Host "  [3] service_stderr.log" -ForegroundColor White
    Write-Host "  [B] Back" -ForegroundColor DarkCyan

    $sub = Read-MenuChoice "Action"
    if ($sub.ToUpperInvariant() -eq 'B') { return }

    $selectedPath = switch ($sub) {
        '1' { $auditLog }
        '2' { $serviceStdoutLog }
        '3' { $serviceStderrLog }
        default { $null }
    }

    if (-not $selectedPath) {
        Write-Status "Invalid choice." 'Red'
        Pause-ForKey; return
    }

    if (-not (Test-Path $selectedPath)) {
        Write-Status "Log not found: $selectedPath" 'Yellow'
        Pause-ForKey; return
    }

    Write-Status "Showing last 40 lines. Press Ctrl+C to stop." 'DarkGray'
    Write-Host ""
    Get-Content $selectedPath -Tail 40 | ForEach-Object {
        $color = if ($_ -match '\[ACTION: (Quarantine|LsassAccess|RemoteServiceInstall|NewExternalIPs)') { 'Red' }
                 elseif ($_ -match '\[ACTION: ') { 'Yellow' }
                 else { 'DarkGray' }
        Write-Host "  $_" -ForegroundColor $color
    }
    Pause-ForKey
}

# ============================================================
# Option 5: Whitelist editor
# ============================================================
function Edit-Whitelist {
    Write-Header "Whitelist Editor"

    $wl = Get-JsonConfig $whitelistFile @{}
    $props = @($wl.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })

    if ($props.Count -eq 0) {
        Write-Status "Whitelist is empty or not found." 'DarkGray'
    } else {
        Write-Status "Current whitelist entries:" 'White'
        Write-Host ""
        foreach ($p in $props) {
            Write-Host "  [$($p.Name)]" -ForegroundColor DarkCyan
            if ($p.Value -is [System.Array] -or $p.Value -is [System.Collections.IEnumerable] -and $p.Value -isnot [string]) {
                foreach ($item in $p.Value) { Write-Host "    - $item" -ForegroundColor White }
            } else {
                Write-Host "    $($p.Value)" -ForegroundColor White
            }
        }
    }

    Write-Host ""
    Write-Host "  [A] Add entry    [R] Remove entry    [B] Back" -ForegroundColor DarkCyan
    $sub = Read-MenuChoice "Action"

    switch ($sub.ToUpperInvariant()) {
        'A' {
            $module = Read-MenuChoice "Module name (e.g. ProcessAudit, IOCScanner)"
            $value  = Read-MenuChoice "Value to whitelist"
            if ($module -and $value) {
                if (-not $wl.PSObject.Properties[$module]) {
                    $wl | Add-Member -MemberType NoteProperty -Name $module -Value @() -Force
                }
                $arr = @($wl.$module) + $value
                $wl.$module = $arr
                $wl | ConvertTo-Json -Depth 5 | Set-Content $whitelistFile -Encoding UTF8
                Write-Status "Added '$value' to module '$module' whitelist." 'Green'
            }
            Pause-ForKey
        }
        'R' {
            $module = Read-MenuChoice "Module name"
            $value  = Read-MenuChoice "Value to remove"
            if ($module -and $value -and $wl.PSObject.Properties[$module]) {
                $wl.$module = @($wl.$module | Where-Object { $_ -ne $value })
                $wl | ConvertTo-Json -Depth 5 | Set-Content $whitelistFile -Encoding UTF8
                Write-Status "Removed '$value' from module '$module' whitelist." 'Yellow'
            }
            Pause-ForKey
        }
    }
}

# ============================================================
# Option 6: Settings editor
# ============================================================
function Edit-Settings {
    Write-Header "Settings Editor"

    $defaults = @{
        ScanIntervalMinutes  = 15
        SmtpServer           = ''
        SmtpPort             = 587
        SmtpFrom             = ''
        SmtpTo               = ''
        SmtpUsername         = ''
        SmtpPassword         = ''
        WebhookUrl           = ''
        AlertOnSeverity      = 'Red'
    }
    $settings = Get-JsonConfig $settingsFile $defaults

    Write-Status "Current settings:" 'White'
    Write-Host ""
    $settings.PSObject.Properties | ForEach-Object {
        $displayVal = if ($_.Name -match '[Pp]assword') { '****' } else { $_.Value }
        Write-Host ("  {0,-25} {1}" -f ($_.Name + ':'), $displayVal) -ForegroundColor White
    }

    Write-Host ""
    $key = Read-MenuChoice "Enter setting name to change (or ENTER to cancel)"
    if ($key) {
        $val = Read-MenuChoice "Enter new value for '$key'"
        if ($settings.PSObject.Properties[$key]) {
            # Try numeric conversion
            if ($val -match '^\d+$') {
                $settings.$key = [int]$val
            } else {
                $settings.$key = $val
            }
        } else {
            $settings | Add-Member -MemberType NoteProperty -Name $key -Value $val -Force
        }
        $settings | ConvertTo-Json -Depth 5 | Set-Content $settingsFile -Encoding UTF8
        Write-Status "Setting '$key' updated." 'Green'
        Pause-ForKey
    }
}

# ============================================================
# Option 7: Service management
# ============================================================
function Show-ServiceManager {
    Write-Header "Service Management"

    if (-not (Test-Path $nssmPath)) {
        Write-Status "NSSM missing. Place nssm.exe at: $nssmPath" 'Red'
        Write-Host ""
        Write-Host "  [I] Install Service   [B] Back" -ForegroundColor DarkCyan

        $sub = Read-MenuChoice "Action"
        if ($sub.ToUpperInvariant() -eq 'I') {
            if (Test-Path $installScript) {
                . $installScript
                try { Install-QuietMonitorService -StartNow }
                catch { Write-Status "Install failed: $($_.Exception.Message)" 'Red' }
            } else {
                Write-Status "Install-QuietMonitor.ps1 not found at $installScript" 'Red'
            }
            Pause-ForKey
        }
        return
    }

    $statusObj = Get-NssmServiceUiStatus

    if ($statusObj.Label -ne 'NOT INSTALLED') {
        Write-Status "Service: $ServiceName" 'White'
        Write-Status "Status : $($statusObj.Label)" $statusObj.Color

        $hbFile = Join-Path $logsDir 'service_heartbeat.txt'
        if (Test-Path $hbFile) {
            $hb = Get-Content $hbFile -Raw
            Write-Status "Heartbeat: $hb" 'DarkGray'
        }
        Write-Host ""
        Write-Host "  [S] Start   [T] Stop   [R] Restart   [U] Uninstall   [B] Back" -ForegroundColor DarkCyan
    } else {
        Write-Status "Service '$ServiceName' is NOT installed." 'Yellow'
        Write-Host ""
        Write-Host "  [I] Install Service   [B] Back" -ForegroundColor DarkCyan
    }

    $sub = Read-MenuChoice "Action"

    switch ($sub.ToUpperInvariant()) {
        'I' {
            if (Test-Path $installScript) {
                . $installScript
                Install-QuietMonitorService -StartNow
            } else {
                Write-Status "Install-QuietMonitor.ps1 not found at $installScript" 'Red'
            }
            Pause-ForKey
        }
        'S' {
            try { Invoke-NssmCommand -Arguments @('start', $ServiceName) | Out-Null; Write-Status "Started." 'Green' }
            catch { Write-Status "Failed: $($_.Exception.Message)" 'Red' }
            Pause-ForKey
        }
        'T' {
            try { Invoke-NssmCommand -Arguments @('stop', $ServiceName) | Out-Null; Write-Status "Stopped." 'Yellow' }
            catch { Write-Status "Failed: $($_.Exception.Message)" 'Red' }
            Pause-ForKey
        }
        'R' {
            try { Invoke-NssmCommand -Arguments @('restart', $ServiceName) | Out-Null; Write-Status "Restarted." 'Green' }
            catch { Write-Status "Failed: $($_.Exception.Message)" 'Red' }
            Pause-ForKey
        }
        'U' {
            $confirm = Read-MenuChoice "Type YES to uninstall service"
            if ($confirm -eq 'YES') {
                if (Test-Path $installScript) {
                    . $installScript
                    Uninstall-QuietMonitorService
                    Write-Status "Uninstalled." 'Yellow'
                } else {
                    Write-Status "Install script not found." 'Red'
                }
            } else {
                Write-Status "Cancelled." 'DarkGray'
            }
            Pause-ForKey
        }
    }
}

# ============================================================
# Option 8: Quick scan (no report)
# ============================================================
function Invoke-QuickScan {
    Write-Header "Quick Scan"
    if (-not (Test-Path $suiteScript)) {
        Write-Status "ERROR: Run-SecuritySuite.ps1 not found." 'Red'
        Pause-ForKey; return
    }
    Write-Status "Running quick scan (scan only, no HTML report)..." 'Cyan'
    Write-Host ""
    & $suiteScript -ScanOnly
    Pause-ForKey
}

# ============================================================
# Option 9: Forensic package export
# ============================================================
function Export-ForensicsMenu {
    Write-Header "Forensic IR Package Export"
    Write-Status "This will create a ZIP containing:" 'White'
    Write-Status "  - All logs, reports, quarantine manifest" 'DarkGray'
    Write-Status "  - Live process snapshot with parent-child tree" 'DarkGray'
    Write-Status "  - Active network connections snapshot" 'DarkGray'
    Write-Status "  - Running services list" 'DarkGray'
    Write-Status "  - System info" 'DarkGray'
    Write-Host ""

    $confirm = Read-MenuChoice "Press ENTER to proceed or type NO to cancel"
    if ($confirm.ToUpperInvariant() -eq 'NO') { return }

    $forensicScript = Join-Path $modulesDir 'ForensicCapture.ps1'
    if (-not (Test-Path $forensicScript)) {
        Write-Status "ForensicCapture.ps1 not found at $forensicScript" 'Red'
        Pause-ForKey; return
    }

    . $forensicScript
    Write-Status "Capturing forensic data..." 'Cyan'

    try {
        $zipPath = Export-ForensicPackage -AuditLog $auditLog
        Write-Status "Forensic package saved:" 'Green'
        Write-Status $zipPath 'White'
    } catch {
        Write-Status "Export failed: $_" 'Red'
    }

    Pause-ForKey
}

# ============================================================
# New option functions (menu items 10-15)
# ============================================================
function Invoke-RebuildBaseline {
    Write-Header 'Rebuild System Baseline'
    Write-Status 'This will capture the current system state as the new security baseline.' 'Yellow'
    Write-Status 'Future scans will compare against this snapshot to detect drift.' 'White'
    $confirm = Read-MenuChoice "Type YES to rebuild baseline or ENTER to cancel"
    if ($confirm -ne 'YES') { Write-Status 'Cancelled.' 'DarkGray'; Pause-ForKey; return }

    $blModule = Join-Path $modulesDir 'Baseline.ps1'
    if (-not (Test-Path $blModule)) { Write-Status "Baseline.ps1 not found." 'Red'; Pause-ForKey; return }
    . $blModule
    try {
        $wl = if (Test-Path $whitelistFile) { Get-Content $whitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json } else { [PSCustomObject]@{} }
        $cfg = if (Test-Path $settingsFile)  { Get-Content $settingsFile  -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
        New-SystemBaseline -BaselinePath (Join-Path $baselineDir 'baseline.json') -AuditLog $auditLog -Settings $cfg
        Write-Status 'Baseline captured successfully.' 'Green'
    } catch { Write-Status "Error: $_" 'Red' }
    Pause-ForKey
}

function Show-VulnReport {
    Write-Header 'Vulnerability Report'
    $vcModule = Join-Path $modulesDir 'VulnCheck.ps1'
    if (-not (Test-Path $vcModule)) { Write-Status "VulnCheck.ps1 not found." 'Red'; Pause-ForKey; return }
    . $vcModule
    $wl = if (Test-Path $whitelistFile) { Get-Content $whitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json } else { [PSCustomObject]@{} }
    Write-Status 'Running vulnerability check...' 'Cyan'
    try {
        $results = Invoke-VulnCheck -Whitelist $wl -AuditLog $auditLog
        Write-Host ''
        foreach ($r in $results) {
            $col = switch ($r.Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Green' } }
            Write-Host "  [$($r.Severity.ToUpper())] $($r.DisplayName)" -ForegroundColor $col
            if ($r.Details) { Write-Host "         $($r.Details)" -ForegroundColor DarkGray }
        }
        Write-Host ''
        $rCnt = @($results | Where-Object {$_.Severity -eq 'Red'}).Count
        $yCnt = @($results | Where-Object {$_.Severity -eq 'Yellow'}).Count
        Write-Status "Total: RED=$rCnt  YELLOW=$yCnt  CLEAN=$(@($results | Where-Object {$_.Severity -eq 'Green'}).Count)" 'Cyan'
    } catch { Write-Status "Error: $_" 'Red' }
    Pause-ForKey
}

function Show-ThreatIntelCheck {
    Write-Header 'Threat Intelligence Check'
    $tiModule = Join-Path $modulesDir 'ThreatIntel.ps1'
    if (-not (Test-Path $tiModule)) { Write-Status "ThreatIntel.ps1 not found." 'Red'; Pause-ForKey; return }
    . $tiModule
    $wl = if (Test-Path $whitelistFile) { Get-Content $whitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json } else { [PSCustomObject]@{} }
    Write-Status 'Running threat intelligence check (may take a moment if APIs are enabled)...' 'Cyan'
    try {
        $results = Invoke-ThreatIntelCheck -Whitelist $wl -AuditLog $auditLog
        Write-Host ''
        foreach ($r in $results) {
            $col = switch ($r.Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Green' } }
            Write-Host "  [$($r.Severity.ToUpper())] $($r.DisplayName)" -ForegroundColor $col
            if ($r.Details) { Write-Host "         $($r.Details)" -ForegroundColor DarkGray }
        }
    } catch { Write-Status "Error: $_" 'Red' }
    Pause-ForKey
}

function Invoke-WeeklyReportNow {
    Write-Header 'Generate Weekly Report'
    $wrModule = Join-Path $modulesDir 'WeeklyReport.ps1'
    if (-not (Test-Path $wrModule)) { Write-Status "WeeklyReport.ps1 not found." 'Red'; Pause-ForKey; return }
    . $wrModule
    Write-Status 'Generating weekly HTML security report...' 'Cyan'
    try {
        $outPath = New-WeeklyReport -ReportPath $reportsDir -AuditLog $auditLog -SettingsFile $settingsFile
        Write-Status "Report saved: $outPath" 'Green'
        $open = Read-MenuChoice "Open in browser? [Y/N]"
        if ($open -match '^[Yy]') {
            try { Start-Process $outPath } catch { Write-Status "Could not open browser." 'Yellow' }
        }
    } catch { Write-Status "Error generating report: $_" 'Red' }
    Pause-ForKey
}

function Show-UBADashboard {
    Write-Header 'User Behavior Analytics Dashboard'
    $ubaModule = Join-Path $modulesDir 'UBA.ps1'
    if (-not (Test-Path $ubaModule)) { Write-Status "UBA.ps1 not found." 'Red'; Pause-ForKey; return }
    . $ubaModule
    $wl = if (Test-Path $whitelistFile) { Get-Content $whitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json } else { [PSCustomObject]@{} }
    Write-Status 'Analyzing user behavior events (last 24h)...' 'Cyan'
    try {
        $results = Invoke-UBAAnalysis -Whitelist $wl -AuditLog $auditLog
        Write-Host ''
        foreach ($r in $results) {
            $col = switch ($r.Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Green' } }
            Write-Host "  [$($r.Severity.ToUpper())] $($r.DisplayName)" -ForegroundColor $col
            if ($r.Details) { Write-Host "         $($r.Details)" -ForegroundColor DarkGray }
        }
        Write-Host ''
        $rCnt = @($results | Where-Object {$_.Severity -eq 'Red'}).Count
        $yCnt = @($results | Where-Object {$_.Severity -eq 'Yellow'}).Count
        Write-Status "Total: RED=$rCnt  YELLOW=$yCnt  CLEAN=$(@($results | Where-Object {$_.Severity -eq 'Green'}).Count)" 'Cyan'
    } catch { Write-Status "Error: $_" 'Red' }
    Pause-ForKey
}

function Show-RansomwareGuardStatus {
    Write-Header 'Ransomware Guard'
    $rgModule = Join-Path $modulesDir 'RansomwareGuard.ps1'
    if (-not (Test-Path $rgModule)) { Write-Status "RansomwareGuard.ps1 not found." 'Red'; Pause-ForKey; return }
    . $rgModule
    $wl = if (Test-Path $whitelistFile) { Get-Content $whitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json } else { [PSCustomObject]@{} }

    # Show current guard status
    $status = Get-RansomwareGuardStatus
    Write-Host ''
    Write-Host '  Guard State:' -ForegroundColor White
    Write-Host "    Enabled        : $($status.Enabled)" -ForegroundColor $(if ($status.Enabled) {'Green'} else {'Red'})
    Write-Host "    Last Check     : $($status.LastCheck)" -ForegroundColor DarkGray
    Write-Host "    Events Detected: $($status.EventsDetected)" -ForegroundColor $(if ($status.EventsDetected -gt 0) {'Red'} else {'Green'})
    Write-Host "    Honeypot Intact: $($status.HoneypotIntact)" -ForegroundColor $(if ($status.HoneypotIntact) {'Green'} else {'Yellow'})
    Write-Host ''

    Write-Host '  Options:' -ForegroundColor White
    Write-Host '  [1] Run scan now' -ForegroundColor White
    Write-Host '  [2] Rebuild honeypot files' -ForegroundColor White
    Write-Host '  [0] Back' -ForegroundColor DarkCyan

    $sub = Read-MenuChoice '[0-2]'
    switch ($sub) {
        '1' {
            Write-Status 'Running ransomware guard scan...' 'Cyan'
            $results = Invoke-RansomwareGuardScan -Whitelist $wl -AuditLog $auditLog
            Write-Host ''
            foreach ($r in $results) {
                $col = switch ($r.Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Green' } }
                Write-Host "  [$($r.Severity.ToUpper())] $($r.DisplayName)" -ForegroundColor $col
                if ($r.Details) { Write-Host "         $($r.Details)" -ForegroundColor DarkGray }
            }
            Pause-ForKey
        }
        '2' {
            $cfg = if (Test-Path $settingsFile) { (Get-Content $settingsFile -Raw -Encoding UTF8 | ConvertFrom-Json).ransomwareGuard } else { $null }
            $n = New-HoneypotFiles -Settings $cfg -AuditLog $auditLog
            Write-Status "Created $n honeypot canary files." 'Green'
            Pause-ForKey
        }
        default { return }
    }
}

# ============================================================
# Anti-tamper / integrity menu functions (items 16-19)
# ============================================================
function Invoke-ManualIntegrityCheck {
    Write-Header 'Integrity Check'
    . (Join-Path $modulesDir 'IntegrityEngine.ps1')
    . (Join-Path $modulesDir 'ProcessIntegrity.ps1')
    Write-Status 'Running file integrity manifest check...' 'Cyan'
    $findings = Invoke-IntegrityCheck -AuditLog $auditLog
    Write-Status 'Running process integrity check...' 'Cyan'
    $findings += Invoke-ProcessIntegrityCheck -AuditLog $auditLog
    foreach ($f in $findings) {
        $col = switch ($f.Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Green' } }
        Write-Host "  [$($f.Severity.ToUpper().PadRight(6))] $($f.DisplayName)" -ForegroundColor $col
        if ($f.Details) { Write-Host "          $($f.Details)" -ForegroundColor DarkGray }
    }
    if ($findings.Count -eq 0) { Write-Status 'All integrity checks passed.' 'Green' }
    Pause-ForKey
}

function Invoke-RMMScan {
    Write-Header 'RMM Detection Scan'
    . (Join-Path $modulesDir 'RMMDetect.ps1')
    $wl = if (Test-Path $whitelistFile) { Get-Content $whitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    $findings = Invoke-RMMDetection -Whitelist $wl -AuditLog $auditLog
    $auth   = @($findings | Where-Object { $_.ActionTaken -eq 'Whitelisted' })
    $unauth = @($findings | Where-Object { $_.ActionTaken -ne 'Whitelisted' })
    Write-Host "  AUTHORIZED  : $($auth.Count) tool(s)" -ForegroundColor Green
    Write-Host "  UNAUTHORIZED: $($unauth.Count) tool(s)" -ForegroundColor $(if ($unauth.Count -gt 0) {'Red'} else {'Green'})
    Write-Host ''
    foreach ($f in $findings) {
        $col = switch ($f.Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Green' } }
        Write-Host "  [$($f.ActionTaken.PadRight(12))] $($f.DisplayName)" -ForegroundColor $col
        if ($f.Details) { Write-Host "          $($f.Details)" -ForegroundColor DarkGray }
    }
    if ($findings.Count -eq 0) { Write-Status 'No RMM tools detected.' 'Green' }
    Pause-ForKey
}

function Invoke-AuditChainVerifyMenu {
    Write-Header 'Verify Audit Log Chain'
    . (Join-Path $modulesDir 'AuditChain.ps1')
    $wl = $null
    $findings = Invoke-AuditChainVerify -Whitelist $wl -AuditLog $auditLog
    foreach ($f in $findings) {
        $col = switch ($f.Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Green' } }
        Write-Host "  [$($f.Severity.ToUpper().PadRight(6))] $($f.DisplayName)" -ForegroundColor $col
        if ($f.Details) { Write-Host "          $($f.Details)" -ForegroundColor DarkGray }
    }
    if ($findings.Count -eq 0) { Write-Status 'Audit log chain integrity verified.' 'Green' }
    Pause-ForKey
}

function Invoke-RemoteAnchorSyncMenu {
    Write-Header 'Remote Anchor Sync'
    . (Join-Path $modulesDir 'RemoteAnchor.ps1')
    $wl = $null
    Invoke-RemoteAnchorSync -Whitelist $wl -AuditLog $auditLog | ForEach-Object {
        $col = switch ($_.Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Green' } }
        Write-Host "  [$($_.Severity.ToUpper().PadRight(6))] $($_.DisplayName)" -ForegroundColor $col
        if ($_.Details) { Write-Host "          $($_.Details)" -ForegroundColor DarkGray }
    }
    Write-Host ''
    Export-FingerprintQRText
    Pause-ForKey
}

# ============================================================
# Main interactive loop
# ============================================================
function Show-MainMenu {
    Clear-Host

    # Read latest scan summary for live stats
    $latestSummary  = $null
    $riskScore      = 'N/A'
    $riskLevel      = 'N/A'
    $activeThreatCt = 0
    $cveCount       = 0
    $patchMissCt    = 0
    $lastScanTime   = 'Never'
    try {
        $summaryFiles = @(Get-ChildItem -Path $reportsDir -Filter 'scan_*_summary.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($summaryFiles.Count -gt 0) {
            $latestSummary = Get-Content $summaryFiles[0].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $riskScore     = $latestSummary.riskScore
            $riskLevel     = $latestSummary.riskLevel
            $activeThreatCt = $latestSummary.findings.red
            $cveCount       = $latestSummary.cvesFound
            $patchMissCt    = $latestSummary.patchesMissing
            $lastScanTime   = ([datetime]$latestSummary.timestamp).ToString('HH:mm')
        }
    } catch {}

    # Service status
    $svcState = Get-NssmServiceUiStatus
    $svcLabel = $svcState.Label
    $svcColor = $svcState.Color

    # Quarantine count
    $quarCount = 0
    try {
        if (Test-Path $quarManifest) { $quarCount = @(Get-Content $quarManifest -Raw -Encoding UTF8 | ConvertFrom-Json).Count }
    } catch {}

    # Risk color
    $riskColor = switch ($riskLevel) {
        'CRITICAL' { 'Red'     }
        'HIGH'     { 'Red'     }
        'MEDIUM'   { 'Yellow'  }
        'LOW'      { 'Green'   }
        default    { 'Gray'    }
    }

    # Unicode dashboard box
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║         QuietMonitor Security Suite v2.0         ║" -ForegroundColor Cyan
    Write-Host "  ║  Service: " -NoNewline -ForegroundColor Cyan
    Write-Host $svcLabel.PadRight(10) -NoNewline -ForegroundColor $svcColor
    Write-Host " | Last Scan: $($lastScanTime.PadRight(8))║" -ForegroundColor Cyan
    Write-Host "  ║  Risk Score: " -NoNewline -ForegroundColor Cyan
    Write-Host ("$riskScore/100 [$riskLevel]").PadRight(34) -NoNewline -ForegroundColor $riskColor
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║  Active Threats: " -NoNewline -ForegroundColor Cyan
    Write-Host ("$activeThreatCt").PadRight(4) -NoNewline -ForegroundColor $(if ($activeThreatCt -gt 0) {'Red'} else {'Green'})
    Write-Host " | Quarantine: " -NoNewline -ForegroundColor Cyan
    Write-Host ("$quarCount").PadRight(14) -NoNewline -ForegroundColor $(if ($quarCount -gt 0) {'Yellow'} else {'Green'})
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║  CVEs Found: " -NoNewline -ForegroundColor Cyan
    Write-Host ("$cveCount").PadRight(6) -NoNewline -ForegroundColor $(if ($cveCount -gt 0) {'Red'} else {'Green'})
    Write-Host " | Patches Missing: " -NoNewline -ForegroundColor Cyan
    Write-Host ("$patchMissCt").PadRight(9) -NoNewline -ForegroundColor $(if ($patchMissCt -gt 0) {'Yellow'} else {'Green'})
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Run Full Security Scan    [3] Quarantine Manager" -ForegroundColor White
    Write-Host "  [2] View Threat Report        [4] Live Audit Log" -ForegroundColor White
    Write-Host "  [5] Manage Whitelist          [6] Configure Settings" -ForegroundColor White
    Write-Host "  [7] Service Control           [8] Quick Scan" -ForegroundColor White
    Write-Host "  [9] Forensic IR Package       [0] Exit" -ForegroundColor White
    Write-Host ("  " + ('-' * 44)) -ForegroundColor DarkGray
    Write-Host "  [10] Rebuild System Baseline  [13] Weekly Report Now" -ForegroundColor DarkCyan
    Write-Host "  [11] Vulnerability Report     [14] UBA Dashboard" -ForegroundColor DarkCyan
    Write-Host "  [12] Threat Intel Check       [15] Ransomware Guard" -ForegroundColor DarkCyan
    Write-Host ("  " + ('-' * 44)) -ForegroundColor DarkGray
    Write-Host "  [16] Integrity Check          [19] Remote Anchor Sync" -ForegroundColor DarkCyan
    Write-Host "  [17] RMM Detection Scan" -ForegroundColor DarkCyan
    Write-Host "  [18] Verify Audit Log Chain" -ForegroundColor DarkCyan
    Write-Host ""
}

$running = $true
while ($running) {
    Show-MainMenu
    $choice = Read-MenuChoice "[0-19]"

    switch ($choice) {
        '1'  { Invoke-FullScan }
        '2'  { Open-LastReport }
        '3'  { Show-QuarantineManager }
        '4'  { Show-AuditLogTail }
        '5'  { Edit-Whitelist }
        '6'  { Edit-Settings }
        '7'  { Show-ServiceManager }
        '8'  { Invoke-QuickScan }
        '9'  { Export-ForensicsMenu }
        '10' { Invoke-RebuildBaseline }
        '11' { Show-VulnReport }
        '12' { Show-ThreatIntelCheck }
        '13' { Invoke-WeeklyReportNow }
        '14' { Show-UBADashboard }
        '15' { Show-RansomwareGuardStatus }
        '16' { Invoke-ManualIntegrityCheck }
        '17' { Invoke-RMMScan }
        '18' { Invoke-AuditChainVerifyMenu }
        '19' { Invoke-RemoteAnchorSyncMenu }
        '0'  { $running = $false }
        default {
            Write-Host ""
            Write-Status "Invalid choice. Please enter 0-19." 'Red'
            Start-Sleep -Milliseconds 800
        }
    }
}

Write-Host ""
Write-Host "  Goodbye." -ForegroundColor DarkCyan
Write-Host ""

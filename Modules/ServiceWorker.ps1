<#
.SYNOPSIS
    ServiceWorker.ps1 - Background loop for the QuietMonitor Windows Service.
.DESCRIPTION
    This script is the worker loop registered as a Windows Service by Install-QuietMonitor.ps1.
    It runs indefinitely, waking up at a configurable interval to execute the full security
    scan suite. Between scans it maintains a FileSystemWatcher on high-risk directories for
    immediate alerting on new file creation/changes.

    Behaviour:
      - Reads scan interval from Config\settings.json (ScanIntervalMinutes, default: 15)
      - Invokes Run-SecuritySuite.ps1 with -FullReport on each cycle
      - Writes a heartbeat timestamp to Logs\service_heartbeat.txt every minute
      - Monitors via FileSystemWatcher: C:\Windows\System32 (*.exe, *.dll),
        %TEMP%, %APPDATA%, C:\ProgramData for new/changed files
      - On FSW event, writes an immediate alert to the audit log
      - Gracefully handles Stop-Service SIGTERM via Register-EngineEvent PowerShell.Exiting

    Requirements:
      - Run as SYSTEM or Administrator
      - C:\QuietMonitor\ must already be initialized by Install-QuietMonitor.ps1
#>

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # Don't crash the service on non-fatal errors

# ============================================================
# Paths
# ============================================================
$baseDir    = 'C:\QuietMonitor'
$logDir     = Join-Path $baseDir 'Logs'
$auditLog   = Join-Path $logDir  'audit.log'
$heartbeat  = Join-Path $logDir  'service_heartbeat.txt'
$settingsFile = Join-Path (Join-Path $baseDir 'Config') 'settings.json'
$suiteScript  = Join-Path $baseDir 'Run-SecuritySuite.ps1'

$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition

# If running from the project directory rather than C:\QuietMonitor
if (-not (Test-Path $suiteScript)) {
    $suiteScript = Join-Path $scriptDir 'Run-SecuritySuite.ps1'
}

foreach ($dir in $logDir, (Join-Path $baseDir 'Reports'), (Join-Path $baseDir 'Quarantine')) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# ============================================================
# Load settings
# ============================================================
function Get-Settings {
    $defaults = @{
        ScanIntervalMinutes = 15
        HeartbeatIntervalSeconds = 60
        FSWatchPaths = @(
            "$env:SystemRoot\System32",
            "$env:TEMP",
            "$env:APPDATA",
            'C:\ProgramData',
            "$env:LOCALAPPDATA\Temp"
        )
        FSWatchExtensions = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js')
    }

    if (Test-Path $settingsFile) {
        try {
            $loaded = Get-Content $settingsFile -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            foreach ($key in $defaults.Keys) {
                if ($loaded.PSObject.Properties[$key]) {
                    $defaults[$key] = $loaded.$key
                }
            }
        } catch {
            Add-Content -Path $auditLog -Value (
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: Settings] " +
                "[DETAILS: Failed to parse settings.json, using defaults - $_]"
            ) -Encoding UTF8
        }
    }
    return $defaults
}

# ============================================================
# File System Watcher setup
# ============================================================
$watchers = [System.Collections.Generic.List[System.IO.FileSystemWatcher]]::new()
$fswEvents = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

function Start-FileSystemWatchers ([hashtable]$settings) {
    $extFilter = ($settings.FSWatchExtensions | ForEach-Object { $_.TrimStart('.') }) -join '|'

    foreach ($watchPath in $settings.FSWatchPaths) {
        if (-not (Test-Path $watchPath -ErrorAction SilentlyContinue)) { continue }

        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path                  = $watchPath
            $watcher.IncludeSubdirectories = $true
            $watcher.NotifyFilter          = [System.IO.NotifyFilters]::FileName -bor
                                              [System.IO.NotifyFilters]::LastWrite
            $watcher.Filter                = '*'
            $watcher.EnableRaisingEvents   = $false  # will enable after registering

            $null = Register-ObjectEvent -InputObject $watcher -EventName 'Created' -Action {
                $e   = $Event.SourceEventArgs
                $ext = [System.IO.Path]::GetExtension($e.FullPath).ToLowerInvariant()
                $fswEvents.Enqueue("CREATED|$($e.FullPath)|$ext|$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
            }

            $null = Register-ObjectEvent -InputObject $watcher -EventName 'Changed' -Action {
                $e   = $Event.SourceEventArgs
                $ext = [System.IO.Path]::GetExtension($e.FullPath).ToLowerInvariant()
                $fswEvents.Enqueue("CHANGED|$($e.FullPath)|$ext|$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
            }

            $watcher.EnableRaisingEvents = $true
            $watchers.Add($watcher)

        } catch {
            Add-Content -Path $auditLog -Value (
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: FSWatcher] " +
                "[DETAILS: Failed to start watcher for '$watchPath' - $_]"
            ) -Encoding UTF8
        }
    }
}

function Stop-FileSystemWatchers {
    foreach ($w in $watchers) {
        try {
            $w.EnableRaisingEvents = $false
            $w.Dispose()
        } catch {}
    }
    $watchers.Clear()
}

# ============================================================
# Drain FSW event queue and log alerts
# ============================================================
function Process-FSWEvents ([hashtable]$settings) {
    $item = ''
    while ($fswEvents.TryDequeue([ref]$item)) {
        $parts    = $item -split '\|'
        $action   = $parts[0]
        $filePath = $parts[1]
        $ext      = $parts[2]
        $ts       = $parts[3]

        # Check if extension is in watchlist
        if ($settings.FSWatchExtensions -contains $ext) {
            Add-Content -Path $auditLog -Value (
                "[$ts UTC] [MODULE: ServiceWorker] [ACTION: FSW-$action] " +
                "[DETAILS: Path='$filePath' Ext='$ext']"
            ) -Encoding UTF8
        }
    }
}

# ============================================================
# Run security suite
# ============================================================
function Invoke-SecuritySuiteScan {
    if (-not (Test-Path $suiteScript)) {
        Add-Content -Path $auditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: Scan] " +
            "[DETAILS: ERROR - Run-SecuritySuite.ps1 not found at '$suiteScript']"
        ) -Encoding UTF8
        return
    }

    try {
        Add-Content -Path $auditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: ScanStart] " +
            "[DETAILS: Invoking Run-SecuritySuite.ps1 -FullReport]"
        ) -Encoding UTF8

        & $suiteScript -FullReport 2>&1 | ForEach-Object {
            # Discard normal output; errors already go to audit log inside the suite
        }

        Add-Content -Path $auditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: ScanComplete] " +
            "[DETAILS: Scan cycle finished]"
        ) -Encoding UTF8
    } catch {
        Add-Content -Path $auditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: ScanError] " +
            "[DETAILS: $_]"
        ) -Encoding UTF8
    }
}

# ============================================================
# Graceful shutdown hook
# ============================================================
$script:shouldExit = $false

$null = Register-EngineEvent -SourceIdentifier 'PowerShell.Exiting' -Action {
    $script:shouldExit = $true
    Add-Content -Path $auditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: Shutdown] " +
        "[DETAILS: Service stop signal received]"
    ) -Encoding UTF8
    Stop-FileSystemWatchers
}

# ============================================================
# Main service loop
# ============================================================
Add-Content -Path $auditLog -Value (
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: Start] " +
    "[DETAILS: QuietMonitor Service Worker started on '$env:COMPUTERNAME' as '$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)']"
) -Encoding UTF8

$settings = Get-Settings
Start-FileSystemWatchers $settings

$lastScan      = [datetime]::MinValue
$lastHeartbeat = [datetime]::MinValue
$lastSettings  = (Get-Date)

while ($true) {
    try {
        if ($script:shouldExit) { break }

        $now = Get-Date

        # Reload settings every 5 minutes
        if (($now - $lastSettings).TotalMinutes -ge 5) {
            $settings = Get-Settings
            $lastSettings = $now
        }

        # Heartbeat
        if (($now - $lastHeartbeat).TotalSeconds -ge $settings.HeartbeatIntervalSeconds) {
            Set-Content -Path $heartbeat -Value "LastHeartbeat: $(Get-Date -Format 'o') | Host: $env:COMPUTERNAME" -Encoding UTF8
            $lastHeartbeat = $now
        }

        # Drain FS watcher events
        Process-FSWEvents $settings

        # Periodic scan
        if (($now - $lastScan).TotalMinutes -ge $settings.ScanIntervalMinutes) {
            Invoke-SecuritySuiteScan
            $lastScan = Get-Date
        }

        # Sleep 10 seconds between loop iterations (keeps CPU near zero)
        Start-Sleep -Seconds 10
    } catch {
        Add-Content -Path $auditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: LoopError] " +
            "[DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8 -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 10
    }
}

Add-Content -Path $auditLog -Value (
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceWorker] [ACTION: Stopped] " +
    "[DETAILS: Service Worker exited cleanly]"
) -Encoding UTF8

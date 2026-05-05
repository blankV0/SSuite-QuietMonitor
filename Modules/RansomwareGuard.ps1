<#
.SYNOPSIS
    RansomwareGuard.ps1 - Ransomware detection, prevention, and response capabilities.
.DESCRIPTION
    Four functions:
      Invoke-RansomwareGuardScan  - Orchestrator-compatible scan: checks event logs for VSS deletion
                                     attempts, Defender disable, and honeypot file integrity.
      Start-RansomwareGuard       - Service context: sets up FileSystemWatcher on watched folders
                                     for mass rename/encrypt detection.
      New-HoneypotFiles           - Creates canary files designed to attract ransomware.
      Get-RansomwareGuardStatus   - Reads Logs\rg_state.json and returns guard status.

    MITRE ATT&CK:
      T1486 - Data Encrypted for Impact
      T1490 - Inhibit System Recovery (VSS deletion)
      T1562 - Impair Defenses (AV/firewall disable)
.OUTPUTS
    Invoke-RansomwareGuardScan: [PSCustomObject[]] - QuietMonitor finding schema
#>

# ============================================================
# Constants
# ============================================================
$script:RG_STATE_FILE = 'C:\QuietMonitor\Logs\rg_state.json'

$script:KNOWN_RANSOMWARE_EXTENSIONS = @(
    '.locked', '.encrypted', '.crypt', '.cry', '.enc', '.zzz',
    '.micro', '.teslacrypt', '.locky', '.cerber', '.cryptowall',
    '.wncry', '.wannacry', '.petya', '.notpetya', '.ryuk'
)

# ============================================================
# Helpers
# ============================================================
function script:New-RGFinding {
    param($Sev, $Cat, $Name, $DisplayName, $Path, $Details, $MitreId, $MitreName)
    [PSCustomObject]@{
        Module      = 'RansomwareGuard'
        Severity    = $Sev
        Category    = $Cat
        Title       = $DisplayName
        Path        = $Path
        Detail          = $Details
        ActionTaken = ''
        MitreId     = $MitreId
        MitreName   = $MitreName
    }
}

function script:Load-RGSettings {
    $cfgPath = 'C:\QuietMonitor\Config\settings.json'
    if (-not (Test-Path $cfgPath)) {
        $cfgPath = Join-Path (Split-Path $PSCommandPath -Parent) '..\Config\settings.json'
    }
    try {
        $cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        return $cfg.ransomwareGuard
    } catch {}
    return $null
}

function script:Save-RGState {
    param([object]$State)
    try {
        $dir = Split-Path $script:RG_STATE_FILE -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $State | ConvertTo-Json -Depth 5 | Set-Content $script:RG_STATE_FILE -Encoding UTF8
    } catch {}
}

# ============================================================
# Invoke-RansomwareGuardScan (orchestrator-compatible)
# ============================================================
function Invoke-RansomwareGuardScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Whitelist,
        [Parameter(Mandatory)] [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $settings = script:Load-RGSettings

    if ($settings -and $settings.enabled -eq $false) {
        return @((script:New-RGFinding 'Green' 'RansomwareGuard' 'rg-disabled' 'RansomwareGuard: Disabled' '' 'Ransomware protection is disabled in settings.json.' '' ''))
    }

    Write-Host "  [RansomwareGuard] Scanning for ransomware indicators..." -ForegroundColor Cyan

    $cutoff = (Get-Date).AddDays(-7)

    # ---- 1. Check for VSS Deletion (Shadow Copy attacks) ----
    Write-Host "  [RansomwareGuard]   -> VSS deletion attempts..." -ForegroundColor DarkGray
    try {
        # Look for vssadmin/wmic shadow delete in PowerShell event log (event 4104)
        $psEvents = @(Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -gt $cutoff } | Select-Object -First 200)

        foreach ($ev in $psEvents) {
            $msg = $ev.Message
            if ($msg -match 'vssadmin.*(delete|resize)\s+shadows|wmic.*shadowcopy.*delete|Remove-WmiObject.*Win32_ShadowCopy|gwmi.*shadowcopy') {
                $findings.Add((script:New-RGFinding `
                    -Sev 'Red' -Cat 'RansomwareGuard - VSS' `
                    -Name "rg-vss-$($ev.TimeCreated.ToString('yyyyMMddHHmmss'))" `
                    -DisplayName 'VSS Deletion Attempt Detected' `
                    -Path '' `
                    -Details "PowerShell script block (Event 4104) contains shadow copy deletion command at $($ev.TimeCreated). This is a critical ransomware indicator (deletes backup recovery points)." `
                    -MitreId 'T1490' -MitreName 'Inhibit System Recovery'))
            }
        }
    } catch {}

    # Also check System log for VSS service stopped abruptly
    try {
        $sysEvents = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036; StartTime=$cutoff} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'Volume Shadow Copy.*stopped' } | Select-Object -First 5)

        foreach ($ev in $sysEvents) {
            $findings.Add((script:New-RGFinding `
                -Sev 'Yellow' -Cat 'RansomwareGuard - VSS' `
                -Name "rg-vss-stop-$($ev.TimeCreated.ToString('yyyyMMddHHmmss'))" `
                -DisplayName 'VSS Service Stopped Unexpectedly' `
                -Path '' `
                -Details "Volume Shadow Copy service stopped at $($ev.TimeCreated). Verify this was not triggered by ransomware. Check for shadow copy deletions." `
                -MitreId 'T1490' -MitreName 'Inhibit System Recovery'))
        }
    } catch {}

    # ---- 2. Check for Defender / Firewall Disable Attempts ----
    Write-Host "  [RansomwareGuard]   -> Security tool disable attempts..." -ForegroundColor DarkGray
    try {
        $defEvents = @(Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -gt $cutoff } | Select-Object -First 200)

        foreach ($ev in $defEvents) {
            $msg = $ev.Message
            if ($msg -match 'Set-MpPreference.*Disable|DisableAntiSpyware|DisableRealtimeMonitoring|DisableWindowsFirewall|netsh.*firewall.*disable|sc\s+stop\s+(WinDefend|MpsSvc|wscsvc)') {
                $findings.Add((script:New-RGFinding `
                    -Sev 'Red' -Cat 'RansomwareGuard - AV Tamper' `
                    -Name "rg-avdisable-$($ev.TimeCreated.ToString('yyyyMMddHHmmss'))" `
                    -DisplayName 'Security Tool Disable Attempt' `
                    -Path '' `
                    -Details "PowerShell event 4104 at $($ev.TimeCreated) contains command to disable Windows Defender or Firewall. Classic ransomware pre-staging indicator." `
                    -MitreId 'T1562' -MitreName 'Impair Defenses'))
            }
        }
    } catch {}

    # Check Security log for Windows Defender disabled (Event 5001/5010)
    try {
        $defDisabled = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=@(5001,5010,5012); StartTime=$cutoff} -ErrorAction SilentlyContinue | Select-Object -First 5)
        foreach ($ev in $defDisabled) {
            $findings.Add((script:New-RGFinding `
                -Sev 'Red' -Cat 'RansomwareGuard - AV Tamper' `
                -Name "rg-defenabled-$($ev.Id)-$($ev.TimeCreated.ToString('yyyyMMddHHmmss'))" `
                -DisplayName "Defender Protection Disabled (Event $($ev.Id))" `
                -Path '' `
                -Details "Windows Defender event $($ev.Id) detected at $($ev.TimeCreated). Real-time protection may have been disabled — ransomware pre-condition." `
                -MitreId 'T1562' -MitreName 'Impair Defenses'))
        }
    } catch {}

    # ---- 3. Check Honeypot File Integrity ----
    Write-Host "  [RansomwareGuard]   -> Honeypot file integrity..." -ForegroundColor DarkGray
    $honeypotPath = 'C:\QuietMonitor\Honeypot'
    if ($settings -and $settings.honeypotPath) { $honeypotPath = $settings.honeypotPath }
    $honeypotEnabled = $true
    if ($settings -and $null -ne $settings.honeypotEnabled) { $honeypotEnabled = [bool]$settings.honeypotEnabled }

    if ($honeypotEnabled -and (Test-Path $honeypotPath)) {
        $hpFiles = Get-ChildItem -Path $honeypotPath -File -ErrorAction SilentlyContinue
        if ($hpFiles.Count -gt 0) {
            $recentlyModified = @($hpFiles | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) })
            if ($recentlyModified.Count -gt 0) {
                $fileNames = ($recentlyModified | ForEach-Object { $_.Name }) -join ', '
                $findings.Add((script:New-RGFinding `
                    -Sev 'Red' -Cat 'RansomwareGuard - Honeypot' `
                    -Name 'rg-honeypot-modified' `
                    -DisplayName 'Honeypot Files Modified!' `
                    -Path $honeypotPath `
                    -Details "$($recentlyModified.Count) honeypot canary file(s) were modified in the last 24 hours: $fileNames. CRITICAL — ransomware activity likely in progress. Isolate system immediately." `
                    -MitreId 'T1486' -MitreName 'Data Encrypted for Impact'))
            } else {
                $findings.Add((script:New-RGFinding `
                    -Sev 'Green' -Cat 'RansomwareGuard - Honeypot' `
                    -Name 'rg-honeypot-intact' `
                    -DisplayName 'Honeypot Files: Intact' `
                    -Path $honeypotPath `
                    -Details "$($hpFiles.Count) honeypot canary files present and unmodified in $honeypotPath." `
                    -MitreId '' -MitreName ''))
            }
        } else {
            $findings.Add((script:New-RGFinding `
                -Sev 'Yellow' -Cat 'RansomwareGuard - Honeypot' `
                -Name 'rg-honeypot-empty' `
                -DisplayName 'Honeypot Directory: Empty' `
                -Path $honeypotPath `
                -Details "Honeypot directory exists but contains no canary files. Run 'New-HoneypotFiles' to create them." `
                -MitreId '' -MitreName ''))
        }
    } elseif ($honeypotEnabled) {
        $findings.Add((script:New-RGFinding `
            -Sev 'Yellow' -Cat 'RansomwareGuard - Honeypot' `
            -Name 'rg-honeypot-absent' `
            -DisplayName 'Honeypot Directory: Not Found' `
            -Path $honeypotPath `
            -Details "Honeypot directory '$honeypotPath' not found. Run 'New-HoneypotFiles' or option [15] to initialize canary files." `
            -MitreId '' -MitreName ''))
    }

    # ---- 4. Check for known ransomware extensions in temp/download folders ----
    Write-Host "  [RansomwareGuard]   -> Ransomware extension scan..." -ForegroundColor DarkGray
    $extensions = if ($settings -and $settings.knownRansomwareExtensions) {
        @($settings.knownRansomwareExtensions)
    } else { $script:KNOWN_RANSOMWARE_EXTENSIONS }

    $scanDirs = @("$env:TEMP", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents") | Where-Object { Test-Path $_ }
    $rgFiles  = [System.Collections.Generic.List[string]]::new()
    foreach ($dir in $scanDirs) {
        try {
            Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue -Depth 2 |
                Where-Object { $extensions -contains $_.Extension.ToLower() } |
                Select-Object -First 10 | ForEach-Object { $rgFiles.Add($_.FullName) }
        } catch {}
    }
    if ($rgFiles.Count -gt 0) {
        $findings.Add((script:New-RGFinding `
            -Sev 'Red' -Cat 'RansomwareGuard - Extension Scan' `
            -Name 'rg-known-extension' `
            -DisplayName "Known Ransomware Extensions Found ($($rgFiles.Count) files)" `
            -Path $scanDirs[0] `
            -Details "$($rgFiles.Count) file(s) with known ransomware extensions found: $($rgFiles -join '; ')" `
            -MitreId 'T1486' -MitreName 'Data Encrypted for Impact'))
    }

    # ---- Update state file ----
    $rCnt = @($findings | Where-Object { $_.Severity -eq 'Red' }).Count
    $state = [PSCustomObject]@{
        Enabled        = $true
        LastCheck      = (Get-Date -Format 'o')
        EventsDetected = $rCnt
        HoneypotIntact = ($findings | Where-Object { $_.Name -eq 'rg-honeypot-intact' }).Count -gt 0
        HoneypotPath   = $honeypotPath
    }
    script:Save-RGState $state

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: RansomwareGuard] [ACTION: Scan] " +
            "[DETAILS: RED=$rCnt HoneypotIntact=$($state.HoneypotIntact)]"
        ) -Encoding UTF8
    }

    if ($rCnt -eq 0 -and ($findings | Where-Object { $_.Severity -eq 'Yellow' }).Count -eq 0) {
        $findings.Add((script:New-RGFinding 'Green' 'RansomwareGuard' 'rg-clean' 'RansomwareGuard: No Indicators Detected' '' 'No VSS deletion attempts, AV tampering, honeypot modifications, or known ransomware extensions found.' '' ''))
    }

    Write-Host ("  [RansomwareGuard] Complete — RED: $rCnt") -ForegroundColor Cyan
    return $findings
}

# ============================================================
# Start-RansomwareGuard (service context - FileSystemWatcher)
# ============================================================
function Start-RansomwareGuard {
    [CmdletBinding()]
    param(
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log',
        [object]$Settings = $null
    )

    if (-not $Settings) { $Settings = script:Load-RGSettings }

    $massRenameThreshold = if ($Settings -and $Settings.massRenameThreshold) { [int]$Settings.massRenameThreshold } else { 10 }
    $massRenameWindow    = if ($Settings -and $Settings.massRenameWindowSeconds) { [int]$Settings.massRenameWindowSeconds } else { 5 }

    $watchedFolderNames = if ($Settings -and $Settings.watchedFolders) {
        @($Settings.watchedFolders)
    } else {
        @('Documents', 'Desktop', 'Downloads', 'Pictures')
    }

    $allUserProfiles = @()
    try {
        $allUserProfiles = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '^(Public|Default|All Users|Default User)$' })
    } catch {}

    $watchedPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($prof in $allUserProfiles) {
        foreach ($folder in $watchedFolderNames) {
            $full = Join-Path $prof.FullName $folder
            if (Test-Path $full) { $watchedPaths.Add($full) }
        }
    }

    Write-Host "  [RansomwareGuard] Starting FileSystemWatcher on $($watchedPaths.Count) directories..." -ForegroundColor Yellow

    # Track rename counts per time window in a shared hashtable
    $renameTracker = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
    $watchers      = [System.Collections.Generic.List[object]]::new()

    foreach ($watchPath in $watchedPaths) {
        $watcher = [System.IO.FileSystemWatcher]::new($watchPath)
        $watcher.IncludeSubdirectories = $true
        $watcher.NotifyFilter          = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
        $watcher.EnableRaisingEvents   = $true

        $handler = {
            param($source, $e)
            $now = [datetime]::UtcNow
            $key = 'rg_rename_times'

            $times = $null
            if (-not $renameTracker.TryGetValue($key, [ref]$times)) {
                $times = [System.Collections.Generic.List[datetime]]::new()
                $renameTracker.TryAdd($key, $times) | Out-Null
            }
            $times.Add($now)
            # Clean old entries
            $old = @($times | Where-Object { ($now - $_).TotalSeconds -gt $massRenameWindow })
            foreach ($o in $old) { $times.Remove($o) | Out-Null }

            if ($times.Count -ge $massRenameThreshold) {
                $alert = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [RansomwareGuard] MASS RENAME ALERT: $($times.Count) renames in $massRenameWindow seconds. LastFile: $($e.FullPath)"
                try { Add-Content $AuditLog $alert -Encoding UTF8 } catch {}

                # Update state
                $state = [PSCustomObject]@{
                    Enabled        = $true
                    LastCheck      = (Get-Date -Format 'o')
                    EventsDetected = $times.Count
                    HoneypotIntact = $false
                    MassRenameAlert = $true
                    AlertPath      = $e.FullPath
                    AlertTime      = (Get-Date -Format 'o')
                }
                try {
                    $state | ConvertTo-Json | Set-Content $script:RG_STATE_FILE -Encoding UTF8 -Force
                } catch {}

                # Attempt to write Windows event log alert
                try {
                    Write-EventLog -LogName Application -Source 'QuietMonitor' -EventId 9001 -EntryType Warning `
                        -Message "RansomwareGuard: Mass file rename detected ($($times.Count) files/$massRenameWindow s). Last: $($e.FullPath)"
                } catch {}
            }
        }

        Register-ObjectEvent -InputObject $watcher -EventName Renamed -Action $handler | Out-Null
        $watchers.Add($watcher)
    }

    Write-Host "  [RansomwareGuard] FileSystemWatcher active on $($watchers.Count) paths. Monitoring for mass renames (threshold: $massRenameThreshold/$massRenameWindow`s)." -ForegroundColor Yellow

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: RansomwareGuard] [ACTION: StartWatcher] " +
            "[DETAILS: Paths=$($watchers.Count) Threshold=$massRenameThreshold Window=${massRenameWindow}s]"
        ) -Encoding UTF8
    }

    return $watchers
}

# ============================================================
# New-HoneypotFiles
# ============================================================
function New-HoneypotFiles {
    [CmdletBinding()]
    param(
        [object]$Settings = $null,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    if (-not $Settings) { $Settings = script:Load-RGSettings }

    $honeypotPath = if ($Settings -and $Settings.honeypotPath) { $Settings.honeypotPath } else { 'C:\QuietMonitor\Honeypot' }
    if (-not (Test-Path $honeypotPath)) { New-Item -ItemType Directory -Path $honeypotPath -Force | Out-Null }

    # Canary file names designed to attract ransomware (alphabetically early = processed first)
    $canaryFiles = @(
        'AAAA_DO_NOT_ENCRYPT_canary.txt'
        'AAAB_backup_passwords.txt'
        'AABK_wallet_seed_phrase.txt'
        'zz_backup_credentials.txt'
        'zz_important_do_not_delete.txt'
    )

    $canaryContent = "This is a canary/honeypot file created by QuietMonitor Security Suite.`nAny modification triggers an immediate ransomware alert.`nCreated: $(Get-Date -Format 'o')`nHostname: $env:COMPUTERNAME"

    $created = 0
    foreach ($name in $canaryFiles) {
        $filePath = Join-Path $honeypotPath $name
        try {
            [System.IO.File]::WriteAllText($filePath, $canaryContent, [System.Text.Encoding]::UTF8)
            $created++
        } catch { Write-Host "  [RansomwareGuard] Failed to create $filePath`: $_" -ForegroundColor Red }
    }

    # Also drop one canary in each user Documents / Desktop
    $userFolders = @()
    try {
        $userFolders = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '^(Public|Default|All Users|Default User)$' })
    } catch {}

    foreach ($uf in $userFolders) {
        foreach ($sub in @('Documents', 'Desktop')) {
            $dir = Join-Path $uf.FullName $sub
            if (Test-Path $dir) {
                $fp = Join-Path $dir 'AAAA_DO_NOT_ENCRYPT_canary.txt'
                try {
                    [System.IO.File]::WriteAllText($fp, $canaryContent, [System.Text.Encoding]::UTF8)
                    # Set read-only attribute so modification is even more obvious
                    (Get-Item $fp).Attributes = 'ReadOnly'
                    $created++
                } catch {}
            }
        }
    }

    Write-Host "  [RansomwareGuard] Created $created honeypot canary files." -ForegroundColor Green

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: RansomwareGuard] [ACTION: CreateHoneypot] " +
            "[DETAILS: Files=$created Path='$honeypotPath']"
        ) -Encoding UTF8
    }

    return $created
}

# ============================================================
# Get-RansomwareGuardStatus
# ============================================================
function Get-RansomwareGuardStatus {
    if (-not (Test-Path $script:RG_STATE_FILE)) {
        return [PSCustomObject]@{ Enabled = $false; LastCheck = 'Never'; EventsDetected = 0; HoneypotIntact = $false; Status = 'Not initialized' }
    }
    try {
        return Get-Content $script:RG_STATE_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return [PSCustomObject]@{ Enabled = $false; LastCheck = 'Error'; EventsDetected = 0; HoneypotIntact = $false; Status = 'State file corrupt' }
    }
}

<#
.SYNOPSIS
    ServiceQuarantine.ps1 - Interactive quarantine workflow for suspicious services and processes.
.DESCRIPTION
    Provides an interactive menu-driven workflow to stop, disable, and quarantine
    suspicious services and processes flagged by the detection modules.

    Workflow options per finding:
      [Q] Stop + Disable service (if applicable) + Quarantine the binary
      [I] Ignore this time (log as acknowledged, no action)
      [W] Add path to whitelist in whitelist.json (suppress future alerts)
      [S] Skip all remaining prompts (save to pending_quarantine.json for later review)

    If the binary is currently locked/in-use, the user is offered the option to
    schedule the quarantine move on next reboot via RunOnce registry key.

    Audit trail: every action (quarantine, ignore, whitelist) is logged to audit.log
    with timestamp, finding title, file path, SHA256, action taken, and current user.

    IMPORTANT: Never auto-quarantines. Requires explicit user input "CONFIRM" to proceed.

    ThreatLocker Note: This module stops services/processes and moves files.
    Sign with: Set-AuthenticodeSignature .\Modules\ServiceQuarantine.ps1 -Certificate $cert
.OUTPUTS
    Returns a string: 'Quarantined' | 'Ignored' | 'Whitelisted' | 'SkipAll' | 'Error'
#>

# ─── Display helper ──────────────────────────────────────────────────────────
function script:Write-FindingBox {
    param([PSCustomObject]$Finding)

    $title     = if ($Finding.PSObject.Properties['Title'])    { $Finding.Title }     else { 'Unknown' }
    $module    = if ($Finding.PSObject.Properties['Module'])   { $Finding.Module }    else { 'Unknown' }
    $fPath     = if ($Finding.PSObject.Properties['Path'])     { $Finding.Path }      else { '' }
    $detail    = if ($Finding.PSObject.Properties['Detail'])   { $Finding.Detail }    else { '' }
    $mitreId   = if ($Finding.PSObject.Properties['MitreId'])  { $Finding.MitreId }   else { '' }
    $mitreName = if ($Finding.PSObject.Properties['MitreName']){ $Finding.MitreName } else { '' }

    # Truncate detail at 90 chars to keep the box readable
    $detailShort = if ($detail.Length -gt 90) { $detail.Substring(0, 87) + '...' } else { $detail }

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║  ⚠ SUSPICIOUS: [$module] $title" -ForegroundColor Red
    Write-Host "  ║  Path  : $fPath" -ForegroundColor Yellow
    Write-Host "  ║  Reason: $detailShort" -ForegroundColor White
    Write-Host "  ║  MITRE : $mitreId - $mitreName" -ForegroundColor DarkCyan
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "  [Q] Stop + Disable + Quarantine binary" -ForegroundColor Red
    Write-Host "  [I] Ignore this time" -ForegroundColor Yellow
    Write-Host "  [W] Add to whitelist (never alert again)" -ForegroundColor Cyan
    Write-Host "  [S] Skip all remaining (continue scan)" -ForegroundColor DarkGray
    Write-Host ""
}

# ─── Quarantine-on-reboot helper ────────────────────────────────────────────
function script:Request-RebootQuarantine {
    param([string]$FilePath, [string]$QuarantinePath, [string]$AuditLog)

    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    try {
        if (-not (Test-Path $QuarantinePath)) {
            New-Item -ItemType Directory -Path $QuarantinePath -Force | Out-Null
        }
        $destName  = [System.IO.Path]::GetFileName($FilePath) + '.qmenc'
        $quarDest  = Join-Path $QuarantinePath $destName
        $runOnceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        $cmd = "cmd /c move /Y `"$FilePath`" `"$quarDest`""
        Set-ItemProperty -Path $runOnceKey -Name "QMQuarantine_$(Get-Random)" -Value $cmd -ErrorAction Stop

        Write-Host "  [+] Move scheduled on next reboot: '$FilePath' -> '$quarDest'" -ForegroundColor Green
        Add-Content -Path $AuditLog -Value (
            "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: QuarantineScheduledOnReboot] " +
            "[DETAILS: Path=$FilePath Dest=$quarDest]"
        ) -Encoding UTF8
        return $true
    } catch {
        Write-Host "  [!] Failed to schedule reboot quarantine: $($_.Exception.Message)" -ForegroundColor Red
        Add-Content -Path $AuditLog -Value (
            "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: ScheduleRebootError] " +
            "[DETAILS: $($_.Exception.Message) Path=$FilePath]"
        ) -Encoding UTF8
        return $false
    }
}

# ─── Public: Stop + disable a suspicious service ────────────────────────────
function Stop-SuspiciousService {
    <#
    .SYNOPSIS
        Stops and disables a suspicious Windows service, verifies the stop, and logs the result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ServiceName,
        [Parameter(Mandatory)] [string]$AuditLog
    )

    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop

        if ($svc.Status -ne 'Stopped') {
            Write-Host "  [*] Stopping service: $ServiceName..." -ForegroundColor Yellow -NoNewline
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 2500
            $svc.Refresh()
            if ($svc.Status -eq 'Stopped') {
                Write-Host " stopped." -ForegroundColor Green
            } else {
                Write-Host " still running (status: $($svc.Status))." -ForegroundColor Red
                Add-Content -Path $AuditLog -Value (
                    "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: StopServiceFailed] " +
                    "[DETAILS: Service $ServiceName still has status $($svc.Status)]"
                ) -Encoding UTF8
                return $false
            }
        } else {
            Write-Host "  [i] Service already stopped: $ServiceName" -ForegroundColor DarkGray
        }

        # Disable so it cannot restart on reboot
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
        Write-Host "  [+] Service disabled: $ServiceName" -ForegroundColor Green

        Add-Content -Path $AuditLog -Value (
            "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: ServiceStoppedAndDisabled] " +
            "[DETAILS: ServiceName=$ServiceName]"
        ) -Encoding UTF8
        return $true

    } catch {
        Write-Host "  [!] Failed to stop/disable service '$ServiceName': $($_.Exception.Message)" -ForegroundColor Red
        Add-Content -Path $AuditLog -Value (
            "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: StopServiceError] " +
            "[DETAILS: $($_.Exception.Message) ServiceName=$ServiceName]"
        ) -Encoding UTF8
        return $false
    }
}

# ─── Public: Kill a suspicious process ──────────────────────────────────────
function Stop-SuspiciousProcess {
    <#
    .SYNOPSIS
        Forcibly terminates a process by PID, verifies it exited, and logs the result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [int]$ProcessId,
        [Parameter(Mandatory)] [string]$ProcessName,
        [Parameter(Mandatory)] [string]$AuditLog
    )

    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) {
            Write-Host "  [i] Process PID $ProcessId ($ProcessName) is already gone." -ForegroundColor DarkGray
            Add-Content -Path $AuditLog -Value (
                "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: ProcessAlreadyGone] " +
                "[DETAILS: PID=$ProcessId Name=$ProcessName]"
            ) -Encoding UTF8
            return $true
        }

        Write-Host "  [*] Killing PID $ProcessId ($ProcessName)..." -ForegroundColor Yellow -NoNewline
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 1500

        $verify = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($verify) {
            Write-Host " still running." -ForegroundColor Red
            Add-Content -Path $AuditLog -Value (
                "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: KillProcessFailed] " +
                "[DETAILS: PID=$ProcessId Name=$ProcessName still running after Stop-Process]"
            ) -Encoding UTF8
            return $false
        }

        Write-Host " killed." -ForegroundColor Green
        Add-Content -Path $AuditLog -Value (
            "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: ProcessKilled] " +
            "[DETAILS: PID=$ProcessId Name=$ProcessName]"
        ) -Encoding UTF8
        return $true

    } catch {
        Write-Host " ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Add-Content -Path $AuditLog -Value (
            "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: KillProcessError] " +
            "[DETAILS: $($_.Exception.Message) PID=$ProcessId Name=$ProcessName]"
        ) -Encoding UTF8
        return $false
    }
}

# ─── Public: Main interactive quarantine workflow ────────────────────────────
function Invoke-ServiceQuarantineWorkflow {
    <#
    .SYNOPSIS
        Presents an interactive per-finding menu and executes the chosen action.
    .OUTPUTS
        String: 'Quarantined' | 'Ignored' | 'Whitelisted' | 'SkipAll' | 'Error'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSCustomObject]$Finding,
        [Parameter(Mandatory)] [string]$Password,
        [Parameter(Mandatory)] [string]$AuditLog,
        [string]$QuarantinePath = 'C:\QuietMonitor\Quarantine',
        [string]$WhitelistFile  = 'C:\QuietMonitor\Config\whitelist.json'
    )

    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $user  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    $fModule = if ($Finding.PSObject.Properties['Module'])   { $Finding.Module }   else { 'Unknown' }
    $fTitle  = if ($Finding.PSObject.Properties['Title'])    { $Finding.Title }    else { 'Unknown' }
    $fPath   = if ($Finding.PSObject.Properties['Path'])     { $Finding.Path }     else { '' }
    $fDetail = if ($Finding.PSObject.Properties['Detail'])   { $Finding.Detail }   else { '' }
    $fMitId  = if ($Finding.PSObject.Properties['MitreId'])  { $Finding.MitreId }  else { '' }

    # Display the finding box
    script:Write-FindingBox -Finding $Finding

    # Read user choice
    $choice = ''
    while ($choice -notin @('Q','I','W','S')) {
        $raw = Read-Host "  Choice (Q/I/W/S)"
        $choice = $raw.Trim().ToUpperInvariant()
        if ($choice -notin @('Q','I','W','S')) {
            Write-Host "  Invalid choice. Enter Q, I, W, or S." -ForegroundColor DarkGray
        }
    }

    switch ($choice) {

        # ── [Q] Quarantine ──────────────────────────────────────────────────
        'Q' {
            Write-Host ""
            Write-Host "  [!] This will perform the following actions:" -ForegroundColor Yellow
            Write-Host "      1. Stop the process (if running)" -ForegroundColor White
            Write-Host "      2. Stop and disable service startup (if applicable)" -ForegroundColor White
            Write-Host "      3. Encrypt and move binary to: $QuarantinePath" -ForegroundColor White
            Write-Host ""

            # Require explicit CONFIRM
            $confirm = (Read-Host "  Type CONFIRM to proceed (anything else cancels)").Trim()
            if ($confirm -ne 'CONFIRM') {
                Write-Host "  [i] Quarantine cancelled by user." -ForegroundColor DarkGray
                Add-Content -Path $AuditLog -Value (
                    "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: QuarantineAborted] " +
                    "[DETAILS: User did not type CONFIRM. Title=$fTitle Path=$fPath]"
                ) -Encoding UTF8
                return 'Ignored'
            }

            # ── Step 1: Stop service (if ServiceAudit finding with ServiceName) ──
            $stopOk = $true
            if ($fModule -eq 'ServiceAudit' -and $Finding.PSObject.Properties['ServiceName'] -and $Finding.ServiceName) {
                $stopOk = Stop-SuspiciousService -ServiceName $Finding.ServiceName -AuditLog $AuditLog
            }

            # ── Step 2: Stop process by path ────────────────────────────────
            if ($fPath) {
                $procBaseName = [System.IO.Path]::GetFileNameWithoutExtension($fPath)
                $matchedProcs = @(Get-Process -Name $procBaseName -ErrorAction SilentlyContinue)
                foreach ($proc in $matchedProcs) {
                    $killed = Stop-SuspiciousProcess -ProcessId $proc.Id -ProcessName $proc.Name -AuditLog $AuditLog
                    if (-not $killed) { $stopOk = $false }
                }
            }

            # ── Step 3: Handle stop failure ──────────────────────────────────
            if (-not $stopOk) {
                Write-Host ""
                Write-Host "  [!] Process/service could not be fully stopped." -ForegroundColor Yellow
                Write-Host "      The binary may still be in use and the quarantine move could fail." -ForegroundColor White
                Write-Host ""
                Write-Host "  [C] Continue with quarantine attempt anyway" -ForegroundColor White
                Write-Host "  [R] Schedule quarantine on next reboot (via RunOnce)" -ForegroundColor Cyan
                Write-Host "  [X] Cancel" -ForegroundColor DarkGray
                Write-Host ""

                $subChoice = ''
                while ($subChoice -notin @('C','R','X')) {
                    $subChoice = (Read-Host "  Choice (C/R/X)").Trim().ToUpperInvariant()
                }

                if ($subChoice -eq 'X') {
                    Write-Host "  [i] Quarantine cancelled." -ForegroundColor DarkGray
                    Add-Content -Path $AuditLog -Value (
                        "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: QuarantineCancelled] " +
                        "[DETAILS: Process could not be stopped, user cancelled. Title=$fTitle Path=$fPath]"
                    ) -Encoding UTF8
                    return 'Ignored'
                }
                if ($subChoice -eq 'R') {
                    $scheduled = script:Request-RebootQuarantine -FilePath $fPath -QuarantinePath $QuarantinePath -AuditLog $AuditLog
                    if ($scheduled) {
                        if ($Finding.PSObject.Properties['ActionTaken']) { $Finding.ActionTaken = 'ScheduledQuarantine:NextReboot' }
                        return 'Quarantined'
                    }
                    return 'Error'
                }
                # 'C' falls through to the quarantine attempt below
            }

            # ── Step 4: Verify file exists then quarantine ───────────────────
            if (-not $fPath -or -not (Test-Path $fPath -PathType Leaf -ErrorAction SilentlyContinue)) {
                Write-Host "  [!] Binary not found on disk: '$fPath'" -ForegroundColor Red
                Write-Host "      Cannot quarantine. The file may have already been removed." -ForegroundColor DarkGray
                Add-Content -Path $AuditLog -Value (
                    "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: QuarantineError] " +
                    "[DETAILS: File not found on disk. Title=$fTitle Path=$fPath]"
                ) -Encoding UTF8
                return 'Error'
            }

            # Compute SHA256 before moving
            $sha256 = 'N/A'
            try { $sha256 = (Get-FileHash -Path $fPath -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}

            try {
                $result = Invoke-QuarantineFile `
                    -FilePath       $fPath `
                    -Reason         "ServiceQuarantine: $fTitle | $fDetail" `
                    -QuarantinePath $QuarantinePath `
                    -Password       $Password `
                    -AuditLog       $AuditLog `
                    -Confirmed      # Caller already obtained CONFIRM above

                if ($result) {
                    if ($Finding.PSObject.Properties['ActionTaken']) {
                        $Finding.ActionTaken = "CONFIRMED QUARANTINE: $QuarantinePath"
                    }
                    Add-Content -Path $AuditLog -Value (
                        "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: CONFIRMED QUARANTINE] " +
                        "[DETAILS: Title=$fTitle Module=$fModule Path=$fPath SHA256=$sha256 MitreId=$fMitId]"
                    ) -Encoding UTF8
                    Write-Host "  [+] Binary quarantined successfully." -ForegroundColor Green
                    return 'Quarantined'
                } else {
                    Write-Host "  [!] Quarantine function returned false." -ForegroundColor Red
                    return 'Error'
                }
            } catch {
                Write-Host "  [!] Quarantine failed: $($_.Exception.Message)" -ForegroundColor Red

                # Offer reboot schedule if file appears locked
                if ($_.Exception.Message -match 'lock|in use|access|denied|sharing violation') {
                    Write-Host ""
                    Write-Host "  The file appears to be locked. Schedule move on next reboot?" -ForegroundColor Yellow
                    Write-Host "  [Y] Yes   [N] No" -ForegroundColor White
                    Write-Host ""
                    $retry = (Read-Host "  Choice (Y/N)").Trim().ToUpperInvariant()
                    if ($retry -eq 'Y') {
                        $scheduled = script:Request-RebootQuarantine -FilePath $fPath -QuarantinePath $QuarantinePath -AuditLog $AuditLog
                        if ($scheduled) { return 'Quarantined' }
                    }
                }

                Add-Content -Path $AuditLog -Value (
                    "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: QuarantineError] " +
                    "[DETAILS: $($_.Exception.Message) Title=$fTitle Path=$fPath SHA256=$sha256]"
                ) -Encoding UTF8
                return 'Error'
            }
        }

        # ── [I] Ignore ──────────────────────────────────────────────────────
        'I' {
            Add-Content -Path $AuditLog -Value (
                "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: IGNORED] " +
                "[DETAILS: Title=$fTitle Module=$fModule Path=$fPath MitreId=$fMitId acknowledged, no action]"
            ) -Encoding UTF8
            Write-Host "  [i] Finding acknowledged — no action taken." -ForegroundColor DarkGray
            return 'Ignored'
        }

        # ── [W] Whitelist ───────────────────────────────────────────────────
        'W' {
            try {
                # Load current whitelist
                $wl = if (Test-Path $WhitelistFile) {
                    Get-Content $WhitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json
                } else {
                    [PSCustomObject]@{}
                }

                # Ensure WhitelistedPaths array exists
                $wlPaths = if ($wl.PSObject.Properties['WhitelistedPaths']) {
                    [System.Collections.Generic.List[string]]@($wl.WhitelistedPaths)
                } else {
                    [System.Collections.Generic.List[string]]::new()
                }

                if ($fPath -and -not ($wlPaths -icontains $fPath)) {
                    $wlPaths.Add($fPath)
                    if ($wl.PSObject.Properties['WhitelistedPaths']) {
                        $wl.WhitelistedPaths = $wlPaths.ToArray()
                    } else {
                        $wl | Add-Member -NotePropertyName 'WhitelistedPaths' -NotePropertyValue $wlPaths.ToArray() -Force
                    }
                    $wl | ConvertTo-Json -Depth 10 | Set-Content $WhitelistFile -Encoding UTF8
                    Write-Host "  [+] Path added to whitelist: $fPath" -ForegroundColor Green
                } elseif (-not $fPath) {
                    Write-Host "  [!] Finding has no file path — nothing added to whitelist." -ForegroundColor Yellow
                } else {
                    Write-Host "  [i] Path already in whitelist." -ForegroundColor DarkGray
                }

                Add-Content -Path $AuditLog -Value (
                    "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: WHITELISTED] " +
                    "[DETAILS: Title=$fTitle Module=$fModule Path=$fPath added to WhitelistedPaths in whitelist.json]"
                ) -Encoding UTF8
                return 'Whitelisted'

            } catch {
                Write-Host "  [!] Failed to update whitelist: $($_.Exception.Message)" -ForegroundColor Red
                Add-Content -Path $AuditLog -Value (
                    "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: WhitelistError] " +
                    "[DETAILS: $($_.Exception.Message) Path=$fPath]"
                ) -Encoding UTF8
                return 'Error'
            }
        }

        # ── [S] Skip all remaining ──────────────────────────────────────────
        'S' {
            Add-Content -Path $AuditLog -Value (
                "[$ts] [USER: $user] [MODULE: ServiceQuarantine] [ACTION: SkipAll] " +
                "[DETAILS: User skipped remaining quarantine prompts at Title=$fTitle]"
            ) -Encoding UTF8
            Write-Host "  [i] Skipping remaining findings. They will be saved for pending review." -ForegroundColor DarkGray
            return 'SkipAll'
        }
    }

    return 'Error'
}

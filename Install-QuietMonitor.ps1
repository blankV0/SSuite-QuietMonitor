<#
.SYNOPSIS
    Install-QuietMonitor.ps1 - Installs or removes the QuietMonitor Windows Service.
.DESCRIPTION
    Registers Modules\ServiceWorker.ps1 as a persistent Windows Service using the
    built-in PowerShell executable as the service host (via -NonInteractive -NoProfile).

    Functions:
      Install-QuietMonitorService
        - Creates C:\QuietMonitor\ directory structure with hardened ACLs
        - Copies the project to C:\QuietMonitor\ if not already there
        - Registers the Windows Service 'QuietMonitorSvc'
        - Sets automatic failure recovery (restart after 30s, up to 3 times/day)
        - Optionally starts the service immediately

      Uninstall-QuietMonitorService
        - Stops and removes the 'QuietMonitorSvc' service
        - Leaves all data under C:\QuietMonitor\ intact

    NSSM Alternative:
      For a more robust service wrapper, NSSM (Non-Sucking Service Manager) is recommended:
        nssm install QuietMonitorSvc powershell.exe
        nssm set QuietMonitorSvc AppParameters "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"C:\QuietMonitor\Modules\ServiceWorker.ps1`""
        nssm set QuietMonitorSvc Start SERVICE_AUTO_START
        nssm set QuietMonitorSvc ObjectName LocalSystem
        nssm start QuietMonitorSvc

    Requirements:
      - Must be run as Administrator
      - PowerShell 5.1 or later
#>

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName   = 'QuietMonitorSvc'
$DisplayName   = 'QuietMonitor Security Suite'
$Description   = 'Continuous security monitoring: IOC detection, persistence hunting, network anomaly, credential access, lateral movement detection. Part of the QuietMonitor Security Suite.'
$BaseDir       = 'C:\QuietMonitor'
$WorkerScript  = Join-Path $BaseDir 'Modules\ServiceWorker.ps1'
$SrcDir        = Split-Path -Parent $MyInvocation.MyCommand.Definition

# PowerShell executable path (prefer pwsh for PS7, fallback to powershell.exe for PS5.1)
$_pwshCmd = Get-Command pwsh.exe -ErrorAction SilentlyContinue
$PwshExe = if ($_pwshCmd) { $_pwshCmd.Source } else { $null }
if (-not $PwshExe) { $PwshExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }

function Install-QuietMonitorService {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # ServiceAccount to run as. Default: LocalSystem. Use '.\SvcUser' for dedicated account.
        [string]$ServiceAccount = 'LocalSystem',
        [string]$ServicePassword = '',

        # Start the service immediately after installation
        [switch]$StartNow
    )

    Write-Host "[*] Installing QuietMonitor Security Service..." -ForegroundColor Cyan

    # ------------------------------------------------------------------
    # 1. Create C:\QuietMonitor directory structure
    # ------------------------------------------------------------------
    $dirs = @(
        $BaseDir,
        (Join-Path $BaseDir 'Modules'),
        (Join-Path $BaseDir 'Config'),
        (Join-Path $BaseDir 'Logs'),
        (Join-Path $BaseDir 'Reports'),
        (Join-Path $BaseDir 'Quarantine')
    )

    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "    Created: $dir" -ForegroundColor DarkGray
        }
    }

    # ------------------------------------------------------------------
    # 2. Copy project files if source differs from destination
    # ------------------------------------------------------------------
    if ($SrcDir -ne $BaseDir -and (Test-Path $SrcDir)) {
        Write-Host "[*] Copying project files to $BaseDir..." -ForegroundColor Cyan

        Get-ChildItem -Path $SrcDir -Recurse -File |
            Where-Object { $_.FullName -notmatch '\\QuietMonitor\\' } |
            ForEach-Object {
                $rel      = $_.FullName.Substring($SrcDir.Length).TrimStart('\')
                $destPath = Join-Path $BaseDir $rel
                $destDir  = Split-Path $destPath -Parent
                if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                Copy-Item -Path $_.FullName -Destination $destPath -Force
            }
    }

    # ------------------------------------------------------------------
    # 3. Harden directory ACLs (Administrators + SYSTEM only)
    # ------------------------------------------------------------------
    Write-Host "[*] Hardening directory ACLs..." -ForegroundColor Cyan
    try {
        $acl = Get-Acl $BaseDir
        $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance

        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
        $type   = [System.Security.AccessControl.AccessControlType]::Allow
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                   [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $prop    = [System.Security.AccessControl.PropagationFlags]::None

        foreach ($identity in @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity, $rights, $inherit, $prop, $type
            )
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $BaseDir -AclObject $acl -ErrorAction SilentlyContinue
        Write-Host "    ACLs hardened." -ForegroundColor DarkGray
    } catch {
        Write-Warning "ACL hardening failed (non-critical): $_"
    }

    # ------------------------------------------------------------------
    # 4. Remove existing service if present
    # ------------------------------------------------------------------
    $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingSvc) {
        Write-Host "[*] Removing existing service '$ServiceName'..." -ForegroundColor Yellow
        if ($existingSvc.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 1
    }

    # ------------------------------------------------------------------
    # 5. Build service binary path
    # ------------------------------------------------------------------
    $binPath = "`"$PwshExe`" -NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$WorkerScript`""

    # ------------------------------------------------------------------
    # 6. Create the service
    # ------------------------------------------------------------------
    Write-Host "[*] Creating Windows Service '$ServiceName'..." -ForegroundColor Cyan

    $scArgs = @(
        'create', $ServiceName,
        "binPath=$binPath",
        "DisplayName=$DisplayName",
        'start=auto',
        'type=own'
    )

    if ($ServiceAccount -ne 'LocalSystem' -and $ServiceAccount) {
        $scArgs += "obj=$ServiceAccount"
        if ($ServicePassword) { $scArgs += "password=$ServicePassword" }
    }

    $result = & sc.exe $scArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe create failed (exit code $LASTEXITCODE): $result"
    }

    # Set description
    & sc.exe description $ServiceName $Description | Out-Null

    # ------------------------------------------------------------------
    # 7. Configure failure recovery actions
    # ------------------------------------------------------------------
    & sc.exe failure $ServiceName `
        reset=86400 `
        actions=restart/30000/restart/30000/restart/30000 | Out-Null

    Write-Host "[+] Service '$ServiceName' created successfully." -ForegroundColor Green
    Write-Host "    Binary : $binPath" -ForegroundColor DarkGray
    Write-Host "    Account: $ServiceAccount" -ForegroundColor DarkGray
    Write-Host "    Startup: Automatic" -ForegroundColor DarkGray
    Write-Host "    Failure: Restart after 30s (up to 3/day)" -ForegroundColor DarkGray

    # ------------------------------------------------------------------
    # 8. Optionally start the service
    # ------------------------------------------------------------------
    if ($StartNow) {
        Write-Host "[*] Starting service..." -ForegroundColor Cyan
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 2
        $svc = Get-Service -Name $ServiceName
        Write-Host "[+] Service status: $($svc.Status)" -ForegroundColor Green
    }

    # ------------------------------------------------------------------
    # 9. Register Weekly Report Scheduled Task
    # ------------------------------------------------------------------
    try {
        Write-Host "[*] Registering Weekly Report scheduled task..." -ForegroundColor Cyan
        $settingsJson = Get-Content (Join-Path $BaseDir 'Config\settings.json') -Raw -Encoding UTF8 -ErrorAction SilentlyContinue | ConvertFrom-Json
        $wrDay  = if ($settingsJson -and $settingsJson.weeklyReport.dayOfWeek) { $settingsJson.weeklyReport.dayOfWeek } else { 'Monday' }
        $wrTime = if ($settingsJson -and $settingsJson.weeklyReport.time)      { $settingsJson.weeklyReport.time }      else { '08:00' }

        # Map day name to DayOfWeek enum
        $dayMap = @{Monday='Monday';Tuesday='Tuesday';Wednesday='Wednesday';Thursday='Thursday';Friday='Friday';Saturday='Saturday';Sunday='Sunday'}
        $triggerDay = if ($dayMap.ContainsKey($wrDay)) { $wrDay } else { 'Monday' }

        $timeParts = $wrTime -split ':'
        $triggerAt = [datetime]::Today.AddHours([int]$timeParts[0]).AddMinutes([int]$timeParts[1])

        $taskAction  = New-ScheduledTaskAction -Execute $PwshExe `
            -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -Command `"& '$BaseDir\Modules\WeeklyReport.ps1'; New-WeeklyReport`""
        $taskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $triggerDay -At $triggerAt
        $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -StartWhenAvailable
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

        Register-ScheduledTask -TaskName 'QuietMonitorWeeklyReport' -TaskPath '\QuietMonitor\' `
            -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal `
            -Description 'QuietMonitor v2.0 — Automated weekly HTML security report' `
            -Force -ErrorAction Stop | Out-Null

        Write-Host "[+] Scheduled task registered: \QuietMonitor\QuietMonitorWeeklyReport (Every $triggerDay at $wrTime)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not register scheduled task: $_" -ForegroundColor Yellow
    }

    # ------------------------------------------------------------------
    # 10. Initialize SelfProtect hash manifest
    # ------------------------------------------------------------------
    try {
        Write-Host "[*] Initializing SelfProtect module hash manifest..." -ForegroundColor Cyan
        $spModule = Join-Path $BaseDir 'Modules\SelfProtect.ps1'
        if (Test-Path $spModule) {
            . $spModule
            $hashFile = Join-Path $BaseDir 'Config\module_hashes.json'
            $initAudit = Join-Path $BaseDir 'Logs\audit.log'
            Initialize-SelfProtection -SrcDir $BaseDir -HashesFile $hashFile -AuditLog $initAudit
            Write-Host "[+] SelfProtect manifest saved: $hashFile" -ForegroundColor Green
        } else {
            Write-Host "[!] SelfProtect.ps1 not found at expected path; skipping." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] SelfProtect initialization error: $_" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[+] QuietMonitor installation complete." -ForegroundColor Green
    Write-Host "    To start : Start-Service $ServiceName" -ForegroundColor DarkCyan
    Write-Host "    To stop  : Stop-Service $ServiceName" -ForegroundColor DarkCyan
    Write-Host "    To remove: .\Install-QuietMonitor.ps1 then Uninstall-QuietMonitorService" -ForegroundColor DarkCyan
    Write-Host "    Logs     : $BaseDir\Logs\" -ForegroundColor DarkCyan
    Write-Host "    Heartbeat: $BaseDir\Logs\service_heartbeat.txt" -ForegroundColor DarkCyan
}

function Uninstall-QuietMonitorService {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Also remove the C:\QuietMonitor directory and all data
        [switch]$RemoveData
    )

    Write-Host "[*] Removing QuietMonitor Service..." -ForegroundColor Yellow

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "[!] Service '$ServiceName' not found." -ForegroundColor Yellow
    } else {
        if ($svc.Status -eq 'Running') {
            Write-Host "[*] Stopping service..." -ForegroundColor Cyan
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 3
        }
        $result = & sc.exe delete $ServiceName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Service '$ServiceName' removed." -ForegroundColor Green
        } else {
            Write-Warning "sc.exe delete returned $LASTEXITCODE : $result"
        }
    }

    if ($RemoveData) {
        if ($PSCmdlet.ShouldProcess($BaseDir, 'Remove all QuietMonitor data')) {
            Write-Host "[*] Removing $BaseDir..." -ForegroundColor Red
            Remove-Item -Path $BaseDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Data directory removed." -ForegroundColor Green
        }
    } else {
        Write-Host "[i] Data preserved at $BaseDir. Use -RemoveData to delete." -ForegroundColor Cyan
    }
}

# ============================================================
# Entry point (if invoked directly with arguments)
# ============================================================
$action = if ($args.Count -gt 0) { $args[0].ToLowerInvariant() } else { '' }

switch ($action) {
    'install'   { Install-QuietMonitorService -StartNow }
    'uninstall' { Uninstall-QuietMonitorService }
    'remove'    { Uninstall-QuietMonitorService -RemoveData }
    default {
        Write-Host ""
        Write-Host "QuietMonitor Service Installer" -ForegroundColor Cyan
        Write-Host "Usage: .\Install-QuietMonitor.ps1 [install|uninstall|remove]" -ForegroundColor White
        Write-Host ""
        Write-Host "  install   - Deploy service to C:\QuietMonitor and register Windows Service" -ForegroundColor White
        Write-Host "  uninstall - Stop and remove the Windows Service (keep data)" -ForegroundColor White
        Write-Host "  remove    - Stop, remove service AND delete all data" -ForegroundColor White
        Write-Host ""
        Write-Host "Or dot-source this file and call functions directly:" -ForegroundColor DarkGray
        Write-Host "  . .\Install-QuietMonitor.ps1" -ForegroundColor DarkGray
        Write-Host "  Install-QuietMonitorService -StartNow" -ForegroundColor DarkGray
        Write-Host "  Uninstall-QuietMonitorService" -ForegroundColor DarkGray
        Write-Host ""
    }
}

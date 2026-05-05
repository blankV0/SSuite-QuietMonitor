<#
.SYNOPSIS
    Install-QuietMonitor.ps1 - Installs or removes the QuietMonitor Windows Service.
.DESCRIPTION
    Installs QuietMonitorSvc as a real Windows Service using NSSM (Non-Sucking Service Manager)
    to avoid Windows Service Control Manager timeout issues (Error 1053).

    Functions:
      Install-NSSM
        - Downloads NSSM 2.24 when missing
        - Verifies ZIP SHA256 before extraction
        - Extracts win64\nssm.exe to C:\QuietMonitor\Tools\nssm.exe

      Install-QuietMonitorService
        - Creates C:\QuietMonitor\ directory structure with hardened ACLs
        - Copies the project to C:\QuietMonitor\ if needed
        - Registers QuietMonitorSvc using NSSM
        - Configures auto-restart and stdout/stderr log capture
        - Registers weekly report task

      Uninstall-QuietMonitorService
        - Stops and removes QuietMonitorSvc through NSSM
        - Optionally removes C:\QuietMonitor data

    Requirements:
      - Must be run as Administrator
      - PowerShell 5.1+
#>

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName   = 'QuietMonitorSvc'
$DisplayName   = 'QuietMonitor Security Suite'
$Description   = 'Endpoint security monitoring and threat detection suite'
$BaseDir       = 'C:\QuietMonitor'
$SrcDir        = Split-Path -Parent $MyInvocation.MyCommand.Definition

$ToolsDir      = Join-Path $BaseDir 'Tools'
$LogsDir       = Join-Path $BaseDir 'Logs'
$ConfigDir     = Join-Path $BaseDir 'Config'
$WorkerScript  = Join-Path $BaseDir 'Modules\ServiceWorker.ps1'
$SuiteScript   = Join-Path $BaseDir 'Run-SecuritySuite.ps1'
$NssmPath      = Join-Path $ToolsDir 'nssm.exe'

$NssmZipUrl            = 'https://nssm.cc/release/nssm-2.24.zip'
$NssmZipExpectedSha256 = '727d1e42275c605e0f04aba98095c38a8e1e46def453cdffce42869428aa6743'
$NssmZipDownloadPath   = Join-Path $env:TEMP 'nssm-2.24.zip'

$ServiceHostExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Invoke-Nssm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [switch]$IgnoreExitCode
    )

    if (-not (Test-Path $NssmPath)) {
        throw "nssm.exe missing: place file at '$NssmPath' and re-run installer."
    }

    try {
        $output = & $NssmPath @Arguments 2>&1
        if (-not $IgnoreExitCode -and $LASTEXITCODE -ne 0) {
            throw "NSSM command failed (exit $LASTEXITCODE): nssm $($Arguments -join ' ')`n$output"
        }
        return $output
    } catch {
        throw "NSSM execution error: $($_.Exception.Message)"
    }
}

function Install-NSSM {
    [CmdletBinding()]
    param()

    if (Test-Path $NssmPath) {
        Write-Host "[i] NSSM already present: $NssmPath" -ForegroundColor DarkGray
        return
    }

    if (-not (Test-Path $ToolsDir)) {
        New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
    }

    Write-Host "[*] NSSM not found. Downloading NSSM 2.24..." -ForegroundColor Cyan

    try {
        Invoke-WebRequest -Uri $NssmZipUrl -OutFile $NssmZipDownloadPath -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Host "[!] Failed to download NSSM: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[!] No internet or download blocked." -ForegroundColor Yellow
        Write-Host "[!] Manually place nssm.exe at: $NssmPath" -ForegroundColor Yellow
        throw "NSSM download failed."
    }

    if (-not (Test-Path $NssmZipDownloadPath)) {
        throw "NSSM ZIP download missing at '$NssmZipDownloadPath'."
    }

    $zipHash = (Get-FileHash -Path $NssmZipDownloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($zipHash -ne $NssmZipExpectedSha256) {
        Remove-Item -Path $NssmZipDownloadPath -Force -ErrorAction SilentlyContinue
        throw "NSSM ZIP SHA256 mismatch. Expected '$NssmZipExpectedSha256' but got '$zipHash'. Download aborted."
    }

    $extractDir = Join-Path $env:TEMP ("nssm_extract_{0}" -f ([Guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($NssmZipDownloadPath, $extractDir)

        $extractedNssm = Join-Path $extractDir 'nssm-2.24\win64\nssm.exe'
        if (-not (Test-Path $extractedNssm)) {
            throw "Could not locate win64\\nssm.exe inside archive."
        }

        Copy-Item -Path $extractedNssm -Destination $NssmPath -Force
    } finally {
        Remove-Item -Path $NssmZipDownloadPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path $NssmPath)) {
        throw "NSSM extraction failed. Place nssm.exe manually at '$NssmPath' and re-run installer."
    }

    Write-Host "[+] NSSM installed: $NssmPath" -ForegroundColor Green
}

function Install-QuietMonitorService {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$StartNow
    )

    Write-Host "[*] Installing QuietMonitor Security Service (NSSM)..." -ForegroundColor Cyan

    # ------------------------------------------------------------------
    # 1. Create C:\QuietMonitor directory structure
    # ------------------------------------------------------------------
    $dirs = @(
        $BaseDir,
        (Join-Path $BaseDir 'Modules'),
        $ConfigDir,
        $LogsDir,
        (Join-Path $BaseDir 'Reports'),
        (Join-Path $BaseDir 'Quarantine'),
        $ToolsDir
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
                $rel      = $_.FullName.Substring($SrcDir.Length).TrimStart('\\')
                $destPath = Join-Path $BaseDir $rel
                $destDir  = Split-Path $destPath -Parent
                if (-not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                Copy-Item -Path $_.FullName -Destination $destPath -Force
            }
    }

    # ------------------------------------------------------------------
    # 3. Harden directory ACLs (Administrators + SYSTEM only)
    # ------------------------------------------------------------------
    Write-Host "[*] Hardening directory ACLs..." -ForegroundColor Cyan
    try {
        $acl = Get-Acl $BaseDir
        $acl.SetAccessRuleProtection($true, $false)
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
    # 4. Ensure NSSM is present and verified
    # ------------------------------------------------------------------
    Install-NSSM

    # ------------------------------------------------------------------
    # 5. Remove existing service if present
    # ------------------------------------------------------------------
    try {
        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingSvc) {
            Write-Host "[*] Removing existing service '$ServiceName'..." -ForegroundColor Yellow
            try { Invoke-Nssm -Arguments @('stop', $ServiceName) -IgnoreExitCode | Out-Null } catch {}
            Start-Sleep -Seconds 1
            Invoke-Nssm -Arguments @('remove', $ServiceName, 'confirm') -IgnoreExitCode | Out-Null
            Start-Sleep -Seconds 1
        }
    } catch {
        Write-Host "[!] Existing service cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ------------------------------------------------------------------
    # 6. Create and configure NSSM service
    # ------------------------------------------------------------------
    Write-Host "[*] Creating Windows Service '$ServiceName' via NSSM..." -ForegroundColor Cyan

    $appParameters = "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$WorkerScript`""
    $stdoutLog = Join-Path $LogsDir 'service_stdout.log'
    $stderrLog = Join-Path $LogsDir 'service_stderr.log'

    try {
        Invoke-Nssm -Arguments @('install', $ServiceName, $ServiceHostExe) | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'AppParameters', $appParameters) | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'DisplayName', $DisplayName) | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'Description', $Description) | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'Start', 'SERVICE_AUTO_START') | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'ObjectName', 'LocalSystem') | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'AppStdout', $stdoutLog) | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'AppStderr', $stderrLog) | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'AppRotateFiles', '1') | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'AppRotateSeconds', '86400') | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'AppRotateBytes', '10485760') | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'AppExit', 'Default', 'Restart') | Out-Null
        Invoke-Nssm -Arguments @('set', $ServiceName, 'AppRestartDelay', '30000') | Out-Null
    } catch {
        throw "Failed to configure service via NSSM: $($_.Exception.Message)"
    }

    Write-Host "[+] Service '$ServiceName' created successfully." -ForegroundColor Green
    Write-Host "    Wrapper : $NssmPath" -ForegroundColor DarkGray
    Write-Host "    Host    : $ServiceHostExe" -ForegroundColor DarkGray
    Write-Host "    Script  : $WorkerScript" -ForegroundColor DarkGray
    Write-Host "    StdOut  : $stdoutLog" -ForegroundColor DarkGray
    Write-Host "    StdErr  : $stderrLog" -ForegroundColor DarkGray

    # ------------------------------------------------------------------
    # 7. Optionally start the service
    # ------------------------------------------------------------------
    if ($StartNow) {
        Write-Host "[*] Starting service..." -ForegroundColor Cyan
        try {
            Invoke-Nssm -Arguments @('start', $ServiceName) | Out-Null
            Start-Sleep -Seconds 2
            $status = (Invoke-Nssm -Arguments @('status', $ServiceName) -IgnoreExitCode | Out-String).Trim()
            Write-Host "[+] Service status: $status" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ------------------------------------------------------------------
    # 8. Register Weekly Report Scheduled Task (SYSTEM, Monday 08:00)
    # ------------------------------------------------------------------
    try {
        Write-Host "[*] Registering Weekly Report scheduled task..." -ForegroundColor Cyan

        $taskAction = New-ScheduledTaskAction -Execute $ServiceHostExe `
            -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$SuiteScript`" -FullReport"
        $taskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At ([datetime]::Today.AddHours(8))
        $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -StartWhenAvailable
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

        Register-ScheduledTask -TaskName 'QuietMonitor_WeeklyReport' `
            -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal `
            -Description 'QuietMonitor v2.0 - Automated weekly HTML security report' `
            -Force -ErrorAction Stop | Out-Null

        Write-Host "[+] Scheduled task registered: QuietMonitor_WeeklyReport (Every Monday at 08:00)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not register scheduled task: $_" -ForegroundColor Yellow
    }

    # ------------------------------------------------------------------
    # 9. Initialize SelfProtect hash manifest
    # ------------------------------------------------------------------
    try {
        Write-Host "[*] Initializing SelfProtect module hash manifest..." -ForegroundColor Cyan
        $spModule = Join-Path $BaseDir 'Modules\SelfProtect.ps1'
        if (Test-Path $spModule) {
            . $spModule
            $hashFile = Join-Path $ConfigDir 'module_hashes.json'
            $initAudit = Join-Path $LogsDir 'audit.log'
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
    Write-Host "    NSSM      : $NssmPath" -ForegroundColor DarkCyan
    Write-Host "    Start     : & '$NssmPath' start $ServiceName" -ForegroundColor DarkCyan
    Write-Host "    Stop      : & '$NssmPath' stop $ServiceName" -ForegroundColor DarkCyan
    Write-Host "    Status    : & '$NssmPath' status $ServiceName" -ForegroundColor DarkCyan
    Write-Host "    Remove    : .\Install-QuietMonitor.ps1 uninstall" -ForegroundColor DarkCyan
    Write-Host "    Logs      : $LogsDir" -ForegroundColor DarkCyan
    Write-Host "    Heartbeat : $(Join-Path $LogsDir 'service_heartbeat.txt')" -ForegroundColor DarkCyan
}

function Uninstall-QuietMonitorService {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$RemoveData
    )

    Write-Host "[*] Removing QuietMonitor Service..." -ForegroundColor Yellow

    try {
        if (-not (Test-Path $NssmPath)) {
            throw "nssm.exe missing: place file at '$NssmPath' to uninstall service cleanly."
        }

        Invoke-Nssm -Arguments @('stop', $ServiceName) -IgnoreExitCode | Out-Null
        Start-Sleep -Seconds 1
        Invoke-Nssm -Arguments @('remove', $ServiceName, 'confirm') -IgnoreExitCode | Out-Null
        Write-Host "[+] Service '$ServiceName' removed." -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to remove service via NSSM: $($_.Exception.Message)" -ForegroundColor Red
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
        Write-Host "  install   - Deploy service to C:\QuietMonitor using NSSM" -ForegroundColor White
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

<#
.SYNOPSIS
    SelfProtect.ps1 - Anti-tamper self-protection for QuietMonitor Security Suite.
.DESCRIPTION
    Three functions:
      Initialize-SelfProtection    - Hashes all PS1 files at install time, saves to Config\module_hashes.json.
      Invoke-SelfIntegrityCheck    - Orchestrator-compatible wrapper: re-hashes and compares.
                                     Returns Red if any file was MODIFIED, DELETED, or NEW (unexpected).
      Set-ProtectedFileACLs        - Applies DENY Write/Delete ACL entries to protect suite files.

    MITRE ATT&CK:
      T1562 - Impair Defenses (tampering with security tools)
      T1070 - Indicator Removal (deleting/modifying log/audit files)
.OUTPUTS
    Invoke-SelfIntegrityCheck: [PSCustomObject[]] - QuietMonitor finding schema
#>

# ============================================================
# Helpers
# ============================================================
function script:New-SPFinding {
    param($Sev, $Cat, $Name, $DisplayName, $Path, $Details, $MitreId, $MitreName)
    [PSCustomObject]@{
        Module      = 'SelfProtect'
        Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity    = $Sev
        Category    = $Cat
        Name        = $Name
        DisplayName = $DisplayName
        Path        = $Path
        Hash        = ''
        Details     = $Details
        ActionTaken = ''
        MitreId     = $MitreId
        MitreName   = $MitreName
    }
}

function script:Get-SPDefaultHashesPath {
    return 'C:\QuietMonitor\Config\module_hashes.json'
}

# ============================================================
# Initialize-SelfProtection
# Called once during Install-QuietMonitor.ps1 (Step 10).
# ============================================================
function Initialize-SelfProtection {
    [CmdletBinding()]
    param(
        [string]$SrcDir     = 'C:\QuietMonitor',
        [string]$HashesFile = '',
        [string]$AuditLog   = 'C:\QuietMonitor\Logs\audit.log'
    )

    if (-not $HashesFile) { $HashesFile = script:Get-SPDefaultHashesPath }

    $cfgDir = Split-Path $HashesFile -Parent
    if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null }

    Write-Host "  [SelfProtect] Hashing module files in $SrcDir..." -ForegroundColor Cyan

    $files = @(Get-ChildItem -Path $SrcDir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)
    $fileEntries = [System.Collections.Generic.List[object]]::new()

    foreach ($f in $files) {
        try {
            $h = (Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            $fileEntries.Add([ordered]@{
                path         = $f.FullName
                hash         = $h
                size         = $f.Length
                lastModified = $f.LastWriteTimeUtc.ToString('o')
            })
        } catch {
            Write-Host "  [SelfProtect] Warning: could not hash $($f.FullName): $_" -ForegroundColor Yellow
        }
    }

    $manifest = [PSCustomObject]@{
        createdAt = (Get-Date -Format 'o')
        hostname  = $env:COMPUTERNAME
        srcDir    = $SrcDir
        files     = $fileEntries
    }

    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $HashesFile -Encoding UTF8
    Write-Host "  [SelfProtect] Module hash manifest saved: $HashesFile ($($fileEntries.Count) files)" -ForegroundColor Green

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: SelfProtect] [ACTION: Initialize] " +
            "[DETAILS: Files=$($fileEntries.Count) HashFile='$HashesFile']"
        ) -Encoding UTF8
    }

    return $HashesFile
}

# ============================================================
# Invoke-SelfIntegrityCheck (orchestrator-compatible)
# ============================================================
function Invoke-SelfIntegrityCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Whitelist,
        [Parameter(Mandatory)] [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ---- Load settings ----
    $cfgPath = 'C:\QuietMonitor\Config\settings.json'
    if (-not (Test-Path $cfgPath)) {
        $cfgPath = Join-Path (Split-Path $PSCommandPath -Parent) '..\Config\settings.json'
    }
    $spEnabled    = $true
    $alertTamper  = $true
    $hashesFile   = script:Get-SPDefaultHashesPath

    if (Test-Path $cfgPath) {
        try {
            $cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($cfg.selfProtect) {
                if ($null -ne $cfg.selfProtect.enabled)     { $spEnabled   = [bool]$cfg.selfProtect.enabled }
                if ($null -ne $cfg.selfProtect.alertOnTamper){ $alertTamper = [bool]$cfg.selfProtect.alertOnTamper }
                if ($cfg.selfProtect.moduleHashesPath)      { $hashesFile  = $cfg.selfProtect.moduleHashesPath }
            }
        } catch {}
    }

    if (-not $spEnabled) {
        return @((script:New-SPFinding 'Green' 'SelfProtect' 'sp-disabled' 'SelfProtect: Disabled' '' 'Self-protection integrity checking is disabled in settings.json.' '' ''))
    }

    Write-Host "  [SelfProtect] Running self-integrity check..." -ForegroundColor Cyan

    if (-not (Test-Path $hashesFile)) {
        $findings.Add((script:New-SPFinding `
            -Sev 'Yellow' -Cat 'SelfProtect' `
            -Name 'sp-nohashfile' `
            -DisplayName 'SelfProtect: Hash Manifest Missing' `
            -Path $hashesFile `
            -Details "Module hash manifest not found at '$hashesFile'. Run Initialize-SelfProtection or reinstall the suite to establish a baseline." `
            -MitreId 'T1562' -MitreName 'Impair Defenses'))
        return $findings
    }

    # ---- Load manifest ----
    $manifest = $null
    try {
        $manifest = Get-Content $hashesFile -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $findings.Add((script:New-SPFinding `
            -Sev 'Red' -Cat 'SelfProtect' `
            -Name 'sp-manifest-corrupt' `
            -DisplayName 'SelfProtect: Hash Manifest Corrupt' `
            -Path $hashesFile `
            -Details "Failed to parse module hash manifest '$hashesFile': $($_.Exception.Message). Hash file may have been tampered." `
            -MitreId 'T1562' -MitreName 'Impair Defenses'))
        return $findings
    }

    $knownFiles  = @{}
    $seenFiles   = @{}

    foreach ($entry in $manifest.files) {
        $knownFiles[$entry.path] = $entry
    }

    # ---- Re-hash all known files ----
    foreach ($entry in $manifest.files) {
        $seenFiles[$entry.path] = $true
        $filePath = $entry.path

        if (-not (Test-Path $filePath -PathType Leaf -ErrorAction SilentlyContinue)) {
            if ($alertTamper) {
                $findings.Add((script:New-SPFinding `
                    -Sev 'Red' -Cat 'SelfProtect - Tamper' `
                    -Name "sp-deleted-$(Split-Path $filePath -Leaf)" `
                    -DisplayName "Module DELETED: $(Split-Path $filePath -Leaf)" `
                    -Path $filePath `
                    -Details "Monitored module '$filePath' has been DELETED since baseline was established ($(($manifest.createdAt))). This may indicate tamper or attack." `
                    -MitreId 'T1562' -MitreName 'Impair Defenses'))
            }
            continue
        }

        try {
            $currentHash = (Get-FileHash $filePath -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($currentHash -ne $entry.hash) {
                if ($alertTamper) {
                    $findings.Add((script:New-SPFinding `
                        -Sev 'Red' -Cat 'SelfProtect - Tamper' `
                        -Name "sp-modified-$(Split-Path $filePath -Leaf)" `
                        -DisplayName "Module MODIFIED: $(Split-Path $filePath -Leaf)" `
                        -Path $filePath `
                        -Details "Module '$filePath' hash mismatch. Expected: $($entry.hash.Substring(0,16))... Actual: $($currentHash.Substring(0,16))... File was modified after baseline was captured. Possible unauthorized change or attack." `
                        -MitreId 'T1562' -MitreName 'Impair Defenses'))
                }
            }
        } catch {
            Write-Host "  [SelfProtect] Cannot hash $filePath`: $_" -ForegroundColor Yellow
        }
    }

    # ---- Check for NEW unexpected PS1 files in the suite directory ----
    if ($manifest.srcDir) {
        $currentFiles = @(Get-ChildItem -Path $manifest.srcDir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)
        foreach ($cf in $currentFiles) {
            if (-not $seenFiles.ContainsKey($cf.FullName)) {
                $findings.Add((script:New-SPFinding `
                    -Sev 'Yellow' -Cat 'SelfProtect - New File' `
                    -Name "sp-newfile-$(Split-Path $cf.FullName -Leaf)" `
                    -DisplayName "Unexpected NEW Module: $(Split-Path $cf.FullName -Leaf)" `
                    -Path $cf.FullName `
                    -Details "New PS1 file '$($cf.FullName)' found in suite directory but was not in the hash manifest. Added since baseline was established on $($manifest.createdAt). Verify legitimacy." `
                    -MitreId 'T1562' -MitreName 'Impair Defenses'))
            }
        }
    }

    # ---- Check Windows Service is running ----
    $svcName = 'QuietMonitorSvc'
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            $findings.Add((script:New-SPFinding `
                -Sev 'Yellow' -Cat 'SelfProtect - Service' `
                -Name 'sp-service-stopped' `
                -DisplayName "Service Not Running: $svcName" `
                -Path '' `
                -Details "QuietMonitor Windows service '$svcName' is currently '$($svc.Status)'. Restart the service to resume continuous monitoring." `
                -MitreId 'T1562' -MitreName 'Impair Defenses'))
        }
    } catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        # Service not installed — not an error (may be running in standalone mode)
    } catch {}

    # ---- Summary ----
    $rCnt = @($findings | Where-Object { $_.Severity -eq 'Red'    }).Count
    $yCnt = @($findings | Where-Object { $_.Severity -eq 'Yellow' }).Count

    if ($rCnt -eq 0 -and $yCnt -eq 0) {
        $findings.Add((script:New-SPFinding `
            -Sev 'Green' -Cat 'SelfProtect' `
            -Name 'sp-intact' `
            -DisplayName 'SelfProtect: All Modules Intact' `
            -Path $hashesFile `
            -Details "All $($manifest.files.Count) monitored module files match the baseline hash manifest (established $($manifest.createdAt)). No tampering detected." `
            -MitreId '' -MitreName ''))
    }

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: SelfProtect] [ACTION: IntegrityCheck] " +
            "[DETAILS: Checked=$($manifest.files.Count) RED=$rCnt YELLOW=$yCnt]"
        ) -Encoding UTF8
    }

    Write-Host ("  [SelfProtect] Complete — Checked: $($manifest.files.Count)  RED: $rCnt  YELLOW: $yCnt") -ForegroundColor Cyan
    return $findings
}

# ============================================================
# Set-ProtectedFileACLs
# Applies DENY Write + DENY Delete ACLs for non-Admins.
# ============================================================
function Set-ProtectedFileACLs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]]$Paths,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    # DENY rule for "Everyone" (excluding SYSTEM and Administrators, which override DENY in most configs)
    # In practice we deny write/delete for the "Users" group so non-admins can't modify suite files.
    $denyIdentity = 'BUILTIN\Users'
    $denyRights   = [System.Security.AccessControl.FileSystemRights]::Write -bor
                    [System.Security.AccessControl.FileSystemRights]::Delete -bor
                    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $inherit      = [System.Security.AccessControl.InheritanceFlags]::None
    $prop         = [System.Security.AccessControl.PropagationFlags]::None
    $type         = [System.Security.AccessControl.AccessControlType]::Deny

    $protected = 0
    foreach ($path in $Paths) {
        if (-not (Test-Path $path -ErrorAction SilentlyContinue)) { continue }
        try {
            $acl  = Get-Acl -Path $path -ErrorAction Stop
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($denyIdentity, $denyRights, $inherit, $prop, $type)
            $acl.AddAccessRule($rule)
            Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
            $protected++
        } catch {
            Write-Host "  [SelfProtect] ACL hardening failed for '$path': $_" -ForegroundColor Yellow
        }
    }

    Write-Host "  [SelfProtect] ACL hardening applied to $protected files (DENY Write/Delete for $denyIdentity)." -ForegroundColor Green

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: SelfProtect] [ACTION: HardenACLs] " +
            "[DETAILS: Files=$protected Identity='$denyIdentity']"
        ) -Encoding UTF8
    }

    return $protected
}

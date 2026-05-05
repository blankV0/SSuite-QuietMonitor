#Requires -RunAsAdministrator
# =============================================================
# RemoteAnchor.ps1 — Installation fingerprint + remote sync
# Fingerprint = SHA256(MachineGUID + InstallTimestamp + salt)
# stored locally; verified against a user-configured endpoint.
# Optional: ASCII QR code representation for offline verification.
# The password is used to derive the fingerprint salt — never stored.
# MITRE: T1553 (Subvert Trust Controls)
# =============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:RA_FINGERPRINT_FILE = 'C:\QuietMonitor\Config\fingerprint.json'
$script:RA_TAMPER_LOG       = 'C:\QuietMonitor\Logs\tamper.log'

function script:Get-RASalt {
    # Derive a stable salt from machine GUID (not secret — used only for fingerprint uniqueness)
    $guid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction SilentlyContinue).MachineGuid
    if (-not $guid) { $guid = $env:COMPUTERNAME }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $salt = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("QuietMonitor-FP-Salt-$guid"))
    $sha.Dispose()
    return $salt
}

function script:Invoke-RASHASH {
    param([string]$Data)
    $sha  = [System.Security.Cryptography.SHA256]::Create()
    $hash = [BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Data))).Replace('-','').ToLower()
    $sha.Dispose()
    return $hash
}

function script:Write-RATamper {
    param([string]$Message, [string]$AuditLog)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [TAMPER-CRITICAL] [RemoteAnchor] $Message"
    try { Add-Content -LiteralPath $script:RA_TAMPER_LOG -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    if ($AuditLog) { try { Add-Content -LiteralPath $AuditLog -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {} }
    Write-Host "  [!!!] REMOTE ANCHOR: $Message" -ForegroundColor Red
}

# ── Fingerprint generation ────────────────────────────────────
function New-InstallFingerprint {
    <#
    .SYNOPSIS
        Computes the installation fingerprint:
          SHA256( MachineGUID + InstallTimestamp + PBKDF2(password, salt, 100k) )
        Stores the fingerprint (NOT the password) in Config\fingerprint.json.
        Pushes fingerprint to the user-configured remote endpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Security.SecureString]$Password,
        [string]$RemoteEndpoint,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $bstr  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $pwStr = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

    try {
        $machineGuid   = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction SilentlyContinue).MachineGuid
        $installTs     = Get-Date -Format 'o'
        $salt          = script:Get-RASalt

        # Derive password component
        $pdb = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            [System.Text.Encoding]::UTF8.GetBytes($pwStr), $salt, 100000,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $pwDerived = [BitConverter]::ToString($pdb.GetBytes(32)).Replace('-','').ToLower()
        $pdb.Dispose()

        $fingerprint = script:Invoke-RASHASH "$machineGuid|$installTs|$pwDerived"

        $fpObj = [PSCustomObject]@{
            fingerprint  = $fingerprint
            installTime  = $installTs
            hostname     = $env:COMPUTERNAME
            # MachineGuid is stored to detect machine changes (not secret, available in registry)
            machineGuid  = $machineGuid
            version      = '2.0'
        }

        $fpObj | ConvertTo-Json | Set-Content $script:RA_FINGERPRINT_FILE -Encoding UTF8
        if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [RemoteAnchor] [ACTION: NewFingerprint] [DETAILS: Fingerprint $($fingerprint.Substring(0,16))... created for $env:COMPUTERNAME]" -Encoding UTF8 -ErrorAction SilentlyContinue }

        # Push to remote endpoint
        if ($RemoteEndpoint) {
            try {
                $body = $fpObj | ConvertTo-Json -Compress
                $wc   = [System.Net.WebClient]::new()
                $wc.Headers.Add('Content-Type', 'application/json')
                $wc.Headers.Add('User-Agent', 'QuietMonitor-RemoteAnchor/2.0')
                $wc.UploadString($RemoteEndpoint, 'POST', $body)
                $wc.Dispose()
                Write-Host "  [RemoteAnchor] Fingerprint pushed to: $RemoteEndpoint" -ForegroundColor Green
            } catch {
                Write-Host "  [RemoteAnchor] Could not push to remote endpoint: $_ (fingerprint saved locally)" -ForegroundColor Yellow
            }
        }

        Write-Host "  [RemoteAnchor] Fingerprint: $fingerprint" -ForegroundColor Cyan
        return $fingerprint

    } finally {
        $pwStr = $null
    }
}

function Get-InstallFingerprint {
    <#
    .SYNOPSIS
        Returns the locally stored fingerprint object (does not require password).
    #>
    if (Test-Path $script:RA_FINGERPRINT_FILE) {
        return Get-Content $script:RA_FINGERPRINT_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    return $null
}

function Test-InstallFingerprintRemote {
    <#
    .SYNOPSIS
        Compares local fingerprint against the remote endpoint.
        A mismatch indicates reinstallation or core identity tamper.
    #>
    [CmdletBinding()]
    param(
        [string]$RemoteEndpoint,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not $RemoteEndpoint) { return $findings.ToArray() }

    $local = Get-InstallFingerprint
    if (-not $local) {
        $findings.Add([PSCustomObject]@{
            Severity='Yellow'; Module='RemoteAnchor'; Category='FingerprintCheck'
            Title='Installation fingerprint not found'
            Detail='Run New-InstallFingerprint during first install'
            Path=$script:RA_FINGERPRINT_FILE
            MitreId='T1553'; MitreName='Subvert Trust Controls'; ActionTaken='Alert'
        })
        return $findings.ToArray()
    }

    try {
        $wc      = [System.Net.WebClient]::new()
        $wc.Headers.Add('User-Agent', 'QuietMonitor-RemoteAnchor/2.0')
        $wc.Headers.Add('Cache-Control', 'no-cache')
        $remote  = $wc.DownloadString($RemoteEndpoint).Trim() | ConvertFrom-Json
        $wc.Dispose()

        if ($remote.fingerprint -ne $local.fingerprint) {
            $msg = "Fingerprint MISMATCH: local=$($local.fingerprint.Substring(0,16))... remote=$($remote.fingerprint.Substring(0,16))... — possible reinstall or identity tamper"
            script:Write-RATamper $msg $AuditLog
            $findings.Add([PSCustomObject]@{
                Severity='Red'; Module='RemoteAnchor'; Category='FingerprintMismatch'
                Title='Installation fingerprint changed — possible tamper'
                Detail=$msg; Path=$script:RA_FINGERPRINT_FILE
                MitreId='T1553'; MitreName='Subvert Trust Controls'; ActionTaken='Alert'
            })
        } elseif ($remote.hostname -ne $local.hostname) {
            $findings.Add([PSCustomObject]@{
                Severity='Yellow'; Module='RemoteAnchor'; Category='FingerprintCheck'
                Title='Hostname changed since fingerprint creation'
                Detail="Local hostname: $($local.hostname) — Remote hostname: $($remote.hostname)"
                Path=$script:RA_FINGERPRINT_FILE
                MitreId='T1553'; MitreName='Subvert Trust Controls'; ActionTaken='Alert'
            })
        } else {
            if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [RemoteAnchor] [ACTION: FingerprintVerify] [DETAILS: Remote fingerprint matches — identity confirmed]" -Encoding UTF8 -ErrorAction SilentlyContinue }
            Write-Host '  [RemoteAnchor] Remote fingerprint verified OK.' -ForegroundColor Green
        }
    } catch [System.Net.WebException] {
        Write-Host '  [RemoteAnchor] Remote endpoint unreachable — fingerprint check skipped.' -ForegroundColor Yellow
    } catch {
        Write-Host "  [RemoteAnchor] Fingerprint check error: $_" -ForegroundColor Yellow
    }

    return $findings.ToArray()
}

# ── ASCII QR-style fingerprint display ────────────────────────
function Export-FingerprintQRText {
    <#
    .SYNOPSIS
        Renders a visual "QR-like" ASCII block from the fingerprint hex string.
        Useful for offline/air-gapped verification — print and store physically.
        Each nibble pair → 4x4 block of ▓ or ░
    #>
    [CmdletBinding()]
    param(
        [string]$Fingerprint,
        [string]$OutPath
    )

    if (-not $Fingerprint) {
        $fp = Get-InstallFingerprint
        $Fingerprint = if ($fp) { $fp.fingerprint } else { $null }
    }
    if (-not $Fingerprint) { Write-Host '  No fingerprint available.' -ForegroundColor Yellow; return }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("╔══ QuietMonitor Installation Fingerprint ══╗")
    $lines.Add("║  Machine : $env:COMPUTERNAME".PadRight(44) + '║')
    $lines.Add("║  Date    : $(Get-Date -Format 'yyyy-MM-dd')".PadRight(44) + '║')
    $lines.Add("╠═══════════════════════════════════════════╣")

    # Render hex as 8×8 block grid (64 nibble pairs → 64 cells → 8 rows of 8)
    $cells = for ($i = 0; $i -lt [Math]::Min(64, $Fingerprint.Length - 1); $i += 2) {
        $val = [Convert]::ToInt32($Fingerprint.Substring($i, 2), 16)
        if ($val -ge 128) { '▓▓' } else { '░░' }
    }
    for ($row = 0; $row -lt 8; $row++) {
        $rowCells = ($cells[($row * 8)..($row * 8 + 7)] -join '')
        $lines.Add("║  $rowCells  ║")
    }

    $lines.Add("╠═══════════════════════════════════════════╣")
    # Split fingerprint into 4 lines of 16 chars each
    for ($i = 0; $i -lt 4; $i++) {
        $chunk = $Fingerprint.Substring($i * 16, 16)
        $lines.Add("║  $chunk  ║")
    }
    $lines.Add("╚═══════════════════════════════════════════╝")

    $output = $lines -join "`n"
    Write-Host $output -ForegroundColor Cyan

    if ($OutPath) {
        $lines | Set-Content $OutPath -Encoding UTF8
        Write-Host "  Saved to: $OutPath" -ForegroundColor Green
    }
    return $output
}

# ── Orchestrator ──────────────────────────────────────────────
function Invoke-RemoteAnchorSync {
    <#
    .SYNOPSIS
        Entry point for menu option [19].
        Shows current fingerprint, checks remote endpoint, offers to re-sync.
    #>
    [CmdletBinding()]
    param(
        [object]$Whitelist,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $fp = Get-InstallFingerprint
    if ($fp) {
        Write-Host "  [RemoteAnchor] Current fingerprint: $($fp.fingerprint)" -ForegroundColor Cyan
        Write-Host "  [RemoteAnchor] Created: $($fp.installTime) on $($fp.hostname)" -ForegroundColor DarkGray
    } else {
        Write-Host '  [RemoteAnchor] No fingerprint found.' -ForegroundColor Yellow
    }

    # Check settings for remote endpoint
    $settings = $null
    try {
        $sf = 'C:\QuietMonitor\Config\settings.json'
        if (Test-Path $sf) { $settings = Get-Content $sf -Raw -Encoding UTF8 | ConvertFrom-Json }
    } catch {}

    $endpoint = if ($settings -and $settings.selfProtect -and $settings.selfProtect.remoteAnchorEndpoint) { $settings.selfProtect.remoteAnchorEndpoint } else { $null }
    if ($endpoint) {
        foreach ($item in (Test-InstallFingerprintRemote -RemoteEndpoint $endpoint -AuditLog $AuditLog)) { $findings.Add($item) }
    } else {
        Write-Host '  [RemoteAnchor] No remote endpoint configured (settings.selfProtect.remoteAnchorEndpoint).' -ForegroundColor DarkGray
    }

    return $findings.ToArray()
}

#Requires -RunAsAdministrator
# =============================================================
# AuditChain.ps1 — Blockchain-style chained audit log
# Each entry contains HMAC-SHA256 of the previous entry.
# Any deletion or modification breaks the chain → CRITICAL alert.
# Chain key stored in HKLM registry protected by DPAPI.
# Both audit.log and tamper.log use this module.
# MITRE: T1070 (Indicator Removal), T1562 (Impair Defenses)
# =============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

# ── Constants ─────────────────────────────────────────────────
$script:AC_REG_PATH    = 'HKLM:\SOFTWARE\QuietMonitor\Security'
$script:AC_REG_KEY     = 'AuditChainKey'
$script:AC_GENESIS     = '0000000000000000000000000000000000000000000000000000000000000000'
$script:AC_TAMPER_LOG  = 'C:\QuietMonitor\Logs\tamper.log'
$script:AC_SEPARATOR   = ' |CHAIN| '

# ── Key management ────────────────────────────────────────────
function Initialize-AuditChainKey {
    <#
    .SYNOPSIS
        Generates a 32-byte HMAC key for audit chain signing.
        Stored in the registry protected by DPAPI (LocalMachine scope).
        Call once during installation.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log')

    $key = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect(
        $key, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Array]::Clear($key, 0, $key.Length)

    if (-not (Test-Path $script:AC_REG_PATH)) { New-Item -Path $script:AC_REG_PATH -Force | Out-Null }
    Set-ItemProperty -LiteralPath $script:AC_REG_PATH -Name $script:AC_REG_KEY -Value $enc -Type Binary

    Write-Host '  [AuditChain] Chain key initialised in registry (DPAPI protected).' -ForegroundColor Green
}

function script:Get-ACKey {
    try {
        if (-not (Test-Path $script:AC_REG_PATH)) { return $null }
        $enc = (Get-ItemProperty -LiteralPath $script:AC_REG_PATH -Name $script:AC_REG_KEY -ErrorAction Stop).$script:AC_REG_KEY
        return [System.Security.Cryptography.ProtectedData]::Unprotect(
            $enc, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    } catch { return $null }
}

function script:Invoke-ACHMAC {
    param([string]$Data, [byte[]]$Key)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    $hash = [BitConverter]::ToString($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Data))).Replace('-','').ToLower()
    $hmac.Dispose()
    return $hash
}

# ── Write a chained entry ─────────────────────────────────────
function Write-ChainedEntry {
    <#
    .SYNOPSIS
        Writes a single entry to a chain-integrity log file.
        Format: [TIMESTAMP] [LEVEL] [CATEGORY] MESSAGE |CHAIN| <hmac_of_prev_entry>
        If the chain key is unavailable, falls back to plain append.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$LogPath,
        [string]$Level    = 'INFO',
        [string]$Category = 'General',
        [Parameter(Mandatory)] [string]$Message
    )

    $ts      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $key     = script:Get-ACKey

    if ($key) {
        # Read last line of log to chain from
        $prevHash = $script:AC_GENESIS
        try {
            if (Test-Path $LogPath) {
                $lines = [System.IO.File]::ReadAllLines($LogPath, [System.Text.Encoding]::UTF8)
                if ($lines.Count -gt 0) {
                    $last = $lines[-1]
                    $prevHash = script:Invoke-ACHMAC $last $key
                }
            }
        } catch {}

        $body  = "[$ts] [$Level] [$Category] $Message"
        $chain = script:Invoke-ACHMAC $prevHash $key   # HMAC(HMAC(prev_line), key) = forward link
        $entry = "$body$($script:AC_SEPARATOR)$chain"
        [Array]::Clear($key, 0, $key.Length)
    } else {
        $entry = "[$ts] [$Level] [$Category] $Message  [CHAIN: unavailable - key not initialised]"
    }

    try {
        $stream = [System.IO.StreamWriter]::new($LogPath, $true, [System.Text.Encoding]::UTF8)
        $stream.WriteLine($entry)
        $stream.Flush()
        $stream.Close()
        $stream.Dispose()
    } catch {
        # Last-resort fallback
        Add-Content -LiteralPath $LogPath -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

# ── Verify full chain integrity ───────────────────────────────
function Test-AuditChainIntegrity {
    <#
    .SYNOPSIS
        Reads the entire log file and verifies each entry's CHAIN field
        against the computed HMAC of the previous entry.
        Returns array of finding objects — empty array = chain intact.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$LogPath,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not (Test-Path $LogPath)) {
        $findings.Add([PSCustomObject]@{
            Severity='Yellow'; Module='AuditChain'; Category='ChainVerification'
            Title="Log file not found: $(Split-Path $LogPath -Leaf)"
            Detail='Log has not been created yet'
            Path=$LogPath
            MitreId='T1070'; MitreName='Indicator Removal'; ActionTaken='Alert'
        })
        return $findings.ToArray()
    }

    $key = script:Get-ACKey
    if (-not $key) {
        $findings.Add([PSCustomObject]@{
            Severity='Yellow'; Module='AuditChain'; Category='ChainVerification'
            Title='Audit chain key not found — chain cannot be verified'
            Detail='Run Initialize-AuditChainKey during installation'
            Path=$script:AC_REG_PATH
            MitreId='T1562'; MitreName='Impair Defenses'; ActionTaken='Alert'
        })
        return $findings.ToArray()
    }

    try {
        $lines = [System.IO.File]::ReadAllLines($LogPath, [System.Text.Encoding]::UTF8)
        if ($lines.Count -eq 0) { return $findings.ToArray() }

        $brokenAt = [System.Collections.Generic.List[int]]::new()
        $prevHash  = $script:AC_GENESIS
        $unchained = 0

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            $sepIdx = $line.LastIndexOf($script:AC_SEPARATOR)
            if ($sepIdx -lt 0) {
                $unchained++
                # Legacy entries without chain field — skip but count
                $prevHash = script:Invoke-ACHMAC $line $key
                continue
            }

            $storedChain  = $line.Substring($sepIdx + $script:AC_SEPARATOR.Length)
            $expectedChain = script:Invoke-ACHMAC $prevHash $key

            if ($storedChain -ne $expectedChain) {
                $brokenAt.Add($i + 1)  # 1-based line number
            }

            # Advance: next entry's PREV = HMAC of this complete line
            $prevHash = script:Invoke-ACHMAC $line $key
        }

        if ($brokenAt.Count -gt 0) {
            $linesStr = $brokenAt -join ', '
            $msg = "Audit log CHAIN BROKEN at $($brokenAt.Count) point(s): lines $linesStr — entries deleted or modified"
            $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [TAMPER-CRITICAL] [AuditChain] $msg"
            try { Add-Content -LiteralPath $script:AC_TAMPER_LOG -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
            if ($AuditLog -and $AuditLog -ne $LogPath) {
                try { Add-Content -LiteralPath $AuditLog -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
            }
            Write-Host "  [!!!] CHAIN INTEGRITY BROKEN: $msg" -ForegroundColor Red

            $findings.Add([PSCustomObject]@{
                Severity='Red'; Module='AuditChain'; Category='ChainViolation'
                Title="Audit chain broken — $(Split-Path $LogPath -Leaf)"
                Detail=$msg
                Path=$LogPath
                MitreId='T1070'; MitreName='Indicator Removal'; ActionTaken='Alert'
            })
        } else {
            $msg = "Chain OK: $($lines.Count) entries verified"
            if ($unchained -gt 0) { $msg += " ($unchained legacy unchained)" }
            if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [AuditChain] [ACTION: Verify] [LOG: $(Split-Path $LogPath -Leaf)] [DETAILS: $msg]" -Encoding UTF8 -ErrorAction SilentlyContinue }
            Write-Host "  [AuditChain] $(Split-Path $LogPath -Leaf): $msg" -ForegroundColor Green
        }

    } finally {
        [Array]::Clear($key, 0, $key.Length)
    }

    return $findings.ToArray()
}

# ── ACL: set append-only on log files ─────────────────────────
function Set-AuditLogACL {
    <#
    .SYNOPSIS
        Sets ACL on the specified log file:
          • DENY Write, Modify, Delete for BUILTIN\Users and NT AUTHORITY\Everyone
          • DENY Write, Modify, Delete for NT AUTHORITY\NETWORK SERVICE
          • SYSTEM retains full control (for the service)
        This enforces append-only semantics at the OS level.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$LogPath,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType File -Path $LogPath -Force | Out-Null
    }

    try {
        $acl   = Get-Acl -LiteralPath $LogPath
        $rights = [System.Security.AccessControl.FileSystemRights]::Write -bor
                  [System.Security.AccessControl.FileSystemRights]::Modify -bor
                  [System.Security.AccessControl.FileSystemRights]::Delete

        $denyAccounts = @('BUILTIN\Users', 'Everyone', 'NT AUTHORITY\NETWORK SERVICE')
        foreach ($acct in $denyAccounts) {
            try {
                $id   = [System.Security.Principal.NTAccount]::new($acct)
                $ace  = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $id, $rights,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Deny)
                $acl.AddAccessRule($ace)
            } catch {}
        }
        Set-Acl -LiteralPath $LogPath -AclObject $acl -ErrorAction Stop
        if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [AuditChain] [ACTION: SetACL] [LOG: $LogPath] [DETAILS: Append-only DENY ACL applied]" -Encoding UTF8 -ErrorAction SilentlyContinue }
        Write-Host "  [AuditChain] Append-only ACL set on: $(Split-Path $LogPath -Leaf)" -ForegroundColor Green
    } catch {
        Write-Host "  [AuditChain] Warning — could not set ACL on $LogPath : $_" -ForegroundColor Yellow
    }
}

# ── Backup audit log to remote ────────────────────────────────
function Backup-AuditLogRemote {
    <#
    .SYNOPSIS
        Copies audit.log to a user-configured remote endpoint.
        Supports: local UNC path, SFTP target (stub — requires WinSCP), OneDrive path.
    #>
    [CmdletBinding()]
    param(
        [string]$LogPath,
        [string]$RemotePath,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    if (-not $RemotePath -or -not (Test-Path $LogPath)) { return }

    try {
        $destName = "$(Split-Path $LogPath -Leaf).$(Get-Date -Format 'yyyyMMdd_HHmmss').bak"

        # UNC or local path backup
        if ($RemotePath -match '^\\\\' -or (Test-Path (Split-Path $RemotePath -Parent) -ErrorAction SilentlyContinue)) {
            $dest = Join-Path $RemotePath $destName
            Copy-Item -LiteralPath $LogPath -Destination $dest -Force -ErrorAction Stop
            Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [AuditChain] [ACTION: Backup] [DETAILS: Log backed up to $dest]" -Encoding UTF8 -ErrorAction SilentlyContinue
            Write-Host "  [AuditChain] Audit log backed up to: $dest" -ForegroundColor Green
        } else {
            Write-Host "  [AuditChain] Remote path '$RemotePath' not accessible — backup skipped." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [AuditChain] Backup failed: $_" -ForegroundColor Yellow
    }
}

# ── Orchestrator (both logs) ──────────────────────────────────
function Invoke-AuditChainVerify {
    <#
    .SYNOPSIS
        Verifies both audit.log and tamper.log chain integrity.
        Returns combined findings array.
    #>
    [CmdletBinding()]
    param(
        [object]$Whitelist,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $logs = @(
        $AuditLog,
        'C:\QuietMonitor\Logs\tamper.log'
    )

    foreach ($log in $logs) {
        foreach ($item in (Test-AuditChainIntegrity -LogPath $log -AuditLog $AuditLog)) { $findings.Add($item) }
    }

    return $findings.ToArray()
}

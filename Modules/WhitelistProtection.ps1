#Requires -RunAsAdministrator
# =============================================================
# WhitelistProtection.ps1 — AES-256/HMAC-SHA256 encrypted whitelist
# Password NEVER written to disk or registry.
# Encrypt-then-MAC with PBKDF2-SHA256 (100,000 iterations).
# Remote HMAC anchor: compare local signature against a user-
# configured URL (GitHub raw, Pastebin private, self-hosted).
# MITRE: T1553 (Subvert Trust Controls), T1562 (Impair Defenses)
# =============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── Constants ─────────────────────────────────────────────────
$script:WLP_BASE     = 'C:\QuietMonitor\Config'
$script:WLP_ENC      = Join-Path $script:WLP_BASE 'whitelist.enc'
$script:WLP_SIG      = Join-Path $script:WLP_BASE 'whitelist.sig'
$script:WLP_SALT     = Join-Path $script:WLP_BASE 'whitelist.salt'
$script:WLP_AUDITKEY = 'WhitelistProtection'
$script:WLP_TAMPER   = 'C:\QuietMonitor\Logs\tamper.log'
$script:PBKDF2_ITER  = 100000

# ── Internal helpers ──────────────────────────────────────────
function script:Invoke-WLPDeriveKey {
    param([string]$Password, [byte[]]$Salt, [int]$Size = 32)
    $pdb = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        [System.Text.Encoding]::UTF8.GetBytes($Password),
        $Salt, $script:PBKDF2_ITER,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $pdb.GetBytes($Size)
    $pdb.Dispose()
    return $key
}

function script:Write-WLPTamper {
    param([string]$Message, [string]$AuditLog)
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $entry = "[$ts] [TAMPER-CRITICAL] [$script:WLP_AUDITKEY] $Message"
    try { Add-Content -LiteralPath $script:WLP_TAMPER -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    if ($AuditLog) { try { Add-Content -LiteralPath $AuditLog -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {} }
    Write-Host ''
    Write-Host '  ╔══════════════════════════════════════════════════╗' -ForegroundColor Red
    Write-Host '  ║  !!! CRITICAL TAMPER ALERT                    !!!║' -ForegroundColor Red
    Write-Host "  ║  $($Message.PadRight(48))║" -ForegroundColor Red
    Write-Host '  ╚══════════════════════════════════════════════════╝' -ForegroundColor Red
    Write-Host ''
}

function script:Invoke-WLPAudit {
    param([string]$Action, [string]$Details, [string]$AuditLog)
    $ts      = Get-Date -Format 'o'
    $who     = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $pid_    = $PID
    $entry   = "[$ts] [$script:WLP_AUDITKEY] [ACTION: $Action] [BY: $who PID:$pid_] [DETAILS: $Details]"
    if ($AuditLog) { try { Add-Content -LiteralPath $AuditLog -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {} }
}

function script:Get-WLPBytes {
    param([System.Security.SecureString]$Secure)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# ── Public API ────────────────────────────────────────────────

function Initialize-WhitelistProtection {
    <#
    .SYNOPSIS
        Encrypts an existing plaintext whitelist.json with AES-256-CBC.
        The password is NEVER stored — only a random PBKDF2 salt is saved.
        Plaintext file is securely deleted after encryption.
    #>
    [CmdletBinding()]
    param(
        [string]$PlainPath  = 'C:\QuietMonitor\Config\whitelist.json',
        [Parameter(Mandatory)]
        [System.Security.SecureString]$Password,
        [string]$AuditLog   = 'C:\QuietMonitor\Logs\audit.log'
    )

    $json = if (Test-Path $PlainPath) {
        Get-Content $PlainPath -Raw -Encoding UTF8
    } else { '{}' }
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    # Generate independent salts (enc salt | hmac salt) — 32 bytes each
    $rng      = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $saltEnc  = [byte[]]::new(32); $rng.GetBytes($saltEnc)
    $saltHMAC = [byte[]]::new(32); $rng.GetBytes($saltHMAC)
    $rng.Dispose()

    $pwBytes = script:Get-WLPBytes $Password
    $encKey  = $null; $hmacKey = $null

    try {
        $encKey  = script:Invoke-WLPDeriveKey ([System.Text.Encoding]::UTF8.GetString($pwBytes)) $saltEnc  32
        $hmacKey = script:Invoke-WLPDeriveKey ([System.Text.Encoding]::UTF8.GetString($pwBytes)) $saltHMAC 32

        # AES-256-CBC encrypt
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.KeySize = 256; $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key     = $encKey
        $aes.GenerateIV()
        $iv     = $aes.IV
        $cipher = $aes.CreateEncryptor().TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        $aes.Dispose()

        # IV prepended to ciphertext
        $encBlob = [byte[]]::new(16 + $cipher.Length)
        [Buffer]::BlockCopy($iv, 0, $encBlob, 0, 16)
        [Buffer]::BlockCopy($cipher, 0, $encBlob, 16, $cipher.Length)

        # HMAC-SHA256 over ciphertext (Encrypt-then-MAC)
        $hmac    = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
        $sigBytes= $hmac.ComputeHash($encBlob)
        $hmac.Dispose()
        $sigHex  = [BitConverter]::ToString($sigBytes).Replace('-', '').ToLower()

        # Salt bundle: [saltEnc(32)][saltHMAC(32)]
        $saltBundle = [byte[]]::new(64)
        [Buffer]::BlockCopy($saltEnc, 0, $saltBundle, 0, 32)
        [Buffer]::BlockCopy($saltHMAC, 0, $saltBundle, 32, 32)

        [System.IO.File]::WriteAllBytes($script:WLP_SALT, $saltBundle)
        [System.IO.File]::WriteAllBytes($script:WLP_ENC, $encBlob)
        [System.IO.File]::WriteAllText($script:WLP_SIG, $sigHex, [System.Text.Encoding]::ASCII)

        # Secure-delete plaintext
        if (Test-Path $PlainPath) {
            # Overwrite with random bytes before deleting
            $size = (Get-Item $PlainPath).Length
            $garbage = [byte[]]::new($size)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($garbage)
            [System.IO.File]::WriteAllBytes($PlainPath, $garbage)
            Remove-Item $PlainPath -Force -ErrorAction SilentlyContinue
        }

        script:Invoke-WLPAudit 'Initialize' 'Whitelist encrypted AES-256-CBC; plaintext securely erased' $AuditLog
        Write-Host '  [WhitelistProtection] Whitelist encrypted. Plaintext erased from disk.' -ForegroundColor Green

    } finally {
        [Array]::Clear($pwBytes,   0, $pwBytes.Length)
        if ($encKey)    { [Array]::Clear($encKey,   0, $encKey.Length)  }
        if ($hmacKey)   { [Array]::Clear($hmacKey,  0, $hmacKey.Length) }
        [Array]::Clear($plainBytes, 0, $plainBytes.Length)
    }
}

function Get-DecryptedWhitelist {
    <#
    .SYNOPSIS
        Decrypts whitelist.enc in memory. Returns PSCustomObject.
        Plaintext NEVER touches disk. Returns $null on tamper/wrong password.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.SecureString]$Password,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    # Fallback: encrypted store not yet initialised — use plaintext
    if (-not (Test-Path $script:WLP_ENC) -or
        -not (Test-Path $script:WLP_SIG) -or
        -not (Test-Path $script:WLP_SALT)) {
        $plain = 'C:\QuietMonitor\Config\whitelist.json'
        script:Invoke-WLPAudit 'Read-Plaintext' 'Encrypted store not found; reading whitelist.json' $AuditLog
        if (Test-Path $plain) { return Get-Content $plain -Raw -Encoding UTF8 | ConvertFrom-Json }
        return [PSCustomObject]@{}
    }

    $pwBytes = script:Get-WLPBytes $Password
    $encKey  = $null; $hmacKey = $null

    try {
        $saltBundle = [System.IO.File]::ReadAllBytes($script:WLP_SALT)
        $saltEnc    = $saltBundle[0..31]
        $saltHMAC   = $saltBundle[32..63]

        $encKey  = script:Invoke-WLPDeriveKey ([System.Text.Encoding]::UTF8.GetString($pwBytes)) $saltEnc  32
        $hmacKey = script:Invoke-WLPDeriveKey ([System.Text.Encoding]::UTF8.GetString($pwBytes)) $saltHMAC 32

        $encBlob   = [System.IO.File]::ReadAllBytes($script:WLP_ENC)
        $storedSig = ([System.IO.File]::ReadAllText($script:WLP_SIG, [System.Text.Encoding]::ASCII)).Trim()

        # Verify HMAC before decrypting (fail fast on tamper)
        $hmac      = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
        $computed  = [BitConverter]::ToString($hmac.ComputeHash($encBlob)).Replace('-','').ToLower()
        $hmac.Dispose()

        # Constant-time comparison (CryptographicOperations.FixedTimeEquals is .NET Core only)
        $aBytes = [System.Text.Encoding]::ASCII.GetBytes($computed)
        $bBytes = [System.Text.Encoding]::ASCII.GetBytes($storedSig)
        $sigEqual = ($aBytes.Length -eq $bBytes.Length)
        $maxLen = [Math]::Max($aBytes.Length, $bBytes.Length)
        for ($i = 0; $i -lt $maxLen; $i++) {
            $aVal = if ($i -lt $aBytes.Length) { $aBytes[$i] } else { 0 }
            $bVal = if ($i -lt $bBytes.Length) { $bBytes[$i] } else { 0 }
            if ($aVal -ne $bVal) { $sigEqual = $false }
        }
        if (-not $sigEqual) {
            script:Write-WLPTamper 'Whitelist HMAC mismatch — file tampered or wrong password. Scan aborted.' $AuditLog
            return $null
        }

        # Decrypt
        $iv     = $encBlob[0..15]
        $cipher = $encBlob[16..($encBlob.Length - 1)]

        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.KeySize = 256; $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $encKey; $aes.IV = $iv
        $plain = $aes.CreateDecryptor().TransformFinalBlock($cipher, 0, $cipher.Length)
        $aes.Dispose()

        $json = [System.Text.Encoding]::UTF8.GetString($plain)
        [Array]::Clear($plain, 0, $plain.Length)

        script:Invoke-WLPAudit 'Read-Encrypted' 'Whitelist decrypted in memory; no plaintext written to disk' $AuditLog
        return $json | ConvertFrom-Json

    } catch {
        if ($_.Exception.Message -notmatch 'HMAC') {
            script:Write-WLPTamper "Whitelist decrypt error (possibly wrong password): $($_.Exception.Message)" $AuditLog
        }
        return $null
    } finally {
        [Array]::Clear($pwBytes, 0, $pwBytes.Length)
        if ($encKey)  { [Array]::Clear($encKey,  0, $encKey.Length)  }
        if ($hmacKey) { [Array]::Clear($hmacKey, 0, $hmacKey.Length) }
    }
}

function Save-EncryptedWhitelist {
    <#
    .SYNOPSIS
        Re-encrypts a modified whitelist object back to whitelist.enc.
        Used by the whitelist editor in QuietMonitor.ps1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $WhitelistObject,
        [Parameter(Mandatory)] [System.Security.SecureString]$Password,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )
    $json = $WhitelistObject | ConvertTo-Json -Depth 10 -Compress
    # Re-use Initialize-WhitelistProtection logic by writing to a temp path then encrypting
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmp, $json, [System.Text.Encoding]::UTF8)
        Initialize-WhitelistProtection -PlainPath $tmp -Password $Password -AuditLog $AuditLog
        script:Invoke-WLPAudit 'Write-Encrypted' 'Whitelist re-encrypted after edit' $AuditLog
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-WhitelistRemoteIntegrity {
    <#
    .SYNOPSIS
        Compares local whitelist.sig against a remote anchor URL.
        Returns $true (OK) or $false (TAMPER DETECTED / abort scan).
        Network failures are treated as non-fatal warnings.
    #>
    [CmdletBinding()]
    param(
        [string]$RemoteUrl,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    if (-not $RemoteUrl) { return $true }
    if (-not (Test-Path $script:WLP_SIG)) { return $true }

    try {
        $localSig = ([System.IO.File]::ReadAllText($script:WLP_SIG, [System.Text.Encoding]::ASCII)).Trim()

        $wc = [System.Net.WebClient]::new()
        $wc.Headers.Add('User-Agent', 'QuietMonitor-IntegrityAnchor/2.0')
        $wc.Headers.Add('Cache-Control', 'no-cache')
        $remoteSig = $wc.DownloadString($RemoteUrl).Trim()
        $wc.Dispose()

        if ($localSig -ne $remoteSig) {
            $preview = if ($remoteSig.Length -ge 16) { $remoteSig.Substring(0,16) } else { $remoteSig }
            script:Write-WLPTamper "REMOTE ANCHOR MISMATCH: local=$($localSig.Substring(0,16))... remote=$preview... — Possible local tamper. Scan aborted until reviewed." $AuditLog
            return $false
        }

        script:Invoke-WLPAudit 'RemoteVerify' "Remote anchor matches — integrity confirmed (URL: $RemoteUrl)" $AuditLog
        return $true

    } catch [System.Net.WebException] {
        Write-Host "  [WhitelistProtection] Remote anchor unreachable (network issue) — skipping remote check." -ForegroundColor Yellow
        script:Invoke-WLPAudit 'RemoteVerify-Skipped' "Network error: $($_.Exception.Message)" $AuditLog
        return $true  # Network unavailability ≠ tamper
    } catch {
        Write-Host "  [WhitelistProtection] Remote check error: $_" -ForegroundColor Yellow
        return $true
    }
}

function Get-WhitelistSigForPublish {
    <#
    .SYNOPSIS
        Returns the local HMAC signature string to be published to
        the remote anchor endpoint (GitHub Gist, Pastebin, self-hosted).
    #>
    if (Test-Path $script:WLP_SIG) {
        return ([System.IO.File]::ReadAllText($script:WLP_SIG, [System.Text.Encoding]::ASCII)).Trim()
    }
    return $null
}

function Invoke-WhitelistIntegrityCheck {
    <#
    .SYNOPSIS
        Orchestrator entry point called by Run-SecuritySuite.ps1.
        Returns finding objects on tamper or policy violations.
    #>
    [CmdletBinding()]
    param(
        [object]$Whitelist,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Check encrypted files exist when protection is supposed to be active
    if ((Test-Path $script:WLP_SALT) -and (-not (Test-Path $script:WLP_ENC) -or -not (Test-Path $script:WLP_SIG))) {
        $findings.Add([PSCustomObject]@{
            Module      = 'WhitelistProtection'
            Severity    = 'Red'; Category = 'IntegrityViolation'
            Title       = 'Whitelist encryption file missing'
            Detail      = 'whitelist.enc or whitelist.sig missing but salt exists — possible tamper/wipe attempt'
            Path        = $script:WLP_BASE
            ActionTaken = 'Alert'; MitreId = 'T1562'; MitreName = 'Impair Defenses'
        })
    }

    # Plaintext whitelist should not exist alongside encrypted version
    $plainPath = 'C:\QuietMonitor\Config\whitelist.json'
    if ((Test-Path $script:WLP_ENC) -and (Test-Path $plainPath)) {
        $findings.Add([PSCustomObject]@{
            Module      = 'WhitelistProtection'
            Severity    = 'Yellow'; Category = 'PolicyViolation'
            Title       = 'Plaintext whitelist.json found alongside encrypted version'
            Detail      = 'Encrypted whitelist is active but plaintext copy still exists on disk — risk of unauthorised modification'
            Path        = $plainPath
            ActionTaken = 'Alert'; MitreId = 'T1553'; MitreName = 'Subvert Trust Controls'
        })
    }

    # Remote anchor check (if configured)
    $cfg = $null
    try {
        $settingsPath = 'C:\QuietMonitor\Config\settings.json'
        if (Test-Path $settingsPath) {
            $cfg = Get-Content $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
        }
    } catch {}

    $remoteUrl = if ($cfg -and $cfg.selfProtect -and $cfg.selfProtect.whitelistRemoteAnchorUrl) { $cfg.selfProtect.whitelistRemoteAnchorUrl } else { $null }
    if ($remoteUrl) {
        $ok = Test-WhitelistRemoteIntegrity -RemoteUrl $remoteUrl -AuditLog $AuditLog
        if (-not $ok) {
            $findings.Add([PSCustomObject]@{
                Module      = 'WhitelistProtection'
                Severity    = 'Red'; Category = 'IntegrityViolation'
                Title       = 'Whitelist remote anchor MISMATCH — possible tamper'
                Detail      = "Local signature does not match remote anchor at $remoteUrl"
                Path        = $script:WLP_SIG
                ActionTaken = 'ScanAborted'; MitreId = 'T1562'; MitreName = 'Impair Defenses'
            })
        }
    }

    return $findings.ToArray()
}
